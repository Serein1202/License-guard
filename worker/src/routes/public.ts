/**
 * 面向客户端（App）的公开接口。
 * 这些接口不需要任何 API Key —— 授权码本身就是凭证。
 */
import type { Env, LicenseClaims, ProductRow } from "../types";
import {
  countActivations,
  getLicenseByKeyHash,
  getProductByAppId,
  deleteActivationByMachine,
  upsertActivation,
  audit,
} from "../db";
import { DAY, evaluate, policyOf } from "../evaluate";
import { issueLicenseToken, issueTimeToken } from "../sign";
import {
  clientMeta,
  fail,
  hashKey,
  json,
  normalizeKey,
  nowSec,
  rateLimit,
} from "../util";

interface ActivateBody {
  app_id?: string;
  key?: string;
  license_key?: string;
  machine_id?: string;
  machine_name?: string;
  app_version?: string;
  platform?: string;
}

async function readBody(req: Request): Promise<ActivateBody> {
  try {
    return (await req.json()) as ActivateBody;
  } catch {
    return {};
  }
}

/** 组装下发给客户端的完整响应体 */
async function buildActivationResponse(
  env: Env,
  product: ProductRow,
  licenseId: string,
  machineId: string,
  customer: string | null,
  features: string[],
  verdict: Awaited<ReturnType<typeof evaluate>>,
  /** 本次 upsert 之后该授权码下真实存在的设备数 */
  activations: number,
) {
  const now = nowSec();
  const tokenTtl = product.token_ttl_sec || 86400;

  const claims: LicenseClaims = {
    v: 1,
    sub: licenseId,
    app: product.app_id,
    mid: machineId,
    cus: customer ?? undefined,
    iat: now,
    // 令牌本身的有效期：取 min(令牌 TTL, 硬到期时间)
    exp: verdict.hexp === null ? now + tokenTtl : Math.min(now + tokenTtl, verdict.hexp),
    hexp: verdict.hexp,
    aexp: verdict.aexp,
    feat: features,
    srv: now,
  };

  const token = await issueLicenseToken(env, product.sign_alg, claims);

  return {
    status: verdict.code === "OK_GRACE" ? "grace" : "active",
    code: verdict.code,
    message: verdict.message,
    sign_alg: product.sign_alg,
    token,
    server_time: now,
    policy: verdict.policy,
    license: {
      id: licenseId,
      customer,
      features,
      /** 名义到期时间，到点后进入宽限期 */
      expires_at: verdict.aexp,
      /** 宽限结束时间，超过必须停止使用 */
      hard_expires_at: verdict.hexp,
      grace_days: verdict.graceDays,
      activations,
      max_devices: product.max_devices,
    },
  };
}

/* ------------------------------------------------------------------ */
/* GET /v1/time?app_id=xxx   服务端时间（签名），用于对抗改系统时间        */
/* ------------------------------------------------------------------ */
export async function handleTime(req: Request, env: Env, url: URL): Promise<Response> {
  const appId = url.searchParams.get("app_id") || "";
  const product = await getProductByAppId(env, appId);
  if (!product) return fail("APP_UNKNOWN", "未知应用", 404);

  const t = nowSec();
  const token = await issueTimeToken(env, product.sign_alg, product.app_id, t);
  return json({ server_time: t, sign_alg: product.sign_alg, token });
}

/* ------------------------------------------------------------------ */
/* POST /v1/activate   首次激活（占用一个设备位）                        */
/* ------------------------------------------------------------------ */
export async function handleActivate(req: Request, env: Env, url: URL): Promise<Response> {
  const body = await readBody(req);
  const appId = String(body.app_id || url.searchParams.get("app_id") || "").trim();
  const rawKey = body.key || body.license_key || url.searchParams.get("key") || "";
  const machineId = String(body.machine_id || "").trim();

  if (!appId) return fail("BAD_REQUEST", "缺少 app_id", 400);
  if (!rawKey) return fail("BAD_REQUEST", "缺少授权码", 400);
  if (!machineId) return fail("BAD_REQUEST", "缺少 machine_id", 400);

  const meta = clientMeta(req);
  if (!(await rateLimit(env.KV, `act:${meta.ip}`, 30))) {
    return fail("RATE_LIMITED", "请求过于频繁，请稍后再试", 429);
  }

  const product = await getProductByAppId(env, appId);
  if (!product) return fail("APP_UNKNOWN", "未知应用", 404);

  const license = await getLicenseByKeyHash(env, await hashKey(rawKey));
  if (!license || license.product_id !== product.id) {
    await audit(env, { actor: "app", action: "activate.fail", target: normalizeKey(rawKey).slice(0, 6) + "***", detail: "KEY_NOT_FOUND", ip: meta.ip });
    return fail("KEY_NOT_FOUND", "授权码不存在", 404);
  }

  const verdict = await evaluate(env, { product, license, machineId, requireActivation: false });
  if (!verdict.allowed) {
    await audit(env, { actor: "app", action: "activate.deny", target: license.id, detail: verdict.code, ip: meta.ip });
    return fail(verdict.code, verdict.message, 403);
  }

  await upsertActivation(env, {
    licenseId: license.id,
    machineId,
    machineName: body.machine_name ?? null,
    appVersion: body.app_version ?? null,
    platform: body.platform ?? null,
    ip: meta.ip,
    country: meta.country,
  });

  let features: string[] = [];
  try {
    features = JSON.parse(product.features || "[]") as string[];
  } catch { /* ignore */ }

  await audit(env, { actor: "app", action: "activate.ok", target: license.id, detail: { machineId, platform: body.platform }, ip: meta.ip });

  return json(
    await buildActivationResponse(
      env, product, license.id, machineId, license.customer, features, verdict,
      await countActivations(env, license.id),
    ),
  );
}

/* ------------------------------------------------------------------ */
/* POST /v1/verify   校验（心跳 / 续令牌），不新增设备位                  */
/* ------------------------------------------------------------------ */
export async function handleVerify(req: Request, env: Env, url: URL): Promise<Response> {
  const body = await readBody(req);
  const appId = String(body.app_id || url.searchParams.get("app_id") || "").trim();
  const rawKey = body.key || body.license_key || url.searchParams.get("key") || "";
  const machineId = String(body.machine_id || "").trim();

  if (!appId || !rawKey || !machineId) return fail("BAD_REQUEST", "缺少参数", 400);

  const meta = clientMeta(req);
  if (!(await rateLimit(env.KV, `vfy:${meta.ip}`, 120))) {
    return fail("RATE_LIMITED", "请求过于频繁", 429);
  }

  const product = await getProductByAppId(env, appId);
  if (!product) return fail("APP_UNKNOWN", "未知应用", 404);

  const license = await getLicenseByKeyHash(env, await hashKey(rawKey));
  if (!license || license.product_id !== product.id) return fail("KEY_NOT_FOUND", "授权码不存在", 404);

  // 注意：verify 不会占用新的设备位。
  // 未激活过的设备必须先走 /v1/activate，否则这里返回 DEVICE_NOT_ACTIVATED。
  const verdict = await evaluate(env, { product, license, machineId, requireActivation: true });
  if (!verdict.allowed) {
    await audit(env, { actor: "app", action: "verify.deny", target: license.id, detail: verdict.code, ip: meta.ip });
    return fail(verdict.code, verdict.message, 403);
  }

  await upsertActivation(env, {
    licenseId: license.id,
    machineId,
    machineName: body.machine_name ?? null,
    appVersion: body.app_version ?? null,
    platform: body.platform ?? null,
    ip: meta.ip,
    country: meta.country,
  });

  let features: string[] = [];
  try {
    features = JSON.parse(product.features || "[]") as string[];
  } catch { /* ignore */ }

  return json(
    await buildActivationResponse(
      env, product, license.id, machineId, license.customer, features, verdict,
      await countActivations(env, license.id),
    ),
  );
}

/** 心跳：语义同 verify，单独暴露方便客户端区分日志 */
export const handleHeartbeat = handleVerify;

/* ------------------------------------------------------------------ */
/* POST /v1/deactivate   解绑当前设备                                    */
/* ------------------------------------------------------------------ */
export async function handleDeactivate(req: Request, env: Env, url: URL): Promise<Response> {
  const body = await readBody(req);
  const appId = String(body.app_id || url.searchParams.get("app_id") || "").trim();
  const rawKey = body.key || body.license_key || url.searchParams.get("key") || "";
  const machineId = String(body.machine_id || "").trim();
  if (!appId || !rawKey || !machineId) return fail("BAD_REQUEST", "缺少参数", 400);

  const product = await getProductByAppId(env, appId);
  if (!product) return fail("APP_UNKNOWN", "未知应用", 404);

  const license = await getLicenseByKeyHash(env, await hashKey(rawKey));
  if (!license || license.product_id !== product.id) return fail("KEY_NOT_FOUND", "授权码不存在", 404);

  await deleteActivationByMachine(env, license.id, machineId);
  await audit(env, { actor: "app", action: "deactivate", target: license.id, detail: { machineId }, ...clientMeta(req) });
  return json({ released: true });
}

/* ------------------------------------------------------------------ */
/* GET /v1/meta?app_id=xxx   下发策略与公钥，便于客户端自检               */
/* ------------------------------------------------------------------ */
export async function handleMeta(req: Request, env: Env, url: URL): Promise<Response> {
  const appId = url.searchParams.get("app_id") || "";
  const product = await getProductByAppId(env, appId);
  if (!product) return fail("APP_UNKNOWN", "未知应用", 404);
  return json({
    app_id: product.app_id,
    name: product.name,
    sign_alg: product.sign_alg,
    policy: policyOf(product),
    default_expires_at: product.default_expires_at,
    now: nowSec(),
    day: DAY,
  });
}
