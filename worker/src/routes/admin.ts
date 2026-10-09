/**
 * 管理端接口 —— 你用它来「给每个软件设置到期时间」。
 *
 * 全部挂在 /admin/api/* 下，需要 Authorization: Bearer <ADMIN_TOKEN>
 */
import type { Env, LicenseRow, ProductRow } from "../types";
import * as db from "../db";
import { clientMeta, fail, hashKey, json, newId, newLicenseKey, normalizeKey, nowSec, parseDate, timingSafeEqual } from "../util";

function ok<T>(data: T) {
  return json(data);
}

async function body(req: Request): Promise<Record<string, unknown>> {
  try {
    return (await req.json()) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function intOrNull(v: unknown): number | null {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

/* ------------------------------------------------------------------ */
/* 路由分发                                                            */
/* ------------------------------------------------------------------ */
export async function handleAdmin(req: Request, env: Env, url: URL): Promise<Response> {
  const path = url.pathname.replace(/^\/admin\/api/, "") || "/";
  const method = req.method.toUpperCase();
  const meta = clientMeta(req);
  const seg = path.split("/").filter(Boolean);

  /* ---------- 登录（唯一免鉴权接口） ---------- */
  if (path === "/login" && method === "POST") {
    const b = await body(req);
    const token = String(b.token || b.password || "");
    if (!env.ADMIN_TOKEN) return fail("NOT_CONFIGURED", "尚未配置 ADMIN_TOKEN", 500);
    if (!timingSafeEqual(token, env.ADMIN_TOKEN)) {
      await db.audit(env, { actor: "admin", action: "login.fail", ip: meta.ip, ua: meta.ua });
      return fail("UNAUTHORIZED", "口令错误", 401);
    }
    await db.audit(env, { actor: "admin", action: "login.ok", ip: meta.ip, ua: meta.ua });
    return ok({ token: env.ADMIN_TOKEN, env: env.ENVIRONMENT || "production" });
  }

  if (path === "/me" && method === "GET") return ok({ env: env.ENVIRONMENT || "production", now: nowSec() });

  /* ---------------------------- 产品 ---------------------------- */
  if (path === "/products" && method === "GET") {
    const rows = await db.listProducts(env);
    return ok(
      rows.map((p) => ({
        ...p,
        features: safeJson(p.features, []),
        license_count: undefined,
      })),
    );
  }

  if (path === "/products" && method === "POST") {
    const b = await body(req);
    const appId = String(b.app_id || "").trim();
    if (!appId || !/^[a-zA-Z0-9_.-]{2,64}$/.test(appId)) {
      return fail("BAD_REQUEST", "app_id 只能包含字母数字和 _ . - ，长度 2-64", 400);
    }
    if (await db.getProductByAppId(env, appId)) return fail("CONFLICT", "app_id 已存在", 409);

    const alg = String(b.sign_alg || "ed25519").toLowerCase();
    if (alg === "es256" && !env.LICENSE_KEY_ES256) return fail("NOT_CONFIGURED", "未配置 LICENSE_KEY_ES256", 500);
    if (alg !== "es256" && !env.LICENSE_KEY_ED25519) return fail("NOT_CONFIGURED", "未配置 LICENSE_KEY_ED25519", 500);

    const p = await db.createProduct(env, {
      app_id: appId,
      name: String(b.name || appId),
      sign_alg: alg,
      default_expires_at: "default_expires_at" in b ? parseDate(b.default_expires_at) : null,
      default_grace_days: intOrNull(b.default_grace_days) ?? 0,
      max_devices: intOrNull(b.max_devices) ?? 1,
      token_ttl_sec: intOrNull(b.token_ttl_sec) ?? 86400,
      heartbeat_sec: intOrNull(b.heartbeat_sec) ?? 21600,
      offline_grace_days: intOrNull(b.offline_grace_days) ?? 7,
      fail_mode: b.fail_mode === "message" ? "message" : "hard",
      exit_code: intOrNull(b.exit_code) ?? 0,
      features: Array.isArray(b.features) ? (b.features as string[]) : [],
    });
    await db.audit(env, { actor: "admin", action: "product.create", target: p.id, detail: { app_id: appId }, ...meta });
    return ok({ ...p, features: safeJson(p.features, []) });
  }

  if (seg[0] === "products" && seg[1]) {
    const id = seg[1];
    if (method === "PATCH" || method === "PUT") {
      const b = await body(req);
      const patch: Record<string, unknown> = {};
      for (const k of ["name", "sign_alg", "default_grace_days", "max_devices", "token_ttl_sec", "heartbeat_sec", "offline_grace_days", "fail_mode", "exit_code", "status"]) {
        if (k in b) patch[k] = b[k];
      }
      if ("features" in b) patch.features = JSON.stringify(b.features ?? []);
      if ("default_expires_at" in b) patch.default_expires_at = parseDate(b.default_expires_at);
      const changed = await db.updateProduct(env, id, patch);
      await db.audit(env, { actor: "admin", action: "product.update", target: id, detail: patch, ...meta });
      return changed ? ok({ updated: true }) : fail("NO_CHANGE", "没有可更新的字段", 400);
    }
    if (method === "DELETE") {
      await db.deleteProduct(env, id);
      await db.audit(env, { actor: "admin", action: "product.delete", target: id, ...meta });
      return ok({ deleted: true });
    }
    if (method === "GET") {
      const p = await db.getProductById(env, id);
      return p ? ok({ ...p, features: safeJson(p.features, []) }) : fail("NOT_FOUND", "产品不存在", 404);
    }
  }

  /* --------------------------- 授权码 --------------------------- */
  if (path === "/licenses" && method === "GET") {
    const r = await db.listLicenses(env, {
      productId: url.searchParams.get("product_id") || undefined,
      q: url.searchParams.get("q") || undefined,
      status: url.searchParams.get("status") || undefined,
      limit: Number(url.searchParams.get("limit") || 50),
      offset: Number(url.searchParams.get("offset") || 0),
    });
    return ok({
      total: r.total,
      items: r.rows.map((l) => ({ ...l, key_display: unmask(l.key_display) })),
      server_time: nowSec(),
    });
  }

  if (path === "/licenses" && method === "POST") {
    const b = await body(req);
    const productId = String(b.product_id || "");
    const product = await db.getProductById(env, productId);
    if (!product) return fail("NOT_FOUND", "产品不存在", 404);

    const countRaw = intOrNull(b.count) ?? 1;
    const count = Math.min(Math.max(countRaw, 1), 200);

    let expiresAt: number | null;
    if ("expires_at" in b) expiresAt = parseDate(b.expires_at);
    else if (b.expires_in_days !== undefined && b.expires_in_days !== null && b.expires_in_days !== "")
      expiresAt = nowSec() + (intOrNull(b.expires_in_days) ?? 0) * 86400;
    else expiresAt = product.default_expires_at;

    const graceDays = "grace_days" in b ? intOrNull(b.grace_days) : null;
    const maxDevices = "max_devices" in b ? intOrNull(b.max_devices) : null;
    const customer = b.customer ? String(b.customer) : null;
    const note = b.note ? String(b.note) : null;

    const created: { id: string; key: string; expires_at: number | null; hard_expires_at: number | null }[] = [];
    for (let i = 0; i < count; i++) {
      const display = newLicenseKey();
      const id = newId("lic");
      const row = await db.createLicense(env, {
        id,
        keyDisplay: display,
        keyHash: await hashKey(display),
        productId: product.id,
        customer,
        expiresAt,
        graceDays,
        maxDevices,
        note,
      });
      const grace = row.grace_days ?? product.default_grace_days ?? 0;
      created.push({
        id: row.id,
        key: display,
        expires_at: expiresAt,
        hard_expires_at: expiresAt === null ? null : expiresAt + grace * 86400,
      });
    }

    await db.audit(env, {
      actor: "admin",
      action: "license.create",
      target: product.id,
      detail: { count, expires_at: expiresAt, customer },
      ...meta,
    });
    return ok({ created, count });
  }

  if (path === "/licenses/import" && method === "POST") {
    const b = await body(req);
    const productId = String(b.product_id || "");
    const product = await db.getProductById(env, productId);
    if (!product) return fail("NOT_FOUND", "产品不存在", 404);
    const keys: string[] = Array.isArray(b.keys) ? (b.keys as string[]).map((k) => String(k).trim()).filter(Boolean) : [];
    if (!keys.length) return fail("BAD_REQUEST", "keys 为空", 400);

    const expiresAt = "expires_at" in b ? parseDate(b.expires_at) : product.default_expires_at;
    const out: string[] = [];
    for (const k of keys.slice(0, 500)) {
      if (await db.getLicenseByKeyHash(env, await hashKey(k))) continue;
      await db.createLicense(env, {
        id: newId("lic"),
        keyDisplay: k,
        keyHash: await hashKey(k),
        productId: product.id,
        customer: b.customer ? String(b.customer) : null,
        expiresAt,
        graceDays: "grace_days" in b ? intOrNull(b.grace_days) : null,
        maxDevices: "max_devices" in b ? intOrNull(b.max_devices) : null,
        note: b.note ? String(b.note) : null,
      });
      out.push(k);
    }
    await db.audit(env, { actor: "admin", action: "license.import", target: product.id, detail: { imported: out.length }, ...meta });
    return ok({ imported: out.length, keys: out });
  }

  if (seg[0] === "licenses" && seg[1]) {
    const id = seg[1];

    if (method === "GET" && !seg[2]) {
      const l = await db.getLicenseById(env, id);
      if (!l) return fail("NOT_FOUND", "授权码不存在", 404);
      const product = await db.getProductById(env, l.product_id);
      const acts = await db.listActivations(env, id);
      return ok({ ...l, key_display: unmask(l.key_display), activations: acts, product });
    }

    /** 核心：修改到期时间 / 状态 */
    if (method === "PATCH" || method === "PUT") {
      const b = await body(req);
      const patch: Record<string, unknown> = {};
      if ("expires_at" in b) patch.expires_at = parseDate(b.expires_at);
      if ("expires_in_days" in b && b.expires_in_days !== null && b.expires_in_days !== "") {
        const d = intOrNull(b.expires_in_days);
        patch.expires_at = d === null || d < 0 ? null : nowSec() + d * 86400;
      }
      if ("customer" in b) patch.customer = b.customer ? String(b.customer) : null;
      if ("note" in b) patch.note = b.note ? String(b.note) : null;
      if ("grace_days" in b) patch.grace_days = intOrNull(b.grace_days);
      if ("max_devices" in b) patch.max_devices = intOrNull(b.max_devices);
      if ("status" in b) {
        const s = String(b.status);
        if (!["active", "suspended", "revoked"].includes(s)) return fail("BAD_REQUEST", "status 非法", 400);
        patch.status = s;
      }
      if (!Object.keys(patch).length) return fail("BAD_REQUEST", "没有可更新的字段", 400);

      const changed = await db.updateLicense(env, id, patch);
      await db.audit(env, { actor: "admin", action: "license.update", target: id, detail: patch, ...meta });
      if (!changed) return fail("NOT_FOUND", "授权码不存在或未变更", 404);

      const l = await db.getLicenseById(env, id);
      return ok({ ...l, key_display: unmask(l!.key_display) });
    }

    if (method === "DELETE") {
      await db.deleteLicense(env, id);
      await db.audit(env, { actor: "admin", action: "license.delete", target: id, ...meta });
      return ok({ deleted: true });
    }

    if (seg[2] === "activations" && method === "GET") {
      return ok(await db.listActivations(env, id));
    }

    if (seg[2] === "reset" && method === "POST") {
      const acts = await db.listActivations(env, id);
      for (const a of acts) await db.deleteActivation(env, a.id);
      await db.audit(env, { actor: "admin", action: "license.reset", target: id, detail: { cleared: acts.length }, ...meta });
      return ok({ cleared: acts.length });
    }
  }

  if (seg[0] === "activations" && seg[1] && method === "DELETE") {
    await db.deleteActivation(env, seg[1]);
    await db.audit(env, { actor: "admin", action: "activation.delete", target: seg[1], ...meta });
    return ok({ deleted: true });
  }

  /* ---------------------------- 其他 ---------------------------- */
  if (path === "/stats" && method === "GET") return ok(await db.stats(env));
  if (path === "/audit" && method === "GET") return ok(await db.listAudit(env, Number(url.searchParams.get("limit") || 100)));

  if (path === "/pubkeys" && method === "GET") {
    return ok({
      ed25519_configured: Boolean(env.LICENSE_KEY_ED25519),
      es256_configured: Boolean(env.LICENSE_KEY_ES256),
      hint: "公钥在客户端内嵌；用 node scripts/gen-keys.mjs 生成密钥时会一并输出",
    });
  }

  return fail("NOT_FOUND", `未知管理接口: ${method} ${path}`, 404);
}

/* ---------------------------- 工具 ---------------------------- */

function safeJson<T>(s: string, fallback: T): T {
  try {
    return JSON.parse(s) as T;
  } catch {
    return fallback;
  }
}

/** 数据库中 key_display 存的就是明文，这里原样返回；保留函数便于将来改成掩码 */
function unmask(k: string): string {
  return k;
}

export type { LicenseRow, ProductRow };
