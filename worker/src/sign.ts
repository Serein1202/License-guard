/**
 * 令牌签发。
 *
 * 令牌格式（类似 JWS Compact，但做了简化）：
 *     base64url(header) . base64url(payload) . base64url(signature)
 *
 * header:  { alg: "Ed25519" | "ES256", kid: "<app_id>", typ: "LIC" }
 * payload: LicenseClaims (JSON)
 *
 * 客户端只需内嵌公钥即可离线验签，不需要任何密钥服务。
 */
import type { Env, LicenseClaims, SignAlg } from "./types";
import { b64uDecode, b64uEncode } from "./util";

const encoder = new TextEncoder();

/** 模块级缓存：同一 isolate 内复用 CryptoKey（Workers 允许缓存 CryptoKey） */
const keyCache = new Map<string, CryptoKey>();

function algName(alg: SignAlg): "Ed25519" | "ES256" {
  return alg === "es256" ? "ES256" : "Ed25519";
}

function jwsAlg(alg: SignAlg): string {
  return alg === "es256" ? "ES256" : "Ed25519";
}

async function importSignKey(env: Env, alg: SignAlg): Promise<CryptoKey> {
  const raw = alg === "es256" ? env.LICENSE_KEY_ES256 : env.LICENSE_KEY_ED25519;
  if (!raw) {
    throw new Error(
      alg === "es256"
        ? "缺少 LICENSE_KEY_ES256 密钥，请执行 wrangler secret put LICENSE_KEY_ES256"
        : "缺少 LICENSE_KEY_ED25519 密钥，请执行 wrangler secret put LICENSE_KEY_ED25519",
    );
  }
  const cacheKey = `${alg}:${raw.slice(-16)}`;
  const hit = keyCache.get(cacheKey);
  if (hit) return hit;

  const der = b64uDecode(raw);
  const key =
    alg === "es256"
      ? await crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
      : await crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, false, ["sign"]);
  keyCache.set(cacheKey, key);
  return key;
}

export async function signPayload(
  env: Env,
  alg: SignAlg,
  appId: string,
  typ: string,
  payload: unknown,
): Promise<string> {
  const header = { alg: jwsAlg(alg), kid: appId, typ };
  const h = b64uEncode(encoder.encode(JSON.stringify(header)));
  const p = b64uEncode(encoder.encode(JSON.stringify(payload)));
  const data = encoder.encode(`${h}.${p}`);

  const key = await importSignKey(env, alg);
  const sig =
    alg === "es256"
      ? await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data)
      : await crypto.subtle.sign("Ed25519", key, data);

  return `${h}.${p}.${b64uEncode(sig)}`;
}

/** 签发授权令牌 */
export async function issueLicenseToken(env: Env, alg: SignAlg, claims: LicenseClaims): Promise<string> {
  return signPayload(env, alg, claims.app, "LIC", claims);
}

/**
 * 签发「服务端时间」凭证。
 * 客户端用它对抗「把系统时间调回过去」这种最朴素的绕过手段。
 */
export async function issueTimeToken(env: Env, alg: SignAlg, appId: string, t: number): Promise<string> {
  return signPayload(env, alg, appId, "TS", { v: 1, t });
}

export { algName };
