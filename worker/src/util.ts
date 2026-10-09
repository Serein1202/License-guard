/**
 * 通用工具：base64url、ID 生成、时间、响应封装、限流
 */
import type { ApiErr, ApiOk } from "./types";

const HTML_ESCAPE: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export function escapeHtml(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => HTML_ESCAPE[c]);
}

/* ------------------------------------------------------------------ */
/* base64 / base64url                                                   */
/* ------------------------------------------------------------------ */

export function b64uEncode(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(s: string): Uint8Array {
  let t = s.replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4 !== 0) t += "=";
  const bin = atob(t);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** 标准 base64（带 padding），用于存放 pkcs8 私钥 */
export function b64Encode(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

export function b64Decode(s: string): Uint8Array {
  let t = s.replace(/-/g, "+").replace(/_/g, "/").trim();
  while (t.length % 4 !== 0) t += "=";
  const bin = atob(t);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* ------------------------------------------------------------------ */
/* ID / 授权码                                                          */
/* ------------------------------------------------------------------ */

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // 去掉易混淆字符 I L O U

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function newId(prefix: string): string {
  const b = randomBytes(10);
  let s = "";
  for (const x of b) s += CROCKFORD[x % 32];
  return `${prefix}_${s.toLowerCase()}`;
}

/** 生成形如 ABCD-EFGH-JKMN-PQRS 的授权码 */
export function newLicenseKey(): string {
  const groups: string[] = [];
  const b = randomBytes(16);
  for (let g = 0; g < 4; g++) {
    let s = "";
    for (let i = 0; i < 4; i++) s += CROCKFORD[b[g * 4 + i] % 32];
    groups.push(s);
  }
  return groups.join("-");
}

/** 规范化用户输入的授权码：去掉所有非字母数字并大写 */
export function normalizeKey(raw: string): string {
  return String(raw || "")
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, "");
}

/** 授权码哈希：SHA-256(规范化后的 key) hex */
export async function hashKey(raw: string): Promise<string> {
  const norm = normalizeKey(raw);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(norm));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* ------------------------------------------------------------------ */
/* 时间                                                                 */
/* ------------------------------------------------------------------ */

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

/** 解析日期字符串为 unix 秒；支持 "2026-12-31" / "2026-12-31 23:59:59" / ISO / 数字 */
export function parseDate(input: unknown): number | null {
  if (input === null || input === undefined || input === "" || input === "never") return null;
  if (typeof input === "number" && Number.isFinite(input)) {
    // 毫秒自动降级为秒
    return input > 1e12 ? Math.floor(input / 1000) : Math.floor(input);
  }
  const s = String(input).trim();
  if (/^\d+$/.test(s)) {
    const n = Number(s);
    return n > 1e12 ? Math.floor(n / 1000) : n;
  }
  // 允许 "YYYY-MM-DD HH:mm:ss" 这种非标准写法
  const norm = s.includes("T") ? s : s.replace(" ", "T");
  const t = Date.parse(norm);
  if (Number.isNaN(t)) throw new Error(`无法解析日期: ${s}`);
  return Math.floor(t / 1000);
}

export function fmtTime(ts: number | null | undefined): string {
  if (!ts) return "永久";
  return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

/* ------------------------------------------------------------------ */
/* HTTP 响应                                                            */
/* ------------------------------------------------------------------ */

export const CORS_HEADERS = {
  "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Max-Age": "86400",
};

export function json<T>(data: T, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify({ ok: true, data } satisfies ApiOk<T>), {
    ...init,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...CORS_HEADERS,
      ...(init.headers || {}),
    },
  });
}

export function fail(code: string, message: string, status = 400, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ ok: false, code, message } satisfies ApiErr), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...CORS_HEADERS,
      ...extra,
    },
  });
}

export function noContent(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

/* ------------------------------------------------------------------ */
/* 鉴权 & 限流                                                          */
/* ------------------------------------------------------------------ */

/** 常量时间字符串比较，避免时序侧信道 */
export function timingSafeEqual(a: string, b: string): boolean {
  const ab = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  let diff = ab.length ^ bb.length;
  const len = Math.max(ab.length, bb.length);
  for (let i = 0; i < len; i++) {
    diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  }
  return diff === 0;
}

export function checkAdmin(req: Request, env: { ADMIN_TOKEN?: string }): boolean {
  if (!env.ADMIN_TOKEN) return false;
  const h = req.headers.get("Authorization") || "";
  const token = h.toLowerCase().startsWith("bearer ") ? h.slice(7).trim() : h.trim();
  if (!token) return false;
  return timingSafeEqual(token, env.ADMIN_TOKEN);
}

/**
 * 基于 KV 的滑动窗口限流。
 * 免费版 KV 每天写入有限，因此窗口粒度放到分钟级。
 */
export async function rateLimit(
  kv: KVNamespace,
  bucket: string,
  limit: number,
  windowSec = 60,
): Promise<boolean> {
  const slot = Math.floor(nowSec() / windowSec);
  const key = `rl:${bucket}:${slot}`;
  const cur = Number((await kv.get(key)) || "0");
  if (cur >= limit) return false;
  // 异步写，不阻塞响应
  await kv.put(key, String(cur + 1), { expirationTtl: windowSec * 2 });
  return true;
}

/** 从 Cloudflare 请求头取客户端信息 */
export function clientMeta(req: Request) {
  const cf = (req as unknown as { cf?: Record<string, unknown> }).cf;
  return {
    ip: req.headers.get("CF-Connecting-IP") || "",
    country: (cf?.country as string) || "",
    ua: req.headers.get("User-Agent") || "",
  };
}
