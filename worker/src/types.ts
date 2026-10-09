/**
 * 全局类型定义
 */

export interface Env {
  DB: D1Database;
  KV: KVNamespace;
  ENVIRONMENT?: string;
  ADMIN_CORS_ORIGIN?: string;

  /** 管理后台口令，wrangler secret put ADMIN_TOKEN */
  ADMIN_TOKEN: string;
  /** Ed25519 私钥 pkcs8 DER (base64)，wrangler secret put LICENSE_KEY_ED25519 */
  LICENSE_KEY_ED25519?: string;
  /** ECDSA P-256 私钥 pkcs8 DER (base64)，wrangler secret put LICENSE_KEY_ES256 */
  LICENSE_KEY_ES256?: string;
}

export type SignAlg = "ed25519" | "es256";
export type FailMode = "hard" | "message";
export type LicenseStatus = "active" | "suspended" | "revoked";
export type ProductStatus = "active" | "disabled";

export interface ProductRow {
  id: string;
  app_id: string;
  name: string;
  sign_alg: SignAlg;
  default_expires_at: number | null;
  default_grace_days: number;
  max_devices: number;
  token_ttl_sec: number;
  heartbeat_sec: number;
  offline_grace_days: number;
  fail_mode: FailMode;
  exit_code: number;
  features: string;
  status: ProductStatus;
  created_at: number;
  updated_at: number;
}

export interface LicenseRow {
  id: string;
  key_hash: string;
  key_display: string;
  product_id: string;
  customer: string | null;
  expires_at: number | null;
  grace_days: number | null;
  max_devices: number | null;
  status: LicenseStatus;
  note: string | null;
  created_at: number;
  updated_at: number;
}

export interface ActivationRow {
  id: string;
  license_id: string;
  machine_id: string;
  machine_name: string | null;
  app_version: string | null;
  platform: string | null;
  ip: string | null;
  country: string | null;
  activated_at: number;
  last_seen_at: number;
}

/** 下发给客户端的策略快照 */
export interface PolicySnapshot {
  heartbeat_sec: number;
  token_ttl_sec: number;
  offline_grace_days: number;
  fail_mode: FailMode;
  exit_code: number;
  max_devices: number;
}

/** 签发进令牌的载荷 */
export interface LicenseClaims {
  v: 1;
  /** 授权码 id */
  sub: string;
  /** 产品 app_id */
  app: string;
  /** 绑定的机器码 */
  mid: string;
  /** 客户标识 */
  cus?: string;
  /** 签发时间 */
  iat: number;
  /** 令牌本身失效时间（需重新联网校验） */
  exp: number;
  /** 授权硬到期时间（含宽限），客户端超过此值必须停用 */
  hexp: number | null;
  /** 授权名义到期时间（不含宽限） */
  aexp: number | null;
  /** 功能开关 */
  feat: string[];
  /** 下发时的服务端时间，作为客户端时间锚点 */
  srv: number;
}

/** 统一的 API 响应 */
export interface ApiOk<T> {
  ok: true;
  data: T;
}
export interface ApiErr {
  ok: false;
  code: string;
  message: string;
}
export type ApiResp<T> = ApiOk<T> | ApiErr;
