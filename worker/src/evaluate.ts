/**
 * 授权状态裁决 —— 后端唯一判定入口。
 * 所有「这台设备还能不能用」的判断都在这里，客户端只是执行者。
 */
import type { Env, LicenseRow, PolicySnapshot, ProductRow } from "./types";
import { countActivations, getActivation } from "./db";
import { nowSec } from "./util";

export const DAY = 86400;

export type VerdictCode =
  | "OK_ACTIVE"
  | "OK_GRACE"
  | "APP_UNKNOWN"
  | "APP_DISABLED"
  | "KEY_NOT_FOUND"
  | "LICENSE_REVOKED"
  | "LICENSE_SUSPENDED"
  | "LICENSE_EXPIRED"
  | "DEVICE_LIMIT"
  | "DEVICE_NOT_ACTIVATED"
  | "BLOCKED";

export interface Verdict {
  allowed: boolean;
  code: VerdictCode;
  message: string;
  /** 名义到期时间（不含宽限） */
  aexp: number | null;
  /** 硬到期时间（含宽限），超过即必须停用 */
  hexp: number | null;
  graceDays: number;
  policy: PolicySnapshot;
  licenseId: string;
  activations: number;
}

export function policyOf(p: ProductRow): PolicySnapshot {
  return {
    heartbeat_sec: p.heartbeat_sec,
    token_ttl_sec: p.token_ttl_sec,
    offline_grace_days: p.offline_grace_days,
    fail_mode: p.fail_mode,
    exit_code: p.exit_code,
    max_devices: p.max_devices,
  };
}

export interface EvaluateInput {
  product: ProductRow | null;
  license: LicenseRow | null;
  machineId?: string | null;
  /** 是否要求该机器已激活（false 用于首次激活场景） */
  requireActivation: boolean;
  blocked?: boolean;
}

export async function evaluate(env: Env, input: EvaluateInput): Promise<Verdict> {
  const { product, license, machineId, requireActivation } = input;
  const now = nowSec();

  const fallbackPolicy: PolicySnapshot = {
    heartbeat_sec: 21600,
    token_ttl_sec: 86400,
    offline_grace_days: 0,
    fail_mode: "hard",
    exit_code: 0,
    max_devices: 1,
  };

  const deny = (code: VerdictCode, message: string, policy = fallbackPolicy): Verdict => ({
    allowed: false,
    code,
    message,
    aexp: null,
    hexp: null,
    graceDays: 0,
    policy,
    licenseId: license?.id ?? "",
    activations: 0,
  });

  if (!product) return deny("APP_UNKNOWN", "未知应用");
  if (product.status !== "active") return deny("APP_DISABLED", "该应用已被停用", policyOf(product));

  const policy = policyOf(product);
  if (!license) return deny("KEY_NOT_FOUND", "授权码不存在", policy);

  // 名义到期 / 宽限 / 硬到期
  const aexp = license.expires_at ?? product.default_expires_at ?? null;
  const graceDays = license.grace_days ?? product.default_grace_days ?? 0;
  const hexp = aexp === null ? null : aexp + graceDays * DAY;

  const base = {
    aexp,
    hexp,
    graceDays,
    policy,
    licenseId: license.id,
    activations: await countActivations(env, license.id),
  };

  if (input.blocked) {
    return { allowed: false, code: "BLOCKED", message: "该授权已被封禁", ...base };
  }

  if (license.status === "revoked") {
    return { allowed: false, code: "LICENSE_REVOKED", message: "授权已被吊销", ...base };
  }
  if (license.status === "suspended") {
    return { allowed: false, code: "LICENSE_SUSPENDED", message: "授权已被暂停", ...base };
  }

  // ── 到期判定（核心）──────────────────────────────────────────────
  if (hexp !== null && now > hexp) {
    return {
      allowed: false,
      code: "LICENSE_EXPIRED",
      message: `授权已于 ${new Date(aexp! * 1000).toISOString().slice(0, 10)} 到期`,
      ...base,
    };
  }

  // ── 设备数判定 ──────────────────────────────────────────────────
  if (machineId) {
    const act = await getActivation(env, license.id, machineId);
    const maxDevices = license.max_devices ?? product.max_devices ?? 1;
    if (!act && requireActivation) {
      return { allowed: false, code: "DEVICE_NOT_ACTIVATED", message: "该设备尚未激活", ...base };
    }
    if (!act && base.activations >= maxDevices) {
      return {
        allowed: false,
        code: "DEVICE_LIMIT",
        message: `授权设备数已达上限（${maxDevices}），请先在后台解绑其他设备`,
        ...base,
      };
    }
  }

  const inGrace = aexp !== null && now > aexp;
  return {
    allowed: true,
    code: inGrace ? "OK_GRACE" : "OK_ACTIVE",
    message: inGrace ? "已进入宽限期，请尽快续期" : "正常",
    ...base,
  };
}
