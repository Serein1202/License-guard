/**
 * D1 数据访问层
 */
import type { ActivationRow, Env, LicenseRow, ProductRow } from "./types";
import { newId, nowSec } from "./util";

/* ---------------------------- 产品 ---------------------------- */

export async function getProductByAppId(env: Env, appId: string): Promise<ProductRow | null> {
  return env.DB.prepare("SELECT * FROM products WHERE app_id = ?1").bind(appId).first<ProductRow>();
}

export async function getProductById(env: Env, id: string): Promise<ProductRow | null> {
  return env.DB.prepare("SELECT * FROM products WHERE id = ?1").bind(id).first<ProductRow>();
}

export async function listProducts(env: Env): Promise<ProductRow[]> {
  const r = await env.DB.prepare("SELECT * FROM products ORDER BY created_at DESC").all<ProductRow>();
  return r.results ?? [];
}

export async function createProduct(
  env: Env,
  p: {
    app_id: string;
    name: string;
    sign_alg?: string;
    default_expires_at?: number | null;
    default_grace_days?: number;
    max_devices?: number;
    token_ttl_sec?: number;
    heartbeat_sec?: number;
    offline_grace_days?: number;
    fail_mode?: string;
    exit_code?: number;
    features?: string[];
  },
): Promise<ProductRow> {
  const id = newId("prod");
  const ts = nowSec();
  await env.DB.prepare(
    `INSERT INTO products
      (id, app_id, name, sign_alg, default_expires_at, default_grace_days, max_devices,
       token_ttl_sec, heartbeat_sec, offline_grace_days, fail_mode, exit_code, features, status, created_at, updated_at)
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'active',?14,?14)`,
  )
    .bind(
      id,
      p.app_id,
      p.name,
      (p.sign_alg || "ed25519").toLowerCase(),
      p.default_expires_at ?? null,
      p.default_grace_days ?? 0,
      p.max_devices ?? 1,
      p.token_ttl_sec ?? 86400,
      p.heartbeat_sec ?? 21600,
      p.offline_grace_days ?? 7,
      p.fail_mode ?? "hard",
      p.exit_code ?? 0,
      JSON.stringify(p.features ?? []),
      ts,
    )
    .run();
  return (await getProductById(env, id))!;
}

const PRODUCT_PATCHABLE = new Set([
  "name",
  "sign_alg",
  "default_expires_at",
  "default_grace_days",
  "max_devices",
  "token_ttl_sec",
  "heartbeat_sec",
  "offline_grace_days",
  "fail_mode",
  "exit_code",
  "status",
]);

export async function updateProduct(env: Env, id: string, patch: Record<string, unknown>): Promise<boolean> {
  const sets: string[] = [];
  const vals: unknown[] = [];
  let i = 1;
  for (const [k, v] of Object.entries(patch)) {
    if (!PRODUCT_PATCHABLE.has(k)) continue;
    sets.push(`${k} = ?${i++}`);
    vals.push(v);
  }
  if (!sets.length) return false;
  sets.push(`updated_at = ?${i++}`);
  vals.push(nowSec());
  vals.push(id);
  const sql = `UPDATE products SET ${sets.join(", ")} WHERE id = ?${i}`;
  const res = await env.DB.prepare(sql).bind(...vals).run();
  return (res.meta?.changes ?? 0) > 0;
}

export async function deleteProduct(env: Env, id: string): Promise<void> {
  await env.DB.prepare("DELETE FROM products WHERE id = ?1").bind(id).run();
}

/* --------------------------- 许可证 --------------------------- */

export async function getLicenseByKeyHash(env: Env, hash: string): Promise<LicenseRow | null> {
  return env.DB.prepare("SELECT * FROM licenses WHERE key_hash = ?1").bind(hash).first<LicenseRow>();
}

export async function getLicenseById(env: Env, id: string): Promise<LicenseRow | null> {
  return env.DB.prepare("SELECT * FROM licenses WHERE id = ?1").bind(id).first<LicenseRow>();
}

export async function listLicenses(
  env: Env,
  opts: { productId?: string; q?: string; status?: string; limit?: number; offset?: number },
): Promise<{ rows: (LicenseRow & { activation_count: number })[]; total: number }> {
  const where: string[] = [];
  const vals: unknown[] = [];
  let i = 1;

  if (opts.productId) {
    where.push(`l.product_id = ?${i++}`);
    vals.push(opts.productId);
  }
  if (opts.status) {
    where.push(`l.status = ?${i++}`);
    vals.push(opts.status);
  }
  if (opts.q) {
    where.push(`(l.key_display LIKE ?${i} OR l.customer LIKE ?${i} OR l.note LIKE ?${i})`);
    vals.push(`%${opts.q}%`);
    i++;
  }
  const w = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const totalRow = await env.DB.prepare(`SELECT COUNT(*) AS c FROM licenses l ${w}`)
    .bind(...vals)
    .first<{ c: number }>();

  const limit = Math.min(Math.max(opts.limit ?? 50, 1), 200);
  const offset = Math.max(opts.offset ?? 0, 0);

  const rows = await env.DB.prepare(
    `SELECT l.*, (SELECT COUNT(*) FROM activations a WHERE a.license_id = l.id) AS activation_count
       FROM licenses l ${w}
      ORDER BY l.created_at DESC
      LIMIT ?${i++} OFFSET ?${i++}`,
  )
    .bind(...vals, limit, offset)
    .all<LicenseRow & { activation_count: number }>();

  return { rows: rows.results ?? [], total: totalRow?.c ?? 0 };
}

export async function createLicense(
  env: Env,
  p: {
    id: string;
    keyDisplay: string;
    keyHash: string;
    productId: string;
    customer?: string | null;
    expiresAt?: number | null;
    graceDays?: number | null;
    maxDevices?: number | null;
    note?: string | null;
  },
): Promise<LicenseRow> {
  const ts = nowSec();
  await env.DB.prepare(
    `INSERT INTO licenses
      (id, key_hash, key_display, product_id, customer, expires_at, grace_days, max_devices, status, note, created_at, updated_at)
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'active',?9,?10,?10)`,
  )
    .bind(
      p.id,
      p.keyHash,
      p.keyDisplay,
      p.productId,
      p.customer ?? null,
      p.expiresAt ?? null,
      p.graceDays ?? null,
      p.maxDevices ?? null,
      p.note ?? null,
      ts,
    )
    .run();
  return (await getLicenseById(env, p.id))!;
}

const LICENSE_PATCHABLE = new Set([
  "customer",
  "expires_at",
  "grace_days",
  "max_devices",
  "status",
  "note",
]);

export async function updateLicense(env: Env, id: string, patch: Record<string, unknown>): Promise<boolean> {
  const sets: string[] = [];
  const vals: unknown[] = [];
  let i = 1;
  for (const [k, v] of Object.entries(patch)) {
    if (!LICENSE_PATCHABLE.has(k)) continue;
    sets.push(`${k} = ?${i++}`);
    vals.push(v);
  }
  if (!sets.length) return false;
  sets.push(`updated_at = ?${i++}`);
  vals.push(nowSec());
  vals.push(id);
  const res = await env.DB.prepare(`UPDATE licenses SET ${sets.join(", ")} WHERE id = ?${i}`)
    .bind(...vals)
    .run();
  return (res.meta?.changes ?? 0) > 0;
}

export async function deleteLicense(env: Env, id: string): Promise<void> {
  await env.DB.prepare("DELETE FROM licenses WHERE id = ?1").bind(id).run();
}

/* --------------------------- 激活记录 --------------------------- */

export async function getActivation(
  env: Env,
  licenseId: string,
  machineId: string,
): Promise<ActivationRow | null> {
  return env.DB.prepare("SELECT * FROM activations WHERE license_id = ?1 AND machine_id = ?2")
    .bind(licenseId, machineId)
    .first<ActivationRow>();
}

export async function countActivations(env: Env, licenseId: string): Promise<number> {
  const r = await env.DB.prepare("SELECT COUNT(*) AS c FROM activations WHERE license_id = ?1")
    .bind(licenseId)
    .first<{ c: number }>();
  return r?.c ?? 0;
}

export async function listActivations(env: Env, licenseId: string): Promise<ActivationRow[]> {
  const r = await env.DB.prepare(
    "SELECT * FROM activations WHERE license_id = ?1 ORDER BY last_seen_at DESC",
  )
    .bind(licenseId)
    .all<ActivationRow>();
  return r.results ?? [];
}

/**
 * 指纹迁移结果。
 *
 * signId      —— 写进令牌 mid 的值，必须是**客户端自己算出来的那个**指纹，
 *                否则客户端校验 mid 时会判 MACHINE_MISMATCH。
 * canonicalId —— 数据库里这台设备的规范主键，用于设备数判定、心跳刷新、解绑。
 *
 * 两者在正常路径上相同；只有「用户把软件降级回旧 SDK」时才会分叉：
 * 旧 SDK 只上报 v1 指纹，服务端靠 machine_id_alt 认回记录，但令牌 mid 仍要回 v1。
 */
export interface ResolvedMachine {
  signId: string;
  canonicalId: string;
}

/**
 * `activations.machine_id_alt` 列是否可用。null = 还没探测过。
 *
 * 这一列是 v2 指纹那次改版新增的，已有实例靠 ensureSchema 里的 ALTER 补上。
 * 万一 ALTER 失败（权限、PRAGMA 差异等），这里会探测到 false 并缓存住，
 * 让主链路退化成「不认降级」继续跑 —— 绝不能因为一个兼容列把激活打挂。
 */
let altColumn: boolean | null = null;

async function altColumnAvailable(env: Env): Promise<boolean> {
  if (altColumn !== null) return altColumn;
  try {
    await env.DB.prepare("SELECT machine_id_alt FROM activations LIMIT 1").run();
    altColumn = true;
  } catch {
    console.error("[license-guard] activations.machine_id_alt 不可用，降级兼容已关闭");
    altColumn = false;
  }
  return altColumn;
}

/**
 * 把旧版指纹的激活记录迁移到新指纹，并处理反向兼容。
 *
 * 改版历史：v1 指纹把 MachineName / OSVersion / arch 也拼进了哈希，
 * 用户改电脑名或升级系统就会导致指纹漂移、白占一个设备位。
 * v2 指纹去掉了这些可变因子，因此老客户端升级后上报的是新 machine_id。
 * 这里让服务端认旧账：命中旧记录就地把 machine_id 改成新值，同时把旧值
 * 留在 machine_id_alt —— 这样用户把软件降级回旧版本时还能认回同一台设备，
 * 不会因为「记录已经叫 v2 了」而被判 DEVICE_NOT_ACTIVATED。
 *
 * @param machineId 当前（新）指纹
 * @param legacyMachineId 旧算法算出的指纹，客户端通过 machine_id_alt 上报
 */
export async function resolveMachineId(
  env: Env,
  licenseId: string,
  machineId: string,
  legacyMachineId?: string | null,
): Promise<ResolvedMachine> {
  const legacy = (legacyMachineId || "").trim();

  /* 1) 当前指纹直接命中主键 —— 最常见路径，一次查询 */
  const direct = await getActivation(env, licenseId, machineId);
  if (direct) return { signId: machineId, canonicalId: machineId };

  /* 2) 当前指纹命中某条记录的 machine_id_alt —— 说明这是降级回旧 SDK 的机器。
        只刷新原记录（canonicalId 用记录主键），不新建行、不占新设备位。 */
  const alt = await altColumnAvailable(env);
  if (alt) {
    const byAlt = await env.DB
      .prepare("SELECT * FROM activations WHERE license_id = ?1 AND machine_id_alt = ?2")
      .bind(licenseId, machineId)
      .first<ActivationRow>();
    if (byAlt) return { signId: machineId, canonicalId: byAlt.machine_id };
  }

  if (!legacy || legacy === machineId) return { signId: machineId, canonicalId: machineId };

  /* 3) 新指纹还没入库，但老指纹有记录 —— 把记录迁到新指纹。
        COALESCE 保留最早的 alt，避免连续迁移（v1→v2→v3）把 v1 冲掉。 */
  const old = await getActivation(env, licenseId, legacy);
  if (!old) return { signId: machineId, canonicalId: machineId };

  // UPDATE OR IGNORE：新指纹若已被同授权下的另一条记录占用则放弃迁移，
  // 让上层按正常流程判定（通常是 DEVICE_LIMIT），不覆盖别人的记录。
  // 列缺失时退回只改主键的写法（代价仅是降级兼容失效，主链路照常）。
  const sql = alt
    ? "UPDATE OR IGNORE activations SET machine_id = ?1, machine_id_alt = COALESCE(machine_id_alt, ?3) " +
      "WHERE license_id = ?2 AND machine_id = ?3"
    : "UPDATE OR IGNORE activations SET machine_id = ?1 WHERE license_id = ?2 AND machine_id = ?3";
  await env.DB.prepare(sql).bind(machineId, licenseId, legacy).run();

  return { signId: machineId, canonicalId: machineId };
}

export type UpsertActivationResult = "ok" | "device_limit";

/**
 * 写入/刷新一条激活记录，并保证不超出设备位上限。
 *
 * 计数与写入必须在**同一条 SQL** 内完成：拆成 countActivations() + INSERT 两步的话，
 * 两台设备并发首次激活同一授权码会同时通过检查，实际设备数超过 max_devices。
 * SQLite 的单条写语句是原子的，D1 会把并发写串行化，第二个执行时 COUNT 已包含第一个。
 *
 * @param maxDevices 该授权允许的设备数；传 null 表示不做上限约束（仅用于已激活设备的续期）
 */
export async function upsertActivation(
  env: Env,
  a: {
    licenseId: string;
    machineId: string;
    machineName?: string | null;
    appVersion?: string | null;
    platform?: string | null;
    ip?: string | null;
    country?: string | null;
  },
  maxDevices: number | null = null,
): Promise<UpsertActivationResult> {
  const ts = nowSec();
  const limit = maxDevices === null ? Number.MAX_SAFE_INTEGER : Math.max(0, Math.floor(maxDevices));

  await env.DB.prepare(
    `INSERT INTO activations
       (id, license_id, machine_id, machine_name, app_version, platform, ip, country, activated_at, last_seen_at)
     SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?9
      WHERE EXISTS (SELECT 1 FROM activations WHERE license_id = ?2 AND machine_id = ?3)
         OR (SELECT COUNT(*) FROM activations WHERE license_id = ?2) < ?10
     ON CONFLICT(license_id, machine_id) DO UPDATE SET
       last_seen_at = excluded.last_seen_at,
       machine_name = COALESCE(excluded.machine_name, activations.machine_name),
       app_version  = COALESCE(excluded.app_version,  activations.app_version),
       platform     = COALESCE(excluded.platform,     activations.platform),
       ip           = excluded.ip,
       country      = excluded.country`,
  )
    .bind(
      newId("act"),
      a.licenseId,
      a.machineId,
      a.machineName ?? null,
      a.appVersion ?? null,
      a.platform ?? null,
      a.ip ?? null,
      a.country ?? null,
      ts,
      limit,
    )
    .run();

  // 复检：语句执行后仍查不到本设备，只可能是被设备数上限挡掉了
  const act = await getActivation(env, a.licenseId, a.machineId);
  return act ? "ok" : "device_limit";
}

export async function deleteActivation(env: Env, id: string): Promise<void> {
  await env.DB.prepare("DELETE FROM activations WHERE id = ?1").bind(id).run();
}

export async function deleteActivationByMachine(env: Env, licenseId: string, machineId: string): Promise<void> {
  await env.DB.prepare("DELETE FROM activations WHERE license_id = ?1 AND machine_id = ?2")
    .bind(licenseId, machineId)
    .run();
}

/* --------------------------- 审计日志 --------------------------- */

export async function audit(
  env: Env,
  entry: { actor?: string; action: string; target?: string; detail?: unknown; ip?: string; ua?: string },
): Promise<void> {
  try {
    await env.DB.prepare(
      "INSERT INTO audit_logs (ts, actor, action, target, detail, ip, ua) VALUES (?1,?2,?3,?4,?5,?6,?7)",
    )
      .bind(
        nowSec(),
        entry.actor ?? "admin",
        entry.action,
        entry.target ?? null,
        entry.detail === undefined ? null : JSON.stringify(entry.detail),
        entry.ip ?? null,
        entry.ua ?? null,
      )
      .run();
  } catch {
    /* 审计失败不影响主流程 */
  }
}

export async function listAudit(env: Env, limit = 100): Promise<unknown[]> {
  const r = await env.DB.prepare("SELECT * FROM audit_logs ORDER BY ts DESC LIMIT ?1")
    .bind(Math.min(limit, 500))
    .all();
  return r.results ?? [];
}

/* ---------------------------- 统计 ---------------------------- */

export async function stats(env: Env) {
  const [lic, act, expiring, prod] = await Promise.all([
    env.DB.prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN status='active'  THEN 1 ELSE 0 END) AS active,
         SUM(CASE WHEN status='revoked' THEN 1 ELSE 0 END) AS revoked,
         SUM(CASE WHEN expires_at IS NOT NULL AND expires_at < ?1 THEN 1 ELSE 0 END) AS expired,
         SUM(CASE WHEN expires_at IS NOT NULL AND expires_at BETWEEN ?1 AND ?1 + 604800 THEN 1 ELSE 0 END) AS expiring_7d
       FROM licenses`,
    )
      .bind(nowSec())
      .first(),
    env.DB.prepare("SELECT COUNT(*) AS c FROM activations").first<{ c: number }>(),
    env.DB.prepare(
      "SELECT id, key_display, customer, expires_at FROM licenses WHERE expires_at IS NOT NULL AND expires_at >= ?1 ORDER BY expires_at ASC LIMIT 5",
    )
      .bind(nowSec())
      .all(),
    env.DB.prepare("SELECT COUNT(*) AS c FROM products").first<{ c: number }>(),
  ]);

  return {
    licenses: lic,
    activations: act?.c ?? 0,
    products: prod?.c ?? 0,
    next_expiring: expiring.results ?? [],
  };
}

/* ---------------------------- 维护 ---------------------------- */

/** 定时任务：清理长期失联的激活记录 */
export async function pruneStaleActivations(env: Env, olderThanSec = 90 * 86400): Promise<number> {
  const cutoff = nowSec() - olderThanSec;
  const res = await env.DB.prepare("DELETE FROM activations WHERE last_seen_at < ?1").bind(cutoff).run();
  return res.meta?.changes ?? 0;
}
