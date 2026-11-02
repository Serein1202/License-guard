/**
 * 首次请求时自动建表。
 *
 * 为什么放在这里、而不是部署命令里：
 * Cloudflare Workers Builds 自动生成的构建令牌默认**不含 D1 编辑权限**，
 * 在 deploy 脚本里执行 `wrangler d1 execute` 会因权限不足而失败（而且是静默失败）。
 * Worker 运行时的 D1 绑定不受此限制，所以把建表放到运行时，
 * 让「一键部署」出来的实例开箱即用，无需任何手工步骤。
 *
 * 幂等：schema.sql 里全是 CREATE TABLE / INDEX IF NOT EXISTS，
 * 每个 isolate 只检查一次，已建过表就只花一条 sqlite_master 查询。
 */
import schemaSql from "../schema.sql";
import type { Env } from "./types";

/** 把 .sql 拆成可逐条执行的语句（剔除 -- 行注释与空段） */
function splitStatements(sql: string): string[] {
  return sql
    .split("\n")
    .map((line) => {
      const i = line.indexOf("--");
      return i >= 0 ? line.slice(0, i) : line;
    })
    .join("\n")
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

const STATEMENTS = splitStatements(schemaSql);

/** isolate 级缓存：已就绪则直接跳过 */
let ready = false;
/** 并发请求共享同一次初始化，避免重复建表 */
let inflight: Promise<void> | null = null;

/**
 * 给已存在的表补列。ALTER TABLE ADD COLUMN 在 D1 上不能带 IF NOT EXISTS，
 * 所以先用 PRAGMA table_info 判断。
 */
async function ensureColumn(env: Env, table: string, column: string, type: string): Promise<void> {
  const info = await env.DB.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>();
  const exists = (info.results || []).some((c) => c.name === column);
  if (exists) return;
  try {
    await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`).run();
    console.log(`[license-guard] schema migrated: ${table}.${column}`);
  } catch (e) {
    // 并发 isolate 同时补列时后到的那次会报 duplicate column，忽略即可
    const msg = e instanceof Error ? e.message : String(e);
    if (!/duplicate column/i.test(msg)) throw e;
  }
}

/**
 * 列级迁移的整体容错。
 *
 * 为什么失败也要放行：这些列都是**边缘兼容路径**用的（例：machine_id_alt
 * 只影响「用户降级回旧 SDK」），主链路的激活 / 校验 / 到期判定不依赖它们。
 * 如果因为 ALTER 权限、PRAGMA 变体差异之类的环境问题让迁移抛异常，
 * 正确做法是退化成「没有该列」继续服务，而不是让整个实例 500。
 *
 * @returns 本次实际完成的迁移项，抛错则返回已回滚的空列表
 */
async function migrateColumns(env: Env): Promise<void> {
  try {
    await ensureColumn(env, "activations", "machine_id_alt", "TEXT");
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[license-guard] schema migration skipped (non-fatal): ${msg}`);
  }
}

export async function ensureSchema(env: Env): Promise<void> {
  if (ready) return;
  if (inflight) return inflight;

  inflight = (async () => {
    try {
      if (!env.DB) {
        throw new Error(
          "未绑定 D1 数据库。请在 Cloudflare 控制台 → 本 Worker → Settings → Bindings 添加 D1 数据库，变量名必须为 DB",
        );
      }

      const hasTable = await env.DB
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'products'")
        .first<{ name: string }>();

      if (!hasTable) {
        for (let i = 0; i < STATEMENTS.length; i++) {
          try {
            await env.DB.prepare(STATEMENTS[i]).run();
          } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            throw new Error(`初始化表结构失败（第 ${i + 1}/${STATEMENTS.length} 条）: ${msg}`);
          }
        }
        console.log(`[license-guard] schema initialized (${STATEMENTS.length} statements)`);
      }

      /* 列级迁移：CREATE TABLE IF NOT EXISTS 不会给已存在的表补列，
         所以后续版本新加的列都要在这里逐个 ensure。幂等，失败不阻断服务。 */
      await migrateColumns(env);

      ready = true;
    } finally {
      inflight = null;
    }
  })();

  return inflight;
}
