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

      ready = true;
    } finally {
      inflight = null;
    }
  })();

  return inflight;
}
