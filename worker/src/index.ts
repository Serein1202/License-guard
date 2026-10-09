/**
 * License Guard · Cloudflare Workers 入口
 *
 * 路由一览
 *   ── 客户端（App）─────────────────────────────────────
 *   GET  /v1/time?app_id=            服务端签名时间
 *   GET  /v1/meta?app_id=            产品策略 / 公钥算法
 *   POST /v1/activate                首次激活
 *   POST /v1/verify                  校验 / 续令牌
 *   POST /v1/heartbeat               心跳（同 verify）
 *   POST /v1/deactivate              解绑本机
 *   ── 管理端 ───────────────────────────────────────────
 *   GET  /admin                      管理后台页面
 *   POST /admin/api/login            登录换 token
 *   GET  /admin/api/products         ...
 */
import adminHtml from "../public/admin.html";
import { handleAdmin } from "./routes/admin";
import {
  handleActivate,
  handleDeactivate,
  handleHeartbeat,
  handleMeta,
  handleTime,
  handleVerify,
} from "./routes/public";
import { pruneStaleActivations } from "./db";
import { ensureSchema } from "./schema";
import { CORS_HEADERS, checkAdmin, clientMeta, fail, json } from "./util";
import type { Env } from "./types";

const ROUTES: Record<string, (req: Request, env: Env, url: URL) => Promise<Response>> = {
  "GET /v1/time": handleTime,
  "GET /v1/meta": handleMeta,
  "POST /v1/activate": handleActivate,
  "POST /v1/verify": handleVerify,
  "POST /v1/heartbeat": handleHeartbeat,
  "POST /v1/deactivate": handleDeactivate,
};

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    /* ---------------- CORS 预检 ---------------- */
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }

    try {
      /* -------- 首次运行自动建表（一键部署后无需手工初始化） -------- */
      await ensureSchema(env);

      /* ---------------- 健康检查 ---------------- */
      if (url.pathname === "/" || url.pathname === "/health") {
        return json({ service: "license-guard", status: "ok", time: new Date().toISOString() });
      }

      /* ---------------- 管理后台页面 ---------------- */
      if ((url.pathname === "/admin" || url.pathname === "/admin/") && request.method === "GET") {
        return new Response(adminHtml, {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Robots-Tag": "noindex, nofollow",
            "Content-Security-Policy":
              "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
          },
        });
      }

      /* ---------------- 管理 API ---------------- */
      if (url.pathname.startsWith("/admin/api/")) {
        const isLogin = url.pathname === "/admin/api/login";
        if (!isLogin && !checkAdmin(request, env)) {
          return withCors(fail("UNAUTHORIZED", "缺少或错误的管理口令", 401), env, request);
        }
        if (isLogin && request.method === "POST") {
          // 登录接口单独做一次限流，防暴力破解
          const ip = clientMeta(request).ip;
          const slot = Math.floor(Date.now() / 60000);
          const k = `rl:login:${ip}:${slot}`;
          const cur = Number((await env.KV.get(k)) || "0");
          if (cur >= 10) return withCors(fail("RATE_LIMITED", "尝试次数过多，请 1 分钟后再试", 429), env, request);
          await env.KV.put(k, String(cur + 1), { expirationTtl: 120 });
        }
        return withCors(await handleAdmin(request, env, url), env, request);
      }

      /* ---------------- 公开校验 API ---------------- */
      if (url.pathname.startsWith("/v1/")) {
        const key = `${request.method.toUpperCase()} ${url.pathname.replace(/\/+$/, "")}`;
        const handler = ROUTES[key];
        if (!handler) return withCors(fail("NOT_FOUND", `未知接口 ${key}`, 404), env, request);
        return withCors(await handler(request, env, url), env, request);
      }

      return withCors(fail("NOT_FOUND", "Not Found", 404), env, request);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("unhandled", url.pathname, msg);
      return withCors(fail("INTERNAL_ERROR", `服务端异常: ${msg}`, 500), env, request);
    }
  },

  /** 每天定时清理长期失联的激活记录，避免设备位被占满 */
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      (async () => {
        await ensureSchema(env);
        const n = await pruneStaleActivations(env, 90 * 86400);
        console.log(`pruned ${n} stale activations`);
      })(),
    );
  },
} satisfies ExportedHandler<Env>;

/* ------------------------------------------------------------------ */

function corsHeaders(env: Env, req: Request): Record<string, string> {
  const origin = env.ADMIN_CORS_ORIGIN || req.headers.get("Origin") || "";
  if (!env.ADMIN_CORS_ORIGIN) {
    // 未配置时仅回显同源，浏览器跨域调用会被拒；同源部署无需 CORS
    return { ...CORS_HEADERS };
  }
  return { ...CORS_HEADERS, "Access-Control-Allow-Origin": origin, Vary: "Origin" };
}

function withCors(res: Response, env: Env, req: Request): Response {
  const h = new Headers(res.headers);
  for (const [k, v] of Object.entries(corsHeaders(env, req))) h.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}
