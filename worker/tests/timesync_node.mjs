/**
 * Node 端时钟同步验证（被 tests/e2e_timesync.py 以子进程方式调用）。
 *
 * 环境变量：LG_BASE / LG_APP_ID / LG_KEY / LG_PUB
 * 输出：过程日志 + 最后一行 JSON {"results": [[name, ok, detail], ...]}
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const base = process.env.LG_BASE;
const appId = process.env.LG_APP_ID;
const key = process.env.LG_KEY;
const pub = process.env.LG_PUB;

if (!base || !appId || !key || !pub) {
  console.error("缺少 LG_BASE / LG_APP_ID / LG_KEY / LG_PUB");
  process.exit(2);
}

const mod = await import(new URL("../../clients/node/license-guard.js", import.meta.url).href);
const { LicenseGuard } = mod;

const results = [];
const check = (name, ok, detail = "") => {
  results.push([name, !!ok, String(detail)]);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  → " + detail : ""}`);
};

const dir = mkdtempSync(join(tmpdir(), "lg-node-ts-"));
const guard = new LicenseGuard({
  serverUrl: base,
  appId,
  publicKey: pub,
  signAlg: "ed25519",
  licenseKey: key,
  storageDir: dir,
  retryTimes: 1,
  requestTimeoutMs: 10000,
  onDenied: (code, msg) => { throw new Error(`DENIED ${code} ${msg}`); },
});

// 1. 主动同步
const skew = await guard.syncTime();
check("syncTime() 返回偏差值", Number.isFinite(skew), String(skew));
check("本机与服务端偏差很小（<5s）", Math.abs(skew) < 5, `${skew}s`);

const st1 = guard.store.load();
check("skew 已写入状态文件", st1 && "clock_skew" in st1, JSON.stringify(Object.keys(st1 || {})));

// 2. 篡改 server_time（与签名里的 t 不一致）必须被拒
const origGet = guard._get.bind(guard);
guard._get = async (path) => {
  const r = await origGet(path);
  if (r && r.ok && r.data) {
    return { ...r, data: { ...r.data, server_time: Number(r.data.server_time) - 999999 } };
  }
  return r;
};
try {
  await guard.syncTime();
  check("server_time 与签名不一致时被拒", false, "没有抛错");
} catch (e) {
  check("server_time 与签名不一致时被拒", e && e.code === "BAD_TOKEN", e && e.code);
} finally {
  guard._get = origGet;
}

// 3. 完整 verify 后 skew 刷新
const info = await guard.verify({ allowOffline: false });
check("verify 成功", !!info, info ? info.status : "-");
const st2 = guard.store.load();
check("verify 后 clock_skew 已写入", st2 && "clock_skew" in st2, JSON.stringify(Object.keys(st2 || {})));
check("verify 后 skew 仍然很小", Math.abs(Number((st2 || {}).clock_skew ?? 1e9)) < 5,
  String((st2 || {}).clock_skew));

// 4. 回拨检测（两个口径）
const now = Math.floor(Date.now() / 1000);
const a = guard._effectiveNow({ last_online: now, last_wall: now - 60, clock_skew: -86400 });
check("服务端时间口径回拨被检出", a.tampered === true, JSON.stringify(a));

const b = guard._effectiveNow({ last_wall: now + 86400 });
check("挂钟口径回拨被检出（无 skew 也生效）", b.tampered === true, JSON.stringify(b));

const c = guard._effectiveNow({ last_wall: now - 60, last_online: now - 60, clock_skew: 0 });
check("正常情况不误报篡改", c.tampered === false, JSON.stringify(c));

// 5. install_id 跨校验稳定
await guard.verify({ allowOffline: false });
const s3 = guard.store.load();
await guard.verify({ allowOffline: false });
const s4 = guard.store.load();
check("install_id 跨多次校验稳定", s3.install_id && s3.install_id === s4.install_id,
  `${s3.install_id} vs ${s4.install_id}`);

// 6. 断网时抛 NETWORK
const bad = new LicenseGuard({
  serverUrl: "http://127.0.0.1:1",
  appId,
  publicKey: pub,
  signAlg: "ed25519",
  licenseKey: key,
  storageDir: dir,
  retryTimes: 1,
  requestTimeoutMs: 3000,
  onDenied: (code, msg) => { throw new Error(`DENIED ${code} ${msg}`); },
});
try {
  await bad.syncTime();
  check("断网时 syncTime 抛 NETWORK", false, "没有抛错");
} catch (e) {
  check("断网时 syncTime 抛 NETWORK", e && e.code === "NETWORK", e && e.code);
}

console.log(JSON.stringify({ results }));
