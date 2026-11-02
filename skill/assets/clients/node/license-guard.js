/**
 * License Guard · Node.js / Electron 客户端 SDK
 * ============================================
 * 零第三方依赖。Ed25519 / ECDSA-P256 验签、硬件指纹、防时钟回拨、
 * 离线容忍、后台看门狗，以及「到期立即退出」的强制终止逻辑。
 *
 * 用法
 * ----
 *   import { LicenseGuard } from "./license-guard.js";
 *
 *   const guard = new LicenseGuard({
 *     serverUrl : "https://license-guard.your-name.workers.dev",
 *     appId     : "mytool",
 *     publicKey : "粘贴 gen-keys 输出的公钥",
 *     licenseKey: "ABCD-EFGH-JKMN-PQRS",
 *   });
 *
 *   await guard.authorize();      // 不通过 → 进程直接退出
 *   guard.startWatchdog();        // 运行期看守，到期瞬间退出
 *
 *   if (guard.hasFeature("pro")) { ... }
 */

import {
  createHash,
  createPublicKey,
  createHmac,
  verify as cryptoVerify,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, renameSync, rmSync, chmodSync } from "node:fs";
import { homedir, platform, hostname, arch, networkInterfaces } from "node:os";
import { join, dirname } from "node:path";

export const VERSION = "1.0.0";

const DAY = 86400;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/* ══════════════════════════════════════════════════════════════
   工具
   ══════════════════════════════════════════════════════════════ */

function b64urlDecode(s) {
  let t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  return Buffer.from(t, "base64");
}

function b64Decode(s) {
  let t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  return Buffer.from(t, "base64");
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

/* ══════════════════════════════════════════════════════════════
   硬件指纹
   ══════════════════════════════════════════════════════════════ */

let _machineCache = null;
let _legacyCache = null;

/**
 * v2 指纹因子：只取硬件级、跨重启与跨系统升级都稳定的标识。
 * 刻意不参与哈希：主机名（改电脑名就变）、CPU 架构与系统版本（换运行环境就变）。
 * 这些只会让正版用户白掉一次激活，拦不住真正会改程序的人。
 */
function hardwareTokens() {
  const tokens = [];
  const p = platform();
  let stable = false;

  if (p === "win32") {
    // 一次 PowerShell 调用把注册表里的硬件标识全部取回，避免逐个起进程
    const script = [
      "$ErrorActionPreference='SilentlyContinue'",
      "$b=Get-ItemProperty -Path 'HKLM:\\HARDWARE\\DESCRIPTION\\System\\BIOS'",
      "$c=Get-ItemProperty -Path 'HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0'",
      "$g=(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid",
      "Write-Output \"board=$($b.BaseBoardProduct)\"",
      "Write-Output \"prod=$($b.SystemProductName)\"",
      "Write-Output \"cpu=$($c.Identifier)\"",
      "Write-Output \"cpuname=$($c.ProcessorNameString)\"",
      "Write-Output \"guid=$g\"",
    ].join("; ");
    for (const [cmd, args] of [
      ["powershell", ["-NoProfile", "-NonInteractive", "-Command", script]],
      ["reg", ["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"]],
    ]) {
      try {
        const out = execFileSync(cmd, args, { encoding: "utf8", timeout: 8000, windowsHide: true });
        const guid = (out.match(/guid=([0-9a-fA-F-]{36})/)
          || out.match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/));
        const board = out.match(/board=(.*)/);
        const prod = out.match(/prod=(.*)/);
        const cpu = out.match(/cpu=(.*)/);
        const cpuname = out.match(/cpuname=(.*)/);
        if (board && board[1].trim()) { tokens.push("board:" + board[1].trim()); stable = true; }
        if (prod && prod[1].trim()) { tokens.push("prod:" + prod[1].trim()); stable = true; }
        if (cpu && cpu[1].trim()) tokens.push("cpu:" + cpu[1].trim());
        if (cpuname && cpuname[1].trim()) tokens.push("cpuname:" + cpuname[1].trim());
        if (guid) { tokens.push("guid:" + guid[1].trim().toLowerCase()); stable = true; break; }
        if (guid === null && board === null) continue;
      } catch { /* 换下一个 */ }
    }

    // 系统盘卷序列号：cmd vol 在中英文系统上都会输出 4-4 位十六进制
    try {
      const root = (process.env.SystemDrive || "C:").slice(0, 2) + "\\";
      const out = execFileSync("cmd", ["/c", "vol", root], { encoding: "utf8", timeout: 5000, windowsHide: true });
      const m = out.match(/([0-9a-fA-F]{4})-([0-9a-fA-F]{4})/);
      if (m) { tokens.push("vol:" + (m[1] + m[2]).toUpperCase()); stable = true; }
    } catch { /* ignore */ }
  } else if (p === "darwin") {
    try {
      const out = execFileSync("ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"],
        { encoding: "utf8", timeout: 8000 });
      const m = out.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
      if (m) { tokens.push("uuid:" + m[1]); stable = true; }
    } catch { /* ignore */ }
  } else {
    for (const f of ["/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"]) {
      try {
        const v = readFileSync(f, "utf8").trim();
        if (v) { tokens.push("id:" + v); stable = true; break; }
      } catch { /* ignore */ }
    }
  }

  // 硬件因子一个都没取到时才用 MAC 兜底，避免正常情况下换网卡就漂移
  if (!stable) {
    const mac = firstPhysicalMac();
    if (mac) tokens.push("mac:" + mac);
  }

  return tokens;
}

function firstPhysicalMac() {
  try {
    const macs = [];
    for (const name of Object.keys(networkInterfaces())) {
      for (const ni of networkInterfaces()[name] || []) {
        if (ni.internal || !ni.mac || ni.mac === "00:00:00:00:00:00") continue;
        // 第二个字节 bit1 = 1 是本地管理地址（随机 MAC），会漂移，不能用
        const parts = ni.mac.split(":");
        if (parts.length === 6 && (parseInt(parts[1], 16) & 0x02)) continue;
        if (/^(00:15:5d|00:50:56|08:00:27|52:54:00|00:1c:42|0a:00:27)/i.test(ni.mac)) continue; // 虚拟机
        macs.push(ni.mac.toLowerCase());
      }
    }
    macs.sort();
    return macs[0] || null;
  } catch { return null; }
}

/**
 * v1 指纹因子：逐字复刻历史算法，不能改。
 * 上线版本的构成是「平台唯一标识 + MAC + hostname + arch」，
 * 这里算出的值一旦与老客户端不一致，服务端就认领不回旧激活记录。
 */
function legacyTokens() {
  const tokens = [];
  const p = platform();

  if (p === "win32") {
    for (const [cmd, args] of [
      ["powershell", ["-NoProfile", "-NonInteractive", "-Command",
        "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -Name MachineGuid).MachineGuid"]],
      ["reg", ["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"]],
    ]) {
      try {
        const out = execFileSync(cmd, args, { encoding: "utf8", timeout: 8000, windowsHide: true });
        const m = out.match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/);
        if (m) { tokens.push("guid:" + m[0].toLowerCase()); break; }
      } catch { /* 换下一个 */ }
    }
  } else if (p === "darwin") {
    try {
      const out = execFileSync("ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"],
        { encoding: "utf8", timeout: 8000 });
      const m = out.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
      if (m) tokens.push("uuid:" + m[1]);
    } catch { /* ignore */ }
  } else {
    for (const f of ["/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"]) {
      try {
        const v = readFileSync(f, "utf8").trim();
        if (v) { tokens.push("id:" + v); break; }
      } catch { /* ignore */ }
    }
  }

  // v1 的 MAC 是无条件兜底
  const mac = firstPhysicalMac();
  if (mac) tokens.push("mac:" + mac);

  tokens.push("host:" + hostname());
  tokens.push("arch:" + arch() + ":" + p);
  return tokens;
}

/** 32 位十六进制硬件指纹 */
export function machineId() {
  if (_machineCache) return _machineCache;
  _machineCache = createHash("sha256").update(hardwareTokens().join("|")).digest("hex").slice(0, 32);
  return _machineCache;
}

/** 旧版指纹，随请求上报为 machine_id_alt，用于激活记录迁移 */
export function legacyMachineId() {
  if (_legacyCache) return _legacyCache;
  _legacyCache = createHash("sha256").update(legacyTokens().join("|")).digest("hex").slice(0, 32);
  return _legacyCache;
}

/* ══════════════════════════════════════════════════════════════
   令牌验签
   ══════════════════════════════════════════════════════════════ */

export class LicenseError extends Error {
  constructor(code, message) {
    super(`[${code}] ${message}`);
    this.name = "LicenseError";
    this.code = code;
    this.licMessage = message;
  }
}

function verifyToken(token, publicKey, alg) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new LicenseError("BAD_TOKEN", "令牌格式错误");

  let header;
  let payload;
  try {
    header = JSON.parse(b64urlDecode(parts[0]).toString("utf8"));
    payload = JSON.parse(b64urlDecode(parts[1]).toString("utf8"));
  } catch {
    throw new LicenseError("BAD_TOKEN", "令牌内容无法解析");
  }

  const data = Buffer.from(parts[0] + "." + parts[1], "ascii");
  const sig = b64urlDecode(parts[2]);
  const headerAlg = String(header.alg || "").toUpperCase();
  const es = alg === "es256";

  if (es && headerAlg !== "ES256") throw new LicenseError("ALG_MISMATCH", "令牌算法与本地配置不匹配");
  if (!es && !["ED25519", "EDDSA"].includes(headerAlg)) {
    throw new LicenseError("ALG_MISMATCH", "令牌算法与本地配置不匹配");
  }

  let ok = false;
  try {
    if (es) {
      const key = createPublicKey({ key: b64Decode(publicKey), format: "der", type: "spki" });
      ok = cryptoVerify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, sig);
    } else {
      const raw = b64urlDecode(publicKey);
      if (raw.length !== 32) throw new Error("Ed25519 公钥必须是 32 字节");
      const key = createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
        format: "der",
        type: "spki",
      });
      ok = cryptoVerify(null, data, key, sig);
    }
  } catch (e) {
    throw new LicenseError("BAD_PUBLIC_KEY", "公钥格式错误: " + e.message);
  }

  if (!ok) throw new LicenseError("BAD_SIGNATURE", "授权令牌签名校验失败（文件可能被篡改）");
  return payload;
}

/* ══════════════════════════════════════════════════════════════
   本地状态（HMAC 完整性保护）
   ══════════════════════════════════════════════════════════════ */

const MAGIC = "LGST1";

function dataDir(appId) {
  const p = platform();
  if (p === "win32") {
    return join(process.env.LOCALAPPDATA || process.env.APPDATA || homedir(), appId);
  }
  if (p === "darwin") return join(homedir(), "Library", "Application Support", appId);
  return join(process.env.XDG_DATA_HOME || join(homedir(), ".local", "share"), appId);
}

class StateStore {
  constructor(appId, directory) {
    this.dir = directory || dataDir(appId);
    this.path = join(this.dir, "state.dat");
    this.key = createHash("sha256").update(`license-guard::${appId}::${machineId()}`).digest();
  }

  mac(body) {
    return createHmac("sha256", this.key).update(body).digest("hex");
  }

  load() {
    let raw;
    try {
      raw = readFileSync(this.path);
    } catch {
      return {};
    }
    try {
      const nl = raw.indexOf(0x0a);
      const head = raw.subarray(0, nl).toString("ascii");
      const body = raw.subarray(nl + 1);
      const [magic, mac] = head.split(":");
      if (magic !== MAGIC) return {};
      const expected = Buffer.from(this.mac(body), "hex");
      const actual = Buffer.from(mac, "hex");
      if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
        return { __tampered__: true };
      }
      return JSON.parse(body.toString("utf8"));
    } catch {
      return {};
    }
  }

  save(data) {
    try {
      const body = Buffer.from(JSON.stringify(data), "utf8");
      const head = Buffer.from(`${MAGIC}:${this.mac(body)}`, "ascii");
      mkdirSync(dirname(this.path), { recursive: true });
      const tmp = this.path + ".tmp";
      writeFileSync(tmp, Buffer.concat([head, Buffer.from("\n"), body]));
      renameSync(tmp, this.path);
      try { chmodSync(this.path, 0o600); } catch { /* Windows 上会失败，忽略 */ }
    } catch { /* 磁盘只读时静默降级 */ }
  }

  clear() {
    try { rmSync(this.path, { force: true }); } catch { /* ignore */ }
  }
}

/* ══════════════════════════════════════════════════════════════
   终止策略
   ══════════════════════════════════════════════════════════════ */

function terminate(mode, code, message, errCode) {
  if (mode === "message") {
    const line = "!".repeat(58);
    try {
      process.stderr.write(
        `\n${line}\n  ${message}\n  (错误代码: ${errCode})\n${line}\n  请联系软件供应商续期。\n\n`
      );
    } catch { /* ignore */ }
    try { dialogBestEffort(message); } catch { /* ignore */ }
  }
  // process.exit 不会执行 pending 回调，也不打印堆栈 —— 表现就是「闪退」
  process.exit(code);
}

function dialogBestEffort(message) {
  if (platform() === "win32") {
    try {
      execFileSync("powershell", [
        "-NoProfile", "-NonInteractive", "-Command",
        `[System.Windows.Forms.MessageBox]::Show('${String(message).replace(/'/g, "''")}','授权已到期','OK','Error')`,
      ], { timeout: 30000, windowsHide: true, stdio: "ignore" });
    } catch { /* ignore */ }
  } else if (platform() === "darwin") {
    try {
      execFileSync("osascript", ["-e",
        `display dialog "${String(message).replace(/"/g, "'")}" with title "授权已到期" buttons {"确定"} with icon stop`],
        { timeout: 30000, stdio: "ignore" });
    } catch { /* ignore */ }
  }
}

/* ══════════════════════════════════════════════════════════════
   主体
   ══════════════════════════════════════════════════════════════ */

export class LicenseGuard {
  constructor(options = {}) {
    this.opts = {
      serverUrl: "",
      appId: "",
      publicKey: "",
      licenseKey: "",
      signAlg: "ed25519",
      failMode: "hard",          // hard = 直接闪退；message = 提示后退出
      exitCode: 0,
      strictClock: true,
      clockToleranceSec: 300,
      requestTimeoutMs: 8000,
      retryTimes: 3,
      heartbeatSec: 21600,
      watchdogIntervalSec: 120,  // >0 = 固定复查间隔（不被后端心跳覆盖）；0 = 跟随后端 heartbeatSec
      heartbeatCapSec: 900,      // 仅在 watchdogIntervalSec = 0 时生效：本地复查间隔上限
      onlineCheckIntervalSec: 0, // 缓存令牌免联网的最长时间；0 = 每次 verify 都联网（封禁即时生效）
      storageDir: null,
      onDenied: null,            // (code, message) => void；设了它就不会自动退出
      debug: false,
      ...options,
    };
    if (!this.opts.serverUrl) throw new Error("LicenseGuard: 缺少 serverUrl");
    if (!this.opts.appId) throw new Error("LicenseGuard: 缺少 appId");
    if (!this.opts.publicKey) throw new Error("LicenseGuard: 缺少 publicKey");

    this.serverUrl = this.opts.serverUrl.replace(/\/+$/, "");
    this.machineId = machineId();
    this.store = new StateStore(this.opts.appId, this.opts.storageDir);
    this._state = {};
    this._info = null;
    this._timer = null;
    this._running = false;
  }

  get info() {
    if (!this._info) throw new LicenseError("NOT_VERIFIED", "尚未执行 verify()");
    return this._info;
  }

  _log(...a) {
    if (this.opts.debug) console.error("[license-guard]", ...a);
  }

  _licenseKey() {
    if (this.opts.licenseKey) return this.opts.licenseKey.trim();
    for (const env of ["LICENSE_KEY", `${this.opts.appId.toUpperCase()}_LICENSE_KEY`]) {
      if (process.env[env]) return process.env[env].trim();
    }
    for (const f of [join(process.cwd(), "license.key"),
                     join(this.store.dir, "license.key"),
                     join(process.resourcesPath || "", "license.key")]) {
      try {
        const t = readFileSync(f, "utf8").trim();
        if (t) return t.split("\n")[0].trim();
      } catch { /* ignore */ }
    }
    return "";
  }

  async _get(path) {
    const url = this.serverUrl + path;
    let lastErr = null;
    for (let attempt = 0; attempt < Math.max(1, this.opts.retryTimes); attempt++) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.opts.requestTimeoutMs);
      try {
        const res = await fetch(url, { method: "GET", signal: ctrl.signal });
        const json = await res.json().catch(() => null);
        clearTimeout(timer);
        if (!json) {
          lastErr = new Error("响应不是合法 JSON");
        } else if (!res.ok && [401, 403, 404, 409, 429].includes(res.status)) {
          return json;                        // 服务端明确拒绝，不重试
        } else {
          return json;
        }
      } catch (e) {
        lastErr = e;
      } finally {
        clearTimeout(timer);
      }
      if (attempt < this.opts.retryTimes - 1) {
        await new Promise((r) => setTimeout(r, 800 * (attempt + 1)));
      }
    }
    this._log("网络不可用:", lastErr && lastErr.message);
    return null;
  }

  /**
   * 主动取一次服务端权威时间，算出本机时钟偏差（skew = 服务端时间 − 本机挂钟）并落盘。
   *
   * 作用是让「把系统时间调回过去」这类绕过在本地就算得出来：后续到期判定都用
   * `挂钟 + skew`，而不是裸的本地时间。server_time 带签名，中间人改不了；
   * 这里还会比对签名里的 t 与明文 server_time，不一致直接抛错。
   *
   * 离线时抛 NETWORK；正常校验路径不依赖它，调用方可不处理。
   * @returns {Promise<number>} 本次测得的时钟偏差（秒），正数表示本机偏慢
   */
  async syncTime() {
    this._state = this.store.load() || {};
    if (this._state.__tampered__) {
      await this.store.clear();
      this._state = {};
    }

    const resp = await this._get(`/v1/time?app_id=${encodeURIComponent(this.opts.appId)}`);
    if (!resp) this._raise("NETWORK", "无法连接授权服务器获取时间");
    if (!resp.ok) this._raise(resp.code || "DENIED", resp.message || "获取服务端时间失败");

    const serverTime = Number(resp.data.server_time);
    // 必须验签：明文 server_time 可被中间人改，签名里的 t 才是可信值
    const payload = verifyToken(resp.data.token, this.opts.publicKey, resp.data.sign_alg || this.opts.signAlg);
    if (Number(payload.t) !== serverTime) {
      this._raise("BAD_TOKEN", "服务端时间令牌与明文时间不一致");
    }

    const skew = serverTime - nowSec();
    this._state.clock_skew = skew;
    this.store.save(this._state);
    this._log("时钟同步完成:", `server=${serverTime}`, `skew=${skew}s`);
    return skew;
  }

  async _post(path, body) {
    const url = this.serverUrl + path;
    let lastErr = null;
    for (let attempt = 0; attempt < Math.max(1, this.opts.retryTimes); attempt++) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.opts.requestTimeoutMs);
      try {
        const res = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          signal: ctrl.signal,
        });
        const json = await res.json().catch(() => null);
        clearTimeout(timer);
        if (!json) {
          lastErr = new Error("响应不是合法 JSON");
        } else if (!res.ok && [401, 403, 404, 409, 429].includes(res.status)) {
          return json;                        // 服务端明确拒绝，不重试
        } else {
          return json;
        }
      } catch (e) {
        lastErr = e;
      } finally {
        clearTimeout(timer);
      }
      if (attempt < this.opts.retryTimes - 1) {
        await new Promise((r) => setTimeout(r, 800 * (attempt + 1)));
      }
    }
    this._log("网络不可用:", lastErr && lastErr.message);
    return null;
  }

  /**
   * 算出用于到期判定的「当前时间」，并顺带检测系统时间被回拨。
   *
   * 时间口径 = 本机挂钟 + clock_skew（上次联网测得的服务端偏差，见 syncTime()）。
   * 没有 skew 时退化为裸挂钟，与旧版行为一致。
   *
   * 两条回拨检测分别对应两个口径，互不干扰：
   *   1. 挂钟 vs 上次记录的挂钟（last_wall）—— 覆盖没有 skew 的情况
   *   2. 校正时间 vs 上次服务端时间（last_online）—— 覆盖「改了时间且本地有 skew」的情况
   */
  _effectiveNow(state) {
    const wall = nowSec();
    const lastWall = Number(state.last_wall || 0);
    if (lastWall && wall < lastWall - this.opts.clockToleranceSec) {
      this._log(`检测到系统时间回拨: now=${wall} last=${lastWall}`);
      return { now: lastWall, tampered: true };
    }

    const now = wall + Number(state.clock_skew || 0);
    const lastOnline = Number(state.last_online || 0);
    if (lastOnline && now < lastOnline - this.opts.clockToleranceSec) {
      this._log(`检测到服务端时间回拨: now=${now} last_online=${lastOnline}`);
      return { now: lastOnline, tampered: true };
    }
    return { now, tampered: false };
  }

  _offlineUntil() {
    const last = Number(this._state.last_online || 0);
    if (!last) return 0;
    return last + Number(this._state.offline_grace_days || 0) * DAY;
  }

  /**
   * 缓存令牌能否直接放行（完全不联网）。exp 已在调用处判过，这里只判另外两条：
   *   1. 离线容忍期未耗尽（last_online + offline_grace_days）
   *   2. 距上次成功联网未超过 onlineCheckIntervalSec
   *
   * 第 2 条是关键：间隔为 0 时恒 false，即每次 verify 都联网，
   * 后台吊销 / 改期 / 设过期立即生效；真连不上时才走离线容忍兜底。
   */
  _canSkipOnline(now) {
    if (now > this._offlineUntil()) return false;

    const interval = Number(this.opts.onlineCheckIntervalSec || 0);
    if (interval <= 0) return false;

    const lastOnline = Number(this._state.last_online || 0);
    return lastOnline > 0 && now - lastOnline < interval;
  }

  _expiredMsg(payload) {
    if (payload.aexp) {
      return "授权已于 " + new Date(Number(payload.aexp) * 1000).toISOString().slice(0, 10) + " 到期";
    }
    return "授权已到期";
  }

  _raise(code, message) {
    if (this.opts.onDenied) {
      try { this.opts.onDenied(code, message); } catch { /* ignore */ }
      throw new LicenseError(code, message);
    }
    terminate(this.opts.failMode, this.opts.exitCode, message, code);
    throw new LicenseError(code, message); // 理论上到不了
  }

  /** 执行一次完整校验；不通过则抛 LicenseError（或按策略直接退出） */
  async verify({ allowOffline = true } = {}) {
    this._state = this.store.load() || {};
    if (this._state.__tampered__) {
      this._log("本地状态文件被改动过，已重置");
      this.store.clear();
      this._state = {};
    }

    const rawKey = this._licenseKey();
    if (!rawKey) {
      throw new LicenseError("NO_KEY", "未找到授权码（可传 licenseKey、设环境变量 LICENSE_KEY 或放 license.key 文件）");
    }

    let { now, tampered } = this._effectiveNow(this._state);
    if (tampered && this.opts.strictClock) {
      this._raise("CLOCK_TAMPERED", "检测到系统时间被修改，授权校验失败");
    }

    /* ── 1) 缓存令牌 → 先尝试离线判定 ── */
    let cached = this._state.token || null;
    let payload = null;
    if (cached) {
      try {
        payload = verifyToken(cached, this.opts.publicKey, this.opts.signAlg);
      } catch (e) {
        this._log("缓存令牌无效，转联网:", e.code);
        this.store.clear();
        this._state = {};
        cached = null;
        payload = null;
      }
    }

    if (payload) {
      // 同时接受 v2 与 v1 指纹：升级 SDK 后本地令牌仍是 v1 指纹签发。
      // 只认 v2 会在联网前直接判 MACHINE_MISMATCH，永远走不到服务端的迁移逻辑。
      const acceptedMids = [this.machineId, legacyMachineId()];
      if (payload.mid && !acceptedMids.includes(payload.mid)) {
        this._raise("MACHINE_MISMATCH", "该授权绑定了另一台设备");
      }
      if (payload.hexp && now > Number(payload.hexp)) {
        this._raise("LICENSE_EXPIRED", this._expiredMsg(payload));
      }
      // allowOffline=false 表示调用方要求必须拿到服务端确认，此时跳过快速通道强制联网
      if (allowOffline && now <= Number(payload.exp || 0) && this._canSkipOnline(now)) {
        this._state.last_wall = now;
        this.store.save(this._state);
        this._info = this._infoFromPayload(payload, true);
        return this._info;
      }
    }

    /* ── 2) 联网校验 ── */
    const endpoint = cached ? "/v1/verify" : "/v1/activate";
    const resp = await this._post(endpoint, {
      app_id: this.opts.appId,
      key: rawKey,
      machine_id: this.machineId,
      // 旧版指纹：让服务端认领升级前的激活记录，避免因指纹改版白掉一次激活
      machine_id_alt: legacyMachineId(),
      machine_name: hostname(),
      platform: platform(),
      app_version: VERSION,
    });

    if (resp === null) {
      if (payload && allowOffline) {
        const until = this._offlineUntil();
        if (until && now > until) {
          this._raise("OFFLINE_TOO_LONG", "长时间未联网校验，授权已失效，请连接网络后重试");
        }
        this._log("离线放行，容忍截止", until);
        this._info = this._infoFromPayload(payload, true);
        return this._info;
      }
      throw new LicenseError("NETWORK", "无法连接授权服务器，且本地没有可用的离线授权");
    }

    if (!resp.ok) {
      this._raise(String(resp.code || "DENIED"), String(resp.message || "授权被拒绝"));
    }

    const data = resp.data;
    payload = verifyToken(data.token, this.opts.publicKey, data.sign_alg || this.opts.signAlg);
    if (payload.mid !== this.machineId) {
      this._raise("MACHINE_MISMATCH", "服务端返回的授权与当前设备不匹配");
    }

    ({ now, tampered } = this._effectiveNow(this._state));
    if (tampered && this.opts.strictClock) this._raise("CLOCK_TAMPERED", "检测到系统时间被修改");
    if (payload.hexp && now > Number(payload.hexp)) {
      this._raise("LICENSE_EXPIRED", this._expiredMsg(payload));
    }

    const policy = data.policy || {};
    this._state = {
      token: data.token,
      last_online: Number(data.server_time || now),
      last_wall: now,
      license_key: rawKey,
      offline_grace_days: Number(policy.offline_grace_days || 0),
      heartbeat_sec: Number(policy.heartbeat_sec || this.opts.heartbeatSec),
      // 每次联网都重测一次偏差，避免长时间离线后 skew 过期
      clock_skew: Number(data.server_time || now) - nowSec(),
      install_id: this._state.install_id || randomUUID(),
    };
    this.store.save(this._state);

    if (["hard", "message"].includes(policy.fail_mode)) this.opts.failMode = policy.fail_mode;
    if (Number.isInteger(policy.exit_code)) this.opts.exitCode = policy.exit_code;

    this._info = this._infoFromPayload(payload, false, data);
    this._log("校验通过:", this._info.status, "到期:", this._info.expiresAt);
    return this._info;
  }

  _infoFromPayload(payload, offline, data = {}) {
    const lic = data.license || {};
    return {
      status: data.status === "grace" ? "grace" : "active",
      code: offline ? "OFFLINE_OK" : String(data.code || "OK"),
      message: String(data.message || ""),
      customer: payload.cus || lic.customer || null,
      features: Array.isArray(payload.feat) ? payload.feat.slice() : [],
      expiresAt: payload.aexp ?? null,
      hardExpiresAt: payload.hexp ?? null,
      maxDevices: Number(lic.max_devices || 1),
      activations: Number(lic.activations || 0),
      serverTime: Number(payload.srv || 0),
      offline,
      get daysLeft() {
        if (!this.hardExpiresAt) return null;
        return Math.floor((this.hardExpiresAt * 1000 - Date.now()) / 86400000);
      },
    };
  }

  /** 启动时调用；不通过会按策略终止进程 */
  async authorize() {
    try {
      return await this.verify();
    } catch (e) {
      if (this.opts.onDenied) throw e;
      terminate(this.opts.failMode, this.opts.exitCode, e.licMessage || e.message, e.code || "DENIED");
      throw e;
    }
  }

  /**
   * 看门狗下一次复查要等多久（毫秒）。
   *
   * - watchdogIntervalSec > 0：固定间隔，每轮都用它，不被后端 heartbeat_sec 覆盖。
   *   （旧实现会在首次成功后改成 min(heartbeat, 900)，导致配 15 秒实际 15 分钟才复查）
   * - watchdogIntervalSec <= 0：跟随后端 heartbeat_sec，再用 heartbeatCapSec 夹上限。
   *
   * 下限恒为 15 秒，防止配置失误把服务端打爆。
   */
  _watchdogDelayMs() {
    const fixed = Number(this.opts.watchdogIntervalSec || 0);
    if (fixed > 0) return Math.max(15, fixed) * 1000;
    const hb = Number(this._state.heartbeat_sec || this.opts.heartbeatSec || 21600);
    const cap = Number(this.opts.heartbeatCapSec || 0);
    return Math.max(15, cap > 0 ? Math.min(hb, cap) : hb) * 1000;
  }

  /** 后台看门狗：到期时刻一到，即使程序正在运行也会立刻退出 */
  startWatchdog() {
    if (this._running) return;
    this._running = true;

    const tick = async () => {
      if (!this._running) return;
      try {
        await this.verify();
      } catch (e) {
        this._log("看门狗: 失败", e.code);
        this._running = false;
        if (!this.opts.onDenied) {
          terminate(this.opts.failMode, this.opts.exitCode, e.licMessage || e.message, e.code || "DENIED");
        }
        return;
      }
      if (this._running) {
        this._timer = setTimeout(tick, this._watchdogDelayMs());
        if (this._timer.unref) this._timer.unref();
      }
    };

    this._timer = setTimeout(tick, this._watchdogDelayMs());
    if (this._timer.unref) this._timer.unref();
  }

  stopWatchdog() {
    this._running = false;
    if (this._timer) clearTimeout(this._timer);
    this._timer = null;
  }

  hasFeature(name) {
    return Boolean(this._info && this._info.features.includes(name));
  }

  daysLeft() {
    return this._info ? this._info.daysLeft : null;
  }

  /** 主动解绑当前设备（换机时用） */
  async release() {
    const rawKey = this._licenseKey();
    if (!rawKey) return false;
    const resp = await this._post("/v1/deactivate", {
      app_id: this.opts.appId,
      key: rawKey,
      machine_id: this.machineId,
      machine_id_alt: legacyMachineId(),
    });
    if (resp && resp.ok) {
      this.store.clear();
      this._state = {};
      return true;
    }
    return false;
  }
}

/** 一行接入 */
export async function quickGuard(options) {
  const guard = new LicenseGuard(options);
  await guard.authorize();
  if (options.watchdog !== false) guard.startWatchdog();
  return guard;
}

export default LicenseGuard;
