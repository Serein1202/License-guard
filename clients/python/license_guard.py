"""
License Guard · Python 客户端 SDK
=================================

零第三方依赖。自带 Ed25519 / ECDSA-P256 验签、硬件指纹、防时钟回拨、
离线容忍、后台看门狗，以及「到期立即闪退」的强制退出逻辑。

用法
----
    from license_guard import LicenseGuard, GuardConfig, LicenseError

    guard = LicenseGuard(GuardConfig(
        server_url = "https://license-guard.your-name.workers.dev",
        app_id     = "mytool",
        public_key = "粘贴 gen-keys 输出的 Ed25519 公钥(base64url)",
        license_key= "ABCD-EFGH-JKMN-PQRS",   # 也可从配置文件/输入框读取
    ))

    guard.authorize()          # 校验；不通过则按策略直接终止进程
    guard.start_watchdog()     # 运行期持续看守，到期瞬间闪退

    if guard.has_feature("pro"):
        ...

设计说明
--------
* 到期时间由服务端签发进令牌，客户端只做验签，**改不了**。
* 系统时间被调回过去会被检测到（tamper），不会因此延长有效期。
* 断网超过 offline_grace_days 天后必须联网，否则同样失效。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, Optional

__all__ = [
    "LicenseGuard",
    "GuardConfig",
    "LicenseError",
    "LicenseInfo",
    "machine_id",
    "ed25519_verify",
    "ecdsa_p256_verify",
]

__version__ = "1.0.0"


# ══════════════════════════════════════════════════════════════════
#  1. Ed25519 验签（纯 Python，无依赖）
# ══════════════════════════════════════════════════════════════════

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, -1, _P)
    x = pow(xx % _P, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x % _P


_BY = (4 * pow(5, -1, _P)) % _P
_BX = _xrecover(_BY)
_B = (_BX, _BY)


def _edwards_add(p: tuple, q: tuple) -> tuple:
    x1, y1 = p
    x2, y2 = q
    k = (_D * x1 * x2 * y1 * y2) % _P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + k, -1, _P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - k, -1, _P)
    return (x3 % _P, y3 % _P)


def _scalarmult(p: tuple, e: int) -> tuple:
    q = (0, 1)
    while e > 0:
        if e & 1:
            q = _edwards_add(q, p)
        p = _edwards_add(p, p)
        e >>= 1
    return q


def _isoncurve(p: tuple) -> bool:
    x, y = p
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def _has_small_order(p: tuple) -> bool:
    """
    判定点是否落在 8 阶小阶子群内（含零元的退化点）。
    这类点是 Ed25519 验签的经典陷阱：不排除的话，全零签名在
    h≡3 (mod 4) 时会被误判为合法。libsodium 的严格模式同样会拒绝。
    只需 3 次倍点，开销可忽略。
    """
    return _scalarmult(p, 8) == (0, 1)


def _decodepoint(s: bytes) -> tuple:
    if len(s) != 32:
        raise ValueError("point must be 32 bytes")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("non-canonical y")
    x = _xrecover(y)
    if (x & 1) != (s[31] >> 7):
        x = _P - x
    pt = (x, y)
    if not _isoncurve(pt):
        raise ValueError("point not on curve")
    return pt


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """RFC 8032 Ed25519 验签（含小阶点严格拒绝）。失败返回 False，绝不抛异常。"""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        r = _decodepoint(signature[:32])
        a = _decodepoint(public_key)
    except Exception:
        return False
    # 拒绝小阶点：否则全零签名在特定哈希下会「验签成功」
    if _has_small_order(a) or _has_small_order(r):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:                      # 拒绝非规范标量
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little")
    return _scalarmult(_B, s) == _edwards_add(r, _scalarmult(a, h % _L))


def ecdsa_p256_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """
    ECDSA P-256 (SHA-256) 验签，签名格式为 IEEE P1363 (r||s, 64 字节)。
    没有第三方库时返回 False，请改用 Ed25519 或安装 `cryptography`。
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return False
    try:
        pk = serialization.load_der_public_key(public_key)
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        der = utils.encode_dss_signature(r, s)
        pk.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════
#  2. 硬件指纹
# ══════════════════════════════════════════════════════════════════

_machine_cache: Optional[str] = None


def _hardware_tokens() -> list:
    """尽量收集稳定且跨重启不变的标识"""
    tokens: list = []
    system = platform.system()

    if system == "Windows":
        try:
            import winreg  # type: ignore
            for access in (winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0), winreg.KEY_READ):
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Cryptography",
                        0,
                        access,
                    )
                    val, _ = winreg.QueryValueEx(key, "MachineGuid")
                    if val:
                        tokens.append("guid:" + str(val))
                        break
                except OSError:
                    continue
        except Exception:
            pass

    elif system == "Darwin":
        try:
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).decode("utf-8", "ignore")
            m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out)
            if m:
                tokens.append("uuid:" + m.group(1))
        except Exception:
            pass

    else:  # Linux / 其它 Unix
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"):
            try:
                v = Path(path).read_text(encoding="utf-8", errors="ignore").strip()
                if v:
                    tokens.append("id:" + v)
                    break
            except Exception:
                continue

    # 通用兜底
    try:
        node = uuid.getnode()
        if node and not (node >> 40) & 0x01:   # 排除随机生成的伪造 MAC
            tokens.append("mac:%012x" % node)
    except Exception:
        pass

    tokens.append("host:" + platform.node())
    tokens.append("arch:" + platform.machine())
    return tokens


def machine_id() -> str:
    """返回 32 位十六进制硬件指纹，同一台机器稳定不变。"""
    global _machine_cache
    if _machine_cache:
        return _machine_cache
    raw = "|".join(_hardware_tokens())
    _machine_cache = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    return _machine_cache


# ══════════════════════════════════════════════════════════════════
#  3. 配置与异常
# ══════════════════════════════════════════════════════════════════

def _b64url_decode(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


@dataclass
class GuardConfig:
    server_url: str
    app_id: str
    public_key: str
    license_key: str = ""
    """Ed25519 raw 公钥(b64url) 或 ES256 SPKI 公钥(base64)"""

    sign_alg: str = "ed25519"
    """ed25519 | es256"""

    # ── 本地行为 ──
    fail_mode: str = "hard"
    """hard = 直接闪退；message = 打印提示后退出"""

    exit_code: int = 0
    strict_clock: bool = True
    """检测到系统时间被回拨时，是否直接判失效"""

    clock_tolerance_sec: int = 300
    request_timeout: int = 8
    retry_times: int = 2
    heartbeat_sec: int = 21600
    watchdog_interval_sec: int = 120
    """看门狗检查间隔；到期后最多这么久就会闪退"""

    storage_dir: Optional[str] = None
    on_denied: Optional[Callable[[str, str], None]] = None
    """自定义拒绝回调 (code, message) -> None；设了它就不会自动退出"""

    debug: bool = False

    def resolved_license_key(self) -> str:
        if self.license_key:
            return self.license_key.strip()
        for env in ("LICENSE_KEY", f"{self.app_id.upper()}_LICENSE_KEY"):
            v = os.environ.get(env)
            if v:
                return v.strip()
        # 常见放置位置
        for p in _license_file_candidates(self.app_id):
            try:
                text = Path(p).read_text(encoding="utf-8", errors="ignore").strip()
                if text:
                    return text.splitlines()[0].strip()
            except Exception:
                continue
        return ""


def _license_file_candidates(app_id: str) -> list:
    candidates = []
    if getattr(sys, "frozen", False):        # PyInstaller 打包
        base = Path(sys.executable).parent
    else:
        base = Path(__file__).resolve().parent
    candidates.append(base / "license.key")
    candidates.append(base / ".license")
    candidates.append(Path.cwd() / "license.key")
    candidates.append(_data_dir(app_id) / "license.key")
    return candidates


def _data_dir(app_id: str) -> Path:
    system = platform.system()
    if system == "Windows":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
        return Path(root) / app_id
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / app_id
    root = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(root) / app_id


class LicenseError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


@dataclass
class LicenseInfo:
    status: str = "unknown"
    code: str = ""
    message: str = ""
    customer: Optional[str] = None
    features: list = field(default_factory=list)
    expires_at: Optional[int] = None
    hard_expires_at: Optional[int] = None
    max_devices: int = 1
    activations: int = 0
    server_time: int = 0
    offline: bool = False

    def days_left(self) -> Optional[int]:
        if not self.hard_expires_at:
            return None
        return int((self.hard_expires_at - time.time()) // 86400)


# ══════════════════════════════════════════════════════════════════
#  4. 本地状态存储（HMAC 完整性保护）
# ══════════════════════════════════════════════════════════════════

class _StateStore:
    """
    保存令牌与时间锚点。
    用 HMAC-SHA256 做完整性校验 —— 手改 JSON 会被发现。
    （密钥不追求抗逆向，只是拦住「记事本改时间」这一档攻击。）
    """

    MAGIC = "LGST1"

    def __init__(self, app_id: str, directory: Optional[str] = None):
        self.dir = Path(directory) if directory else _data_dir(app_id)
        self.path = self.dir / "state.dat"
        self._key = hashlib.sha256(
            ("license-guard::" + app_id + "::" + machine_id()).encode("utf-8")
        ).digest()

    def _mac(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def load(self) -> Dict[str, Any]:
        try:
            raw = self.path.read_bytes()
        except Exception:
            return {}
        try:
            idx = raw.index(b"\n")
            head, body = raw[:idx].decode("ascii"), raw[idx + 1:]
            magic, mac = head.split(":", 1)
            if magic != self.MAGIC:
                return {}
            if not hmac.compare_digest(mac, self._mac(body)):
                return {"__tampered__": True}
            return json.loads(body.decode("utf-8"))
        except Exception:
            return {}

    def save(self, data: Dict[str, Any]) -> None:
        try:
            body = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
            head = f"{self.MAGIC}:{self._mac(body)}".encode("ascii")
            self.dir.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_bytes(head + b"\n" + body)
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except Exception:
                pass
        except Exception:
            pass

    def clear(self) -> None:
        try:
            self.path.unlink()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════
#  5. 令牌解析 / 验签
# ══════════════════════════════════════════════════════════════════

class _Token:
    @staticmethod
    def parse(token: str) -> tuple:
        parts = token.split(".")
        if len(parts) != 3:
            raise LicenseError("BAD_TOKEN", "令牌格式错误")
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        sig = _b64url_decode(parts[2])
        signing_input = (parts[0] + "." + parts[1]).encode("ascii")
        return header, payload, sig, signing_input

    @staticmethod
    def verify(token: str, public_key: str, alg: str) -> Dict[str, Any]:
        header, payload, sig, signing_input = _Token.parse(token)

        header_alg = str(header.get("alg", "")).upper()
        if alg == "es256" and header_alg != "ES256":
            raise LicenseError("ALG_MISMATCH", "令牌算法与本地配置不匹配")
        if alg == "ed25519" and header_alg not in ("ED25519", "EDDSA"):
            raise LicenseError("ALG_MISMATCH", "令牌算法与本地配置不匹配")

        pub = _b64url_decode(public_key)
        ok = (
            ecdsa_p256_verify(pub, sig, signing_input)
            if alg == "es256"
            else ed25519_verify(pub, sig, signing_input)
        )
        if not ok:
            raise LicenseError("BAD_SIGNATURE", "授权令牌签名校验失败（文件可能被篡改）")
        return payload


# ══════════════════════════════════════════════════════════════════
#  6. 主体
# ══════════════════════════════════════════════════════════════════

class LicenseGuard:
    def __init__(self, config: GuardConfig):
        self.cfg = config
        self.server_url = config.server_url.rstrip("/")
        self.app_id = config.app_id
        self.machine_id = machine_id()
        self.store = _StateStore(config.app_id, config.storage_dir)

        self._state: Dict[str, Any] = {}
        self._info: Optional[LicenseInfo] = None
        self._lock = threading.RLock()
        self._watchdog: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ---------------------------------------------------------- 日志
    def _log(self, *a) -> None:
        if self.cfg.debug:
            print("[license-guard]", *a, file=sys.stderr)

    # ------------------------------------------------------ 网络请求
    def _post(self, path: str, body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url = f"{self.server_url}{path}"
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"license-guard-py/{__version__}",
            },
        )
        last_err: Optional[Exception] = None
        for attempt in range(max(1, self.cfg.retry_times)):
            try:
                with urllib.request.urlopen(req, timeout=self.cfg.request_timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                try:
                    payload = json.loads(e.read().decode("utf-8"))
                except Exception:
                    payload = {"ok": False, "code": "HTTP_%d" % e.code, "message": str(e)}
                if e.code in (401, 403, 404, 409, 429):
                    return payload          # 服务端明确拒绝，不重试
                last_err = e
            except Exception as e:            # 断网 / DNS / 超时
                last_err = e
            if attempt < self.cfg.retry_times - 1:
                time.sleep(0.8 * (attempt + 1))
        self._log("网络不可用:", last_err)
        return None

    # -------------------------------------------------------- 时间锚点
    def _effective_now(self, state: Dict[str, Any]) -> tuple:
        """
        返回 (有效当前时间, 是否疑似时钟被回拨)。
        把「系统时间调回过去」这种最常见的绕过手段堵住。
        """
        wall = int(time.time())
        last = int(state.get("last_wall") or 0)
        if last and wall < last - self.cfg.clock_tolerance_sec:
            self._log(f"检测到系统时间回拨: now={wall} last={last}")
            return last, True
        return wall, False

    def _offline_until(self) -> int:
        """离线容忍截止时间；从未成功联网过则返回 0（意味着必须联网）"""
        last = int(self._state.get("last_online") or 0)
        if not last:
            return 0
        return last + int(self._state.get("offline_grace_days") or 0) * 86400

    # ------------------------------------------------------ 核心校验
    def verify(self, allow_offline: bool = True) -> LicenseInfo:
        """
        执行一次完整校验。返回 LicenseInfo；不通过则抛 LicenseError。
        """
        with self._lock:
            self._state = self.store.load() or {}
            if self._state.get("__tampered__"):
                self._log("本地状态文件被改动过，已重置")
                self.store.clear()
                self._state = {}

            raw_key = self.cfg.resolved_license_key()
            if not raw_key:
                raise LicenseError(
                    "NO_KEY",
                    "未找到授权码（可通过参数、环境变量 LICENSE_KEY 或同目录 license.key 提供）",
                )

            now, tampered = self._effective_now(self._state)
            if tampered and self.cfg.strict_clock:
                self._raise("CLOCK_TAMPERED", "检测到系统时间被修改，授权校验失败")

            # ── 1) 有缓存令牌 → 先尝试离线判定 ──────────────────
            cached = self._state.get("token")
            payload: Optional[Dict[str, Any]] = None
            if cached:
                try:
                    payload = _Token.verify(cached, self.cfg.public_key, self.cfg.sign_alg)
                except LicenseError as e:
                    self._log("缓存令牌无效，重新联网获取:", e.code)
                    self.store.clear()
                    self._state = {}
                    cached = None
                    payload = None

            if payload is not None:
                if payload.get("mid") and payload["mid"] != self.machine_id:
                    self._raise("MACHINE_MISMATCH", "该授权绑定了另一台设备")

                hexp = payload.get("hexp")
                if hexp and now > int(hexp):
                    self._raise("LICENSE_EXPIRED", self._expired_msg(payload))

                # 令牌未过期 且 离线容忍未耗尽 → 直接放行，不联网
                if now <= int(payload.get("exp") or 0) and now <= self._offline_until():
                    self._state["last_wall"] = now
                    self.store.save(self._state)
                    self._info = self._info_from_payload(payload, offline=True)
                    return self._info

            # ── 2) 联网校验 ────────────────────────────────────
            endpoint = "/v1/activate" if not cached else "/v1/verify"
            resp = self._post(endpoint, {
                "app_id": self.app_id,
                "key": raw_key,
                "machine_id": self.machine_id,
                "machine_name": platform.node(),
                "platform": platform.system().lower(),
                "app_version": _app_version(),
            })

            if resp is None:
                # 完全联不上 → 只能靠离线容忍
                if payload is not None and allow_offline:
                    offline_until = self._offline_until()
                    if offline_until and now > offline_until:
                        self._raise("OFFLINE_TOO_LONG",
                                    "长时间未联网校验，授权已失效，请连接网络后重试")
                    self._log("离线放行，容忍截止", offline_until)
                    self._info = self._info_from_payload(payload, offline=True)
                    return self._info
                raise LicenseError("NETWORK", "无法连接授权服务器，且本地没有可用的离线授权")

            if not resp.get("ok"):
                code = str(resp.get("code") or "DENIED")
                self._raise(code, str(resp.get("message") or "授权被拒绝"))

            data = resp["data"]
            payload = _Token.verify(
                data["token"], self.cfg.public_key, data.get("sign_alg", self.cfg.sign_alg)
            )
            if payload.get("mid") != self.machine_id:
                self._raise("MACHINE_MISMATCH", "服务端返回的授权与当前设备不匹配")

            now, tampered = self._effective_now(self._state)
            if tampered and self.cfg.strict_clock:
                self._raise("CLOCK_TAMPERED", "检测到系统时间被修改")

            hexp = payload.get("hexp")
            if hexp and now > int(hexp):
                self._raise("LICENSE_EXPIRED", self._expired_msg(payload))

            policy = data.get("policy") or {}
            server_time = int(data.get("server_time") or now)
            self._state = {
                "token": data["token"],
                "last_online": server_time,
                "last_wall": now,
                "license_key": raw_key,
                "offline_grace_days": int(policy.get("offline_grace_days") or 0),
                "heartbeat_sec": int(policy.get("heartbeat_sec") or self.cfg.heartbeat_sec),
                "install_id": self._state.get("install_id") or uuid.uuid4().hex,
            }
            self.store.save(self._state)

            # 服务端下发的策略可以覆盖本地默认值
            if policy.get("fail_mode") in ("hard", "message"):
                self.cfg.fail_mode = policy["fail_mode"]
            if isinstance(policy.get("exit_code"), int):
                self.cfg.exit_code = policy["exit_code"]

            self._info = self._info_from_payload(payload, offline=False, data=data)
            self._log("校验通过:", self._info.status, "到期:", self._info.expires_at)
            return self._info

    # ------------------------------------------------------- 辅助
    @staticmethod
    def _expired_msg(payload: Dict[str, Any]) -> str:
        aexp = payload.get("aexp")
        if aexp:
            return "授权已于 %s 到期" % time.strftime("%Y-%m-%d", time.localtime(int(aexp)))
        return "授权已到期"

    def _info_from_payload(
        self, payload: Dict[str, Any], offline: bool, data: Optional[Dict[str, Any]] = None
    ) -> LicenseInfo:
        lic = (data or {}).get("license") or {}
        return LicenseInfo(
            status="grace" if (data or {}).get("status") == "grace" else "active",
            code="OFFLINE_OK" if offline else str((data or {}).get("code") or "OK"),
            message=str((data or {}).get("message") or ""),
            customer=payload.get("cus") or lic.get("customer"),
            features=list(payload.get("feat") or []),
            expires_at=payload.get("aexp"),
            hard_expires_at=payload.get("hexp"),
            max_devices=int(lic.get("max_devices") or 1),
            activations=int(lic.get("activations") or 0),
            server_time=int(payload.get("srv") or 0),
            offline=offline,
        )

    def _raise(self, code: str, message: str) -> None:
        if self.cfg.on_denied:
            self.cfg.on_denied(code, message)
            raise LicenseError(code, message)
        _terminate(self.cfg.fail_mode, self.cfg.exit_code, message, code)

    # ----------------------------------------------------- 公开 API
    def authorize(self) -> LicenseInfo:
        """启动时调用。校验不通过会按策略终止进程（hard = 直接闪退）。"""
        try:
            return self.verify()
        except LicenseError as e:
            if self.cfg.on_denied:
                raise
            _terminate(self.cfg.fail_mode, self.cfg.exit_code, e.message, e.code)
            raise  # 理论上到不了

    def start_watchdog(self) -> None:
        """
        后台看门狗：周期性重新校验。
        效果是「到期时刻一到，即使程序正在运行也会立刻退出」。
        """
        if self._watchdog and self._watchdog.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            interval = max(15, int(self.cfg.watchdog_interval_sec))
            while not self._stop.wait(interval):
                try:
                    info = self.verify()
                    hb = int(self._state.get("heartbeat_sec") or self.cfg.heartbeat_sec)
                    interval = max(15, min(hb, 900))
                    self._log("看门狗: OK", info.days_left())
                except LicenseError as e:
                    self._log("看门狗: 失败", e.code)
                    if self.cfg.on_denied:
                        try:
                            self.cfg.on_denied(e.code, e.message)
                        except Exception:
                            pass
                        self._stop.wait(600)
                        continue
                    _terminate(self.cfg.fail_mode, self.cfg.exit_code, e.message, e.code)

        self._watchdog = threading.Thread(target=loop, name="license-guard-watchdog", daemon=True)
        self._watchdog.start()

    def stop_watchdog(self) -> None:
        self._stop.set()

    def has_feature(self, name: str) -> bool:
        return bool(self._info and name in self._info.features)

    @property
    def info(self) -> LicenseInfo:
        if self._info is None:
            raise LicenseError("NOT_VERIFIED", "尚未执行 verify()")
        return self._info

    def days_left(self) -> Optional[int]:
        return self._info.days_left() if self._info else None

    def release(self) -> bool:
        """主动解绑当前设备（换机时调用）"""
        raw_key = self.cfg.resolved_license_key()
        if not raw_key:
            return False
        resp = self._post("/v1/deactivate", {
            "app_id": self.app_id,
            "key": raw_key,
            "machine_id": self.machine_id,
        })
        if resp and resp.get("ok"):
            self.store.clear()
            self._state = {}
            return True
        return False

    # 上下文管理器写法
    def __enter__(self) -> "LicenseGuard":
        self.authorize()
        self.start_watchdog()
        return self

    def __exit__(self, *exc) -> None:
        self.stop_watchdog()


def _app_version() -> str:
    try:
        from importlib.metadata import version  # type: ignore
        main = sys.modules.get("__main__")
        name = getattr(main, "__package__", None) or getattr(main, "__name__", None)
        if name and name not in ("__main__", None):
            return version(name)
    except Exception:
        pass
    return __version__


# ══════════════════════════════════════════════════════════════════
#  7. 终止策略 —— 「到期直接闪退」
# ══════════════════════════════════════════════════════════════════

def _terminate(mode: str, code: int, message: str, err_code: str) -> None:
    """
    hard    : 不走 Python 清理流程，直接终止进程 —— 表现就是「闪退」。
    message : 输出一行提示后退出。
    两者都保证：代码执行不到后面的业务逻辑。
    """
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass

    if mode == "message":
        banner = "!" * 58
        try:
            sys.stderr.write(
                f"\n{banner}\n  {message}\n  (错误代码: {err_code})\n{banner}\n"
                "  请联系软件供应商续期。\n\n"
            )
            sys.stderr.flush()
        except Exception:
            pass
        _try_dialog(message)
        os._exit(code)

    # hard：不打印堆栈、不触发 atexit，直接走
    os._exit(code)


def _try_dialog(message: str) -> None:
    """尝试弹一个系统对话框（失败静默忽略，不引入任何依赖）"""
    try:
        if platform.system() == "Windows":
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, message, "授权已到期", 0x10)
        elif platform.system() == "Darwin":
            subprocess.run(
                ["osascript", "-e", 'display dialog "%s" with title "授权已到期" buttons {"确定"} with icon stop'
                 % message.replace('"', "'")],
                timeout=30,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════
#  8. 便捷函数
# ══════════════════════════════════════════════════════════════════

def quick_guard(server_url: str, app_id: str, public_key: str, license_key: str = "",
                fail_mode: str = "hard", watchdog: bool = True) -> LicenseGuard:
    """一行接入：校验 + 启动看门狗"""
    guard = LicenseGuard(GuardConfig(
        server_url=server_url, app_id=app_id,
        public_key=public_key, license_key=license_key,
        fail_mode=fail_mode,
    ))
    guard.authorize()
    if watchdog:
        guard.start_watchdog()
    return guard


if __name__ == "__main__":
    # 自检：打印本机指纹
    print("machine_id =", machine_id())
    print("state dir  =", _data_dir("demo"))
