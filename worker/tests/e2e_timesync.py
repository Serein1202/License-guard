#!/usr/bin/env python3
"""
时钟同步端到端测试：三端 SDK 真的去调 /v1/time，并把服务端时间用于到期判定。

之前 /v1/time 只有一个「接口存在」的断言，三端根本没调过它 —— 客户端的到期判定
全靠本地挂钟，用户把系统时间调回过去就能绕过。这个脚本把链路补上：

  Python : 直接 import clients/python/license_guard.py 跑真实请求
  Node   : 子进程跑 tests/timesync_node.mjs（真实请求），这里收断言结果
  C#     : 反射调用 EffectiveNow（私有方法）验证两个口径的回拨检测

跑法：
    python tests/e2e_timesync.py
    python tests/e2e_timesync.py --base-url URL --token ADMIN_TOKEN
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "..", "clients", "python"))

import e2e_upgrade  # noqa: E402
from e2e_upgrade import check, http, rand_app, report, start_worker, stop_worker  # noqa: E402

PY_SDK = os.path.join(ROOT, "..", "clients", "python", "license_guard.py")


def admin_setup(base: str, admin_token: str):
    """建产品 + 授权码，返回 (app_id, key, public_key_spki_b64)。"""
    code, r = http("POST", base + "/admin/api/login", {"token": admin_token})
    if code != 200 or not r.get("ok"):
        raise RuntimeError("admin 登录失败 " + str(code))
    tok = r["data"]["token"]

    app_id = rand_app()
    code, r = http("POST", base + "/admin/api/products", {
        # 用 ed25519：Python SDK 的 Ed25519 是纯标准库实现，
        # ES256 需要 cryptography（测试机不一定装），不是所有环境都能跑
        "app_id": app_id, "name": "TIME", "sign_alg": "ed25519",
        "max_devices": 5, "offline_grace_days": 7, "token_ttl_sec": 3600,
    }, tok)
    if code != 200 or not r.get("ok"):
        raise RuntimeError("创建产品失败 " + str(code) + " " + r.get("code", ""))

    code, r = http("POST", base + "/admin/api/licenses", {"product_id": r["data"]["id"], "count": 1}, tok)
    if code != 200 or not r.get("ok"):
        raise RuntimeError("创建授权码失败 " + str(code))
    created = r["data"]["created"][0]

    with open(os.path.join(ROOT, "keys.json"), encoding="utf-8") as f:
        # 三端的 ed25519 公钥都是 32 字节 raw（base64url），不是 SPKI
        pub = json.load(f)["ed25519"]["public_raw_b64url"]
    return app_id, created["key"], pub


def python_section(base: str, app_id: str, key: str, pub: str) -> None:
    print("\n=== Python SDK ===")
    try:
        import cryptography  # noqa: F401
    except ImportError:
        pass  # ed25519 走标准库实现，不需要它
    import importlib.util
    spec = importlib.util.spec_from_file_location("lg_py", PY_SDK)
    lg = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # 必须先登记到 sys.modules：模块里的 @dataclass 在定义期要回查自己的模块对象
    sys.modules["lg_py"] = lg
    spec.loader.exec_module(lg)

    import tempfile
    tmp = tempfile.mkdtemp(prefix="lg-timesync-")
    cfg = lg.GuardConfig(
        server_url=base, app_id=app_id, public_key=pub, license_key=key,
        sign_alg="ed25519", storage_dir=tmp, retry_times=1, request_timeout=10,
    )
    guard = lg.LicenseGuard(cfg)

    # 1. 主动同步 → skew 落盘
    skew = guard.sync_time()
    check("sync_time() 返回偏差值", isinstance(skew, int), str(skew))
    check("本机与服务端偏差很小（<5s）", abs(skew) < 5, f"{skew}s")
    st = guard.store.load() or {}
    check("skew 已写入状态文件", "clock_skew" in st, str(sorted(st.keys())))

    # 2. 篡改 server_time（与签名里的 t 不一致）必须被拒
    orig_get = guard._get

    def fake_get(path):
        r = orig_get(path)
        if r and r.get("ok") and "data" in r:
            r = json.loads(json.dumps(r))
            r["data"]["server_time"] = int(r["data"]["server_time"]) - 999999
        return r

    guard._get = fake_get
    try:
        guard.sync_time()
        check("server_time 与签名不一致时被拒", False, "没有抛错")
    except lg.LicenseError as e:
        check("server_time 与签名不一致时被拒", e.code == "BAD_TOKEN", e.code)
    finally:
        guard._get = orig_get

    # 3. 完整 verify 后 skew 会被刷新，且联网成功
    info = guard.verify(allow_offline=False)
    check("verify 成功", info is not None and info.status, str(getattr(info, "status", "")))
    st = guard.store.load() or {}
    check("verify 后 clock_skew 已写入", "clock_skew" in st, str(sorted(st.keys())))
    # 注意别写成 `st.get("clock_skew") or 1e9`：skew 恰好为 0 时它是 falsy，会被当成缺失
    cs = st.get("clock_skew")
    check("verify 后 skew 仍然很小", cs is not None and abs(int(cs)) < 5, str(cs))

    # 4. 回拨检测：把 skew 人为调成 -1 天（等价于用户把系统时间往回调 1 天）
    now = int(time.time())
    now2, tampered = guard._effective_now({
        "last_online": now, "last_wall": now - 60, "clock_skew": -86400,
    })
    check("服务端时间口径回拨被检出", tampered is True, f"now={now2} tampered={tampered}")

    # 5. 回拨检测：挂钟口径（没有 skew 时也能检出）
    _, tampered2 = guard._effective_now({"last_wall": now + 86400})
    check("挂钟口径回拨被检出（无 skew 也生效）", tampered2 is True, str(tampered2))

    # 6. 正常状态不应误报
    _, tampered3 = guard._effective_now({"last_wall": now - 60, "last_online": now - 60,
                                         "clock_skew": 0})
    check("正常情况不误报篡改", tampered3 is False, str(tampered3))

    # 7. install_id 跨校验稳定（回归：之前每次联网都重新生成）
    guard.verify(allow_offline=False)
    st1 = guard.store.load() or {}
    id1 = st1.get("install_id")
    guard.verify(allow_offline=False)
    st2 = guard.store.load() or {}
    check("install_id 跨多次校验稳定", id1 and id1 == st2.get("install_id"),
          f"{id1} vs {st2.get('install_id')}")

    # 8. 断网时 sync_time 抛 NETWORK
    bad = lg.LicenseGuard(lg.GuardConfig(
        server_url="http://127.0.0.1:1", app_id=app_id, public_key=pub, license_key=key,
        sign_alg="ed25519", storage_dir=tmp, retry_times=1, request_timeout=3,
    ))
    try:
        bad.sync_time()
        check("断网时 sync_time 抛 NETWORK", False, "没有抛错")
    except lg.LicenseError as e:
        check("断网时 sync_time 抛 NETWORK", e.code == "NETWORK", e.code)


def node_section(base: str, app_id: str, key: str, pub: str) -> None:
    print("\n=== Node SDK ===")
    script = os.path.join(HERE, "timesync_node.mjs")
    proc = subprocess.run(
        ["node", script], capture_output=True, text=True, timeout=180,
        env={**os.environ, "LG_BASE": base, "LG_APP_ID": app_id,
             "LG_KEY": key, "LG_PUB": pub},
    )
    for line in proc.stdout.strip().splitlines():
        print("    " + line)
    if proc.returncode != 0:
        print(proc.stderr[-2000:])
        check("Node 端脚本整体通过", False, f"exit={proc.returncode}")
        return
    try:
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception as e:
        check("Node 端输出可解析", False, str(e))
        return
    for name, ok, detail in payload.get("results", []):
        check("[node] " + name, bool(ok), str(detail))


def csharp_section() -> None:
    print("\n=== C# SDK（反射调用 EffectiveNow，验证两个口径）===")
    proj = os.path.join(ROOT, "..", "clients", "dotnet", "tests", "AotCompat")
    proc = subprocess.run(["dotnet", "run", "--", "timesync"], cwd=proj,
                          capture_output=True, text=True, timeout=420)
    for line in proc.stdout.strip().splitlines():
        print("    " + line)
    if proc.returncode != 0:
        print(proc.stderr[-2000:])
        check("C# 端时钟断言整体通过", False, f"exit={proc.returncode}")
        return
    for line in proc.stdout.strip().splitlines():
        if line.startswith("CS-RESULT "):
            payload = json.loads(line[len("CS-RESULT "):])
            for name, ok, detail in payload.get("results", []):
                check("[csharp] " + name, bool(ok), str(detail))


def run(base: str, admin_token: str) -> None:
    app_id, key, pub = admin_setup(base, admin_token)
    print(f"app_id={app_id}")
    python_section(base, app_id, key, pub)
    node_section(base, app_id, key, pub)
    csharp_section()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="")
    ap.add_argument("--token", default="")
    ap.add_argument("--skip-csharp", action="store_true")
    args = ap.parse_args()

    proc = None
    if args.base_url:
        base, admin_token = args.base_url.rstrip("/"), args.token or ""
        if not admin_token:
            print("--base-url 需要同时给 --token")
            return 2
    else:
        base, admin_token, proc = start_worker()

    try:
        if args.skip_csharp:
            app_id, key, pub = admin_setup(base, admin_token)
            python_section(base, app_id, key, pub)
            node_section(base, app_id, key, pub)
        else:
            run(base, admin_token)
    finally:
        if proc is not None:
            stop_worker(proc)

    return report(e2e_upgrade._results)


if __name__ == "__main__":
    sys.exit(main())
