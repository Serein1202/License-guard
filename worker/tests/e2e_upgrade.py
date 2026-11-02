#!/usr/bin/env python3
"""
升级链路端到端测试：老 SDK（v1 指纹）激活 → 升级到 v2 指纹 → 迁移 → 设备上限。

跑法：
    python tests/e2e_upgrade.py                      # 自己拉起 wrangler dev
    python tests/e2e_upgrade.py --base-url URL --token ADMIN_TOKEN   # 打已有实例

依赖：node/npx（wrangler 已在本目录 node_modules）、python 标准库。
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import random
import shutil
import socket
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PASS, FAIL = "PASS", "FAIL"
_results: list[tuple[bool, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    _results.append((ok, name, detail))
    print(f"{PASS if ok else FAIL}  {name}" + (f"  → {detail}" if detail else ""))


def http(method: str, url: str, body=None, token: str | None = None, timeout: float = 10):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def jwt_payload(tok: str) -> dict:
    seg = tok.split(".")[1]
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg.replace("-", "+").replace("_", "/")))


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_ready(base: str, proc: subprocess.Popen, timeout: float = 90) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            code, _ = http("GET", base + "/v1/meta?app_id=__probe__", timeout=2)
            if code in (200, 404, 400):
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def rand_app() -> str:
    return "e2e" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def start_worker(persist_to: str | None = None) -> tuple[str, str, subprocess.Popen]:
    """拉起本地 wrangler dev，返回 (base_url, admin_token, proc)。失败抛 RuntimeError。

    抽成公共函数是为了让 tests/test_concurrency.py 等复用同一套拉起逻辑。

    persist_to：指定 miniflare 的持久化目录。默认落在 worker/.wrangler/state，
    多个测试串着跑会互相污染；需要控制库初始状态的测试（如 schema 迁移）
    传一个独立目录即可完全隔离。
    """
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = dict(os.environ)
    # .dev.vars 由 scripts/gen-keys.mjs 生成；没有就现场生成
    if not os.path.exists(os.path.join(ROOT, ".dev.vars")):
        subprocess.run(["node", "scripts/gen-keys.mjs"], cwd=ROOT, check=True,
                       stdout=subprocess.DEVNULL)
    admin_token = ""
    with open(os.path.join(ROOT, ".dev.vars"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("ADMIN_TOKEN="):
                admin_token = line.split("=", 1)[1].strip().strip('"')
    if not admin_token:
        raise RuntimeError("读不到 .dev.vars 里的 ADMIN_TOKEN")

    print(f"启动 wrangler dev :{port} …")
    # Windows 上 npx 是 .cmd，必须解析成完整路径才能被 Popen 直接调用
    npx = shutil.which("npx") or shutil.which("npx.cmd") or "npx"
    args = [npx, "wrangler", "dev", "--port", str(port), "--local"]
    if persist_to:
        args += ["--persist-to", persist_to]
    proc = subprocess.Popen(
        args, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**env, "WRANGLER_SEND_METRICS": "false"},
    )
    if not wait_ready(base, proc):
        proc.kill()
        raise RuntimeError("worker 启动失败")
    print("worker 就绪\n")
    return base, admin_token, proc


def stop_worker(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def report(results: list[tuple[bool, str, str]]) -> int:
    """打印汇总并返回进程退出码。"""
    bad = [r for r in results if not r[0]]
    print()
    print(f"{len(results) - len(bad)}/{len(results)} 通过" if bad else "ALL PASS")
    for _, name, detail in bad:
        print(f"  FAIL {name}" + (f" → {detail}" if detail else ""))
    return 0 if not bad else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url")
    ap.add_argument("--token")
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
        run(base, admin_token)
    finally:
        if proc is not None:
            stop_worker(proc)

    return report(_results)


def run(base: str, admin_token: str) -> None:
    # ---------------------------------------------------------------- 准备
    code, r = http("POST", base + "/admin/api/login", {"token": admin_token})
    check("admin 登录", code == 200 and r.get("ok"), str(code))
    tok = r["data"]["token"]

    app_id = rand_app()
    code, r = http("POST", base + "/admin/api/products", {
        "app_id": app_id, "name": "E2E", "sign_alg": "es256",
        "max_devices": 1, "offline_grace_days": 7, "token_ttl_sec": 86400,
    }, tok)
    check("创建产品", code == 200 and r.get("ok"), str(code) + " " + r.get("code", ""))
    product_id = r["data"]["id"]

    code, r = http("POST", base + "/admin/api/licenses", {"product_id": product_id, "count": 1}, tok)
    check("创建授权码", code == 200 and r.get("ok"), str(code))
    lic = r["data"]["created"][0]
    key, lic_id = lic["key"], lic["id"]

    V1 = "1" * 32  # 老 SDK：v1 指纹（含 host/os/arch）
    V2 = "2" * 32  # 升级后：v2 指纹（纯硬件因子）
    V3 = "3" * 32  # 第三台机器

    # ------------------------------------------------- 1. 老 SDK 首次激活
    code, r = http("POST", base + "/v1/activate", {
        "app_id": app_id, "key": key, "machine_id": V1, "platform": "windows",
    })
    check("老 SDK 激活成功", code == 200 and r.get("ok"), str(code) + " " + r.get("code", ""))
    mid1 = jwt_payload(r["data"]["token"])["mid"] if r.get("ok") else None
    check("老令牌 mid == 指纹 v1", mid1 == V1, str(mid1))

    code, d = http("GET", f"{base}/admin/api/licenses/{lic_id}", None, tok)
    acts = d["data"].get("activations", [])
    check("设备表 1 条", len(acts) == 1, f"{len(acts)} 条")
    check("设备 machine_id == v1", acts and acts[0]["machine_id"] == V1,
          acts[0]["machine_id"] if acts else "-")

    # ------------------------------------- 2. 升级到 v2，带 machine_id_alt
    code, r = http("POST", base + "/v1/verify", {
        "app_id": app_id, "key": key, "machine_id": V2, "machine_id_alt": V1,
        "platform": "windows",
    })
    check("升级后首次校验成功", code == 200 and r.get("ok"),
          str(code) + " " + str(r.get("code", "")) + " " + str(r.get("message", "")))
    mid2 = jwt_payload(r["data"]["token"])["mid"] if r.get("ok") else None
    check("新令牌 mid == 指纹 v2（迁移生效）", mid2 == V2, str(mid2))

    code, d = http("GET", f"{base}/admin/api/licenses/{lic_id}", None, tok)
    acts = d["data"].get("activations", [])
    check("迁移后仍只占 1 个设备位", len(acts) == 1, f"{len(acts)} 条")
    check("设备记录已改写为 v2", acts and acts[0]["machine_id"] == V2,
          acts[0]["machine_id"] if acts else "-")

    # ---------------------------------------- 3. 老版本回滚（只报 v1 指纹）
    code, r = http("POST", base + "/v1/verify", {
        "app_id": app_id, "key": key, "machine_id": V1, "platform": "windows",
    })
    check("降级回旧 SDK 仍能通过校验", code == 200 and r.get("ok"),
          str(code) + " " + str(r.get("code", "")) + " " + str(r.get("message", "")))
    mid_rb = jwt_payload(r["data"]["token"])["mid"] if r.get("ok") else None
    check("降级时令牌 mid 回退为 v1（老 SDK 能自校验）", mid_rb == V1, str(mid_rb))

    code2, d = http("GET", f"{base}/admin/api/licenses/{lic_id}", None, tok)
    acts2 = d["data"].get("activations", [])
    check("降级不占第二个设备位", len(acts2) == 1, f"{len(acts2)} 条")
    check("记录主键仍为 v2（规范 ID 不被降级冲掉）",
          acts2 and acts2[0]["machine_id"] == V2, acts2[0]["machine_id"] if acts2 else "-")
    check("machine_id_alt 保留了 v1", acts2 and acts2[0].get("machine_id_alt") == V1,
          str(acts2[0].get("machine_id_alt")) if acts2 else "-")

    # 降级后新版本再回来，不应该被 alt 分支误伤
    code, r = http("POST", base + "/v1/verify", {
        "app_id": app_id, "key": key, "machine_id": V2, "machine_id_alt": V1,
    })
    check("降级后再升级仍正常", code == 200 and r.get("ok"), str(code) + " " + str(r.get("code", "")))

    # ------------------------------------------- 4. 设备上限（max_devices=1）
    code, r = http("POST", base + "/v1/activate", {
        "app_id": app_id, "key": key, "machine_id": V3, "platform": "windows",
    })
    check("超出设备上限被拒", code == 403 and r.get("code") == "DEVICE_LIMIT",
          f"{code} {r.get('code')}")

    # -------------------------------------- 5. 解绑后可以换机器
    code, r = http("POST", base + "/v1/deactivate", {
        "app_id": app_id, "key": key, "machine_id": V2, "machine_id_alt": V1,
    })
    check("解绑成功", code == 200 and r.get("ok"), str(code))
    code, r = http("POST", base + "/v1/activate", {
        "app_id": app_id, "key": key, "machine_id": V3, "platform": "windows",
    })
    check("解绑后新设备可激活", code == 200 and r.get("ok"),
          str(code) + " " + str(r.get("code", "")))

    # -------------------------------------------- 6. 服务端时间接口可用
    code, r = http("GET", base + f"/v1/time?app_id={app_id}")
    d = r.get("data") or {}
    check("/v1/time 返回签名时间",
          code == 200 and r.get("ok") and "server_time" in d and "token" in d,
          str(code) + " keys=" + ",".join(sorted(d.keys())))


if __name__ == "__main__":
    sys.exit(main())
