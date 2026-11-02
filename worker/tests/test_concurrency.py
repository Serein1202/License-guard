#!/usr/bin/env python3
"""
真并发压测：验证「设备数上限」在并发下不会被击穿。

单条 SQL 的原子性已经在 tests/test_activation_atomic.py 里用本地 SQLite 验过，
这里验的是**完整链路**：HTTP 并发 → 路由 → evaluate → upsertActivation → D1。
单测证明不了的部分（并发调度、D1 写串行化、KV 限流会不会误伤）只有这里能覆盖。

三组场景：
  A. 同一授权码、N 台不同机器并发激活 → 成功数必须恰好 == max_devices，其余 DEVICE_LIMIT
  B. 同一台机器并发激活多次        → 只占 1 个设备位（幂等，不能算成多台）
  C. 并发 verify 已激活的机器       → 不新增设备记录

跑法：
    python tests/test_concurrency.py                     # 自己拉起 wrangler dev
    python tests/test_concurrency.py --base-url URL --token ADMIN_TOKEN

依赖：node/npx（wrangler 已在本目录 node_modules）、python 标准库。
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_upgrade  # noqa: E402  复用 http / check / wait_ready / start_worker
from e2e_upgrade import check, http, rand_app, report, start_worker, stop_worker  # noqa: E402

MAX_DEVICES = 3
CONCURRENCY = 24


def wait_slot() -> None:
    """等到下一个 60s 限流槽。

    rateLimit 用 `floor(now/60)` 当槽位，槽一换计数就清零。
    压测会在同一个 IP（本地 dev 下 CF 头缺失，ip 为空）上打几十次激活，
    不跨槽就会被自己的限流拦住 —— 那是限流在正常工作，不是设备上限的逻辑。
    """
    import time
    time.sleep(61 - (int(time.time()) % 60))


def fire(base: str, path: str, body: dict, n: int) -> list[tuple[int, dict]]:
    """并发打 n 次同一请求，返回全部响应。body 会被 copy 后由 make 覆盖键。"""
    out: list[tuple[int, dict]] = [None] * n  # type: ignore[list-item]
    barrier = threading.Barrier(n)  # 尽量让 n 个请求同时到达，放大竞争窗口

    def one(i: int) -> None:
        try:
            barrier.wait(timeout=15)
        except Exception:
            pass  # 屏障超时也要把请求打出去，否则漏测
        out[i] = http("POST", base + path, dict(body), timeout=30)

    with ThreadPoolExecutor(max_workers=n) as pool:
        list(pool.map(one, range(n)))
    return out  # type: ignore[return-value]


def summarize(resps: list[tuple[int, dict]]) -> dict:
    ok = sum(1 for c, r in resps if c == 200 and r.get("ok"))
    codes: dict[str, int] = {}
    for c, r in resps:
        if c == 200 and r.get("ok"):
            continue
        key = str(r.get("code") or f"HTTP{c}")
        codes[key] = codes.get(key, 0) + 1
    return {"total": len(resps), "ok": ok, "rejected": codes}


def run(base: str, admin_token: str) -> None:
    # ------------------------------------------------------------------ 准备
    code, r = http("POST", base + "/admin/api/login", {"token": admin_token})
    check("admin 登录", code == 200 and r.get("ok"), str(code))
    tok = r["data"]["token"]

    app_id = rand_app()
    code, r = http("POST", base + "/admin/api/products", {
        "app_id": app_id, "name": "CONC", "sign_alg": "es256",
        "max_devices": MAX_DEVICES, "offline_grace_days": 7, "token_ttl_sec": 86400,
    }, tok)
    check("创建产品", code == 200 and r.get("ok"), str(code) + " " + r.get("code", ""))
    product_id = r["data"]["id"]

    code, r = http("POST", base + "/admin/api/licenses", {"product_id": product_id, "count": 1}, tok)
    check("创建授权码", code == 200 and r.get("ok"), str(code))
    lic_id = r["data"]["created"][0]["id"]
    key = r["data"]["created"][0]["key"]

    def count_devices() -> int:
        _, d = http("GET", f"{base}/admin/api/licenses/{lic_id}", None, tok)
        return len(d["data"].get("activations", []))

    # ------------------------------- A. 空位充足时并发抢位（核心并发场景）
    print(f"\n--- A. {CONCURRENCY} 台不同机器同时抢 {MAX_DEVICES} 个空位 ---")
    # 关键：用一个全新的授权码，3 个空位都在，8 台机器用屏障对齐后同时打。
    # 只有这样才能验证「并发下不会超发」—— 空位若先被串行请求占掉就测不出竞争。
    code, r = http("POST", base + "/admin/api/licenses", {"product_id": product_id, "count": 1}, tok)
    key_a = r["data"]["created"][0]["key"]
    lic_a = r["data"]["created"][0]["id"]

    barrier = threading.Barrier(CONCURRENCY)
    machines = [f"c{i:03d}" + "0" * 29 for i in range(CONCURRENCY)]
    conc: list[tuple[int, dict]] = []
    lock = threading.Lock()

    def one(i: int) -> None:
        try:
            barrier.wait(timeout=20)   # 对齐出发，放大竞争窗口
        except Exception:
            pass                        # 屏障超时也要把请求打出去，否则漏测
        res = http("POST", base + "/v1/activate", {
            "app_id": app_id, "key": key_a, "machine_id": machines[i], "platform": "windows",
        }, timeout=30)
        with lock:
            conc.append(res)

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        list(pool.map(one, range(CONCURRENCY)))

    s = summarize(conc)
    print("    并发抢位:", s)
    check(f"并发下成功数恰好等于 max_devices={MAX_DEVICES}（不超发）",
          s["ok"] == MAX_DEVICES, str(s))
    check("其余全部被 DEVICE_LIMIT 拒绝",
          set(s["rejected"].keys()) == {"DEVICE_LIMIT"} and
          s["rejected"]["DEVICE_LIMIT"] == CONCURRENCY - MAX_DEVICES, str(s["rejected"]))
    check("并发中没有 500 / 数据库错误",
          not any(str(c).startswith("5") for c, _ in conc),
          str(sorted({c for c, _ in conc})))

    _, da = http("GET", f"{base}/admin/api/licenses/{lic_a}", None, tok)
    acts_a = da["data"].get("activations", [])
    check(f"入库设备记录恰好 {MAX_DEVICES} 条", len(acts_a) == MAX_DEVICES, f"{len(acts_a)} 条")
    check("入库记录互不重复",
          len({a["machine_id"] for a in acts_a}) == len(acts_a),
          str(len({a["machine_id"] for a in acts_a})))

    # ------------------------------- A2. 位满后并发再打，必须全拒
    wait_slot()
    print(f"\n--- A2. 位满后 {CONCURRENCY} 台并发再抢 ---")
    conc2: list[tuple[int, dict]] = []
    barrier2 = threading.Barrier(CONCURRENCY)

    def one2(i: int) -> None:
        try:
            barrier2.wait(timeout=20)
        except Exception:
            pass
        res = http("POST", base + "/v1/activate", {
            "app_id": app_id, "key": key_a,
            "machine_id": f"x{i:03d}" + "0" * 29, "platform": "windows",
        }, timeout=30)
        with lock:
            conc2.append(res)

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        list(pool.map(one2, range(CONCURRENCY)))

    s_full = summarize(conc2)
    print("    位满并发:", s_full)
    check("设备位已满时并发激活 0 成功", s_full["ok"] == 0, str(s_full))
    check("拒绝原因是 DEVICE_LIMIT（不是 500/限流）",
          set(s_full["rejected"].keys()) == {"DEVICE_LIMIT"}, str(s_full["rejected"]))

    # --------------------------------------------- B. 同一台机器并发激活
    wait_slot()
    print(f"\n--- B. 同一台机器并发激活 {CONCURRENCY} 次 ---")
    # 换一个干净授权码，确保有空位
    code, r = http("POST", base + "/admin/api/licenses", {"product_id": product_id, "count": 1}, tok)
    key2 = r["data"]["created"][0]["key"]
    lic2 = r["data"]["created"][0]["id"]

    MID = "d" * 32
    same = fire(base, "/v1/activate", {
        "app_id": app_id, "key": key2, "machine_id": MID, "platform": "windows",
    }, 8)
    s2 = summarize(same)
    print("    同一机器:", s2)
    check("同机并发激活至少成功一次", s2["ok"] >= 1, str(s2))
    check("同机并发不产生重复拒绝",
          set(s2["rejected"].keys()) <= {"DEVICE_LIMIT", "RATE_LIMITED"}, str(s2["rejected"]))

    _, d2 = http("GET", f"{base}/admin/api/licenses/{lic2}", None, tok)
    acts2 = d2["data"].get("activations", [])
    check("同机并发只占 1 个设备位", len(acts2) == 1, f"{len(acts2)} 条")
    check("设备位记录的是同一 machine_id", acts2 and acts2[0]["machine_id"] == MID,
          acts2[0]["machine_id"] if acts2 else "-")

    # ----------------------------------------- C. 并发 verify 不新增设备
    wait_slot()
    print(f"\n--- C. 并发 verify 已激活机器 ---")
    ver = fire(base, "/v1/verify", {
        "app_id": app_id, "key": key2, "machine_id": MID, "platform": "windows",
    }, 8)
    s3 = summarize(ver)
    print("    verify:", s3)
    check("并发 verify 全部成功", s3["ok"] >= 6, str(s3))
    _, d3 = http("GET", f"{base}/admin/api/licenses/{lic2}", None, tok)
    check("并发 verify 后设备数仍为 1",
          len(d3["data"].get("activations", [])) == 1,
          f'{len(d3["data"].get("activations", []))} 条')

    # ------------------------------------------- D. 顺序激活恰好占满上限
    wait_slot()
    print(f"\n--- D. 顺序激活 {MAX_DEVICES} 台应全部成功 ---")
    code, r = http("POST", base + "/admin/api/licenses", {"product_id": product_id, "count": 1}, tok)
    key3 = r["data"]["created"][0]["key"]
    lic3 = r["data"]["created"][0]["id"]
    for i in range(MAX_DEVICES):
        code, r = http("POST", base + "/v1/activate", {
            "app_id": app_id, "key": key3,
            "machine_id": f"s{i:03d}" + "0" * 29, "platform": "windows",
        })
        check(f"第 {i + 1}/{MAX_DEVICES} 台激活成功", code == 200 and r.get("ok"),
              str(code) + " " + str(r.get("code", "")))
    code, r = http("POST", base + "/v1/activate", {
        "app_id": app_id, "key": key3, "machine_id": "z" * 32, "platform": "windows",
    })
    check(f"第 {MAX_DEVICES + 1} 台被拒 DEVICE_LIMIT",
          r.get("code") == "DEVICE_LIMIT", str(r.get("code")))
    _, d4 = http("GET", f"{base}/admin/api/licenses/{lic3}", None, tok)
    check(f"设备记录恰好 {MAX_DEVICES} 条",
          len(d4["data"].get("activations", [])) == MAX_DEVICES,
          f'{len(d4["data"].get("activations", []))} 条')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="")
    ap.add_argument("--token", default="")
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

    return report(e2e_upgrade._results)


if __name__ == "__main__":
    sys.exit(main())
