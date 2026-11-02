#!/usr/bin/env python3
"""已有实例升级验证：模拟「线上跑着旧版表结构」的实例部署新版代码后的行为。

为什么单独做这个测试：
  schema.sql 里的 CREATE TABLE IF NOT EXISTS 对**已存在的表**没有任何作用。
  新版本新加的列只能靠 ALTER TABLE 补。如果这一步出问题（PRAGMA 不支持、
  ALTER 权限、SQL 拼错），受影响的不是新用户，而是线上每一个正在跑的实例 ——
  而且是第一个请求就 500，全站不可用。这个测试就是冲着这个场景来的。

流程：
  1. 清空本地 D1 状态，用当前代码建库（等价于一个健康的新实例）
  2. 通过 admin API 灌入产品 / 授权码 / 一台已激活设备（老 v1 指纹）
  3. 用 sqlite 直接把 machine_id_alt 列删掉 —— 现在它就等价于线上老实例
  4. 重新启动 worker（同一份新代码），打请求
  5. 断言：不 500、老数据没丢、列被补回、新老客户端都能正常校验

用法：
    python tests/test_schema_migration.py
"""

import os
import shutil
import sqlite3
import tempfile
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_upgrade import (  # noqa: E402
    ROOT, check, http, rand_app, start_worker, stop_worker, report, _results,
)

# 每个测试用独立的持久化目录，避免复用 worker/.wrangler/state 里的旧数据
PERSIST = os.path.join(tempfile.gettempdir(), "lg-schema-migration")


def db_dir() -> str:
    return os.path.join(PERSIST, "v3", "d1", "miniflare-D1DatabaseObject")


def kill_workers() -> None:
    """确保没有残留的 wrangler / workerd 占着 sqlite 文件。"""
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/IM", "workerd.exe"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["taskkill", "/F", "/IM", "node.exe", "/FI", "WINDOWTITLE eq *wrangler*"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.run(["pkill", "-f", "workerd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "wrangler dev"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)


def find_db() -> str:
    """本地 D1 的库文件名是 miniflare 按内部规则生成的，按体积挑最大的那个 .sqlite。"""
    d = db_dir()
    cands = [f for f in os.listdir(d) if f.endswith(".sqlite")]
    if not cands:
        raise RuntimeError(f"找不到本地 D1 库文件: {d}")
    cands.sort(key=lambda f: os.path.getsize(os.path.join(d, f)), reverse=True)
    return os.path.join(d, cands[0])


def drop_alt_column(path: str) -> None:
    """把 machine_id_alt 列删掉，把库还原成升级前的样子。"""
    con = sqlite3.connect(path)
    cols = [r[1] for r in con.execute("PRAGMA table_info(activations)")]
    if "machine_id_alt" not in cols:
        con.close()
        return
    # WAL 必须 checkpoint，否则 DROP COLUMN 之后 workerd 可能读到旧页
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.execute("ALTER TABLE activations DROP COLUMN machine_id_alt")
    con.commit()
    con.close()


def column_exists(path: str, column: str) -> bool:
    con = sqlite3.connect(path)
    cols = [r[1] for r in con.execute("PRAGMA table_info(activations)")]
    con.close()
    return column in cols


def seed(base: str, tok: str) -> tuple[str, str, str, str]:
    """建产品 + 授权码，再用老 v1 指纹激活一台设备。返回 (app_id, key, lic_id, v1_mid)。"""
    app_id = rand_app()
    code, r = http("POST", base + "/admin/api/products",
                   {"app_id": app_id, "name": "MIG", "sign_alg": "ed25519",
                    "max_devices": 2, "token_ttl_sec": 600}, tok)
    check("建产品成功", code == 200 and r.get("ok"), str(code))
    product_id = r["data"]["id"]

    code, r = http("POST", base + "/admin/api/licenses",
                   {"product_id": product_id, "count": 1}, tok)
    check("签发授权码成功", code == 200 and r.get("ok"), str(code))
    key = r["data"]["created"][0]["key"]
    lic_id = r["data"]["created"][0]["id"]

    # 模拟线上老用户：只上报 machine_id，没有 machine_id_alt
    v1 = "legacy" + "0" * 26
    code, r = http("POST", base + "/v1/activate",
                   {"app_id": app_id, "key": key, "machine_id": v1, "platform": "windows"})
    check("老指纹激活成功", code == 200 and r.get("ok"), str(code) + " " + str(r.get("code", "")))
    return app_id, key, lic_id, v1


def run() -> None:
    kill_workers()

    # ---------- 1. 干净起点：用当前代码建库并灌入老数据 ----------
    shutil.rmtree(PERSIST, ignore_errors=True)
    os.makedirs(PERSIST, exist_ok=True)
    print("--- 1. 干净建库并写入老数据 ---")
    base, tok, proc = start_worker(persist_to=PERSIST)
    try:
        app_id, key, lic_id, v1 = seed(base, tok)
    finally:
        stop_worker(proc)
        kill_workers()

    db = find_db()
    before = column_exists(db, "machine_id_alt")
    check("新库本身带 machine_id_alt 列", before)

    # ---------- 2. 还原成线上老实例：删掉这一列 ----------
    print("\n--- 2. 删掉 machine_id_alt，模拟线上老实例 ---")
    drop_alt_column(db)
    check("列已删除（模拟成功）", not column_exists(db, "machine_id_alt"))

    con = sqlite3.connect(db)
    rows_before = con.execute("SELECT id, machine_id FROM activations").fetchall()
    lic_before = con.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
    con.close()
    print(f"    删列后残留数据：激活 {len(rows_before)} 条 / 授权码 {lic_before} 个")
    check("删列没有连带丢数据", len(rows_before) == 1 and lic_before >= 1,
          f"{len(rows_before)} 条 / {lic_before} 个")

    # ---------- 3. 部署新版代码：重新启动 worker，打第一个请求 ----------
    print("\n--- 3. 用新代码启动，第一个请求触发迁移 ---")
    base, tok, proc = start_worker(persist_to=PERSIST)
    try:
        code, r = http("GET", base + "/v1/time?app_id=" + app_id)
        check("升级后第一个请求不是 500", code == 200, f"HTTP {code}")
        check("升级后 /v1/time 仍返回签名时间", r.get("ok") and "token" in (r.get("data") or {}),
              str(code))

        # 老客户端（不带 machine_id_alt）必须照常通过
        code, r = http("POST", base + "/v1/verify",
                       {"app_id": app_id, "key": key, "machine_id": v1})
        check("老客户端不带 alt 仍能校验通过", code == 200 and r.get("ok"),
              str(code) + " " + str(r.get("code", "")))

        # 新客户端（v2 指纹 + alt=v1）应认回老记录，不占新设备位
        v2 = "brandnw" + "0" * 25
        code, r = http("POST", base + "/v1/verify",
                       {"app_id": app_id, "key": key, "machine_id": v2, "machine_id_alt": v1})
        check("新指纹带 alt 能认回老记录", code == 200 and r.get("ok"),
              str(code) + " " + str(r.get("code", "")))

        _, d = http("GET", f"{base}/admin/api/licenses/{lic_id}", None, tok)
        acts = d["data"].get("activations", [])
        check("迁移后仍只有 1 个设备位", len(acts) == 1, f"{len(acts)} 条")
        check("设备记录主键已迁到 v2", acts and acts[0]["machine_id"] == v2,
              acts[0]["machine_id"] if acts else "-")

        # 降级回老 SDK：靠 alt 认回
        code, r = http("POST", base + "/v1/verify",
                       {"app_id": app_id, "key": key, "machine_id": v1})
        check("降级回老 SDK 仍能通过（依赖新列）", code == 200 and r.get("ok"),
              str(code) + " " + str(r.get("code", "")))

        # 管理后台列表（含新列读取）不能挂
        code, r = http("GET", base + "/admin/api/licenses?limit=20", None, tok)
        check("后台列表接口正常", code == 200 and r.get("ok"), str(code))
    finally:
        stop_worker(proc)
        kill_workers()

    # ---------- 4. 迁移真的落盘了吗 ----------
    print("\n--- 4. 校验迁移结果落盘 ---")
    db2 = find_db()
    check("machine_id_alt 列已被自动补回", column_exists(db2, "machine_id_alt"))

    con = sqlite3.connect(db2)
    rows = con.execute("SELECT machine_id, machine_id_alt FROM activations").fetchall()
    con.close()
    print("    最终激活记录:", rows)
    check("迁移后记录仍只有 1 条", len(rows) == 1, f"{len(rows)} 条")
    check("记录主键为 v2、alt 保留 v1", rows and rows[0][0] == v2 and rows[0][1] == v1,
          str(rows))

    # ---------- 5. 二次启动：迁移必须幂等，不能重复 ALTER 报错 ----------
    print("\n--- 5. 再次启动（验证幂等）---")
    base, tok, proc = start_worker(persist_to=PERSIST)
    try:
        code, r = http("POST", base + "/v1/verify",
                       {"app_id": app_id, "key": key, "machine_id": v2})
        check("二次启动后校验正常", code == 200 and r.get("ok"),
              str(code) + " " + str(r.get("code", "")))
    finally:
        stop_worker(proc)
        kill_workers()


if __name__ == "__main__":
    try:
        run()
    except Exception as e:  # noqa: BLE001
        print(f"\nEXCEPTION: {type(e).__name__}: {e}")
        sys.exit(2)
    sys.exit(report(_results))
