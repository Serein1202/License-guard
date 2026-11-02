#!/usr/bin/env python3
"""
worker/src/db.ts 中激活写入逻辑的离线验证。

用本地 SQLite 复刻 schema.sql 的 activations 表，验证两件事：
  1. 设备位已满时，新设备无法激活（不超发）；
  2. 已激活设备刷新 last_seen_at 不受设备位限制。

用法：
    python worker/tests/test_activation_atomic.py
预期输出：全部用例 PASS，进程退出码 0。
"""
import os
import sqlite3
import sys
import tempfile

# 与 db.ts upsertActivation 中完全一致的 SQL
UPSERT_SQL = """
INSERT INTO activations
   (id, license_id, machine_id, machine_name, app_version, platform, ip, country, activated_at, last_seen_at)
SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?9
 WHERE EXISTS (SELECT 1 FROM activations WHERE license_id = ?2 AND machine_id = ?3)
    OR (SELECT COUNT(*) FROM activations WHERE license_id = ?2) < ?10
 ON CONFLICT(license_id, machine_id) DO UPDATE SET
   last_seen_at = excluded.last_seen_at,
   machine_name = COALESCE(excluded.machine_name, activations.machine_name),
   app_version  = COALESCE(excluded.app_version,  activations.app_version),
   platform     = COALESCE(excluded.platform,     activations.platform),
   ip           = excluded.ip,
   country      = excluded.country
"""

# 与 db.ts::resolveMachineId 的第 3 步保持一致：
# 迁主键的同时把旧指纹留在 machine_id_alt，供客户端降级回旧 SDK 时认回本机。
# COALESCE 保证连续迁移（v1→v2→v3）时最早的 alt 不被覆盖。
MIGRATE_SQL = ("UPDATE OR IGNORE activations "
               "SET machine_id = ?1, machine_id_alt = COALESCE(machine_id_alt, ?3) "
               "WHERE license_id = ?2 AND machine_id = ?3")

# 与 db.ts::resolveMachineId 的第 2 步保持一致：按 alt 认回降级的客户端
BY_ALT_SQL = "SELECT * FROM activations WHERE license_id = ?1 AND machine_id_alt = ?2"


def new_db():
    con = sqlite3.connect(":memory:")
    con.execute("""
        CREATE TABLE activations (
          id            TEXT PRIMARY KEY,
          license_id    TEXT NOT NULL,
          machine_id      TEXT NOT NULL,
          machine_id_alt  TEXT,
          machine_name  TEXT,
          app_version   TEXT,
          platform      TEXT,
          ip            TEXT,
          country       TEXT,
          activated_at  INTEGER NOT NULL,
          last_seen_at  INTEGER NOT NULL,
          UNIQUE (license_id, machine_id)
        )
    """)
    con.commit()
    return con


def upsert(con, license_id, machine_id, ts, max_devices):
    """返回 True 表示写入成功（占用到设备位），False 表示被上限挡掉。"""
    limit = 2 ** 62 if max_devices is None else max_devices
    con.execute(UPSERT_SQL, (f"act_{machine_id}", license_id, machine_id,
                             None, None, None, None, None, ts, limit))
    con.commit()
    row = con.execute("SELECT 1 FROM activations WHERE license_id=? AND machine_id=?",
                      (license_id, machine_id)).fetchone()
    return row is not None


def count(con, license_id):
    return con.execute("SELECT COUNT(*) FROM activations WHERE license_id=?",
                       (license_id,)).fetchone()[0]


def check(name, cond):
    print(("PASS  " if cond else "FAIL  ") + name)
    return cond


def main():
    ok = True
    lic = "lic_test"

    # 用例 1：max_devices=2，第 1、2 台激活成功，第 3 台被拒
    con = new_db()
    ok &= check("第 1 台激活成功", upsert(con, lic, "m1", 1000, 2))
    ok &= check("第 2 台激活成功", upsert(con, lic, "m2", 1001, 2))
    ok &= check("第 3 台被上限挡掉", not upsert(con, lic, "m3", 1002, 2))
    ok &= check("设备数仍然只有 2", count(con, lic) == 2)

    # 用例 2：不传上限（verify 续期路径），已激活设备不受影响
    ok &= check("已激活设备续期成功", upsert(con, lic, "m2", 2000, None))
    ok &= check("续期不新增设备位", count(con, lic) == 2)
    seen = con.execute("SELECT last_seen_at FROM activations WHERE license_id=? AND machine_id=?",
                       (lic, "m2")).fetchone()[0]
    ok &= check("last_seen_at 已刷新", seen == 2000)

    # 用例 3：max_devices=1 的边界
    con = new_db()
    ok &= check("单机授权第 1 台通过", upsert(con, lic, "a", 1, 1))
    ok &= check("单机授权第 2 台被拒", not upsert(con, lic, "b", 2, 1))
    ok &= check("单机授权只占 1 位", count(con, lic) == 1)

    # 用例 4：指纹迁移——旧记录挂 v1 指纹，升级后上报 v2 指纹
    con = new_db()
    upsert(con, lic, "legacy_fp", 10, 1)
    con.execute(MIGRATE_SQL, ("new_fp", lic, "legacy_fp"))
    con.commit()
    ok &= check("迁移后旧指纹记录消失",
                con.execute("SELECT COUNT(*) FROM activations WHERE license_id=? AND machine_id=?",
                            (lic, "legacy_fp")).fetchone()[0] == 0)
    ok &= check("迁移后新指纹接管设备位",
                con.execute("SELECT COUNT(*) FROM activations WHERE license_id=? AND machine_id=?",
                            (lic, "new_fp")).fetchone()[0] == 1)
    ok &= check("迁移不新增设备位", count(con, lic) == 1)

    ok &= check("迁移时把旧指纹记进 machine_id_alt",
                con.execute("SELECT machine_id_alt FROM activations WHERE license_id=? AND machine_id=?",
                            (lic, "new_fp")).fetchone()[0] == "legacy_fp")

    # 用例 4b：客户端降级回旧 SDK，只上报 v1 指纹 —— 必须能按 alt 认回同一台设备
    row = con.execute(BY_ALT_SQL, (lic, "legacy_fp")).fetchone()
    ok &= check("降级上报 v1 能按 alt 命中记录", row is not None)
    ok &= check("降级命中后不新增设备位", count(con, lic) == 1)

    # 用例 4c：连续迁移不冲掉最早的 alt
    con.execute(MIGRATE_SQL, ("newer_fp", lic, "new_fp"))
    con.commit()
    ok &= check("连续迁移保留最早的 alt",
                con.execute("SELECT machine_id_alt FROM activations WHERE license_id=? AND machine_id=?",
                            (lic, "newer_fp")).fetchone()[0] == "legacy_fp")

    # 用例 5：新指纹已被另一台设备占用时，UPDATE OR IGNORE 不覆盖对方记录
    con = new_db()
    upsert(con, lic, "old", 1, 2)
    upsert(con, lic, "taken", 2, 2)
    con.execute(MIGRATE_SQL, ("taken", lic, "old"))
    con.commit()
    ok &= check("冲突时保留双方记录", count(con, lic) == 2)

    print("\n" + ("全部通过" if ok else "存在失败用例"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
