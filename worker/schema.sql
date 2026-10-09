-- ============================================================
--  License Guard · Cloudflare D1 表结构
--  执行： wrangler d1 execute license-guard --remote --file=./schema.sql
-- ============================================================

-- ---------- 产品（一款软件 = 一个 product） ----------
CREATE TABLE IF NOT EXISTS products (
  id                  TEXT    PRIMARY KEY,          -- prod_xxxxxxxx
  app_id              TEXT    NOT NULL UNIQUE,      -- 客户端硬编码的标识，如 "myapp"
  name                TEXT    NOT NULL,             -- 显示名
  sign_alg            TEXT    NOT NULL DEFAULT 'ed25519', -- ed25519 | es256
  default_expires_at  INTEGER,                      -- 默认到期时间(unix 秒)，NULL = 永久
  default_grace_days  INTEGER NOT NULL DEFAULT 0,   -- 到期后的宽限天数
  max_devices         INTEGER NOT NULL DEFAULT 1,   -- 同时可激活设备数
  token_ttl_sec       INTEGER NOT NULL DEFAULT 86400,  -- 在线令牌有效期(秒)，超时需重新联网校验
  heartbeat_sec       INTEGER NOT NULL DEFAULT 21600,  -- 客户端心跳间隔(秒)
  offline_grace_days  INTEGER NOT NULL DEFAULT 7,   -- 断网容忍天数，超过则直接判失效
  fail_mode           TEXT    NOT NULL DEFAULT 'hard', -- hard=闪退  message=提示后退出
  exit_code           INTEGER NOT NULL DEFAULT 0,
  features            TEXT    NOT NULL DEFAULT '[]',-- JSON 数组，如 ["pro","export"]
  status              TEXT    NOT NULL DEFAULT 'active', -- active | disabled
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL
);

-- ---------- 授权码 / 许可证 ----------
CREATE TABLE IF NOT EXISTS licenses (
  id            TEXT    PRIMARY KEY,                -- lic_xxxxxxxx
  key_hash      TEXT    NOT NULL UNIQUE,            -- SHA-256(规范化 key)，查询用
  key_display   TEXT    NOT NULL,                   -- 明文（后台展示用，可删列加固）
  product_id    TEXT    NOT NULL,
  customer      TEXT,                               -- 客户名 / 备注
  expires_at    INTEGER,                            -- 到期时间(unix 秒)，NULL = 永久
  grace_days    INTEGER,                            -- 覆盖产品默认宽限，NULL = 继承
  max_devices   INTEGER,                            -- 覆盖产品默认设备数，NULL = 继承
  status        TEXT    NOT NULL DEFAULT 'active',  -- active | suspended | revoked
  note          TEXT,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_licenses_product  ON licenses(product_id);
CREATE INDEX IF NOT EXISTS idx_licenses_expires  ON licenses(expires_at);
CREATE INDEX IF NOT EXISTS idx_licenses_status   ON licenses(status);

-- ---------- 设备激活记录 ----------
CREATE TABLE IF NOT EXISTS activations (
  id            TEXT    PRIMARY KEY,
  license_id    TEXT    NOT NULL,
  machine_id    TEXT    NOT NULL,
  machine_name  TEXT,
  app_version   TEXT,
  platform      TEXT,
  ip            TEXT,
  country       TEXT,
  activated_at  INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  UNIQUE (license_id, machine_id),
  FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_act_license ON activations(license_id);
CREATE INDEX IF NOT EXISTS idx_act_seen    ON activations(last_seen_at);

-- ---------- 审计日志 ----------
CREATE TABLE IF NOT EXISTS audit_logs (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      INTEGER NOT NULL,
  actor   TEXT,
  action  TEXT    NOT NULL,
  target  TEXT,
  detail  TEXT,
  ip      TEXT,
  ua      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);

-- ---------- 失效 / 封禁名单（可选：用于紧急全局封禁） ----------
CREATE TABLE IF NOT EXISTS blocklist (
  kind       TEXT NOT NULL,   -- license | machine | ip
  value      TEXT NOT NULL,
  reason     TEXT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (kind, value)
);
