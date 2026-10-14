# License Guard · 后台运维

管理后台地址见 Skill 根目录 `config.json` 的 `admin_url`（形如 `https://<worker>/admin`）。
登录口令是 Worker 的 `ADMIN_TOKEN` secret。

**日常操作建议直接在网页后台点**；下面记的是对应的 HTTP 接口，用于脚本化或排查。

---

## 鉴权

```bash
curl -X POST "$ADMIN_URL/api/login" -H "Content-Type: application/json" \
  -d '{"token":"<ADMIN_TOKEN>"}'
# => {"token":"<ADMIN_TOKEN>","env":"production"}
```

之后所有请求带 `Authorization: Bearer <ADMIN_TOKEN>`。登录接口限流 10 次/分/IP。

> ⚠️ 不要把手里的 `ADMIN_TOKEN` 写进任何会提交的文件。建议放在环境变量里：
> `export LICENSE_GUARD_ADMIN_TOKEN=...`

---

## 产品（Product）—— 一个产品对应一个 `app_id`

### 新建

```bash
curl -X POST "$ADMIN_URL/api/products" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "app_id": "mytool",
    "name": "我的工具",
    "sign_alg": "ed25519",
    "default_expires_at": "2026-12-31",
    "default_grace_days": 0,
    "max_devices": 1,
    "token_ttl_sec": 86400,
    "heartbeat_sec": 21600,
    "offline_grace_days": 3,
    "fail_mode": "hard",
    "exit_code": 0,
    "features": ["pro", "export"]
  }'
```

| 字段 | 说明 |
|---|---|
| `app_id` | **必填**，只允许字母数字与 `_ . -`，长度 2–64，全局唯一 |
| `sign_alg` | `ed25519`（默认）或 `es256`。**C#/.NET 客户端必须选 `es256`** |
| `default_expires_at` | 默认到期日；`null` = 永久 |
| `default_grace_days` | 到期后宽限天数，`0` = 到点即不可用 |
| `max_devices` | 同时可激活的设备数 |
| `token_ttl_sec` | 在线令牌有效期，超时需重新联网校验 |
| `heartbeat_sec` | 客户端心跳间隔 |
| `offline_grace_days` | **断网容忍天数** —— 决定「断网能跑多久」。想断网即失效请设 `0` |
| `fail_mode` | `hard` 静默闪退 / `message` 提示后退出 |
| `exit_code` | 退出码。想让用户以为是崩溃可设非 0 |
| `features` | 功能开关数组，客户端用 `has_feature("pro")` 判断 |

### 修改 / 删除

- `PATCH /admin/api/products/{id}` —— 传要改的字段即可（字段同上）
- `DELETE /admin/api/products/{id}` —— 级联删除其下所有授权码

---

## 授权码（License）

### 批量生成

```bash
curl -X POST "$ADMIN_URL/api/licenses" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"product_id":"prod_xxx","count":5,"expires_in_days":365,"customer":"某客户"}'
```

| 字段 | 说明 |
|---|---|
| `product_id` | **必填**，产品的 `id`（`prod_` 开头，不是 `app_id`） |
| `count` | 生成数量，1–200 |
| `expires_at` | 绝对到期时间（`2026-12-31` 或 unix 秒）。**优先级最高** |
| `expires_in_days` | 相对天数。都不传则用产品的 `default_expires_at` |
| `customer` / `note` | 客户名 / 备注 |
| `grace_days` / `max_devices` | 覆盖产品默认值，`null` = 继承 |

返回里含**明文授权码**，这是唯一一次能拿到明文的时机之一（后台列表是掩码展示的）。

### 改到期时间 —— 最常用的操作

```bash
# 指定绝对日期
curl -X PATCH "$ADMIN_URL/api/licenses/lic_xxx" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"expires_at":"2027-06-30"}'

# 或从今天起算的天数
curl -X PATCH "$ADMIN_URL/api/licenses/lic_xxx" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"expires_in_days":30}'
```

把 `expires_at` 设成过去的日期 = **立即到期**（客户端下次校验就会被拦下）。

### 吊销 / 暂停

```bash
curl -X PATCH "$ADMIN_URL/api/licenses/lic_xxx" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"status":"revoked"}'      # active | suspended | revoked
```

**生效时机**：客户端默认 `online_check_interval_sec = 0`，即每次校验都必须联网，
所以后台一改，客户端下次校验（启动时或看门狗周期）就会失效。
服务端明确判失效时客户端会**同时清掉本地缓存令牌**，防止用户靠断网续命。

### 设备管理（换机解绑）

```bash
# 看某授权码下已激活的设备
curl "$ADMIN_URL/api/licenses/lic_xxx/activations" -H "Authorization: Bearer $TOKEN"

# 清空该授权码的全部设备位（旧机器坏了的情况）
curl -X POST "$ADMIN_URL/api/licenses/lic_xxx/reset" -H "Authorization: Bearer $TOKEN"

# 删单台设备
curl -X DELETE "$ADMIN_URL/api/activations/act_xxx" -H "Authorization: Bearer $TOKEN"
```

### 导入预生成的授权码

`POST /admin/api/licenses/import`，body `{"product_id":"...","keys":["AAA-BBB-...","..."]}`，单次最多 500 条。

---

## 审计与统计

```bash
curl "$ADMIN_URL/api/stats" -H "Authorization: Bearer $TOKEN"
curl "$ADMIN_URL/api/audit?limit=100" -H "Authorization: Bearer $TOKEN"
```

审计日志记录 `login.ok/fail`、`product.*`、`license.*`、`activate.ok/deny`、`verify.deny`、
`deactivate` 等动作，含 IP 与 UA。

> 注意：审计日志会记录操作细节（含客户名、到期时间）。**这是敏感数据，
> 不要导出成文件提交到任何仓库**（曾因此发生过泄露事故）。

---

## 常见运维场景速查

| 场景 | 做法 |
|---|---|
| 给某客户延期 | 找到授权码 → `PATCH` `{"expires_in_days":N}` |
| 立刻停掉某个授权 | `PATCH` `{"status":"revoked"}` |
| 客户换电脑 | 后台「设备」→ 解绑旧机器；或让用户在旧机跑 `guard.release()` |
| 旧机器已损坏 | `POST /licenses/{id}/reset` 清空全部设备位 |
| 到期立刻生效（不等到期日） | 把 `expires_at` 改成过去时间 |
| 断网也想失效 | 产品设 `offline_grace_days: 0` |
| 想少发请求 | 客户端设 `online_check_interval_sec`（代价：后台改动生效变慢） |
