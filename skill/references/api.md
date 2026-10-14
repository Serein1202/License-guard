# License Guard · HTTP API 契约

Worker 源码位置（上游仓库）：`worker/src/routes/public.ts`、`worker/src/routes/admin.ts`。
**这层接口不需要任何 API Key** —— 授权码本身就是凭证。

所有请求/响应均为 JSON（UTF-8）。CORS 已开启。

---

## 客户端接口

| 方法 | 路径 | 用途 | 限流 |
|---|---|---|---|
| `GET` | `/health` | 存活检查 | 无 |
| `GET` | `/v1/time?app_id=` | 服务端签名时间（抗改系统时间） | 无 |
| `GET` | `/v1/meta?app_id=` | 产品策略与算法（可用来校验 app_id 是否有效） | 无 |
| `POST` | `/v1/activate` | 首次激活，**占用一个设备位** | 30 次/分/IP |
| `POST` | `/v1/verify` | 校验 / 续令牌，**不占设备位** | 120 次/分/IP |
| `POST` | `/v1/heartbeat` | 与 `/v1/verify` 完全等价（仅便于区分日志） | 120 次/分/IP |
| `POST` | `/v1/deactivate` | 解绑本机 | 无 |

---

### 请求体（activate / verify / heartbeat / deactivate 通用）

```jsonc
{
  "app_id":       "mytool",              // 必填，与后台建产品时的 app_id 一致
  "key":          "ABCD-EFGH-JKMN-PQRS", // 必填，也可写 license_key
  "machine_id":   "268a8b14ea6f99dc...", // 必填，本机硬件指纹
  "machine_name": "xhdong-02805",        // 可选，仅用于后台展示
  "app_version":  "1.0.0",               // 可选
  "platform":     "windows"              // 可选（windows/macos/linux）
}
```

参数也可放在 query string 上（`?app_id=&key=`），但 `machine_id` 只从 body 读。

### 成功响应（activate / verify / heartbeat）

```jsonc
{
  "status":       "active",     // active | grace
  "code":         "OK",         // OK | OK_GRACE
  "message":      "授权有效",
  "sign_alg":     "ed25519",
  "token":        "eyJ...",     // 签名令牌，客户端必须验签后才可使用
  "server_time":  1791525699,
  "policy": {                   // 服务端下发的策略快照，客户端照此执行
    "fail_mode": "hard", "exit_code": 0, "grace_days": 0,
    "offline_grace_days": 3, "heartbeat_sec": 21600,
    "token_ttl_sec": 86400, "max_devices": 1
  },
  "license": {
    "id":              "lic_9h8m2jhz4c",
    "customer":        "客户名",
    "features":        ["pro", "export"],
    "expires_at":      1917014400,   // 名义到期，到点后进入宽限期
    "hard_expires_at": 1917014400,   // 宽限结束，超过必须停止使用
    "grace_days":      0,
    "activations":     1,            // 该授权码当前已占用设备数
    "max_devices":     1
  }
}
```

### 拒绝响应

HTTP `403`（参数错误为 `400`、限流为 `429`、未知应用/授权码为 `404`）：

```jsonc
{
  "ok":      false,
  "code":    "LICENSE_EXPIRED",       // 见 references/integration.md 错误码表
  "message": "授权已到期",
  "policy":  { /* 策略快照，客户端据此决定闪退还是弹提示 */ }
}
```

> `policy` 的存在让「被拒绝」这条路径也能跟随后端设置。旧版后端不带 `policy` 时，
> Python SDK 会自动补一次 `GET /v1/meta` 拉取策略，再失败才退回本地默认值。

### 令牌结构（JWT 风格，`header.payload.signature`，base64url）

```jsonc
{
  "v": 1,
  "sub": "lic_9h8m2jhz4c",   // 授权码 id
  "app": "mytool",
  "mid": "268a8b14...",      // 绑定的机器指纹 —— 换机即失效
  "cus": "客户名",
  "iat": 1791525699,         // 签发时间
  "exp": 1791612099,         // min(令牌 TTL, 硬到期时间)
  "hexp": 1917014400,        // 硬到期
  "aexp": 1917014400,        // 名义到期
  "feat": ["pro"],
  "srv": 1791525699          // 服务端时间，用于校时
}
```

签名算法按产品的 `sign_alg`：`ed25519`（默认）或 `es256`。

---

### 各接口细节

#### `GET /health`

```jsonc
{ "service": "license-guard", "status": "ok", "time": "2026-10-12T10:16:11.000Z" }
```

用于 Skill 自检：能返回这个就说明 `server_url` 填对了。

#### `GET /v1/meta?app_id=mytool`

```jsonc
{
  "app_id": "mytool", "name": "显示名", "sign_alg": "ed25519",
  "policy": { ... },
  "default_expires_at": null, "now": 1791525699, "day": 86400
}
```

`app_id` 不存在时返回 `404 APP_UNKNOWN`。**这是校验 app_id 拼写的最快方式。**

#### `GET /v1/time?app_id=mytool`

```jsonc
{ "server_time": 1791525699, "sign_alg": "ed25519", "token": "eyJ..." }
```

`token` 是签名的服务端时间，客户端用它判断本机时钟有没有被回拨。

#### `POST /v1/deactivate`

成功返回 `{ "released": true }`。幂等——解绑一台本来就没绑定的机器也返回 true。

#### `POST /v1/verify` 与 `POST /v1/activate` 的关键差异

| | activate | verify / heartbeat |
|---|---|---|
| 占用新设备位 | 是 | 否 |
| 未激活设备 | 放行并登记 | 返回 `DEVICE_NOT_ACTIVATED` |
| 适用时机 | 首次拿到授权码 | 启动校验、心跳、续令牌 |

客户端 SDK 会自动选择：本地有令牌走 verify，没有则走 activate。

---

## 管理端接口

后台页面 `GET /admin`（单页，带 CSP 与 `X-Robots-Tag: noindex`）。

管理 API 前缀 `/admin/api/`，**除登录外都需要 `Authorization: Bearer <ADMIN_TOKEN>`**。

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/admin/api/login` | 用 ADMIN_TOKEN 换管理会话；限流 10 次/分/IP |
| `GET` | `/admin/api/me` | 当前身份 |
| `GET` | `/admin/api/stats` | 总览统计 |
| `GET` `POST` | `/admin/api/products` | 产品列表 / 新建 |
| `GET` `POST` | `/admin/api/licenses` | 授权码列表 / 批量生成 |
| `POST` | `/admin/api/licenses/import` | 预先生成的授权码导入 |
| `GET` | `/admin/api/audit` | 审计日志（`?limit=`，默认 100） |
| `GET` | `/admin/api/pubkeys` | 仅返回「私钥是否已配置」的布尔值，**不下发公钥** |

> `/pubkeys` 不返回公钥，所以**无法用它反推客户端该内嵌哪把公钥**。
> 公钥只能来自生成密钥时的 `keys.json` 输出，或已存在于 `config.json` 中。

详见 `references/admin.md`。

---

## 错误码

完整错误码表见 `references/integration.md` 的「授权失败的错误码」一节。
服务端还会返回几个 SDK 层未列出的码：

| 错误码 | HTTP | 含义 |
|---|---|---|
| `BAD_REQUEST` | 400 | 缺少 `app_id` / 授权码 / `machine_id` |
| `APP_UNKNOWN` | 404 | 该 `app_id` 没有对应的产品 |
| `APP_DISABLED` | 403 | 产品被停用 |
| `RATE_LIMITED` | 429 | 触发限流；属临时性拒绝，客户端不应清缓存 |
| `NOT_FOUND` | 404 | 接口不存在（拼错了路径） |
| `INTERNAL_ERROR` | 500 | 服务端异常 |
| `UNAUTHORIZED` | 401 | 管理接口缺/错口令 |
