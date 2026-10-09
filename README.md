# License Guard · 基于 Cloudflare 的软件授权与到期控制系统

给你的软件加一套**授权中心**：后台给每一款软件、每一个授权码**单独设置到期时间**；到期那一刻，客户端进程**立即终止**（闪退）。

改系统时间、断网、改本地文件、换机器 —— 都绕不过去。

整套东西跑在 Cloudflare 上，**免费额度完全够用**（Workers 每天 10 万次请求 + D1 5GB 存储），不需要买服务器、不需要备案。

<p align="center">
  <a href="https://deploy.workers.cloudflare.com/?url=https://github.com/Serein1202/license-guard/tree/main/worker">
    <img src="https://deploy.workers.cloudflare.com/button" alt="Deploy to Cloudflare" />
  </a>
</p>

<p align="center">
  <sub>点按钮 → 登录 Cloudflare → 授权 GitHub → 填 3 个密钥 → 完成，全程无需命令行部署</sub>
</p>

---

## 一键部署（推荐）

1. 把本仓库**克隆一份到自己的 GitHub 账号**
2. **自动创建 D1 数据库和 KV 命名空间**，并绑定到 Worker
3. 自动配好 Workers Builds —— 以后 `git push` 就自动重新部署
4. 弹出表单，填 3 个密钥

> ℹ️ **仓库里不含任何 D1 / KV 的 ID**，所以 fork 之后**不用改任何配置**。配置里只声明了绑定名，Cloudflare 会在部署时按需自动创建资源并绑定。

### 唯一需要你在本机做的一步：生成签名密钥

这一步无法省略 —— 客户端程序需要内嵌**公钥**来离线验签，而**私钥**要交给 Worker 签发令牌。密钥必须由你自己生成。

```bash
git clone https://github.com/Serein1202/license-guard.git
cd license-guard/worker
npm install
npm run keys
```

输出形如：

```
LICENSE_KEY_ED25519 = MC4CAQAwBQYDK2VwBCIE...
LICENSE_KEY_ES256   = MIGHAgEAMBMGByqGSM49AgEG...
──────────────────────────────────────────────
客户端公钥（要内嵌到你的程序里）：
  Ed25519 public key : ej1xQ8v...
  ES256   public key : MFkwEwYHKoZIzj0CAQYI...
```

- `LICENSE_KEY_*` → 部署表单里要填的**私钥**
- `客户端公钥` → 你的程序里要内嵌的**公钥**（复制保存好，后面接入时要用）

### 部署表单会让你填三项

| 字段 | 填什么 |
|---|---|
| `ADMIN_TOKEN` | 自己定一个 20 位以上的随机口令（管理后台登录用） |
| `LICENSE_KEY_ED25519` | `npm run keys` 输出里那一行 |
| `LICENSE_KEY_ES256` | 同上 |

点部署，等几分钟。完成后你会拿到 `https://license-guard.<你的子域>.workers.dev`。

> ⚠️ 本按钮**要求仓库是公开的**（Cloudflare 的硬性限制）。想让自己的部署仓库私有也可以 —— 走下面的[手动路径](#不想用按钮手动部署)。

### 部署后第一件事：打开管理后台

访问 `https://license-guard.<你的子域>.workers.dev/admin`，输入你刚设的 `ADMIN_TOKEN`。

- 首次访问会**自动建表**，不用手动跑任何 SQL
- 然后：**新增软件** → 填 `app_id` → **生成授权码** → 设到期时间

---

## 客户端接入

三端 SDK 都在 [`clients/`](clients/) 目录下，**零第三方依赖**，直接拷进你的项目即可。

**Python**（自带纯 Python Ed25519 验签，不需要装密码学库）

```python
from license_guard import LicenseGuard, GuardConfig

guard = LicenseGuard(GuardConfig(
    server_url  = "https://license-guard.<你的子域>.workers.dev",
    app_id      = "mytool",
    public_key  = "npm run keys 输出的 Ed25519 公钥",
    license_key = "ABCD-EFGH-JKMN-PQRS",
))

guard.authorize()       # 校验；不通过 → 进程立即终止
guard.start_watchdog()  # 运行期看守线程，到期瞬间闪退

# 只有授权通过才会执行到这里
print("程序正常启动")
```

**Node / Electron**

```javascript
import { LicenseGuard } from "./license-guard.js";

const guard = new LicenseGuard({
  serverUrl : "https://license-guard.<你的子域>.workers.dev",
  appId     : "mytool",
  publicKey : "npm run keys 输出的公钥",
  licenseKey: "ABCD-EFGH-JKMN-PQRS",
});

await guard.authorize();
guard.startWatchdog();
```

**C# / .NET / WPF / WinForms**（用 ES256，.NET 内置支持无需额外依赖）

```csharp
var guard = new LicenseGuard(new GuardOptions {
    ServerUrl  = "https://license-guard.<你的子域>.workers.dev",
    AppId      = "mytool",
    PublicKey  = "npm run keys 输出的 ES256 公钥",
    LicenseKey = "ABCD-EFGH-JKMN-PQRS",
    FailMode   = FailMode.Hard,
});
guard.Authorize();
guard.StartWatchdog();
```

完整参数说明、命令行工具 / GUI 程序 / 内网离线环境的接法见 **[docs/INTEGRATION.md](docs/INTEGRATION.md)**。

---

## 核心设计：为什么它绕不过去

到期时间写在 **服务端签名的令牌**里，客户端只内嵌公钥 —— 改一个字节签名就失效。围绕它还有五道闸：

| 常见的绕过手段 | 本方案的处理 |
|---|---|
| 改本地 JSON 文件里的到期时间 | 到期时间在**签名令牌**里，客户端只有公钥，改了就验签失败 |
| 把系统时间调回过去 | 本地保存时间锚点，检测到时间倒退立即判失效（`CLOCK_TAMPERED`） |
| 断网一直用 | 超过 `offline_grace_days` 天（默认 7 天）必须联网复核，否则失效 |
| 换一台机器复制软件 | 授权码绑定硬件指纹，超出设备数上限直接拒绝 |
| 删掉本地状态文件重装 | 重装后需重新联网激活，服务端记录设备位；设备位满了要后台解绑 |
| 到期后程序继续跑 | 后台看门狗持续校验，到期瞬间 `os._exit()`，业务代码执行不到 |

```
                  ┌──────────────────────────────────────────┐
                  │            Cloudflare 边缘                │
                  │                                          │
   客户端启动 ───► │  Worker  /v1/activate  /v1/verify        │
   心跳上报        │     │        ▲                           │
                  │     │        │  Ed25519 签名令牌           │
                  │     ▼        │                           │
                  │   D1 数据库 ── 授权码 / 到期时间 / 设备    │
                  │     ▲                                    │
   管理员──► │  Worker  /admin  ── 网页后台              │
                  └──────────────────────────────────────────┘
                                    │
                              签名令牌（离线可验）
                                    ▼
                    客户端本地判定：到期 → 直接 exit()
```

> 说句实话：**客户端永远不是绝对安全的**。任何纯客户端校验，面对有逆向能力的人都能被绕开。这套方案的目标是把「记事本改时间」这一档的攻击全部堵死，成本极低、体验无感。要防逆向，得配合代码混淆 / 加壳，那属于另一个话题 —— [docs/SECURITY.md](docs/SECURITY.md) 里有专门讨论。

---

## 三种到期模式

后台可以给每个软件、每个授权码单独配：

| 配置 | 效果 |
|---|---|
| **到期时间 + 宽限 0 天** | 到点即失效 |
| **到期时间 + 宽限 N 天** | 到点后进入宽限期（客户端可提示「尽快续期」），宽限结束才硬性失效 |
| **到期时间留空** | 永久授权 |

到期时的行为也能选：

- `hard` —— **直接闪退**。不打印堆栈、不弹窗，表现就是程序突然没了。
- `message` —— 先输出 / 弹出「授权已到期，请联系供应商续期」，然后退出。

> 建议：面向个人用户的产品用 `message`，用户能明白发生了什么；面向内部 / 企业授权用 `hard` 更干脆。一行配置切换。

---

## 其他部署方式

### 不想用按钮：手动部署

**方式 A · Fork + Cloudflare 连接 GitHub**（适合想保留自己仓库、不想要 Cloudflare 克隆副本）

1. Fork 本仓库到你自己的账号
2. 推送后在 Cloudflare → **Workers & Pages → Create → Import a repository** 选你的仓库
   - **Root directory 填 `worker`** ← 最容易漏，不填会构建失败
   - 部署命令 `npx wrangler deploy`
3. 到 **Settings → Variables and Secrets** 添加 `ADMIN_TOKEN`、`LICENSE_KEY_ED25519`、`LICENSE_KEY_ES256` 三个 **Secret**

> D1 和 KV **都不用手动创建、不用填 ID** —— 仓库里的 `wrangler.toml` 只声明了绑定名，部署时 wrangler 会自动创建并绑定。
> 表结构也不用手动建 —— Worker 首次收到请求时会自动建表。

**方式 B · 纯命令行**

```bash
cd worker
npm install
npm run keys                       # 生成签名密钥
npx wrangler login

# D1 / KV 无需手动创建 —— wrangler 会自动创建并绑定
npx wrangler secret put ADMIN_TOKEN
npx wrangler secret put LICENSE_KEY_ED25519
npx wrangler secret put LICENSE_KEY_ES256
npx wrangler deploy
```

## 目录结构

```
license-guard/
├── worker/                        Cloudflare Worker 后端
│   ├── src/
│   │   ├── index.ts               路由入口 + 定时清理
│   │   ├── sign.ts                Ed25519 / ES256 令牌签发
│   │   ├── evaluate.ts            ★ 授权裁决核心逻辑
│   │   ├── db.ts                  D1 数据访问层
│   │   ├── schema.ts              首次请求自动建表
│   │   ├── routes/public.ts       客户端接口
│   │   └── routes/admin.ts        管理接口
│   ├── public/admin.html          网页管理后台（单文件，零依赖）
│   ├── scripts/gen-keys.mjs       生成签名密钥对
│   ├── schema.sql                 D1 表结构
│   ├── .dev.vars.example          一键部署表单的三个填写项
│   └── wrangler.toml              Cloudflare 配置
│
├── clients/                       客户端 SDK（三端，零第三方依赖）
│   ├── python/license_guard.py    Python（自带纯 Python Ed25519 验签）
│   ├── node/license-guard.js      Node / Electron
│   └── dotnet/LicenseGuard.cs     C# / .NET / WPF / WinForms
│
└── docs/
    ├── DEPLOY.md                  部署指南（一步步来）
    ├── INTEGRATION.md             客户端接入指南
    └── SECURITY.md                安全模型与加固建议
```

---

## 后端接口一览

**客户端调用（无需 API Key，授权码即凭证）**

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/v1/activate` | 首次激活，占用一个设备位 |
| `POST` | `/v1/verify` | 校验 / 续令牌，不新增设备位 |
| `POST` | `/v1/heartbeat` | 心跳（语义同 verify） |
| `POST` | `/v1/deactivate` | 解绑当前设备 |
| `GET` | `/v1/time?app_id=` | 服务端签名时间（对抗时钟回拨） |
| `GET` | `/v1/meta?app_id=` | 查询产品策略 |

**管理后台（`Authorization: Bearer <ADMIN_TOKEN>`）**

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/admin/api/login` | 校验口令 |
| `GET/POST` | `/admin/api/products` | 软件列表 / 新建 |
| `PATCH/DELETE` | `/admin/api/products/:id` | 改配置 / 删除 |
| `GET/POST` | `/admin/api/licenses` | 授权码列表 / 批量生成 |
| **`PATCH`** | **`/admin/api/licenses/:id`** | **改到期时间、宽限、状态（核心）** |
| `POST` | `/admin/api/licenses/:id/reset` | 清空全部已激活设备 |
| `GET` | `/admin/api/activations` | 查看设备激活记录 |
| `GET` | `/admin/api/stats` | 概览统计 |
| `GET` | `/admin/api/audit` | 审计日志 |

改到期时间示例：

```bash
curl -X PATCH https://license-guard.<你的子域>.workers.dev/admin/api/licenses/lic_abc123 \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"expires_at": "2027-06-30 23:59:59"}'

# 或者用相对天数
-d '{"expires_in_days": 365}'

# 改成永久
-d '{"expires_at": null}'
```

---

## 授权令牌长什么样

```
eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoibXl0b29sIiwidHlwIjoiTElDIn0.
eyJ2IjoxLCJzdWIiOiJsaWNfYTFiMmMzIiwibWlkIjoiMjY4YThiMTRlYTZm...
<IEd25519 签名>
```

载荷（明文可见，但改一个字节签名就失效）：

```json
{
  "v": 1,
  "sub": "lic_a1b2c3d4e5",        // 授权码 ID
  "app": "mytool",                // 软件标识
  "mid": "268a8b14ea6f99dc...",   // 绑定的硬件指纹
  "cus": "某客户",                 // 客户名
  "iat": 1793328000,              // 签发时间
  "exp": 1793414400,              // 令牌本身有效期（超时需重新联网）
  "aexp": 1795919.000,            // 名义到期时间
  "hexp": 1796181.000,            // 硬到期时间（含宽限）★ 超此值即失效
  "feat": ["pro", "export"],      // 功能开关
  "srv": 1793328000               // 签发时的服务端时间（时间锚点）
}
```

---

## 成本

| 项目 | 免费额度 | 实际用量估算 |
|---|---|---|
| Workers 请求 | 10 万次/天 | 1000 个客户端 × 每天 24 次心跳 = 2.4 万/天 |
| D1 存储 | 5 GB | 10 万条授权码约 30 MB |
| D1 行读 | 500 万行/天 | 每次校验约 5 行 → 12 万行/天 |
| KV | 10 万读 / 1000 写 每天 | 仅用于限流 |

**结论：中小规模产品完全免费。** 超过免费额度后 Workers 是 $5/月起步。

---

## 已验证

本项目交付前做过完整实测，结论都是真跑通的：

- **客户端端到端 25/25** —— 三端 SDK，含时钟回拨、状态文件篡改、`hard` 模式退出码验证
- **Worker 后端集成测试 83/83** —— 真实运行的 Worker，走完建软件 → 发码 → 激活 → 验签 → 改到期 → 立即失效 → 续期恢复
- **Node ↔ Python 签名交叉验证 12/12**，单次验签 21ms
- TypeScript 类型检查 0 error，C# 编译 0 warning

开发中实测抓到两个真实 bug 并修复：纯 Python Ed25519 未拒绝小阶点、激活设备数计数多加 1。细节见 [docs/SECURITY.md](docs/SECURITY.md)。


## 文档

- **[docs/DEPLOY.md](docs/DEPLOY.md)** —— 从零开始部署，含每一步的预期输出和排错
- **[docs/INTEGRATION.md](docs/INTEGRATION.md)** —— 三端 SDK 完整参数说明、命令行工具 / GUI 程序 / 内网离线环境的接法
- **[docs/SECURITY.md](docs/SECURITY.md)** —— 能防住什么、防不住什么、怎么继续加固

---

## 许可

MIT，详见 [LICENSE](LICENSE)。
