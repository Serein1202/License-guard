# 部署指南

三条路径，按你的情况选一条：

| 你的情况 | 走哪条 |
|---|---|
| **全新部署**（第一次用，没有历史数据） | **[0.1 一键部署](#01-一键部署全新部署推荐)** ← 最省事，几乎全在网页完成 |
| 想 fork 到自己仓库、连 GitHub 自动部署 | **[0.2 连接 GitHub 自动部署](#02-连接-github-自动部署fork-到自己仓库)** |
| 想完全用命令行控制 | **[0.3 纯命令行部署](#03-纯命令行部署)** |

三条路径部署的是同一个 Worker，差别只在「部署怎么触发」。

**D1 / KV 三条路径都不用手动创建、不用填 ID** —— 仓库里的配置只写了绑定名，部署时 wrangler 会按需自动创建并绑定（见 0.2 步骤 1 的说明）。
无论走哪条，**最终都要给 Worker 配同样的 3 个密钥**，这是最容易漏的一步。

---

## 0. 前置条件

- 一个 Cloudflare 账号（免费版即可，<https://dash.cloudflare.com/sign-up>）
- 本机装了 Node.js 18+（`node -v` 能看到版本号）—— 用于生成签名密钥
- 走 0.1 的话还需要一个 GitHub 账号；走 0.2 / 0.3 的话需要这个仓库

先装依赖：

```bash
cd worker
npm install
```

<details>
<summary>如果 npm install 报 peer dependency 冲突</summary>

```bash
npm install --legacy-peer-deps
```

或者把 `@cloudflare/workers-types` 的版本号改成和 wrangler 要求的一致（报错信息里会写明）。

</details>

---

## 0.1 一键部署（全新部署，推荐）

用 README 顶部的 **Deploy to Cloudflare** 按钮。Cloudflare 会自动完成大部分工作：

1. 把仓库克隆到你自己的 GitHub 账号（之后你就在自己账号里改）
2. 自动创建 **D1 数据库**（绑定名 `DB`）和 **KV 命名空间**（绑定名 `KV`）
3. 弹出一个表单，让你填 3 个密钥
4. 构建并部署到 `https://<项目名>.<你的子域>.workers.dev`

> ⚠️ **只适用于全新部署。** 如果你已经有部署、D1 里已有授权数据，千万别点这个按钮 ——
> 它会创建一个**空的新库**，你原来发的授权码全都读不到。走 0.2。

### 步骤 1：先在本地生成密钥（必做）

这一步**无法跳过**。因为你的客户端程序需要内嵌公钥来做离线验签，所以密钥必须由你来生成：

```bash
cd worker
npm install
npm run keys
```

输出长这样，**把私钥和公钥分别存好**：

```
================================================================
  1) Worker 端密钥（部署表单里要填这两个）
================================================================
LICENSE_KEY_ED25519=MC4CAQAwBQYDK2VwBCIEIB...
LICENSE_KEY_ES256=MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHB...

================================================================
  2) 客户端内嵌的公钥（可以公开，写进你的程序里）
================================================================
PUBLIC_KEY_ED25519_B64URL=F15Kid1oTG5oUxBVK6cRQHdt1E-2ae6NtXRuS93SKGA
PUBLIC_KEY_ES256_SPKI_B64=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
```

同时会生成 `worker/keys.json`（本地留存，**已被 .gitignore 排除，不要提交**）。

### 步骤 2：点按钮并登录

点 README 顶部的 **Deploy to Cloudflare** 按钮 → 用 Cloudflare 账号登录 → 授权 GitHub。

首次授权时选 **Only select repositories**，之后 Cloudflare 就能把仓库克隆到你账号下。

### 步骤 3：填部署表单

表单里主要是这几项：

| 字段 | 填什么 |
|---|---|
| GitHub 仓库名 | 随意，比如 `license-guard` |
| Worker 名称 | 随意，会决定你的访问域名 |
| D1 数据库名 | 保持默认 `license-guard` 即可 |
| KV 命名空间名 | 保持默认即可 |
| `ADMIN_TOKEN` | 自己定一个 20 位以上随机口令 |
| `LICENSE_KEY_ED25519` | 粘贴步骤 1 的输出 |
| `LICENSE_KEY_ES256` | 粘贴步骤 1 的输出 |

点 **Deploy**，等 1~2 分钟。

### 步骤 4：验证

1. 打开 `https://<你的域名>/health` —— 应返回 `{"service":"license-guard","status":"ok",...}`
2. 打开 `https://<你的域名>/admin` → 输入 `ADMIN_TOKEN` → 能看到管理后台（此时列表是空的，正常）

**关于建表**：本项目在**首次请求时会自动建表**（见 `worker/src/schema.ts`），
所以一键部署后不需要执行任何 SQL 命令，直接就能用。

> 为什么不用 `wrangler d1 execute` 在部署时建表？因为 Cloudflare Workers Builds
> 自动生成的构建令牌**默认没有 D1 编辑权限**，那样做会静默失败。放在运行时最可靠。

### 常见问题

**Q：部署日志报 `KV namespace 'xxx' is not valid`**
A：说明 `wrangler.toml` 里的 KV/D1 ID 是无效值。一键部署时 Cloudflare 会重写这两个 ID，
如果报这个错，把部署表单里的资源名改一下再重试，或改用 0.3 手动建资源后填 ID。

**Q：页面能打开，但后台登录后一片空白 / 报 500**
A：多半是三个密钥没配全。到 **Settings → Variables and Secrets** 检查。

**Q：我没有 GitHub 账号**
A：走 0.3 纯命令行部署。

---

## 0.2 连接 GitHub 自动部署（Fork 到自己仓库）

这种方式后续每次 `git push` 都会自动重新部署，不用本地执行 `wrangler deploy`。

> 只有在**你已经有部署、且 D1 里有授权数据**时才走这条 —— 因为要用回原来的资源和密钥，数据才不会丢。

### 步骤 1：确认配置里没有写死 ID

仓库里的 `worker/wrangler.toml` **只声明绑定名、不写资源 ID**：

```toml
[[d1_databases]]
binding = "DB"
database_name = "license-guard"

[[kv_namespaces]]
binding = "KV"
```

这是 Cloudflare 官方的「资源自动创建」机制（wrangler ≥ 4.45）：部署时资源不存在就自动创建、已存在就复用；
而且**从 GitHub 部署时，生成的资源 ID 不会回写进仓库**，所以仓库里永远不会出现账号专属 ID。

> 🔑 **如果你已有 D1 数据要保留**：确保 `database_name` 等于你现有数据库的名字（默认就是 `license-guard`），
> wrangler 会按名字匹配到它并复用，不会新建空库。
> 稳妥起见，推送前先导出一份备份：
> ```bash
> npx wrangler d1 export license-guard --remote --output license-backup.sql
> ```

> 表结构也**不用手动建** —— Worker 首次收到请求时会自动建表（见 `src/schema.ts`）。

### 步骤 2：推到 GitHub

```bash
cd ..
git add -A
git commit -m "Add Cloudflare license guard"
git push origin main
```

> ⚠️ 确认 `worker/keys.json` 和 `worker/.dev.vars` **没有**被提交（`.gitignore` 已覆盖）。
> 提交前用 `git status` 核对一遍。

### 步骤 3：在 Cloudflare 连接仓库

1. 打开 <https://dash.cloudflare.com> → **Workers & Pages** → **Create** → **Workers** → **Import a repository**
2. 授权 GitHub，选择你的 `license-guard` 仓库
3. 构建配置填：
   - **Root directory（根目录）**：`worker`
   - **Build command（构建命令）**：留空
   - **Deploy command（部署命令）**：`npx wrangler deploy`
4. 点 **Deploy**

### 步骤 4：配置 Secrets（关键）

Git 集成部署**不会读取** `.dev.vars`，必须在 Dashboard 里配置：

**Workers & Pages → 你的 Worker → Settings → Variables and Secrets**，添加三个 **Secret**（类型选 Secret，不要选 Text）：

| 名称 | 值 |
|---|---|
| `ADMIN_TOKEN` | 你自己定的管理后台口令（≥ 20 位随机字符） |
| `LICENSE_KEY_ED25519` | `keys.json` 里的 `ed25519.secret_pkcs8_b64url` |
| `LICENSE_KEY_ES256` | `keys.json` 里的 `es256.secret_pkcs8_b64url` |

保存后 Worker 会自动重新部署一次。之后访问 `https://<你的域名>/admin` 即可进入管理后台。

### 步骤 5：验证 D1 / KV 绑定生效

构建日志里会看到 wrangler 自动创建或复用资源的信息。到 Dashboard → **Settings → Bindings** 应能看到 `DB`（D1）和 `KV`。

再打开 `https://<你的域名>/admin` 登录：**能看到你的授权码列表 = D1 绑定正确、数据都在。**

如果列表是空的，说明这次绑到了一个新的空库。原来的数据没有删，只是没被绑定 —— 到 **Settings → Bindings**
把 `DB` 改成你原来那个 `license-guard` 数据库即可（或临时在 `wrangler.toml` 里补回 `database_id` 再部署一次）。

---

## 0.3 纯命令行部署

不连 GitHub，全程本地执行。适合没有 GitHub 账号、或想精细控制每一步的情况。

D1 / KV **不需要手动创建** —— `wrangler.toml` 里只声明了绑定名，`wrangler deploy` 会自动创建并绑定。

```bash
cd worker
npx wrangler login
```

然后从下面第 1 步开始，最后用 `npx wrangler deploy` 上线。

> ⚠️ **命令行部署会把自动创建的资源 ID 回写进 `worker/wrangler.toml`。**
> 如果你不希望 ID 进仓库，提交前删掉这几行 —— 或者执行 `git update-index --skip-worktree worker/wrangler.toml`
> 让 Git 忽略这个文件的本机改动。
> （从 GitHub / 面板部署则没有这个问题 —— ID 只留在 Cloudflare 控制台，不会回写仓库。）

> 用命令行时，建议顺手建一次表（GitHub 部署不需要，它会在运行时自动建）：
> ```bash
> npm run db:remote
> ```

---

## 1. 生成签名密钥

```bash
npm run keys
```

会输出三段内容，**先复制到一个安全的地方**：

```
================================================================
  1) Worker 端密钥（用 wrangler secret put 写入，不要提交到 Git）
================================================================

# Ed25519 —— 推荐，令牌短、验签快
LICENSE_KEY_ED25519=MC4CAQAwBQYDK2VwBCIEIB...

# ECDSA P-256 —— C# / .NET 客户端用这个
LICENSE_KEY_ES256=MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHB...

================================================================
  2) 客户端内嵌的公钥（可以公开）
================================================================

# Python / Node (Ed25519)
PUBLIC_KEY_ED25519_B64URL=F15Kid1oTG5oUxBVK6cRQHdt1E-2ae6NtXRuS93SKGA

# C# / .NET (ES256, SPKI base64)
PUBLIC_KEY_ES256_SPKI_B64=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
```

同时会在 `worker/keys.json` 存一份（文件权限 600）。

> ⚠️ **`keys.json` 和那两个 `LICENSE_KEY_*` 绝对不要提交到 Git。** 私钥一旦泄露，任何人都能伪造授权。真泄露了就重新生成，然后所有客户端都要换公钥重新发布。

---

## 2. 创建 Cloudflare 资源（通常可以跳过）

> **默认不需要这一步。** `wrangler.toml` 里只声明了绑定名，`wrangler deploy` 会自动创建 D1 / KV 并绑定。
> 只有当你**想手动指定资源**（复用已有的库、或想自己命名）时，才按下面做。

```bash
npx wrangler login      # 浏览器会弹出授权页
```

<details>
<summary><b>（可选）手动创建 D1 / KV</b></summary>

<br>

```bash
# D1
npx wrangler d1 create license-guard

# KV
npx wrangler kv namespace create LICENSE_KV
```

输出里会有 `database_id` / `id`。要把它们填进 `wrangler.toml`：

```toml
[[d1_databases]]
binding = "DB"
database_name = "license-guard"
database_id = "你的 database_id"

[[kv_namespaces]]
binding = "KV"
id = "你的 KV id"
```

> ⚠️ **一旦填了 ID，它就会随公开仓库暴露。** 这就是为什么默认配置里不写 ID。
> 只想让本机知道、不进仓库的话，用 `git update-index --skip-worktree worker/wrangler.toml`。
> KV 只用来做接口限流，免费版每天 1000 次写入够用。

</details>

### 2.1 建表（可选）

```bash
npm run db:remote
```

> **也可以跳过** —— Worker 首次收到请求时会自动建表（`src/schema.ts`）。

---

## 3. 写入密钥

```bash
npx wrangler secret put ADMIN_TOKEN
# 粘贴你自定义的后台登录口令，回车

npx wrangler secret put LICENSE_KEY_ED25519
# 粘贴上一步的 LICENSE_KEY_ED25519= 后面那一长串

npx wrangler secret put LICENSE_KEY_ES256
# 粘贴 LICENSE_KEY_ES256= 后面那一长串
```

确认一下：

```bash
npx wrangler secret list
```

应该能看到三个名字。

---

## 4. 部署

```bash
npx wrangler deploy
```

成功后输出类似：

```
Uploaded license-guard (1.2 sec)
Deployed license-guard triggers (0.4 sec)
  https://license-guard.your-name.workers.dev
  Schedule: 15 3 * * *
```

用浏览器打开那个地址，应该看到：

```json
{"ok":true,"data":{"service":"license-guard","status":"ok","time":"..."}}
```

---

## 5. 打开管理后台

访问 `https://license-guard.your-name.workers.dev/admin`

输入刚才设的 `ADMIN_TOKEN` 登录。

### 5.1 新增一款软件

点「软件 / 产品」→「+ 新增软件」，填：

| 字段 | 填什么 | 说明 |
|---|---|---|
| 软件名称 | 我的工具箱 | 后台显示用 |
| app_id | `mytool` | **客户端代码里硬编码的标识**，只能用字母数字和 `_ . -` |
| 签名算法 | Ed25519 | Python / Node 用这个；C# 必须选 ES256 |
| 默认到期时间 | 留空 | 留空 = 永久；填了就是所有新授权码的默认到期时间 |
| 到期后宽限天数 | 0 | 填 7 表示到期后还有 7 天缓冲期 |
| 允许同时激活的设备数 | 1 | 超过就会被拒绝，需要在后台解绑 |
| 断网容忍天数 | 7 | 客户端断网超过这个天数必须联网复核 |
| 到期时的行为 | **直接闪退** | 选「弹提示后退出」会更友好 |

### 5.2 生成授权码

「授权码」→「+ 生成授权码」：

- **到期时间**：直接选日期时间
- **或者**「从今天起 N 天后到期」：填 `365` 就是一年
- **两个都留空** = 永久授权
- 可以一次生成多个（最多 200）

生成后会显示授权码列表，比如 `K7M3-9XQP-2WBN-5HFR`。**复制给客户。**

### 5.3 给已有授权码改到期时间

授权码列表里点「改到期」：

- 直接选新的到期时间
- 或者用预设下拉：7 天 / 30 天 / 90 天 / 1 年 / 永久
- 也能顺手把状态改成「暂停」或「吊销」

改完立刻生效（客户端下一次心跳就会拿到新令牌；如果要立即生效，把软件的「令牌有效期」设短一些，比如 3600 秒）。

---

## 6. 验证端到端能跑通

部署完成后，用真实的 Worker 试一次：

```bash
# 换成一个你刚生成的授权码
curl -X POST https://license-guard.your-name.workers.dev/v1/activate \
  -H "Content-Type: application/json" \
  -d '{
    "app_id": "mytool",
    "key": "K7M3-9XQP-2WBN-5HFR",
    "machine_id": "test-machine-0001",
    "platform": "windows"
  }'
```

成功会返回：

```json
{
  "ok": true,
  "data": {
    "status": "active",
    "sign_alg": "ed25519",
    "token": "eyJhbGciOiJFZDI1NTE5Ii...",
    "server_time": 1793328000,
    "policy": { "heartbeat_sec": 21600, "offline_grace_days": 7, "fail_mode": "hard", ... },
    "license": { "expires_at": 1824864000, "hard_expires_at": 1824864000, "max_devices": 1 }
  }
}
```

在后台「授权码」列表里，这台设备应该出现在「设备」列（显示 1/1）。

---

## 7. 绑定自定义域名（可选）

用 `*.workers.dev` 的域名在国内部分地区访问可能不稳。绑自己的域名会好很多：

1. 在 Cloudflare 添加你的域名，把 NS 指过来
2. `wrangler.toml` 里加上：

```toml
routes = [
  { pattern = "license.yourdomain.com/*", zone_name = "yourdomain.com" }
]
```

3. 重新 `npx wrangler deploy`

---

## 常见问题

**Q：`wrangler deploy` 报 "You must be logged in"**
A：`npx wrangler login` 重新登录。CI 环境下改用 `CLOUDFLARE_API_TOKEN` 环境变量。

**Q：`npm run db:remote` 报 "no such table"**
A：用 `npx wrangler d1 list` 看看是不是绑到了别的库。默认配置不写 ID、由 wrangler 自动创建，一般不需要手动跑这条命令 —— Worker 首次收到请求时会自己建表。

**Q：管理后台登录后一片空白**
A：打开浏览器控制台看报错。多半是 `ADMIN_TOKEN` 没设置（`npx wrangler secret list` 检查），或者 KV 没绑定导致登录限流接口抛错。

**Q：客户端报 `BAD_SIGNATURE`**
A：客户端内嵌的公钥和 Worker 里的私钥不是一对。重新 `npm run keys`，两边同时更新。

**Q：客户端报 `MACHINE_MISMATCH`**
A：换了机器，或者硬件有变化。在后台点「设备」→「清空全部设备」再重新激活。

**Q：客户端报 `ALG_MISMATCH`**
A：后台创建软件时选的签名算法和客户端用的公钥不匹配。C# 客户端必须把产品设成 ES256。

**Q：国内访问 workers.dev 慢**
A：绑定自定义域名。Workers 本身在国内大部分地区是可直连的。

**Q：想换签名密钥**
A：重新 `npm run keys` → `wrangler secret put` 覆盖 → 所有客户端更新公钥重新发版。**已发出的令牌会全部失效**，客户端会自动降级为重新联网激活。

---

## 环境变量速查

| 名称 | 类型 | 用途 |
|---|---|---|
| `ADMIN_TOKEN` | secret | 后台登录口令 |
| `LICENSE_KEY_ED25519` | secret | Ed25519 私钥（pkcs8 DER，base64url） |
| `LICENSE_KEY_ES256` | secret | ECDSA P-256 私钥（pkcs8 DER，base64url） |
| `ENVIRONMENT` | var | 环境标识，显示在后台右上角 |
| `ADMIN_CORS_ORIGIN` | var | 管理后台跨域部署时填前端地址；同源部署留空 |

## 定时任务

`wrangler.toml` 默认配置了每天 UTC 03:15 清理 90 天没上报过的激活记录，避免设备位被长期占死。用 `npx wrangler tail` 可以看到日志。
