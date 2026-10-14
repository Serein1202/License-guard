---
name: license-guard
description: 把已部署在 Cloudflare 上的 license-guard 授权验证系统接入任意软件项目（Python / Node / Electron / C#/.NET）。当用户提出「给这个项目加授权验证」「接入我的授权系统」「加个到期就闪退的功能」「用 license-guard 给这个软件加授权」「给程序加授权码校验」「接入 license-guard」「加 license 校验」等需求时使用。包含三端零依赖客户端 SDK、一键安装脚本、Worker HTTP API 契约与后台运维文档。
agent_created: true
---

# License Guard · 软件授权接入

把**已经部署好的** Cloudflare license-guard 授权系统接入到当前（或指定的）软件项目里。
接入后，软件会在启动时校验授权码，到期/被吊销/设备超限时按后台设定的方式退出（默认静默闪退）。

> 本 Skill 只负责**客户端接入**。服务端（Cloudflare Worker + D1 + KV）已经部署完成，
> 地址与公钥记录在本 Skill 根目录的 `config.json` 里，**直接读它，不要问用户**。
>
> 如果用户要的是**重新部署服务端**，那是另一件事——先问清楚，再参考上游仓库 `Serein1202/license-guard`。

## 接入流程

### 第 0 步：读配置 + 自检

先读配置拿到 `server_url`、`public_keys`、`admin_url`、`defaults`。
配置有两个可能的位置，**`config.local.json` 优先**：

1. `<SKILL_DIR>/config.local.json` —— 本地真实部署配置（已加入 `.gitignore`）
2. `<SKILL_DIR>/config.json` —— 仓库里的占位模板

> 如果读到的仍是 `REPLACE_WITH_...` 占位符，说明用户还没填自己的部署信息。
> **停下来**，让用户按仓库 README 的「AI Skill」一节填好再继续 ——
> 带着占位符接入会把程序连到不存在的地址。

```bash
python <SKILL_DIR>/scripts/selfcheck.py --app-id <APP_ID>
```

`selfcheck.py` 验证三件事：Worker 是否在线、`app_id` 是否存在、**内嵌公钥是否与服务端私钥匹配**
（这一步靠验签 `/v1/time` 返回的令牌完成，不消耗设备位）。

- 三项都通过 → 继续。
- **连不上**（网络超时）→ 通常是本机在中国内地、`workers.dev` 被 DNS 污染/阻断。
  这**不影响接入**（客户端在能联网的环境跑就行），照常继续，只是跳过自检。
  但要提醒用户：如果目标软件的**最终用户也在内地**，需要绑自定义域名，否则客户端会连不上。
- **公钥不匹配** → 停下，别接入。先纠正 `config.json` 里的公钥。

### 第 1 步：确定目标项目与 `app_id`

确认要接入哪个项目（用户没说就取当前工作区），然后确定 `app_id`：

- 用户已报出 app_id → 直接用。
- 是已有产品 → 用 `selfcheck.py --app-id` 验证它存在。
- 是**新软件** → 需要先在后台建产品。`app_id` 命名建议用项目名小写下划线，如 `mytool`。
  规则：只允许字母数字与 `_ . -`，长度 2–64。
  ⚠️ **C#/.NET 项目必须把产品的签名算法选成 `es256`**（.NET 没有内置 Ed25519）。

### 第 2 步：安装 SDK

```bash
python <SKILL_DIR>/scripts/install_sdk.py <项目目录> --app-id <APP_ID>
```

脚本会：探测语言 → 把 SDK 拷进 `<项目>/vendor/` → 生成带**真实**服务地址与公钥的配置常量文件
（`license_config.py` / `license-config.js` / `LicenseConfig.cs`）→ 报告可能的程序入口。

- 语言探测不对时用 `--lang python|node|dotnet` 指定。
- 已有配置需要刷新时加 `--force`。

### 第 3 步：注入守卫

**这是唯一需要动业务代码的一步，必须自己看代码再改，不要无脑插。**

核心只有两行：`authorize()` 是阻塞且决定性的——授权无效时**函数不返回**，进程直接结束。
所以放在 `main()` 最开头，后面的代码天然安全。再开一个看门狗，保证长期运行的程序在到期瞬间退出。

**Python**

```python
import sys; sys.path.insert(0, "vendor")

from license_config import SERVER_URL, APP_ID, PUBLIC_KEY, FAIL_MODE, EXIT_CODE
from license_guard import LicenseGuard, GuardConfig

def main():
    guard = LicenseGuard(GuardConfig(
        server_url=SERVER_URL, app_id=APP_ID, public_key=PUBLIC_KEY,
        fail_mode=FAIL_MODE, exit_code=EXIT_CODE,
    ))
    guard.authorize()        # 不通过 → 进程在这里就结束了
    guard.start_watchdog()   # 运行期持续看守，到期瞬间退出

    # ↓↓↓ 以下才是原有业务代码
    run_your_app()

if __name__ == "__main__":
    main()
```

**Node / Electron**

```javascript
import { LicenseGuard } from "./vendor/license-guard/license-guard.js";
import { LICENSE_CONFIG } from "./license-config.js";

const guard = new LicenseGuard({ ...LICENSE_CONFIG, licenseKey: process.env.LICENSE_KEY || "" });
await guard.authorize();     // 不通过 → process.exit()
guard.startWatchdog();

runYourApp();
```

入口是 CommonJS 时改用动态 `import()`；Electron 主进程里用 `app.whenReady().then(...)` 包起来，
并考虑用 `onDenied` 先通知窗口再退出（见 `references/integration.md` 的 Electron 一节）。

**C# / .NET**

```csharp
using LicenseGuard;

var guard = new LicenseGuard.LicenseGuard(new GuardOptions {
    ServerUrl  = LicenseConfig.ServerUrl,
    AppId      = LicenseConfig.AppId,
    PublicKey  = LicenseConfig.PublicKey,   // 必须是 ES256 公钥
    LicenseKey = LicenseStore.Load(),
    FailMode   = FailMode.Hard,
});
guard.Authorize();
guard.StartWatchdog();
```

WPF/WinForms 放在 `App.xaml.cs` 的 `OnStartup` 里，早于主窗口创建。

**注入原则**

- 放在**真正的业务入口**，不要放在库文件或工具函数里。
- 命令行工具生命周期短，只需 `authorize()`，不必开看门狗。
- GUI / 长期运行的程序**必须**开看门狗。
- 用户想让到期时弹提示而不是静默闪退 → 后台把产品的 `fail_mode` 改成 `message`，
  或客户端传 `on_denied` 自定义处理。**不要在客户端写死策略**，它会跟随服务端下发。

### 第 4 步：拿到授权码

- **有 `ADMIN_TOKEN`**（环境变量 `LICENSE_GUARD_ADMIN_TOKEN`）→ 直接调后台接口，见 `references/admin.md`。
- **没有** → 让用户自己去后台点，把这句给他：

  > 打开 `<config.json 里的 admin_url>`，登录后：**产品** → 新建（`app_id` 填 `<APP_ID>`，
  > C# 项目记得选 ECDSA P-256）→ 然后**授权码** → 生成，设置到期时间。把生成的授权码给我。

授权码可以放在环境变量 `LICENSE_KEY`，或程序同目录的 `license.key` 文件里——SDK 会自动找。

### 第 5 步：验证并交付

1. 跑一次目标程序，确认授权通过、能正常启动。
2. 让用户在后台把该授权码的到期时间改成过去 → 重启程序，确认**确实会退出**。
3. 改回正常时间。**到这一步才算接入成功。**

交付说明里要讲清三件事：授权码放哪、后台地址是什么、客户到期了怎么续。

## 关键约定（容易搞错的地方）

- **`app_id` ≠ `product_id`**。客户端用 `app_id`（如 `mytool`）；调后台接口建授权码要用 `product_id`（`prod_` 开头）。
- **客户端不要写死策略**。`fail_mode` / `exit_code` / `offline_grace_days` 都由服务端下发并覆盖本地值，本地那些只是"连不上服务器"时的兜底。
- **断网能跑多久由 `offline_grace_days` 决定**。想断网也立即失效就设 `0`。
- **公钥按算法选**：Python/Node 用 `ed25519` 的 `raw_b64url`；C#/.NET 必须用 `es256` 的 `spki_b64`。
- **私钥和管理口令绝不进客户端、绝不进任何会提交的文件**。它们只在 Cloudflare Worker 的 Secrets 里。
- 目标是 PyInstaller 打包时，`license_guard.py` 无依赖可直接打包；用 `--add-data` 带上。
- `.gitignore` 里要排除 `license.key` 与 `state.dat`，别把授权码提交上去。

## 参考文件

| 文件 | 内容 |
|---|---|
| `config.local.json` | **本地真实部署配置**（不入库，优先级最高）。接入前先读它 |
| `config.json` | 仓库里的占位模板；没写 `config.local.json` 时才读它 |
| `references/integration.md` | 三端完整接入指南：全部配置项、错误码表、Electron/WPF 接入、常见场景（内网、打包、换机解绑、调试） |
| `references/api.md` | Worker HTTP API 契约：请求/响应结构、令牌载荷、限流、错误码 |
| `references/admin.md` | 后台运维：建产品、签发授权码、改到期时间、吊销、解绑设备（含 curl 示例） |
| `scripts/install_sdk.py` | 探测语言 + 拷贝 SDK + 生成配置常量 |
| `scripts/selfcheck.py` | 校验服务地址 / `app_id` / 公钥是否与服务端匹配 |
| `assets/clients/` | 三端 SDK 源码（零第三方依赖） |

## 常见追问

**"能不能不联网也能用？"** —— 支持，靠 `offline_grace_days`（客户端会缓存签名令牌）。
但气隙环境不支持，客户端至少得能连上 Worker。

**"用户把系统时间改回去怎么办？"** —— SDK 已有防护：`strict_clock` 时钟回拨检测 +
服务端签名时间（`/v1/time`）。不用额外做。

**"用户拷贝程序到另一台机器？"** —— 令牌里绑了机器指纹 `mid`，换机会返回 `MACHINE_MISMATCH`。

**"怎么让某个客户立刻失效？"** —— 后台把该授权码 `status` 改成 `revoked`。
客户端默认每次校验都联网，所以下次校验就会被拦下，并清掉本地缓存。

**"想按功能收费？"** —— 后台产品的 `features` 填 `["pro","export"]`，客户端用 `guard.has_feature("pro")` 判断。
