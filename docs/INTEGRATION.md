# 客户端接入指南

三端 SDK 都是**零第三方依赖**，直接拷文件进项目即可。

- [Python](#python) — `clients/python/license_guard.py`
- [Node / Electron](#node--electron) — `clients/node/license-guard.js`
- [C# / .NET](#c--net) — `clients/dotnet/LicenseGuard.cs`
- [常见场景](#常见场景) — 命令行工具、GUI 程序、内网离线、PyInstaller 打包、换机解绑

---

## 通用：三行接入

```python
guard.authorize()       # 校验；不通过 → 进程立即终止
guard.start_watchdog()  # 后台持续看守，到期瞬间退出
# ...你的业务代码
```

`authorize()` 是**阻塞且决定性**的：如果授权无效，函数**不会返回**——进程会按 `fail_mode` 直接结束。所以把它放在 `main()` 的最开头，后面的代码天然安全。

---

## Python

### 安装

把 `clients/python/license_guard.py` 拷到你的项目里。没有依赖，Python 3.8+ 都能跑。

### 基本用法

```python
from license_guard import LicenseGuard, GuardConfig

guard = LicenseGuard(GuardConfig(
    server_url = "https://license-guard.xxx.workers.dev",
    app_id     = "mytool",
    public_key = "2A78SxbIjCLC12HOA1Pwetb5mCOMDPbs3ERjOxd67ME",   # Ed25519 b64url
    license_key= "ABCD-EFGH-JKMN-PQRS",

    fail_mode  = "hard",     # hard=闪退  message=提示后退出
    exit_code  = 0,
))

guard.authorize()
guard.start_watchdog()

def main():
    # 你的业务逻辑，只有授权通过才会执行到这里
    print("软件正常启动")
    print("剩余天数:", guard.days_left())
    if guard.has_feature("export"):
        enable_export()

if __name__ == "__main__":
    main()
```

### 所有配置项

| 参数 | 默认 | 说明 |
|---|---|---|
| `server_url` | 必填 | Worker 地址 |
| `app_id` | 必填 | 和后台建软件时的 `app_id` 一致 |
| `public_key` | 必填 | Ed25519 raw 公钥的 base64url（`gen-keys` 输出） |
| `license_key` | `""` | 留空时依次从环境变量 `LICENSE_KEY`、同目录 `license.key` 读取 |
| `sign_alg` | `"ed25519"` | 或 `"es256"` |
| `fail_mode` | `"hard"` | `hard` 直接闪退；`message` 打印/弹窗后退出 |
| `exit_code` | `0` | 退出码。想让用户以为是崩溃可以用非 0 值 |
| `strict_clock` | `True` | 检测到系统时间回拨时是否判失效 |
| `clock_tolerance_sec` | `300` | 允许的时间偏差（秒），避免 NTP 校时误伤 |
| `request_timeout` | `8` | 单次请求超时（秒） |
| `retry_times` | `2` | 网络失败重试次数 |
| `heartbeat_sec` | `21600` | 心跳间隔默认值（服务端策略会覆盖） |
| `watchdog_interval_sec` | `120` | 看门狗检查间隔——**到期后最多这么久就会退出** |
| `storage_dir` | 系统数据目录 | 本地状态文件位置 |
| `on_denied` | `None` | `(code, message) -> None`。设了它就**不会**自动退出，由你自己处理 |
| `debug` | `False` | 打印调试日志到 stderr |

### API

```python
info = guard.verify()          # 手动校验一次；失败抛 LicenseError
guard.authorize()              # 校验 + 失败即终止（启动时用）
guard.start_watchdog()         # 启动后台看守线程
guard.stop_watchdog()          # 停止
guard.has_feature("pro")       # 功能开关
guard.days_left()              # 剩余天数，永久授权返回 None
guard.info                     # LicenseInfo（status/customer/expires_at/...）
guard.machine_id               # 本机硬件指纹
guard.release()                # 主动解绑本机，返回 bool
```

上下文管理器写法：

```python
with LicenseGuard(cfg) as guard:      # 自动 authorize + start_watchdog
    run_app()
```

一行接入：

```python
from license_guard import quick_guard
guard = quick_guard("https://...", "mytool", "公钥", "授权码")
```

### 授权失败的错误码

用 `on_denied` 时可以从 `LicenseError.code` 拿到：

| 错误码 | 含义 | 该怎么处理 |
|---|---|---|
| `NO_KEY` | 没找到授权码 | 提示用户输入 |
| `KEY_NOT_FOUND` | 授权码不存在 | 提示输入错误 |
| `LICENSE_EXPIRED` | 已到期 | 引导续费 |
| `LICENSE_REVOKED` | 被吊销 | 联系客服 |
| `LICENSE_SUSPENDED` | 被暂停 | 联系客服 |
| `DEVICE_LIMIT` | 设备数超限 | 引导在其他设备解绑，或联系客服 |
| `DEVICE_NOT_ACTIVATED` | 本机未激活 | 用 `activate` 流程 |
| `MACHINE_MISMATCH` | 令牌绑定的是别的机器 | 状态文件被拷贝了 |
| `CLOCK_TAMPERED` | 检测到系统时间被改 | 提示用户校准时间 |
| `OFFLINE_TOO_LONG` | 断网太久 | 提示联网 |
| `NETWORK` | 连不上且无有效离线授权 | 提示检查网络 |
| `BAD_SIGNATURE` | 令牌签名无效 | 可能被篡改，或公钥不匹配 |

自定义处理示例：

```python
from license_guard import LicenseError

def on_denied(code, message):
    if code == "LICENSE_EXPIRED":
        show_dialog("授权已到期", "请访问 xxx.com 续费")
    elif code == "DEVICE_LIMIT":
        show_dialog("设备数已满", "请在旧设备上运行「解绑设备」")
    else:
        show_dialog("授权异常", f"{message} ({code})")

cfg = GuardConfig(..., on_denied=on_denied)

try:
    guard.authorize()
except LicenseError:
    sys.exit(1)     # 你自己决定怎么退出
```

---

## Node / Electron

### 安装

把 `clients/node/` 整个目录拷进项目，或者作为本地依赖：

```json
{ "dependencies": { "@yourorg/license-guard": "file:./vendor/license-guard" } }
```

Node 18+（内置 `fetch` 和 `node:crypto` 的 Ed25519 支持）。

### 基本用法

```javascript
import { LicenseGuard } from "./license-guard.js";

const guard = new LicenseGuard({
  serverUrl : "https://license-guard.xxx.workers.dev",
  appId     : "mytool",
  publicKey : "2A78SxbIjCLC12HOA1Pwetb5mCOMDPbs3ERjOxd67ME",
  licenseKey: "ABCD-EFGH-JKMN-PQRS",
  failMode  : "hard",
});

await guard.authorize();     // 不通过 → process.exit()
guard.startWatchdog();

// 业务代码
console.log("剩余天数:", guard.daysLeft());
if (guard.hasFeature("pro")) { /* ... */ }
```

### Electron 注意点

`process.exit()` 在 Electron 主进程里同样有效。如果你希望渲染进程先收到通知再退出，用 `onDenied`：

```javascript
const guard = new LicenseGuard({
  ...,
  onDenied: (code, message) => {
    // 通知所有窗口
    BrowserWindow.getAllWindows().forEach(w => {
      w.webContents.send("license-denied", { code, message });
    });
    setTimeout(() => app.exit(1), 3000);   // 给用户 3 秒看提示
  },
});

try {
  await guard.authorize();
} catch (e) {
  // 已经通知过了，这里等待定时退出
}
```

### 打包进 asar

`machineId()` 在 Windows 上会调用 `powershell`/`reg` 读注册表，macOS 上调 `ioreg`。打包成 asar 后这些外部调用依然可用（`execFileSync` 走的是系统进程，不受 asar 影响）。

但如果你的 Electron 应用禁用了 `child_process`（比如配了严格的 `sandbox`），把 `machineId` 换成纯 JS 的实现：

```javascript
import { createHash } from "node:crypto";
import { hostname, platform, arch } from "node:os";

export function simpleMachineId() {
  return createHash("sha256")
    .update(`${hostname()}|${platform()}|${arch()}`)
    .digest("hex").slice(0, 32);
}
```

> 注意：这种方式指纹较弱，换主机名就能绕过。仅在无法读注册表时作为降级方案。

### Tauri / Rust

没有官方 SDK。Rust 端可以用 `ed25519-dalek` 验签，或者用 `reqwest` 直接调 API 并把校验交给前端 JS。

---

## C# / .NET

### 引用

把 `clients/dotnet/` 加进解决方案，或者作为项目引用：

```xml
<ItemGroup>
  <ProjectReference Include="..\LicenseGuard\LicenseGuard.csproj" />
</ItemGroup>
```

目标框架 `net8.0-windows`（需要 `-windows` 才能免依赖读注册表）。

> ⚠️ **重要：C# 客户端必须用 ES256。** 因为 .NET 没有内置 Ed25519。在后台创建软件时把「签名算法」选成 **ECDSA P-256**，客户端公钥用 `PUBLIC_KEY_ES256_SPKI_B64`。

### 基本用法

```csharp
using LicenseGuard;

var guard = new LicenseGuard.LicenseGuard(new GuardOptions
{
    ServerUrl  = "https://license-guard.xxx.workers.dev",
    AppId      = "mytool",
    PublicKey  = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",   // ES256 SPKI base64
    LicenseKey = "ABCD-EFGH-JKMN-PQRS",
    FailMode   = FailMode.Hard,
});

guard.Authorize();
guard.StartWatchdog();

// 业务代码
Console.WriteLine($"剩余天数: {guard.DaysLeft()}");
if (guard.HasFeature("pro")) { /* ... */ }
```

### WPF / WinForms 接入

在 `App.xaml.cs` 的 `OnStartup` 里做，早于主窗口创建：

```csharp
protected override void OnStartup(StartupEventArgs e)
{
    var guard = new LicenseGuard.LicenseGuard(new GuardOptions
    {
        ServerUrl  = "https://license-guard.xxx.workers.dev",
        AppId      = "mytool",
        PublicKey  = "...",
        LicenseKey = LicenseStore.Load(),   // 从你的配置文件读
        FailMode   = FailMode.Message,      // 桌面程序建议先提示
        OnDenied   = (code, msg) =>
        {
            MessageBox.Show(msg, "授权已到期", MessageBoxButton.OK, MessageBoxImage.Error);
            // 可以在这里引导用户到续费页面
        },
    });

    try
    {
        guard.Authorize();
    }
    catch (LicenseException)
    {
        Shutdown(1);      // 授权页面处理完后退�出
        return;
    }

    guard.StartWatchdog();
    base.OnStartup(e);
}
```

### API

```csharp
guard.Authorize();                                    // 同步；失败即终止
await guard.VerifyAsync();                            // 异步校验
guard.StartWatchdog() / StopWatchdog();
guard.HasFeature("pro");
guard.DaysLeft();                                     // int?
guard.MachineId;
await guard.ReleaseAsync();
```

---

## 常见场景

### 命令行工具

CLI 工具的生命周期很短，看门狗没意义。只调 `authorize()` 就够了：

```python
guard.authorize()
# 直接干活
```

但要注意：如果只看启动时那一次，用户可以在到期后断网继续用（在离线容忍期内）。对于 CLI，把 `offline_grace_days` 设小（比如 1 天）更合适。

### 长期运行的 GUI 程序

一定要开看门狗：

```python
guard.authorize()
guard.start_watchdog()     # 到期那一刻，即使程序正在跑也会退出
```

`watchdog_interval_sec` 决定「到期后最多多久才退出」。默认 120 秒，对多数场景够用。想让到期立刻生效就设 15，代价是请求次数变多。

### 内网 / 完全断网环境

本方案不支持气隙环境（客户端必须能连到 Worker）。如果客户是内网部署，两个选择：

1. **用 [Cedar-V License-Manager](https://github.com/cedar-v/License-Manager)**（Go 项目，支持离线授权包、内网部署）
2. 让内网机器通过代理访问 Worker，把 `offline_grace_days` 设到 30~90 天

### PyInstaller / Nuitka 打包

`license_guard.py` 没有外部依赖，直接打包就行：

```bash
pyinstaller --onefile --add-data "license_guard.py:." main.py
```

授权码可以放在 exe 同目录的 `license.key`，SDK 会自动找到（`sys.frozen` 分支已处理）。

如果想让用户看不到授权码文件，改成从你的配置里读：

```python
guard = LicenseGuard(GuardConfig(..., license_key=load_from_my_config()))
```

### 换机解绑

用户换电脑时：

**方式一：让用户自己在旧机器上解绑**

```python
guard.release()      # 解绑成功返回 True
```

**方式二：你在后台解绑**

管理后台 → 授权码 → 「设备」→ 找到那台机器 → 「解绑」。

**方式三：清空全部**

「设备」→「清空全部设备」。适合用户旧机器已经坏掉的情况。

### 把授权信息显示给用户

```python
guard.authorize()
guard.start_watchdog()

info = guard.info
print(f"授权给: {info.customer}")
print(f"到期时间: {time.strftime('%Y-%m-%d', time.localtime(info.expires_at))}")
print(f"剩余天数: {info.days_left()}")

if info.status == "grace":
    print("⚠️ 已进入宽限期，请尽快续期")
```

### 按功能点收费

后台创建软件时填「功能开关」：`pro,export,batch`。客户端：

```python
if guard.has_feature("export"):
    enable_export()
else:
    hide_export_button()
```

### 调试技巧

打不开的时候打开 `debug=True`：

```python
cfg = GuardConfig(..., debug=True)
```

会输出每次校验的决策过程：

```
[license-guard] 缓存令牌无效，重新联网获取: BAD_SIGNATURE
[license-guard] 离线放行，容忍截止 1793928000
[license-guard] 看门狗: OK 27
[license-guard] 检测到系统时间回拨: now=1793300000 last=1794166400
```

手动测试各条路径：把后台里该授权码的到期时间改成过去（模拟到期），或先停用再启用（模拟吊销），然后在客户端观察日志输出。

### 本地状态文件在哪

| 系统 | 路径 |
|---|---|
| Windows | `%LOCALAPPDATA%\<app_id>\state.dat` |
| macOS | `~/Library/Application Support/<app_id>/state.dat` |
| Linux | `~/.local/share/<app_id>/state.dat` |

删掉它 = 下次启动需要重新联网激活（会消耗一个设备位，如果设备位已满则需要后台解绑）。
