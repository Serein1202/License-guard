# 安全模型与加固建议

这份文档说清楚三件事：**能防住什么、防不住什么、怎么继续加固**。

---

## 一、威胁模型

我们要防的是「普通用户/小技术团队想办法白嫖」，不是国家级对手。具体是这几类：

| 攻击手法 | 难度 | 本方案的处理 |
|---|---|---|
| 把系统时间调回到到期前 | 极简单 | ✅ **防住**，判 `CLOCK_TAMPERED` |
| 用记事本改本地文件里的到期时间 | 极简单 | ✅ **防住**，到期时间在签名令牌里 |
| 拷贝同事的整个程序目录 | 简单 | ✅ **防住**，令牌绑定硬件指纹 |
| 断网一直用 | 简单 | ✅ **防住**，超过离线容忍期必须联网 |
| 到期后不重启程序继续用 | 简单 | ✅ **防住**，看门狗持续校验 |
| 删状态文件绕过设备限制 | 简单 | ✅ **防住**，设备位记在服务端 |
| 用 Charles/Fiddler 改响应 | 中等 | ✅ **防住**，改了签名就失效 |
| 用 dnSpy/IDA 逆向，把校验函数 NOP 掉 | 中等 | ❌ **防不住**，需要加壳/混淆 |
| Hook `os._exit` / `process.exit` | 中等 | ❌ **防不住**（同上） |
| 内存中提取公钥后自签名 | 困难 | ❌ **防不住**（但拿不到私钥就只能生成自己的授权，无法伪造你的） |
| 提取内嵌的私钥 | — | ✅ **不可能**，客户端里只有公钥 |

**一句话总结：把「低成本绕过」全部堵死，把「高成本绕过」留给逆向工程的门槛。**

---

## 二、密码学部分的设计

### 2.1 为什么用非对称签名

如果用 HMAC（对称密钥），密钥必须内嵌在客户端里。任何人把二进制解出来就能自己签发永久授权。**这是绝大多数自制授权系统的致命伤。**

本方案用 Ed25519 / ECDSA-P256：
- Worker 持有**私钥**（存在 Cloudflare Secret 里，永远不会下发给客户端）
- 客户端内嵌**公钥**，只能验签、不能签发
- 即使公钥被提取，也无法伪造令牌

### 2.2 令牌格式

```
base64url(header) . base64url(payload) . base64url(signature)
```

签名覆盖 `header.payload` 的全部字节。**载荷里的每一个字段都受保护**——包括到期时间、机器绑定、功能开关。

客户端验签流程（`clients/python/license_guard.py`）：

1. 检查 `alg` 字段与本地配置一致（**防算法混淆攻击**）
2. 解码曲线点，拒绝非规范编码
3. **拒绝小阶点**（见下）
4. 检查标量 `S < L`（防可塑性签名）
5. 执行标准 RFC 8032 验签

### 2.3 关于纯 Python Ed25519 实现

为了零依赖，Python 端内置了一份纯 Python Ed25519 验签。它做了这些严格性检查：

```python
def ed25519_verify(public_key, signature, message):
    if len(public_key) != 32 or len(signature) != 64:
        return False
    r = _decodepoint(signature[:32])
    a = _decodepoint(public_key)
    # 拒绝小阶点：否则全零签名在 h≡3 (mod 4) 时会被误判为合法
    if _has_small_order(a) or _has_small_order(r):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:            # 拒绝非规范标量
        return False
    ...
```

> **这是一个真实发现的问题。** 开发过程中端到端测试抓到：不检查小阶点时，`public_key = 0x00*32, signature = 0x00*64` 这种输入在哈希满足 `h ≡ 3 (mod 4)` 时会被判定为验签成功。libsodium 的严格模式同样会拒绝这类点。已修复。

性能：用 Python 内置的 `pow(x, -1, p)` 做模逆（C 实现），单次验签约 **21ms**，对启动时校验一次完全无感。

考虑到纯 Python 实现的审计成本，如果你的环境允许装依赖，**推荐改用 `cryptography` 库**：

```python
# 装了 cryptography 后，ES256 走 OpenSSL，更快更省心
cfg = GuardConfig(..., sign_alg="es256")
# 后台建产品时把算法选成 ECDSA P-256
```

---

## 三、反绕过机制详解

### 3.1 防时钟回拨

最朴素也最常见的绕过：到期了，把系统时间调到去年。

客户端在本地状态里维护 `last_wall`（上次校验时看到的系统时间）：

```python
def _effective_now(self, state):
    wall = int(time.time())
    last = int(state.get("last_wall") or 0)
    if last and wall < last - self.cfg.clock_tolerance_sec:
        return last, True      # 检测到回拨
    return wall, False
```

- `clock_tolerance_sec` 默认 300 秒，避免 NTP 校时误伤
- 检测到回拨 → `CLOCK_TAMPERED` → 按 `fail_mode` 处理
- `strict_clock=False` 可以关掉（不推荐，除非你的用户环境时钟很不准）

**局限**：用户如果在**第一次运行之前**就把时间调好，然后一直不联网……这时还没有 `last_wall` 锚点，防不住。但第一次激活必须联网，服务端会下发 `srv`（服务端时间），所以这个窗口是关闭的。

### 3.2 防本地文件篡改

本地状态文件（`state.dat`）用 HMAC-SHA256 保护：

```
LGST1:<hmac-sha256 十六进制>
{"token":"...","last_online":1793328000,"last_wall":1793328000}
```

密钥由 `app_id + 硬件指纹` 派生。改动任意一个字节，HMAC 校验就失败，状态被整体作废。

**局限**：HMAC 密钥可由逆向得到。但即便如此，攻击者能改的也只是 `last_online`（延长离线容忍）和 `last_wall`（绕过回拨检测）——**改不了到期时间**，因为那在签名令牌里。这是一个可接受的权衡：抗逆向交给加壳，抗小白交给 HMAC。

### 3.3 防设备复制

令牌里的 `mid` 字段是硬件指纹：

| 系统 | 采集来源（按优先级） |
|---|---|
| Windows | 注册表 `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |
| macOS | `ioreg` 的 `IOPlatformUUID` |
| Linux | `/etc/machine-id` → `/var/lib/dbus/machine-id` → DMI product_uuid |
| 通用兜底 | 物理网卡 MAC（排除虚拟机网段）+ 主机名 + 架构 |

服务端记录每台设备的激活，超出 `max_devices` 直接拒绝。

**局限**：虚拟机克隆会让多台机器共享同一个 MachineGuid。如果你的场景需要区分虚拟机，再加上磁盘序列号/CPU ID 组合。

### 3.4 防长期离线白嫖

令牌本身有 `exp`（默认 24 小时），到期需要重新联网。同时本地记录 `last_online`，断网超过 `offline_grace_days` 就失效。

两个旋钮的配合：

| 参数 | 默认 | 作用 | 调小的代价 |
|---|---|---|---|
| `token_ttl_sec` | 86400 | 令牌多久必须刷新 | 请求变多（免费额度 10 万/天，够用） |
| `offline_grace_days` | 7 | 断网多久后失效 | 出差/无网环境用户会投诉 |

**想快速吊销就调小 `token_ttl_sec`。** 想在管理后台封禁后 1 小时内生效，就设成 3600。

### 3.5 到期后立即停止运行

后台看门狗线程周期性调用 `verify()`。到期那一刻，无论程序在干嘛都会退出。

```python
def _terminate(mode, code, message, err_code):
    if mode == "message":
        sys.stderr.write(f"...{message}...")
        _try_dialog(message)
        os._exit(code)
    os._exit(code)     # hard：不走 atexit，不打印堆栈 —— 表现就是「闪退」
```

用 `os._exit()` 而不是 `sys.exit()` 是刻意的：
- `sys.exit()` 抛 `SystemExit`，会被 `except Exception` 之外的地方捕获，还会跑 `finally` 和 `atexit`
- `os._exit()` 直接调系统调用终止进程，不执行任何清理

`watchdog_interval_sec` 决定「到期后最多多久才退出」，默认 120 秒。设成 15 秒能让到期几乎瞬时生效。

---

## 四、服务端加固

### 4.1 已经做了的

| 措施 | 实现位置 |
|---|---|
| 授权码哈希存储 | `util.ts::hashKey` — 明文只存一份 `key_display` 供后台展示 |
| 常量时间口令比较 | `util.ts::timingSafeEqual` — 防时序侧信道 |
| 登录暴力破解防护 | `index.ts` — 每 IP 每分钟最多 10 次 |
| 接口限流 | `util.ts::rateLimit` — 激活 30/min，校验 120/min |
| 统一的错误响应 | 不泄露「是 key 错还是产品错」之外的内部信息 |
| 审计日志 | 所有管理操作 + 激活/拒绝事件入库 |
| 管理接口鉴权 | 除登录外全部要求 `Bearer ADMIN_TOKEN` |
| 管理页面 CSP | `default-src 'self'`，`frame-ancestors 'none'` |
| 管理页面 noindex | 防止被搜索引擎收录 |
| 参数白名单 | 更新接口只接受白名单字段，SQL 全部参数化绑定 |

### 4.2 建议你补上的

**1. 把授权码明文列删掉（如果追求极致）**

`licenses.key_display` 存的是明文，方便你在后台复制给客户。如果被人拖库，所有授权码就泄露了。

```sql
-- 改表结构，只留哈希
ALTER TABLE licenses DROP COLUMN key_display;
```

代价：后台看不到授权码，只能重新生成。适合「授权码只发给客户一次」的场景。

**2. 缩短令牌 TTL**

默认 24 小时意味着封禁后最长 24 小时才生效。生产环境建议 1~4 小时：

```bash
curl -X PATCH .../admin/api/products/prod_xxx -d '{"token_ttl_sec": 3600}'
```

**3. 定期轮换签名密钥**

每年换一次。流程：生成新密钥 → 客户端发版内嵌新公钥（可以同时内嵌新旧两个，逐个尝试）→ 同时用过渡期的双密钥 → 老客户端淘汰后下线旧密钥。

**4. 给管理后台加 Cloudflare Access**

免费版就能用。<https://one.dash.cloudflare.com> → Access → 新建应用，把 `/admin*` 路径保护起来，只允许你的邮箱登录。

这样即使 `ADMIN_TOKEN` 泄露，攻击者没有邮箱验证码也进不来。

**5. 数据库备份**

```bash
wrangler d1 export license-guard --remote --output=backup-$(date +%F).sql
```

挂个定时任务。D1 数据丢了，所有客户都得重新激活，会很狼狈。

---

## 五、诚实的局限

### 5.1 客户端最终是「不设防」的

任何在用户机器上运行的代码，理论上都能被逆向、被 Hook、被 patch。**没有例外。** 商业方案（Keygen、Cryptlex、VMProtect）也做不到绝对，它们是靠「提高成本」而不是「绝对防护」。

所以在设计思路上，不要把安全性押在客户端上，而是：

1. **把有价值的东西留在服务端。** 如果你的软件核心逻辑依赖云端 API，那授权校验只是顺手加的一道门；真正的护城河是 API 鉴权。
2. **让绕过成本 > 付费成本。** 一年几百块的授权，没人愿意花两天时间逆向。
3. **对高价值客户用更硬的方案。** 硬件加密狗（如深思、飞天诚信）、代码虚拟化加壳（VMProtect、Themida）。

### 5.2 如果真要对抗逆向

进阶方向，按成本从低到高：

| 手段 | 说明 |
|---|---|
| PyArmor / Nuitka | Python 代码混淆与编译，能挡住 90% 的 `python -m dis` |
| .NET Reactor / ConfuserEx | .NET 混淆加壳 |
| 关键逻辑抽到云端 | 最有性价比——本地只留壳 |
| 完整性自校验 | 运行时校验自身代码段哈希，被 patch 就退出 |
| 反调试检测 | 检测调试器附加、检测 API Hook |
| VMProtect / Themida | 商业级代码虚拟化，成本高 |

这些都属于「授权系统之外」的工作，本项目的客户端 SDK 预留了 `on_denied` 回调，方便你在拒绝时做额外的处理（比如上报、清理数据）。

---

## 六、安全自检清单

上线前确认：

- [ ] `worker/keys.json` 在 `.gitignore` 里，没有提交到任何仓库
- [ ] `ADMIN_TOKEN` 足够长（≥ 20 位随机字符），不是 `123456`
- [ ] Dashboard → Settings → Variables and Secrets 里能看到三个 secret
- [ ] 管理后台已经用 Cloudflare Access 保护（或至少改成一个强口令）
- [ ] 公开仓库里的 `wrangler.toml` 不含真实资源 ID（默认只写绑定名，由 Cloudflare 自动创建；如需手动指定，用 `git update-index --skip-worktree worker/wrangler.toml` 避免 ID 进仓库）
- [ ] 公开仓库的 Git 历史里没有 `keys.json`、`.dev.vars` 等含密钥的文件（`git log --all --diff-filter=A --name-only`）
- [ ] 客户端内嵌的公钥和 Worker 私钥是同一对（用一次真实激活验证）
- [ ] `token_ttl_sec` 按你的封禁时效要求设置过
- [ ] `offline_grace_days` 按用户网络环境设置过
- [ ] `fail_mode` 选的是你要的（`hard` 闪退 / `message` 提示）
- [ ] D1 备份任务已配置

线上地址的验证方式：

```bash
# 1) 生成一个授权码，2) 用客户端 SDK 走一次 activate
# 3) 在后台把到期时间改成过去，4) 再走一次 verify，应返回 403 / LICENSE_EXPIRED
curl -X POST https://license-guard.xxx.workers.dev/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"app_id":"mytool","key":"你的授权码","machine_id":"test-machine-0001"}'
```
