// =============================================================================
//  License Guard · .NET / C# 客户端 SDK
//  =============================================================================
//  适用：WPF / WinForms / .NET 桌面程序、Unity 桌面端、控制台工具
//
//  签名算法用 ECDSA P-256（ES256），因为 .NET 内置支持，无需第三方库。
//  在后台创建产品时把「签名算法」选成 es256 即可。
//
//  用法：
//      var guard = new LicenseGuard(new GuardOptions {
//          ServerUrl  = "https://license-guard.your-name.workers.dev",
//          AppId      = "mytool",
//          PublicKey  = "粘贴 gen-keys 输出的 ES256 公钥 (SPKI base64)",
//          LicenseKey = "ABCD-EFGH-JKMN-PQRS",
//          FailMode   = FailMode.Hard,   // 到期直接闪退
//      });
//
//      guard.Authorize();        // 校验；不通过则终止进程
//      guard.StartWatchdog();    // 运行期看守，到期瞬间退出
//
//      if (guard.HasFeature("pro")) { ... }
// =============================================================================

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LicenseGuard;

/// <summary>授权失败时抛出的异常。</summary>
public sealed class LicenseException : Exception
{
    public string Code { get; }
    public LicenseException(string code, string message) : base($"[{code}] {message}") => Code = code;
}

/// <summary>到期时的行为。</summary>
public enum FailMode
{
    /// <summary>不走任何清理流程直接终止进程 —— 表现就是「闪退」。</summary>
    Hard,
    /// <summary>写出提示（可选弹窗）后退出。</summary>
    Message,
}

public sealed class GuardOptions
{
    public string ServerUrl { get; set; } = "";
    public string AppId { get; set; } = "";
    /// <summary>ES256 公钥，SPKI DER 的 base64。</summary>
    public string PublicKey { get; set; } = "";
    public string LicenseKey { get; set; } = "";
    public FailMode FailMode { get; set; } = FailMode.Hard;
    public int ExitCode { get; set; } = 0;

    /// <summary>检测到系统时间被回拨时是否直接判失效。</summary>
    public bool StrictClock { get; set; } = true;
    public int ClockToleranceSeconds { get; set; } = 300;
    public int RequestTimeoutSeconds { get; set; } = 8;
    public int RetryTimes { get; set; } = 3;
    public int HeartbeatSeconds { get; set; } = 21600;
    /// <summary>
    /// 看门狗检查间隔（秒）。
    /// &gt;0 = 固定间隔，每轮都用它，不被后端下发的 <c>heartbeat_sec</c> 覆盖；
    /// 0 = 跟随后端心跳。下限恒为 15 秒。
    /// </summary>
    public int WatchdogIntervalSeconds { get; set; } = 120;

    /// <summary>仅在 <see cref="WatchdogIntervalSeconds"/> = 0 时生效：本地复查间隔上限（秒）。0 = 不封顶。</summary>
    public int HeartbeatCapSeconds { get; set; } = 900;

    public string? StorageDirectory { get; set; }

    /// <summary>设置后不会自动退出，而是把失败交给你处理。</summary>
    public Action<string, string>? OnDenied { get; set; }

    public bool Debug { get; set; }
}

public sealed class LicenseInfo
{
    public string Status { get; set; } = "unknown";
    public string Code { get; set; } = "";
    public string Message { get; set; } = "";
    public string? Customer { get; set; }
    public List<string> Features { get; set; } = new();
    public long? ExpiresAt { get; set; }
    public long? HardExpiresAt { get; set; }
    public int MaxDevices { get; set; } = 1;
    public int Activations { get; set; }
    public long ServerTime { get; set; }
    public bool Offline { get; set; }

    public int? DaysLeft => HardExpiresAt is null
        ? null
        : (int)Math.Floor((HardExpiresAt.Value - DateTimeOffset.UtcNow.ToUnixTimeSeconds()) / 86400.0);

    public DateTime? ExpiresAtLocal => ExpiresAt is null
        ? null
        : DateTimeOffset.FromUnixTimeSeconds(ExpiresAt.Value).ToLocalTime().DateTime;
}

// =============================================================================

public sealed class LicenseGuard
{
    private readonly GuardOptions _o;
    private readonly string _machineId;
    private readonly string _machineIdLegacy;
    private readonly StateStore _store;
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    private Dictionary<string, JsonElement> _state = new();
    private LicenseInfo? _info;
    private Timer? _timer;
    private volatile bool _running;

    public string MachineId => _machineId;

    /// <summary>旧版指纹。上报给服务端用于认领 v1 时代留下的激活记录，用户不会因升级 SDK 掉激活。</summary>
    public string MachineIdLegacy => _machineIdLegacy;
    public LicenseInfo Info => _info ?? throw new LicenseException("NOT_VERIFIED", "尚未执行校验");

    /// <summary>
    /// 运行时可以改配置。典型用法：先用 OnDenied 完成启动期校验，
    /// 再把 OnDenied 换成「运行期到期」的处理逻辑，然后 StartWatchdog()。
    /// </summary>
    public GuardOptions Options => _o;

    public LicenseGuard(GuardOptions options)
    {
        _o = options ?? throw new ArgumentNullException(nameof(options));
        if (string.IsNullOrWhiteSpace(_o.ServerUrl)) throw new ArgumentException("缺少 ServerUrl");
        if (string.IsNullOrWhiteSpace(_o.AppId)) throw new ArgumentException("缺少 AppId");
        if (string.IsNullOrWhiteSpace(_o.PublicKey)) throw new ArgumentException("缺少 PublicKey");

        _o.ServerUrl = _o.ServerUrl.TrimEnd('/');
        _machineId = MachineFingerprint.Compute();
        _machineIdLegacy = MachineFingerprint.ComputeLegacy();
        _store = new StateStore(_o.AppId, _machineId, _o.StorageDirectory);
    }

    private void Log(string msg)
    {
        if (_o.Debug) Console.Error.WriteLine("[license-guard] " + msg);
    }

    // ---------------------------------------------------------------- 终止
    private void Deny(string code, string message)
    {
        if (_o.OnDenied is not null)
        {
            try { _o.OnDenied(code, message); } catch { /* ignore */ }
            throw new LicenseException(code, message);
        }
        Terminate(_o.FailMode, _o.ExitCode, message, code);
        throw new LicenseException(code, message); // 正常情况到不了这里
    }

    private static void Terminate(FailMode mode, int exitCode, string message, string code)
    {
        if (mode == FailMode.Message)
        {
            var line = new string('!', 58);
            try
            {
                Console.Error.WriteLine($"\n{line}\n  {message}\n  (错误代码: {code})\n{line}\n  请联系软件供应商续期。\n");
                Console.Error.Flush();
            }
            catch { /* ignore */ }
        }
        // 不走 finally / Dispose / 事件，直接终止 —— 表现就是「闪退」
        Environment.Exit(exitCode);
    }

    // ------------------------------------------------------------ 网络请求
    private async Task<JsonElement?> PostAsync(string path, object payload)
    {
        var body = JsonSerializer.Serialize(payload);
        Exception? last = null;

        for (var attempt = 0; attempt < Math.Max(1, _o.RetryTimes); attempt++)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_o.RequestTimeoutSeconds));
            try
            {
                using var content = new StringContent(body, Encoding.UTF8, "application/json");
                using var resp = await Http.PostAsync(_o.ServerUrl + path, content, cts.Token).ConfigureAwait(false);
                var text = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
                var doc = JsonDocument.Parse(text);
                var root = doc.RootElement.Clone();

                var status = (int)resp.StatusCode;
                if (status is 401 or 403 or 404 or 409 or 429) return root;   // 明确拒绝，不重试
                if (resp.IsSuccessStatusCode) return root;
                last = new HttpRequestException($"HTTP {status}");
            }
            catch (Exception ex)
            {
                last = ex;
            }

            if (attempt < _o.RetryTimes - 1)
                await Task.Delay(800 * (attempt + 1)).ConfigureAwait(false);
        }

        Log("网络不可用: " + last?.Message);
        return null;
    }

    // ---------------------------------------------------------------- 校验
    public async Task<LicenseInfo> VerifyAsync(bool allowOffline = true)
    {
        _state = _store.Load();
        if (_state.ContainsKey("__tampered__"))
        {
            Log("本地状态文件被改动过，已重置");
            _store.Clear();
            _state.Clear();
        }

        var rawKey = ResolveLicenseKey();
        if (string.IsNullOrWhiteSpace(rawKey))
            throw new LicenseException("NO_KEY", "未找到授权码（可传 LicenseKey、设环境变量 LICENSE_KEY 或放 license.key 文件）");

        var (now, tampered) = EffectiveNow();
        if (tampered && _o.StrictClock) Deny("CLOCK_TAMPERED", "检测到系统时间被修改，授权校验失败");

        /* ---- 1) 缓存令牌 → 先尝试离线判定 ---- */
        var cached = _state.TryGetValue("token", out var tEl) ? tEl.GetString() : null;
        Dictionary<string, JsonElement>? payload = null;

        if (!string.IsNullOrEmpty(cached))
        {
            try
            {
                payload = Token.Verify(cached!, _o.PublicKey);
            }
            catch (LicenseException ex)
            {
                Log("缓存令牌无效，转联网: " + ex.Code);
                _store.Clear();
                _state.Clear();
                cached = null;
                payload = null;
            }
        }

        if (payload is not null)
        {
            var mid = GetString(payload, "mid");
            if (!string.IsNullOrEmpty(mid) && mid != _machineId)
                Deny("MACHINE_MISMATCH", "该授权绑定了另一台设备");

            var hexp = GetLong(payload, "hexp");
            if (hexp is not null && now > hexp.Value) Deny("LICENSE_EXPIRED", ExpiredMessage(payload));

            var exp = GetLong(payload, "exp") ?? 0;
            if (now <= exp && now <= OfflineUntil())
            {
                _state["last_wall"] = JsonSerializer.SerializeToElement(now);
                _store.Save(_state);
                _info = FromPayload(payload, true, null);
                return _info;
            }
        }

        /* ---- 2) 联网校验 ---- */
        var endpoint = cached is null ? "/v1/activate" : "/v1/verify";
        var resp = await PostAsync(endpoint, new
        {
            app_id = _o.AppId,
            key = rawKey,
            machine_id = _machineId,
            machine_id_alt = _machineIdLegacy,
            machine_name = Environment.MachineName,
            platform = "windows",
            app_version = typeof(LicenseGuard).Assembly.GetName().Version?.ToString() ?? "1.0.0",
        }).ConfigureAwait(false);

        if (resp is null)
        {
            if (payload is not null && allowOffline)
            {
                var until = OfflineUntil();
                if (until > 0 && now > until)
                    Deny("OFFLINE_TOO_LONG", "长时间未联网校验，授权已失效，请连接网络后重试");
                Log("离线放行，容忍截止 " + until);
                _info = FromPayload(payload, true, null);
                return _info;
            }
            throw new LicenseException("NETWORK", "无法连接授权服务器，且本地没有可用的离线授权");
        }

        if (!resp.Value.TryGetProperty("ok", out var okEl) || !okEl.GetBoolean())
        {
            var code = resp.Value.TryGetProperty("code", out var c) ? c.GetString() ?? "DENIED" : "DENIED";
            var msg = resp.Value.TryGetProperty("message", out var m) ? m.GetString() ?? "授权被拒绝" : "授权被拒绝";
            Deny(code!, msg!);
        }

        var data = resp.Value.GetProperty("data");
        var token = data.GetProperty("token").GetString()!;
        payload = Token.Verify(token, _o.PublicKey);

        if (GetString(payload, "mid") != _machineId)
            Deny("MACHINE_MISMATCH", "服务端返回的授权与当前设备不匹配");

        (now, tampered) = EffectiveNow();
        if (tampered && _o.StrictClock) Deny("CLOCK_TAMPERED", "检测到系统时间被修改");

        var hardExp = GetLong(payload, "hexp");
        if (hardExp is not null && now > hardExp.Value) Deny("LICENSE_EXPIRED", ExpiredMessage(payload));

        var policy = data.TryGetProperty("policy", out var p) ? p : default;
        var serverTime = data.TryGetProperty("server_time", out var st) ? st.GetInt64() : now;

        _state = new Dictionary<string, JsonElement>
        {
            ["token"] = JsonSerializer.SerializeToElement(token),
            ["last_online"] = JsonSerializer.SerializeToElement(serverTime),
            ["last_wall"] = JsonSerializer.SerializeToElement(now),
            ["license_key"] = JsonSerializer.SerializeToElement(rawKey),
            ["offline_grace_days"] = JsonSerializer.SerializeToElement(PolicyInt(policy, "offline_grace_days", 0)),
            ["heartbeat_sec"] = JsonSerializer.SerializeToElement(PolicyInt(policy, "heartbeat_sec", _o.HeartbeatSeconds)),
            ["install_id"] = JsonSerializer.SerializeToElement(Guid.NewGuid().ToString("N")),
        };
        _store.Save(_state);

        var fm = policy.ValueKind == JsonValueKind.Object && policy.TryGetProperty("fail_mode", out var fmEl)
            ? fmEl.GetString() : null;
        if (fm == "hard") _o.FailMode = FailMode.Hard;
        else if (fm == "message") _o.FailMode = FailMode.Message;

        _info = FromPayload(payload, false, data);
        Log($"校验通过: {_info.Status} 到期: {_info.ExpiresAtLocal}");
        return _info;
    }

    /// <summary>启动时调用。不通过则按策略终止进程（Hard = 直接闪退）。</summary>
    public LicenseInfo Authorize()
    {
        try
        {
            return VerifyAsync().GetAwaiter().GetResult();
        }
        catch (LicenseException)
        {
            throw; // Deny() 内部已经处理过退出；只有 OnDenied 模式下才会到这里
        }
    }

    /// <summary>后台看门狗：到期时刻一到，即使程序正在运行也会立刻退出。</summary>
    public void StartWatchdog()
    {
        if (_running) return;
        _running = true;

        _timer = new Timer(async _ =>
        {
            if (!_running) return;
            try
            {
                await VerifyAsync().ConfigureAwait(false);
                if (_running) _timer?.Change(WatchdogInterval(), Timeout.InfiniteTimeSpan);
            }
            catch (LicenseException ex)
            {
                Log("看门狗: 失败 " + ex.Code);
                _running = false;
                if (_o.OnDenied is null) Terminate(_o.FailMode, _o.ExitCode, ex.Message, ex.Code);
            }
        }, null, WatchdogInterval(), Timeout.InfiniteTimeSpan);
    }

    /// <summary>
    /// 下一轮复查间隔。
    ///
    /// WatchdogIntervalSeconds &gt; 0 时是固定间隔：历史实现会在首次成功后改用后端心跳
    /// （上限 900 秒），导致配 15 秒实际 15 分钟才复查一次，配置的语义失效。
    /// </summary>
    private TimeSpan WatchdogInterval()
    {
        var fixedSec = _o.WatchdogIntervalSeconds;
        if (fixedSec > 0) return TimeSpan.FromSeconds(Math.Max(15, fixedSec));

        var hb = _state.TryGetValue("heartbeat_sec", out var h) ? h.GetInt32() : 0;
        if (hb <= 0) hb = _o.HeartbeatSeconds;
        if (hb <= 0) hb = 21600;
        var cap = _o.HeartbeatCapSeconds;
        var sec = cap > 0 ? Math.Min(hb, cap) : hb;
        return TimeSpan.FromSeconds(Math.Clamp(sec, 15, int.MaxValue / 1000));
    }

    public void StopWatchdog()
    {
        _running = false;
        _timer?.Dispose();
        _timer = null;
    }

    public bool HasFeature(string name) => _info?.Features.Contains(name) == true;
    public int? DaysLeft() => _info?.DaysLeft;

    /// <summary>主动解绑当前设备。</summary>
    public async Task<bool> ReleaseAsync()
    {
        var rawKey = ResolveLicenseKey();
        if (string.IsNullOrWhiteSpace(rawKey)) return false;
        var resp = await PostAsync("/v1/deactivate", new
        {
            app_id = _o.AppId,
            key = rawKey,
            machine_id = _machineId,
            machine_id_alt = _machineIdLegacy,
        }).ConfigureAwait(false);
        if (resp is not null && resp.Value.TryGetProperty("ok", out var ok) && ok.GetBoolean())
        {
            _store.Clear();
            _state.Clear();
            return true;
        }
        return false;
    }

    // ---------------------------------------------------------------- 内部
    private string ResolveLicenseKey()
    {
        if (!string.IsNullOrWhiteSpace(_o.LicenseKey)) return _o.LicenseKey.Trim();

        foreach (var name in new[] { "LICENSE_KEY", _o.AppId.ToUpperInvariant() + "_LICENSE_KEY" })
        {
            var v = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrWhiteSpace(v)) return v.Trim();
        }

        var exeDir = AppContext.BaseDirectory;
        foreach (var dir in new[] { exeDir, Directory.GetCurrentDirectory(), _store.Directory })
        {
            var f = Path.Combine(dir, "license.key");
            try
            {
                if (File.Exists(f))
                {
                    var t = File.ReadAllText(f).Trim();
                    if (t.Length > 0) return t.Split('\n')[0].Trim();
                }
            }
            catch { /* ignore */ }
        }
        return "";
    }

    private (long now, bool tampered) EffectiveNow()
    {
        var wall = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var last = _state.TryGetValue("last_wall", out var l) ? l.GetInt64() : 0;
        if (last > 0 && wall < last - _o.ClockToleranceSeconds)
        {
            Log($"检测到系统时间回拨: now={wall} last={last}");
            return (last, true);
        }
        return (wall, false);
    }

    private long OfflineUntil()
    {
        var last = _state.TryGetValue("last_online", out var l) ? l.GetInt64() : 0;
        if (last == 0) return 0;
        var grace = _state.TryGetValue("offline_grace_days", out var g) ? g.GetInt32() : 0;
        return last + grace * 86400L;
    }

    private static string ExpiredMessage(Dictionary<string, JsonElement> p)
    {
        var aexp = GetLong(p, "aexp");
        return aexp is null
            ? "授权已到期"
            : "授权已于 " + DateTimeOffset.FromUnixTimeSeconds(aexp.Value).ToLocalTime().ToString("yyyy-MM-dd") + " 到期";
    }

    private static int PolicyInt(JsonElement policy, string key, int fallback)
        => policy.ValueKind == JsonValueKind.Object && policy.TryGetProperty(key, out var el) && el.TryGetInt32(out var v)
            ? v : fallback;

    private static LicenseInfo FromPayload(Dictionary<string, JsonElement> payload, bool offline, JsonElement? data)
    {
        var info = new LicenseInfo
        {
            Offline = offline,
            Customer = GetString(payload, "cus"),
            ExpiresAt = GetLong(payload, "aexp"),
            HardExpiresAt = GetLong(payload, "hexp"),
            ServerTime = GetLong(payload, "srv") ?? 0,
            Status = "active",
            Code = offline ? "OFFLINE_OK" : "OK",
        };

        if (payload.TryGetValue("feat", out var feat) && feat.ValueKind == JsonValueKind.Array)
            foreach (var f in feat.EnumerateArray())
                if (f.GetString() is { } s) info.Features.Add(s);

        if (data is { } d && d.ValueKind == JsonValueKind.Object)
        {
            if (d.TryGetProperty("status", out var s) && s.GetString() == "grace") info.Status = "grace";
            if (d.TryGetProperty("code", out var c)) info.Code = c.GetString() ?? info.Code;
            if (d.TryGetProperty("message", out var m)) info.Message = m.GetString() ?? "";
            if (d.TryGetProperty("license", out var lic) && lic.ValueKind == JsonValueKind.Object)
            {
                if (lic.TryGetProperty("max_devices", out var md) && md.TryGetInt32(out var mdv)) info.MaxDevices = mdv;
                if (lic.TryGetProperty("activations", out var ac) && ac.TryGetInt32(out var acv)) info.Activations = acv;
            }
        }
        return info;
    }

    private static string? GetString(Dictionary<string, JsonElement> d, string key)
        => d.TryGetValue(key, out var el) && el.ValueKind == JsonValueKind.String ? el.GetString() : null;

    private static long? GetLong(Dictionary<string, JsonElement> d, string key)
        => d.TryGetValue(key, out var el) && el.ValueKind == JsonValueKind.Number ? el.GetInt64() : null;
}

// =============================================================================
//  令牌验签
// =============================================================================

internal static class Token
{
    public static Dictionary<string, JsonElement> Verify(string token, string publicKeySpkiBase64)
    {
        var parts = token.Split('.');
        if (parts.Length != 3) throw new LicenseException("BAD_TOKEN", "令牌格式错误");

        var data = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        var signature = Base64UrlDecode(parts[2]);

        var ok = false;
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeySpkiBase64), out _);
            ok = ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256,
                                  DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception ex)
        {
            throw new LicenseException("BAD_PUBLIC_KEY", "公钥格式错误: " + ex.Message);
        }

        if (!ok) throw new LicenseException("BAD_SIGNATURE", "授权令牌签名校验失败（文件可能被篡改）");

        var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
        using var doc = JsonDocument.Parse(payloadJson);
        var dict = new Dictionary<string, JsonElement>();
        foreach (var prop in doc.RootElement.EnumerateObject()) dict[prop.Name] = prop.Value.Clone();
        return dict;
    }

    private static byte[] Base64UrlDecode(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        switch (t.Length % 4)
        {
            case 2: t += "=="; break;
            case 3: t += "="; break;
        }
        return Convert.FromBase64String(t);
    }
}

// =============================================================================
//  硬件指纹
// =============================================================================

internal static class MachineFingerprint
{
    private static string? _cached;
    private static string? _cachedLegacy;

    /// <summary>当前指纹（v2）。只包含跨重启、跨系统升级都稳定不变的因子。</summary>
    public static string Compute()
    {
        if (_cached is not null) return _cached;
        _cached = Hash(V2Tokens());
        return _cached;
    }

    /// <summary>
    /// 旧版指纹（v1），仅供向服务端上报 machine_id_alt 使用。
    /// v1 把机器名和 OS 版本也拼进了哈希，改电脑名或升级 Windows 就会漂移，
    /// 老用户升级 SDK 后靠它认领原来的激活记录，不会被当成新设备占掉名额。
    /// </summary>
    public static string ComputeLegacy()
    {
        if (_cachedLegacy is not null) return _cachedLegacy;
        _cachedLegacy = Hash(V1Tokens());
        return _cachedLegacy;
    }

    private static string Hash(string raw)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash).ToLowerInvariant()[..32];
    }

    // ── v2：只保留硬件级、不受软件配置影响的因子 ────────────────────
    internal static string V2Tokens()
    {
        var sb = new StringBuilder();
        var stable = false;   // 是否至少拿到了一个硬件级标识

        if (OperatingSystem.IsWindows())
        {
            // 主板 / BIOS
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"HARDWARE\DESCRIPTION\System\BIOS", false);
                if (key?.GetValue("SystemProductName") is string p && p.Length > 0)
                { sb.Append("prod:").Append(p.Trim()).Append('|'); stable = true; }
                if (key?.GetValue("BaseBoardProduct") is string b && b.Length > 0)
                { sb.Append("board:").Append(b.Trim()).Append('|'); stable = true; }
            }
            catch { /* 权限不足或键不存在 */ }

            // CPU：Identifier 形如 "Intel64 Family 6 Model 154 Stepping 3"，
            // 现代 CPU 没有全局唯一序列号，这个只作为弱因子，降低整机克隆的通用性
            try
            {
                using var cpu = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"HARDWARE\DESCRIPTION\System\CentralProcessor\0", false);
                if (cpu?.GetValue("Identifier") is string id && id.Length > 0)
                    sb.Append("cpu:").Append(id.Trim()).Append('|');
                if (cpu?.GetValue("ProcessorNameString") is string nm && nm.Length > 0)
                    sb.Append("cpuname:").Append(nm.Trim()).Append('|');
            }
            catch { /* ignore */ }

            // 系统盘卷序列号（重灌系统会变，但那是换了系统，理应重新激活）
            var vol = SystemVolumeSerial();
            if (vol is not null) { sb.Append("vol:").Append(vol).Append('|'); stable = true; }

            // MachineGuid：重装系统才变，是最贴近"这台机器"的标识。
            // 放在最后但仍参与哈希——它可改，所以不能是唯一因子。
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Cryptography", false);
                if (key?.GetValue("MachineGuid") is string guid && guid.Length > 0)
                { sb.Append("guid:").Append(guid.Trim().ToLowerInvariant()).Append('|'); stable = true; }
            }
            catch { /* 非 Windows 或权限不足 */ }
        }
        else
        {
            var id = UnixMachineId();
            if (id is not null) { sb.Append("id:").Append(id).Append('|'); stable = true; }
        }

        // 硬件因子一个都没取到（容器 / 权限受限）时才用 MAC 兜底，
        // 避免正常情况下换网卡、开随机 MAC 就导致指纹漂移。
        if (!stable)
        {
            var mac = FirstPhysicalMac();
            if (mac is not null) sb.Append("mac:").Append(mac);
        }

        return sb.ToString();
    }

    // ── v1：历史算法，一字不改地保留，仅用于迁移 ────────────────────
    internal static string V1Tokens()
    {
        var sb = new StringBuilder();
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Cryptography", false);
            if (key?.GetValue("MachineGuid") is string guid && guid.Length > 0)
                sb.Append("guid:").Append(guid.ToLowerInvariant()).Append('|');
        }
        catch { /* 非 Windows 或权限不足 */ }

        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\BIOS", false);
            if (key?.GetValue("SystemProductName") is string p) sb.Append("prod:").Append(p).Append('|');
            if (key?.GetValue("BaseBoardProduct") is string b) sb.Append("board:").Append(b).Append('|');
        }
        catch { /* ignore */ }

        sb.Append("host:").Append(Environment.MachineName).Append('|');
        sb.Append("os:").Append(Environment.OSVersion.VersionString);
        return sb.ToString();
    }

    private static string? UnixMachineId()
    {
        foreach (var path in new[] { "/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid" })
        {
            try
            {
                var v = File.ReadAllText(path).Trim();
                if (v.Length > 0) return v;
            }
            catch { /* 不存在或无权限，换下一个 */ }
        }

        // macOS：hw.uuid 等价于 IOPlatformUUID
        try
        {
            var psi = new ProcessStartInfo("sysctl", "-n hw.uuid")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is not null)
            {
                var outp = p.StandardOutput.ReadToEnd().Trim();
                if (!p.WaitForExit(3000)) p.Kill(entireProcessTree: true);
                if (outp.Length > 0) return outp;
            }
        }
        catch { /* ignore */ }

        return null;
    }

    private static string? FirstPhysicalMac()
    {
        try
        {
            // 排除随机本地管理地址（第 2 位十六进制为 2/6/A/E）与常见虚拟网卡网段
            string[] virtualPrefix = { "00155D", "005056", "080027", "525400", "001C42", "0A0027" };
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
                var mac = ni.GetPhysicalAddress().GetAddressBytes();
                if (mac.Length != 6) continue;
                // 第二个字节的 bit1 = 1 表示本地管理地址（随机 MAC），会漂移，不能用
                if ((mac[1] & 0x02) != 0) continue;
                var hex = Convert.ToHexString(mac).ToUpperInvariant();
                if (virtualPrefix.Any(p => hex.StartsWith(p, StringComparison.Ordinal))) continue;
                return hex.ToLowerInvariant();
            }
        }
        catch { /* ignore */ }
        return null;
    }

    [DllImport("kernel32.dll", EntryPoint = "GetVolumeInformationW", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int GetVolumeInformation(
        string lpRootPathName,
        StringBuilder? lpVolumeNameBuffer,
        int nVolumeNameSize,
        out uint lpVolumeSerialNumber,
        out uint lpMaximumComponentLength,
        out uint lpFileSystemFlags,
        StringBuilder? lpFileSystemNameBuffer,
        int nFileSystemNameSize);

    private static string? SystemVolumeSerial()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            // 系统盘根目录，如 "C:\"
            var root = Path.GetPathRoot(Environment.SystemDirectory ?? "C:\\") ?? "C:\\";
            var ok = GetVolumeInformation(root, null, 0, out var serial, out _, out _, null, 0);
            if (ok != 0 && serial != 0) return serial.ToString("X8");
        }
        catch { /* 非 Windows / 调用失败 */ }
        return null;
    }
}

// =============================================================================
//  本地状态存储（HMAC 完整性保护）
// =============================================================================

internal sealed class StateStore
{
    private const string Magic = "LGST1";
    private readonly byte[] _key;

    public string Directory { get; }
    private string Path => System.IO.Path.Combine(Directory, "state.dat");

    public StateStore(string appId, string machineId, string? directory)
    {
        Directory = directory ?? DefaultDir(appId);
        _key = SHA256.HashData(Encoding.UTF8.GetBytes($"license-guard::{appId}::{machineId}"));
    }

    private static string DefaultDir(string appId)
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(root)) root = System.IO.Path.GetTempPath();
        return System.IO.Path.Combine(root, appId);
    }

    private byte[] Mac(byte[] body) => HMACSHA256.HashData(_key, body);

    public Dictionary<string, JsonElement> Load()
    {
        try
        {
            var raw = File.ReadAllBytes(Path);
            var nl = Array.IndexOf(raw, (byte)'\n');
            if (nl < 0) return new();

            var head = Encoding.ASCII.GetString(raw, 0, nl);
            var body = raw[(nl + 1)..];
            var sep = head.IndexOf(':');
            if (sep < 0) return new();

            if (head[..sep] != Magic) return new();

            var expected = Convert.ToHexString(Mac(body)).ToLowerInvariant();
            var actual = head[(sep + 1)..];
            if (expected.Length != actual.Length ||
                !CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(actual)))
            {
                return new() { ["__tampered__"] = JsonSerializer.SerializeToElement(true) };
            }

            using var doc = JsonDocument.Parse(body);
            var dict = new Dictionary<string, JsonElement>();
            foreach (var p in doc.RootElement.EnumerateObject()) dict[p.Name] = p.Value.Clone();
            return dict;
        }
        catch
        {
            return new();
        }
    }

    public void Save(Dictionary<string, JsonElement> data)
    {
        try
        {
            var body = JsonSerializer.SerializeToUtf8Bytes(data);
            var head = Encoding.ASCII.GetBytes($"{Magic}:{Convert.ToHexString(Mac(body)).ToLowerInvariant()}\n");
            System.IO.Directory.CreateDirectory(Directory);

            var tmp = Path + ".tmp";
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.Write(head);
                fs.Write(body);
            }
            File.Move(tmp, Path, overwrite: true);
        }
        catch { /* 磁盘只读时静默降级 */ }
    }

    public void Clear()
    {
        try { if (File.Exists(Path)) File.Delete(Path); } catch { /* ignore */ }
    }
}
