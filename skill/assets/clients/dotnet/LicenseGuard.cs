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
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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

    /// <summary>
    /// 缓存令牌能跳过联网的最长时间（秒）。默认 0 = 每次 <see cref="LicenseGuard.VerifyAsync"/> 都联网。
    /// <para>
    /// 这个值直接决定后台「封禁 / 改期 / 设过期」的最坏生效延迟，与 <c>token_ttl_sec</c> 无关：
    /// <c>token_ttl_sec</c> 管的是断网后本地还能撑多久，本项管的是多久主动回连一次。
    /// </para>
    /// <para>
    /// 调大的唯一理由是在高 QPS 场景省请求；代价是封禁延迟变长。
    /// 服务端连不上时仍走离线容忍兜底（<c>offline_grace_days</c>）。
    /// </para>
    /// </summary>
    public int OnlineCheckIntervalSeconds { get; set; } = 0;

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

    /// <summary>
    /// POST 一个扁平 JSON 对象（键值全部是字符串），返回响应根节点。
    ///
    /// 参数用 (key, value) 元组数组而不是匿名对象：匿名对象只能交给
    /// <c>JsonSerializer.Serialize(object)</c> 序列化，那条路径要走运行时反射生成类型元数据，
    /// 在 NativeAOT / 完全裁剪下会触发 IL2026 / IL3050，运行时直接抛
    /// <c>NotSupportedException</c>。这里改用命令式 <see cref="Utf8JsonWriter"/>，零反射。
    /// </summary>
    private Task<JsonElement?> PostAsync(string path, params (string Key, string? Value)[] fields)
        => SendAsync(HttpMethod.Post, path, JsonValue.Object(fields));

    /// <summary>GET 一个 JSON 接口。重试 / 超时 / 状态码策略与 <see cref="PostAsync"/> 完全一致。</summary>
    private Task<JsonElement?> GetAsync(string path) => SendAsync(HttpMethod.Get, path, null);

    private async Task<JsonElement?> SendAsync(HttpMethod method, string path, byte[]? body)
    {
        Exception? last = null;
        var url = _o.ServerUrl + path;

        for (var attempt = 0; attempt < Math.Max(1, _o.RetryTimes); attempt++)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_o.RequestTimeoutSeconds));
            try
            {
                using var req = new HttpRequestMessage(method, url);
                if (body is not null)
                {
                    req.Content = new ByteArrayContent(body);
                    req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
                }
                using var resp = await Http.SendAsync(req, cts.Token).ConfigureAwait(false);
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

    /// <summary>
    /// 主动向服务端取一次权威时间，算出本机时钟偏差（skew = 服务端时间 − 本机挂钟）并落盘。
    /// <para>
    /// 作用是让「把系统时间调回过去」这类绕过在本地就算得出来：后续所有到期判定都用
    /// <c>挂钟 + skew</c>，而不是裸的本地时间。返回的 <c>server_time</c> 带 Ed25519 签名，
    /// 中间人改不了；这里还会比对签名里的 t 与明文 server_time，不一致直接拒绝。
    /// </para>
    /// <para>离线时抛 <c>NETWORK</c>；调用方可以不处理，正常校验路径不依赖它。</para>
    /// </summary>
    /// <returns>本次测得的时钟偏差（秒），正数表示本机偏慢。</returns>
    public async Task<long> SyncTimeAsync()
    {
        _state = _store.Load();
        if (_state.ContainsKey("__tampered__"))
        {
            _store.Clear();
            _state.Clear();
        }

        var resp = await GetAsync("/v1/time?app_id=" + Uri.EscapeDataString(_o.AppId)).ConfigureAwait(false);
        if (resp is null)
            throw new LicenseException("NETWORK", "无法连接授权服务器获取时间");

        var root = resp.Value;
        if (!root.TryGetProperty("ok", out var okEl) || !okEl.GetBoolean())
        {
            var code = root.TryGetProperty("code", out var c) ? c.GetString() ?? "DENIED" : "DENIED";
            var msg = root.TryGetProperty("message", out var m) ? m.GetString() ?? "获取服务端时间失败" : "获取服务端时间失败";
            throw new LicenseException(code!, msg!);
        }

        var data = root.GetProperty("data");
        var serverTime = data.GetProperty("server_time").GetInt64();

        // 必须验签：明文 server_time 可以被中间人改，签名里的 t 才是可信值
        var payload = Token.Verify(data.GetProperty("token").GetString()!, _o.PublicKey);
        var signed = GetLong(payload, "t");
        if (signed is null || signed.Value != serverTime)
            throw new LicenseException("BAD_TOKEN", "服务端时间令牌与明文时间不一致");

        var skew = serverTime - DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        _state["clock_skew"] = JsonValue.Num(skew);
        _store.Save(_state);
        Log($"时钟同步完成: server={serverTime} skew={skew}s");
        return skew;
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
            // 同时接受 v2 与 v1 指纹：老用户升级 SDK 后本地令牌仍是 v1 指纹签发。
            // 只认 v2 会在这里直接判 MACHINE_MISMATCH，而这个判定发生在联网之前，
            // 永远走不到服务端的激活记录迁移（machine_id_alt）。
            if (!string.IsNullOrEmpty(mid) && mid != _machineId && mid != _machineIdLegacy)
                Deny("MACHINE_MISMATCH", "该授权绑定了另一台设备");

            var hexp = GetLong(payload, "hexp");
            if (hexp is not null && now > hexp.Value) Deny("LICENSE_EXPIRED", ExpiredMessage(payload));

            var exp = GetLong(payload, "exp") ?? 0;
            // allowOffline=false 表示调用方要求必须拿到服务端确认，此时跳过快速通道强制联网
            if (allowOffline && now <= exp && CanSkipOnline(now))
            {
                _state["last_wall"] = JsonValue.Num(now);
                _store.Save(_state);
                _info = FromPayload(payload, true, null);
                return _info;
            }
        }

        /* ---- 2) 联网校验 ---- */
        var endpoint = cached is null ? "/v1/activate" : "/v1/verify";
        var resp = await PostAsync(endpoint,
            ("app_id", _o.AppId),
            ("key", rawKey),
            ("machine_id", _machineId),
            ("machine_id_alt", _machineIdLegacy),
            ("machine_name", Environment.MachineName),
            ("platform", "windows"),
            ("app_version", typeof(LicenseGuard).Assembly.GetName().Version?.ToString() ?? "1.0.0")
        ).ConfigureAwait(false);

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
            ["token"] = JsonValue.Str(token),
            ["last_online"] = JsonValue.Num(serverTime),
            ["last_wall"] = JsonValue.Num(now),
            ["license_key"] = JsonValue.Str(rawKey),
            ["offline_grace_days"] = JsonValue.Num(PolicyInt(policy, "offline_grace_days", 0)),
            ["heartbeat_sec"] = JsonValue.Num(PolicyInt(policy, "heartbeat_sec", _o.HeartbeatSeconds)),
            // 每次联网都重测一次偏差，避免长时间离线后 skew 过期
            ["clock_skew"] = JsonValue.Num(serverTime - DateTimeOffset.UtcNow.ToUnixTimeSeconds()),
            // install_id 是本机安装实例标识，跨进程重启必须稳定：
            // 每次联网都新建会让服务端把它当成不同安装，无法做「同一台机器上的重复激活」统计。
            ["install_id"] = JsonValue.Str(
                _state.TryGetValue("install_id", out var iid) && iid.ValueKind == JsonValueKind.String
                    ? iid.GetString()!
                    : Guid.NewGuid().ToString("N")),
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
        var resp = await PostAsync("/v1/deactivate",
            ("app_id", _o.AppId),
            ("key", rawKey),
            ("machine_id", _machineId),
            ("machine_id_alt", _machineIdLegacy)
        ).ConfigureAwait(false);
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

    /// <summary>
    /// 算出用于到期判定的「当前时间」，并顺带检测系统时间被回拨。
    /// <para>
    /// 时间口径 = 本机挂钟 + <c>clock_skew</c>（上次联网时测得的服务端偏差，见 <see cref="SyncTimeAsync"/>）。
    /// 没有 skew 时退化为裸挂钟，与旧版行为一致。
    /// </para>
    /// <para>两条回拨检测分别对应两个口径，互不干扰：</para>
    /// <list type="number">
    ///   <item>挂钟 vs 上次记录的挂钟（<c>last_wall</c>）—— 覆盖没有 skew 的情况</item>
    ///   <item>校正时间 vs 上次服务端时间（<c>last_online</c>）—— 覆盖「改了时间且本地有 skew」的情况</item>
    /// </list>
    /// </summary>
    private (long now, bool tampered) EffectiveNow()
    {
        var wall = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var lastWall = _state.TryGetValue("last_wall", out var lw) ? lw.GetInt64() : 0;
        if (lastWall > 0 && wall < lastWall - _o.ClockToleranceSeconds)
        {
            Log($"检测到系统时间回拨: now={wall} last={lastWall}");
            return (lastWall, true);
        }

        var now = wall + (_state.TryGetValue("clock_skew", out var s) ? s.GetInt64() : 0);
        var lastOnline = _state.TryGetValue("last_online", out var lo) ? lo.GetInt64() : 0;
        if (lastOnline > 0 && now < lastOnline - _o.ClockToleranceSeconds)
        {
            Log($"检测到服务端时间回拨: now={now} last_online={lastOnline}");
            return (lastOnline, true);
        }
        return (now, false);
    }

    private long OfflineUntil()
    {
        var last = _state.TryGetValue("last_online", out var l) ? l.GetInt64() : 0;
        if (last == 0) return 0;
        var grace = _state.TryGetValue("offline_grace_days", out var g) ? g.GetInt32() : 0;
        return last + grace * 86400L;
    }

    /// <summary>
    /// 缓存令牌能否直接放行（完全不联网）。调用方已判过 <c>exp</c>，这里只判另外两条。
    /// <para>
    /// 1. 离线容忍期未耗尽（last_online + offline_grace_days）
    /// 2. 距上次成功联网未超过 <see cref="GuardOptions.OnlineCheckIntervalSeconds"/>
    /// </para>
    /// <para>
    /// 第 2 条是关键：间隔配成 0 时本方法恒为 false，即每次校验都联网，
    /// 后台的吊销 / 改期 / 设过期立即生效；真连不上时才走离线容忍兜底。
    /// </para>
    /// </summary>
    private bool CanSkipOnline(long now)
    {
        if (now > OfflineUntil()) return false;

        var interval = _o.OnlineCheckIntervalSeconds;
        if (interval <= 0) return false;

        var lastOnline = _state.TryGetValue("last_online", out var l) ? l.GetInt64() : 0;
        return lastOnline > 0 && now - lastOnline < interval;
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
//  JSON 写出（AOT 安全，零反射）
// =============================================================================

/// <summary>
/// 只用 <see cref="Utf8JsonWriter"/> 的命令式 API 拼 JSON。
///
/// 为什么不用 <c>JsonSerializer.Serialize</c>：那条路径对每个类型都要走
/// <c>DefaultJsonTypeInfoResolver</c> 生成属性访问器，NativeAOT 下没有运行时代码生成，
/// 会先报 IL2026 / IL3050，运行时抛 <c>NotSupportedException</c>
/// （错误信息形如 "Metadata for type X was not provided"）。
/// <c>Utf8JsonWriter</c> 是一组纯托管写入调用，不查任何类型元数据。
/// </summary>
internal static class JsonValue
{
    /// <summary>{"k":"v","n":null,...} —— value 为 null 时写 JSON null。</summary>
    public static byte[] Object(IReadOnlyList<(string Key, string? Value)> fields)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            foreach (var (key, value) in fields)
            {
                if (value is null) w.WriteNull(key);
                else w.WriteString(key, value);
            }
            w.WriteEndObject();
        }
        return ms.ToArray();
    }

    /// <summary>把已有的 JsonElement 字典写成 JSON 对象（状态文件用）。</summary>
    public static byte[] Object(IReadOnlyDictionary<string, JsonElement> map)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            foreach (var kv in map)
            {
                w.WritePropertyName(kv.Key);
                kv.Value.WriteTo(w);   // JsonElement.WriteTo 是纯数据拷贝，不涉及反射
            }
            w.WriteEndObject();
        }
        return ms.ToArray();
    }

    /// <summary>构造单值 JsonElement。套一层数组是因为 Utf8JsonWriter 在 depth=0 时不能写裸值。</summary>
    private static JsonElement Single(Action<Utf8JsonWriter> write)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartArray();
            write(w);
            w.WriteEndArray();
        }
        using var doc = JsonDocument.Parse(ms.ToArray());
        return doc.RootElement[0].Clone();
    }

    public static JsonElement Str(string s) => Single(w => w.WriteStringValue(s));
    public static JsonElement Num(long n) => Single(w => w.WriteNumberValue(n));
    public static JsonElement Bool(bool b) => Single(w => w.WriteBooleanValue(b));
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
                return new() { ["__tampered__"] = JsonValue.Bool(true) };
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
            var body = JsonValue.Object(data);
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
