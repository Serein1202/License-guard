// 一次性验证：在「关闭反射序列化」的运行时约束下跑完整激活/校验/解绑流程。
// 关掉反射后，任何残留的 JsonSerializer.Serialize(object) 都会抛 NotSupportedException，
// 等价于 NativeAOT 下缺少类型元数据时的失败模式。
//
// 两种模式：
//   dotnet run                 → 默认模式：激活/校验/解绑 + JsonValue/StateStore 直调
//   dotnet run -- timesync     → 时钟模式：/v1/time 同步 + 回拨检测（供 tests/e2e_timesync.py 调用）
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LicenseGuard;

internal static class Program
{
    private static int _fail;
    private static readonly List<string> Seen = new();
    /** 置 true 时 mock 的 /v1/time 会返回与签名不一致的 server_time，用来验证验签兜底 */
    private static volatile bool _tamperTime;

    private static readonly List<(string Name, bool Ok, string Detail)> Results = new();

    private static void Check(string name, bool ok, string? detail = null)
    {
        Console.WriteLine((ok ? "PASS  " : "FAIL  ") + name + (detail is null ? "" : "  → " + detail));
        Results.Add((name, ok, detail ?? ""));
        if (!ok) _fail++;
    }

    public static async Task<int> Main(string[] args)
    {
        /* 关键：必须在任何 System.Text.Json 调用之前关掉反射回退。
           .NET 8 起这个开关同时影响 JsonSerializer 的默认 resolver，
           关闭后只有 JsonTypeInfo / JsonSerializerContext 能工作。 */
        AppContext.SetSwitch("System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault", false);

        if (args.Length > 0 && args[0] == "timesync")
            return await TimeSyncMode();

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pubB64 = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(() => ServeLoop(listener, key));

        var dir = Path.Combine(Path.GetTempPath(), "lg-aot-" + Guid.NewGuid().ToString("N")[..8]);
        var guard = new LicenseGuard.LicenseGuard(new GuardOptions
        {
            ServerUrl = "http://127.0.0.1:" + port,
            AppId = "aotapp",
            PublicKey = pubB64,
            LicenseKey = "AAAA-BBBB-CCCC-DDDD",
            StorageDirectory = dir,
            Debug = true,
            RetryTimes = 1,
            RequestTimeoutSeconds = 5,
            OnDenied = (code, msg) => { Console.WriteLine("DENIED " + code + " " + msg); _fail++; },
        });

        // 1) 首次校验 → /v1/activate
        var info = await guard.VerifyAsync();
        Check("activate 成功", info.Status == "active", info.Status + " / " + info.Code);
        Check("features 解析", guard.HasFeature("pro"));

        // 2) 请求体字段完整（新 PostAsync 的序列化结果）
        var act = Seen.Last();
        Check("请求体含 app_id/key/machine_id", act.Contains("\"app_id\":\"aotapp\"") &&
                                                act.Contains("\"key\":\"AAAA-BBBB-CCCC-DDDD\"") &&
                                                act.Contains("\"machine_id\":"));
        Check("请求体含 machine_id_alt", act.Contains("\"machine_id_alt\":"));
        Check("请求体是合法 JSON", IsJson(act), act);

        // 3) 有缓存令牌后再次校验 → 走 /v1/verify
        await guard.VerifyAsync();
        Check("verify 端点被调用", Seen.Count >= 2 && Seen.Count > 0, "请求数 " + Seen.Count);

        // 4) 状态文件在联网校验后应已落盘（deactivate 会 Clear，必须在此之前查）
        var stateFile = Path.Combine(dir, "state.dat");
        Check("状态文件已落盘", File.Exists(stateFile), stateFile);

        // 5) 解绑 → /v1/deactivate
        var ok = await guard.ReleaseAsync();
        Check("deactivate 成功", ok);

        Check("deactivate 后状态已清空", !File.Exists(stateFile));

        // 6) 单独探一次 JsonValue + StateStore（Save 内部吞异常，这里要拿到真实结果）
        try
        {
            var map = new Dictionary<string, JsonElement>
            {
                ["token"] = JsonValue.Str("abc"),
                ["n"] = JsonValue.Num(1700000000),
                ["b"] = JsonValue.Bool(true),
            };
            var bytes = JsonValue.Object(map);
            Check("JsonValue.Object(dict)", true, Encoding.UTF8.GetString(bytes));
            new LicenseGuard.StateStore("aotapp", "mid-x", dir).Save(map);
            Check("StateStore.Save 落盘", File.Exists(stateFile));
        }
        catch (Exception ex)
        {
            Check("StateStore 直调", false, ex.GetType().Name + ": " + ex.Message);
        }

        guard.StopWatchdog();
        listener.Stop();
        try { Directory.Delete(dir, true); } catch { }

        Console.WriteLine(_fail == 0 ? "\nALL PASS" : $"\n{_fail} FAILED");
        return _fail == 0 ? 0 : 1;
    }

    // ------------------------------------------------------------------ 时钟模式
    private static async Task<int> TimeSyncMode()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pubB64 = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        _ = Task.Run(() => ServeLoop(listener, key));

        var dir = Path.Combine(Path.GetTempPath(), "lg-ts-" + Guid.NewGuid().ToString("N")[..8]);
        var guard = new LicenseGuard.LicenseGuard(new GuardOptions
        {
            ServerUrl = "http://127.0.0.1:" + port,
            AppId = "tsapp",
            PublicKey = pubB64,
            LicenseKey = "AAAA-BBBB-CCCC-DDDD",
            StorageDirectory = dir,
            RetryTimes = 1,
            RequestTimeoutSeconds = 5,
            OnDenied = (code, msg) => Console.WriteLine("DENIED " + code + " " + msg),
        });

        // 1) 主动同步
        var skew = await guard.SyncTimeAsync();
        Check("SyncTimeAsync 返回偏差值", Math.Abs(skew) < 5, skew + "s");

        var state = ReadField(guard);
        Check("skew 已写入状态", state.ContainsKey("clock_skew"), string.Join(",", state.Keys));

        // 2) server_time 与签名里的 t 不一致 → 必须拒绝
        _tamperTime = true;
        try
        {
            await guard.SyncTimeAsync();
            Check("server_time 与签名不一致时被拒", false, "没有抛错");
        }
        catch (LicenseException ex)
        {
            Check("server_time 与签名不一致时被拒", ex.Code == "BAD_TOKEN", ex.Code);
        }
        finally
        {
            _tamperTime = false;
        }

        // 3) 完整校验后 skew 被刷新，且 install_id 跨次稳定
        await guard.VerifyAsync();
        var s1 = ReadField(guard);
        Check("verify 后 clock_skew 已写入", s1.ContainsKey("clock_skew"), string.Join(",", s1.Keys));
        Check("verify 后 skew 仍然很小",
              s1.TryGetValue("clock_skew", out var sk) && Math.Abs(sk.GetInt64()) < 5,
              s1.TryGetValue("clock_skew", out var sk2) ? sk2.GetInt64() + "s" : "-");
        var id1 = s1.TryGetValue("install_id", out var i1) ? i1.GetString() : null;

        await guard.VerifyAsync();
        var s2 = ReadField(guard);
        var id2 = s2.TryGetValue("install_id", out var i2) ? i2.GetString() : null;
        Check("install_id 跨多次校验稳定", id1 is not null && id1 == id2, $"{id1} vs {id2}");

        // 4) 回拨检测：EffectiveNow 是私有方法，用反射直接验证两个口径
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Check("服务端时间口径回拨被检出",
              EffectiveNow(guard, ("last_online", now), ("last_wall", now - 60), ("clock_skew", -86400L)).tampered,
              "skew=-86400");
        Check("挂钟口径回拨被检出（无 skew 也生效）",
              EffectiveNow(guard, ("last_wall", now + 86400)).tampered, "last_wall=now+1d");
        var normal = EffectiveNow(guard, ("last_wall", now - 60), ("last_online", now - 60), ("clock_skew", 0L));
        Check("正常情况不误报篡改", !normal.tampered, "now=" + normal.now);

        // 5) 断网时 SyncTimeAsync 抛 NETWORK
        var bad = new LicenseGuard.LicenseGuard(new GuardOptions
        {
            ServerUrl = "http://127.0.0.1:1",
            AppId = "tsapp",
            PublicKey = pubB64,
            LicenseKey = "AAAA-BBBB-CCCC-DDDD",
            StorageDirectory = dir,
            RetryTimes = 1,
            RequestTimeoutSeconds = 3,
        });
        try
        {
            await bad.SyncTimeAsync();
            Check("断网时 SyncTimeAsync 抛 NETWORK", false, "没有抛错");
        }
        catch (LicenseException ex)
        {
            Check("断网时 SyncTimeAsync 抛 NETWORK", ex.Code == "NETWORK", ex.Code);
        }

        guard.StopWatchdog();
        listener.Stop();
        try { Directory.Delete(dir, true); } catch { }

        // 这里只能手工拼串：本进程关掉了反射序列化，JsonSerializer.Serialize 会抛
        Console.WriteLine(_fail == 0 ? "ALL PASS" : $"{_fail} FAILED");
        Console.WriteLine("CS-RESULT " + ResultsJson());
        return _fail == 0 ? 0 : 1;
    }

    /// <summary>
    /// 把断言结果拼成 <c>{"results":[["name",true,"detail"],...]}</c>。
    /// 手工拼串而不是 <c>JsonSerializer.Serialize</c>：本进程已经关掉反射序列化，
    /// 测试代码自己也得遵守 AOT 约束，否则先被自己的开关打脸。
    /// </summary>
    private static string ResultsJson()
    {
        var sb = new StringBuilder("{\"results\":[");
        for (var i = 0; i < Results.Count; i++)
        {
            if (i > 0) sb.Append(',');
            var (name, ok, detail) = Results[i];
            sb.Append('[').Append(JsonStr(name)).Append(',')
              .Append(ok ? "true" : "false").Append(',')
              .Append(JsonStr(detail)).Append(']');
        }
        return sb.Append("]}").ToString();
    }

    private static string JsonStr(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    /// <summary>读私有字段 _state（测试专用，业务代码不这么干）。</summary>
    private static Dictionary<string, JsonElement> ReadField(object guard)
    {
        var f = guard.GetType().GetField("_state", BindingFlags.NonPublic | BindingFlags.Instance);
        return (Dictionary<string, JsonElement>)f!.GetValue(guard)!;
    }

    /// <summary>反射调用私有的 EffectiveNow，并先把 _state 换成指定内容。</summary>
    private static (long now, bool tampered) EffectiveNow(object guard, params (string Key, long Value)[] state)
    {
        var map = new Dictionary<string, JsonElement>();
        foreach (var (k, v) in state) map[k] = JsonValue.Num(v);
        guard.GetType().GetField("_state", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(guard, map);

        var m = guard.GetType().GetMethod("EffectiveNow", BindingFlags.NonPublic | BindingFlags.Instance)!;
        return ((long, bool))m.Invoke(guard, null)!;
    }

    private static bool IsJson(string s)
    {
        try { using var _ = JsonDocument.Parse(s); return true; } catch { return false; }
    }

    // ---------------------------------------------------------------- mock server
    private static async Task ServeLoop(TcpListener listener, ECDsa key)
    {
        while (true)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(); }
            catch { return; }
            _ = Task.Run(() => Handle(client, key));
        }
    }

    private static async Task Handle(TcpClient client, ECDsa key)
    {
        using var _c = client;
        var s = client.GetStream();
        var head = new List<byte>();
        var one = new byte[1];
        while (true)
        {
            var n = await s.ReadAsync(one);
            if (n == 0) return;
            head.Add(one[0]);
            if (head.Count >= 4 && head[^1] == 10 && head[^2] == 13 && head[^3] == 10 && head[^4] == 13) break;
        }
        var headStr = Encoding.ASCII.GetString(head.ToArray());
        var lines = headStr.Split("\r\n");
        var path = lines[0].Split(' ')[1];

        var len = 0;
        foreach (var line in lines)
        {
            var idx = line.IndexOf(':');
            if (idx > 0 && line[..idx].Trim().Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                int.TryParse(line[(idx + 1)..].Trim(), out len);
        }
        var body = new byte[len];
        var read = 0;
        while (read < len) read += await s.ReadAsync(body.AsMemory(read));
        var bodyStr = Encoding.UTF8.GetString(body);
        lock (Seen) Seen.Add(bodyStr);

        string respJson;
        if (path.StartsWith("/v1/time"))
        {
            // 与 worker 一致：server_time 明文 + 同值签名令牌（typ=TS, payload {"v":1,"t":ts}）
            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var signed = _tamperTime ? ts : ts;
            var token = MakeTimeToken(key, signed);
            var shown = _tamperTime ? ts - 999999 : ts;
            respJson = "{\"ok\":true,\"data\":{\"server_time\":" + shown +
                       ",\"sign_alg\":\"es256\",\"token\":\"" + token + "\"}}";
        }
        else if (path.EndsWith("/v1/deactivate"))
        {
            respJson = "{\"ok\":true,\"data\":{\"deactivated\":true}}";
        }
        else
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var mid = ExtractString(bodyStr, "machine_id");
            var token = MakeToken(key, mid, now + 86400, now + 90 * 86400);
            respJson = "{\"ok\":true,\"data\":{\"token\":\"" + token +
                       "\",\"server_time\":" + now +
                       ",\"policy\":{\"offline_grace_days\":7,\"heartbeat_sec\":21600,\"fail_mode\":\"hard\",\"features\":[\"pro\"]}}}";
        }

        var bytes = Encoding.UTF8.GetBytes(respJson);
        var header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                     bytes.Length + "\r\nConnection: close\r\n\r\n";
        await s.WriteAsync(Encoding.ASCII.GetBytes(header));
        await s.WriteAsync(bytes);
    }

    private static string ExtractString(string json, string field)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty(field, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? "" : "";
    }

    private static string MakeToken(ECDsa key, string mid, long exp, long hexp)
    {
        var header = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        string payload2 = "{\"mid\":\"" + mid + "\",\"exp\":" + exp + ",\"aexp\":" + exp +
                      ",\"hexp\":" + hexp + ",\"feat\":[\"pro\"],\"key\":\"AAAA-BBBB-CCCC-DDDD\"}";
        var h = B64Url(Encoding.UTF8.GetBytes(header));
        var p = B64Url(Encoding.UTF8.GetBytes(payload2));
        var sig = key.SignData(Encoding.ASCII.GetBytes(h + "." + p), HashAlgorithmName.SHA256,
                               DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return h + "." + p + "." + B64Url(sig);
    }

    private static string MakeTimeToken(ECDsa key, long ts)
    {
        var header = "{\"alg\":\"ES256\",\"typ\":\"TS\"}";
        var payload = "{\"v\":1,\"t\":" + ts + "}";
        var h = B64Url(Encoding.UTF8.GetBytes(header));
        var p = B64Url(Encoding.UTF8.GetBytes(payload));
        var sig = key.SignData(Encoding.ASCII.GetBytes(h + "." + p), HashAlgorithmName.SHA256,
                               DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return h + "." + p + "." + B64Url(sig);
    }

    private static string B64Url(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
