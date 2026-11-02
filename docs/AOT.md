# C# 客户端 NativeAOT 说明

`clients/dotnet/LicenseGuard.cs` 现在对 NativeAOT / 完全裁剪是**代码级就绪**的，
但本机没有 MSVC 链接器，真正落盘 `.exe` 那一步还没跑过。这份文档说清楚现状、原因和验证方法。

---

## 1. 结论先说

| 环节 | 状态 |
|---|---|
| Roslyn AOT/裁剪分析器（IL2026 / IL3050） | **0 警告**，已接入 csproj，改回反射写法立刻报错 |
| 关闭反射序列化的运行时自证（等价 AOT 失败模式） | **全部通过**，`tests/AotCompat` |
| `dotnet publish -p:PublishAot=true` 真实出包 | **未执行通过** —— 卡在 `Platform linker not found` |

最后一条不是代码问题：托管编译、裁剪、ILC 前置全部走完，只差 native 链接。
装好 VS2022「使用 C++ 的桌面开发」工作负载（含 Windows 10/11 SDK）后重跑即可。

---

## 2. 曾经的阻塞点

原来的请求体是匿名对象：

```csharp
var body = JsonSerializer.Serialize(new { app_id = ..., key = ..., machine_id = ... });
```

`JsonSerializer.Serialize(object)` 走 `DefaultJsonTypeInfoResolver`，需要**运行时代码生成**来
构造属性访问器。NativeAOT 下没有这个能力：

- 编译期：IL3050（RequiresDynamicCode）、IL2026（RequiresUnreferencedCode）
- 运行期：`NotSupportedException: Metadata for type '<>f__AnonymousType0...' was not provided`

同样的写法还出现在状态文件落盘（`SerializeToUtf8Bytes(Dictionary<string, JsonElement>)`）
和三处 `SerializeToElement<T>` 上。

## 3. 采用的方案：命令式 `Utf8JsonWriter`

`LicenseGuard.cs` 里新增 `JsonValue` 工具类，只用 `Utf8JsonWriter` 拼 JSON——
纯托管写入调用，不查任何类型元数据，因此不需要反射也不需要源生成：

```csharp
// 请求体
var body = JsonValue.Object(("app_id", _o.AppId), ("key", rawKey), ("machine_id", _mid));
// → {"app_id":"...","key":"...","machine_id":"..."}

// 状态文件里的单值
_state["token"] = JsonValue.Str(token);
_state["last_wall"] = JsonValue.Num(now);
_state["__tampered__"] = JsonValue.Bool(true);
```

`PostAsync` 的签名也随之改为元组参数：

```csharp
await PostAsync("/v1/verify",
    ("app_id", _o.AppId),
    ("key", rawKey),
    ("machine_id", _machineId),
    ("machine_id_alt", _machineIdLegacy)
);
```

### 为什么不选另外两条路

| 方案 | 结论 |
|---|---|
| `JsonSerializerContext` 源生成 | 可行，但要在「单文件 SDK」里塞一堆 `partial class` + `[JsonSerializable]` 特性，每个请求体一个 record。调用方复制这个 `.cs` 时会连编译上下文一起带走，维护成本高于收益 |
| 关掉 AOT，用 ReadyToRun + 混淆 | 最省事，但产物 60MB 量级、托管元数据完整暴露，`dnSpy` 一开就能看到校验逻辑。和「加壳 + VMP」的诉求直接冲突 |
| 命令式 `Utf8JsonWriter` | 零依赖、零反射、体积不变、单文件结构不变。**选的这个** |

注意 `JsonDocument.Parse` / `JsonElement.WriteTo` 本来就不涉及反射，读取侧不需要改动。

---

## 4. 三层验证

### 4.1 编译期：分析器门禁

`LicenseGuard.csproj` 里已经打开：

```xml
<IsAotCompatible>true</IsAotCompatible>
<EnableAotAnalyzer>true</EnableAotAnalyzer>
<EnableTrimAnalyzer>true</EnableTrimAnalyzer>
```

`dotnet build` 只要 0 警告就说明没有反射/动态代码路径。反向验证过：临时插回一行
`JsonSerializer.Serialize(new { a = 1 })`，立刻冒出 IL3050 + IL2026 各一条。

```bash
cd clients/dotnet && dotnet build
# 已成功生成。0 个警告 0 个错误
```

### 4.2 运行期：关掉反射序列化

`clients/dotnet/tests/AotCompat` 在 `Main` 第一行设：

```csharp
AppContext.SetSwitch("System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault", false);
```

此后任何残留的反射序列化都会当场抛异常——和 AOT 下的失败模式一致。
测试自己起一个 TCP mock 服务器签真令牌，跑完整链路：

```bash
cd clients/dotnet/tests/AotCompat
dotnet run
# ALL PASS
```

覆盖：activate → verify → deactivate、请求体字段与 JSON 合法性、状态文件落盘与清除。

### 4.3 真实出包

```bash
# 前置：VS2022 + "使用 C++ 的桌面开发" 工作负载（含 Windows SDK）
cd clients/dotnet
dotnet publish -c Release -r win-x64 -p:PublishAot=true -o out
```

预期产物：`out/LicenseGuard.dll` 对应的 `LicenseGuard.exe`，体积约 2-4MB，无 .NET 运行时依赖。

其它可选参数：

```bash
# 体积优先（禁用反射相关特性）
-p:OptimizationPreference=Size
# 保留调试符号，便于事后 dump 分析
-p:StackTraceSupport=true -p:DebugType=embedded
```

---

## 5. AOT 与加壳/虚拟化的关系

这两件事目标重叠但不互斥：

| | 作用 | 局限 |
|---|---|---|
| NativeAOT | 去掉 IL 和托管元数据，`dnSpy`/`ILSpy` 直接失效 | 反汇编（IDA/x64dbg）依然可读；字符串常量仍在 |
| 加壳 / VMP | 代码虚拟化 + 反调试，抬高动态分析成本 | **与 AOT 有冲突**：多数壳只支持普通 PE 或 .NET IL，不支持 ILC 产物 |

实操建议：**先 AOT 出包，再选一个支持 native PE 的保护器**（VMProtect / Themida 的 native 模式），
不要在 IL 层加壳（.NET Reactor 之类对 AOT 产物无效）。

想进一步提高门槛，成本更低的顺序是：

1. 关键判定内联到 native，别留清晰的 `if (!ok) exit()` 形态
2. 令牌校验结果与业务逻辑交织（校验失败不返回布尔值，而是污染后续计算）
3. 公钥/常量做拆分与运行时拼接，避免明文出现在 `.rdata`

---

## 6. 已知遗留

- `app_version` 用的是 `typeof(LicenseGuard).Assembly.GetName().Version`。AOT 下可用，
  但如果你希望版本号可热改，改成读取 `AppContext.GetData("APP_VERSION")` 之类的注入值。
- 真实 AOT 产物**尚未出过包**（本机缺 MSVC）。要出包就在装了「C++ 桌面开发」工作负载的
  Windows 机器上跑 `dotnet publish -p:PublishAot=true`，或直接用 GitHub 的
  `windows-2022` runner（自带 C++ 工作负载），开箱可用。
