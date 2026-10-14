#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
install_sdk.py —— 把 license-guard 客户端 SDK 装进目标项目。

职责（只做确定性的事，不猜业务代码）：
  1. 探测目标项目语言（python / node / dotnet）
  2. 把对应 SDK 从本 Skill 的 assets/clients/ 拷进项目 vendor/ 下
  3. 生成一份带**真实** server_url / app_id / public_key 的配置常量文件
  4. 报告可能的程序入口，供上层决定把守卫插在哪

不做：不自动改写业务代码。注入守卫由调用方（Agent）按 references/integration.md 完成。

用法：
  python install_sdk.py <project_dir> [--lang python|node|dotnet] [--app-id NAME]
                        [--vendor vendor] [--force]

示例：
  python install_sdk.py D:/code/mytool --app-id mytool
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
ASSETS = SKILL_ROOT / "assets" / "clients"
CONFIG = SKILL_ROOT / "config.json"
# 本地真实配置优先于仓库里的占位模板（config.local.json 已加入 .gitignore）
CONFIG_LOCAL = SKILL_ROOT / "config.local.json"

# 探测用到的标记文件 -> 语言
PY_MARKERS = ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt")
NODE_MARKERS = ("package.json",)
DOTNET_MARKERS = (".sln", ".csproj")

# 各语言常见的入口文件名
PY_ENTRIES = ("main.py", "app.py", "__main__.py", "run.py", "cli.py", "manage.py")
NODE_ENTRIES = ("main.js", "index.js", "app.js", "cli.js", "main.mjs", "index.mjs")
DOTNET_ENTRIES = ("Program.cs", "App.xaml.cs", "MainWindow.xaml.cs", "MainForm.cs")

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "obj", "bin", ".idea", ".vscode", "target",
    # 不要去探测 SDK 自己刚被拷进去的目录
    "vendor",
}


def is_placeholder(value) -> bool:
    return isinstance(value, str) and "REPLACE_WITH" in value


def _deep_merge(base: dict, override: dict) -> dict:
    """override 覆盖 base；`_` 开头的说明字段不参与合并。"""
    out = dict(base)
    for key, val in override.items():
        if key.startswith("_"):
            continue
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def config_path() -> Path:
    """本地真实配置优先，其次才是仓库里的占位模板。"""
    return CONFIG_LOCAL if CONFIG_LOCAL.exists() else CONFIG


def load_config() -> dict:
    """`config.json` 提供默认值，`config.local.json` 里的字段覆盖它。"""
    base = json.loads(CONFIG.read_text(encoding="utf-8")) if CONFIG.exists() else {}
    if CONFIG_LOCAL.exists():
        base = _deep_merge(base, json.loads(CONFIG_LOCAL.read_text(encoding="utf-8")))
    if not base:
        sys.exit(f"找不到配置：{CONFIG_LOCAL} 与 {CONFIG} 都不存在")

    if is_placeholder(base.get("server_url")):
        sys.exit(
            f"部署配置尚未填写（{config_path()}）\n"
            "  · 请填好 server_url / admin_url / public_keys，或\n"
            "  · 在 Skill 目录新建 config.local.json 只覆盖需要的字段"
            "（已加入 .gitignore，不会误提交）\n"
            "  这些值怎么拿：见仓库 README 的「AI Skill」一节。"
        )
    return base


def detect_langs(project: Path) -> list[str]:
    """返回按可能性排序的语言列表。"""
    scores = {"python": 0, "node": 0, "dotnet": 0}
    for name in PY_MARKERS:
        if (project / name).exists():
            scores["python"] += 3
    if (project / "package.json").exists():
        scores["node"] += 3
    if (project / "tsconfig.json").exists():
        scores["node"] += 1
    for p in project.iterdir():
        if p.name in SKIP_DIRS:
            continue
        if p.suffix == ".csproj" or p.suffix == ".sln":
            scores["dotnet"] += 3
    # 按扩展名粗数
    exts = {".py": "python", ".js": "node", ".ts": "node", ".cs": "dotnet"}
    counts = {"python": 0, "node": 0, "dotnet": 0}
    for root, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            lang = exts.get(Path(f).suffix)
            if lang:
                counts[lang] += 1
    for lang, c in counts.items():
        if c:
            scores[lang] += min(c, 10) / 10.0
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    return [lang for lang, s in ranked if s > 0] or ["python"]


def find_entries(project: Path, lang: str) -> list[Path]:
    names = {"python": PY_ENTRIES, "node": NODE_ENTRIES, "dotnet": DOTNET_ENTRIES}[lang]
    found: list[Path] = []
    for root, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        depth = len(Path(root).relative_to(project).parts)
        if depth > 3:
            dirs[:] = []
            continue
        for f in files:
            if f in names:
                found.append(Path(root) / f)
    # 顶层优先
    found.sort(key=lambda p: (len(p.relative_to(project).parts), str(p)))
    return found[:8]


def vendor_dir(project: Path, vendor_name: str) -> Path:
    return project / vendor_name


def copy_sdk(project: Path, lang: str, vendor_name: str, force: bool) -> Path:
    """把 SDK 拷进项目。

    注意 Python 的坑：如果放进 vendor/license_guard/license_guard.py，
    那么 `import license_guard` 会命中同名**目录**（namespace package）而不是模块。
    所以 Python 直接放 vendor/license_guard.py，导入才正常。
    """
    src = ASSETS / lang
    if not src.exists():
        sys.exit(f"Skill 中缺少 {lang} 的 SDK：{src}")
    root = vendor_dir(project, vendor_name)
    root.mkdir(parents=True, exist_ok=True)

    if lang == "python":
        dst_file = root / "license_guard.py"
        if dst_file.exists() and not force:
            print(f"  · 目标已存在，跳过拷贝（--force 可覆盖）：{dst_file}")
            return dst_file
        shutil.copy2(src / "license_guard.py", dst_file)
        print(f"  · 已拷贝 SDK -> {dst_file}")
        return dst_file

    dst = root / {"node": "license-guard", "dotnet": "LicenseGuard"}[lang]
    if dst.exists() and not force:
        print(f"  · 目标已存在，跳过拷贝（--force 可覆盖）：{dst}")
        return dst
    dst.mkdir(parents=True, exist_ok=True)
    for f in src.iterdir():
        if f.is_file():
            shutil.copy2(f, dst / f.name)
    print(f"  · 已拷贝 SDK -> {dst}")
    return dst


def write_constants(project: Path, lang: str, app_id: str, cfg: dict, force: bool) -> Path:
    url = cfg["server_url"]
    alg = cfg.get("default_sign_alg", "ed25519")
    pks = cfg.get("public_keys") or {}
    pk_raw = (pks.get("ed25519") or {}).get("raw_b64url", "")
    pk_es = (pks.get("es256") or {}).get("spki_b64", "")
    d = cfg.get("defaults", {})
    fail_mode = d.get("fail_mode", "hard")
    exit_code = d.get("exit_code", 0)

    if lang == "dotnet":
        if not pk_es or is_placeholder(pk_es):
            sys.exit(
                "部署配置里缺少 es256 公钥（spki_b64）。\n"
                "C#/.NET 没有内置 Ed25519，必须用 ES256 —— 同时记得把后台产品的签名算法设成 es256。"
            )
    elif not pk_raw or is_placeholder(pk_raw):
        sys.exit("部署配置里缺少 ed25519 公钥（raw_b64url）。")

    if lang == "python":
        path = project / "license_config.py"
        body = f'''"""license-guard 接入配置 —— 由 Skill 自动生成，直接 import 即可。"""

SERVER_URL = "{url}"
APP_ID     = "{app_id}"
SIGN_ALG   = "{alg}"

# ed25519 用 raw base64url 公钥
PUBLIC_KEY = "{pk_raw}"

# 兜底策略：后端连不上时才生效，正常情况下后端会下发并覆盖它
FAIL_MODE  = "{fail_mode}"      # "hard" 静默退出 / "message" 提示后退出
EXIT_CODE  = {exit_code}
'''
    elif lang == "node":
        path = project / "license-config.js"
        body = f'''// license-guard 接入配置 —— 由 Skill 自动生成
export const LICENSE_CONFIG = {{
  serverUrl : "{url}",
  appId     : "{app_id}",
  signAlg   : "{alg}",
  // ed25519 用 raw base64url 公钥
  publicKey : "{pk_raw}",
  failMode  : "{fail_mode}",
  exitCode  : {exit_code},
}};
'''
    else:
        path = project / "LicenseConfig.cs"
        body = f'''// license-guard 接入配置 —— 由 Skill 自动生成
namespace LicenseGuard;

public static class LicenseConfig
{{
    public const string ServerUrl = "{url}";
    public const string AppId     = "{app_id}";
    // ⚠️ .NET 没有内置 Ed25519，必须用 ES256 公钥（产品 sign_alg 也要设成 es256）
    public const string PublicKey = "{pk_es}";
}}
'''
    if path.exists() and not force:
        print(f"  · 配置已存在，未覆盖（--force 可覆盖）：{path}")
        return path
    path.write_text(body, encoding="utf-8", newline="\n")
    print(f"  · 已生成配置 -> {path}")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description="把 license-guard SDK 装进目标项目")
    ap.add_argument("project_dir", help="目标项目根目录")
    ap.add_argument("--lang", choices=["auto", "python", "node", "dotnet"], default="auto")
    ap.add_argument("--app-id", help="已建好的产品 app_id；不填则留 TODO")
    ap.add_argument("--vendor", default="vendor", help="SDK 拷贝到的子目录（默认 vendor）")
    ap.add_argument("--force", action="store_true", help="覆盖已存在的文件")
    args = ap.parse_args()

    project = Path(args.project_dir).expanduser().resolve()
    if not project.is_dir():
        sys.exit(f"目录不存在：{project}")

    cfg = load_config()

    print(f"目标项目：{project}")
    if args.lang == "auto":
        ranked = detect_langs(project)
        lang = ranked[0]
        print(f"语言探测：{'、'.join(ranked)}  ->  选用 {lang}")
    else:
        lang = args.lang

    app_id = args.app_id or "TODO_REPLACE_WITH_APP_ID"
    print("执行：")
    copy_sdk(project, lang, args.vendor, args.force)
    const_path = write_constants(project, lang, app_id, cfg, args.force)

    print("\n可能的程序入口（把守卫插在这些文件的最开头）：")
    entries = find_entries(project, lang)
    if entries:
        for e in entries:
            print(f"  - {e.relative_to(project)}")
    else:
        print("  （没找到常见入口名，需要人工确认）")

    print("\n下一步：")
    print("  1. 在项目开头调用 guard.authorize() + guard.start_watchdog()")
    print(f"     —— 具体写法见 {SKILL_ROOT / 'references' / 'integration.md'}")
    if app_id.startswith("TODO"):
        print("  2. ⚠️ 还没有 app_id：先去后台建产品，然后回填 --app-id 重跑本脚本")
        print(f"     后台地址：{cfg['admin_url']}")
    else:
        print(f"  2. 在后台为该产品签发授权码：{cfg['admin_url']}")
    print(f"  3. 自检：python {Path(__file__).name.replace('install_sdk', 'selfcheck')} --app-id {app_id}")
    print(f"\n配置常量文件：{const_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
