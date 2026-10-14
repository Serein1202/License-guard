#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selfcheck.py —— 校验本 Skill 的配置与线上 Worker 是否真的对得上。

做三件事（都不消耗设备位）：
  1. 连通性  GET /health                          -> 确认 server_url 正确、Worker 活着
  2. 产品    GET /v1/meta?app_id=                 -> 确认 app_id 拼写正确、看后端下发的策略
  3. 公钥    GET /v1/time?app_id= + 验签          -> **确认内嵌公钥与服务端私钥是同一对**

第 3 步是关键：/v1/time 会返回一个用产品私钥签名的令牌，
用 config.json 里的公钥去验它——验过了就说明整条信任链是通的。
不需要授权码，也不占用任何设备位。

用法：
  python selfcheck.py                       # 只做连通性
  python selfcheck.py --app-id mytool       # 连通性 + 产品 + 公钥验签
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Windows 控制台默认可能不是 UTF-8，输出中文会乱码
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

SKILL_ROOT = Path(__file__).resolve().parent.parent
CONFIG = SKILL_ROOT / "config.json"
# 本地真实配置优先于仓库里的占位模板（config.local.json 已加入 .gitignore）
CONFIG_LOCAL = SKILL_ROOT / "config.local.json"
SDK_PY = SKILL_ROOT / "assets" / "clients" / "python" / "license_guard.py"

OK = "[OK]"
FAIL = "[!!]"
WARN = "[--]"


def load_sdk():
    """从 Skill 的 assets 里动态加载 Python SDK（含纯 Python 的 Ed25519/ES256 验签）。"""
    spec = importlib.util.spec_from_file_location("_lg_sdk", SDK_PY)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载 SDK：{SDK_PY}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def http_json(url: str, method: str = "GET", payload: dict | None = None, timeout: int = 12):
    """返回 (status, body_dict_or_text)。网络层异常直接抛出。"""
    data = None
    headers = {"Accept": "application/json", "User-Agent": "license-guard-selfcheck/1.0"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


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


def pick_pubkey(cfg: dict, alg: str) -> str | None:
    alg = (alg or "ed25519").lower()
    if alg == "es256":
        pk = cfg.get("public_keys", {}).get("es256", {}).get("spki_b64")
    else:
        pk = cfg.get("public_keys", {}).get("ed25519", {}).get("raw_b64url")
    return None if is_placeholder(pk) else pk


def main() -> int:
    ap = argparse.ArgumentParser(description="校验 license-guard 配置与线上 Worker")
    ap.add_argument("--app-id", help="要校验的产品 app_id（可选）")
    ap.add_argument("--timeout", type=int, default=12)
    args = ap.parse_args()

    cfg = json.loads(CONFIG.read_text(encoding="utf-8")) if CONFIG.exists() else {}
    if CONFIG_LOCAL.exists():
        cfg = _deep_merge(cfg, json.loads(CONFIG_LOCAL.read_text(encoding="utf-8")))

    if not cfg:
        print(f"{FAIL} 找不到配置：{CONFIG_LOCAL} 与 {CONFIG} 都不存在")
        return 2

    cfg_path = CONFIG_LOCAL if CONFIG_LOCAL.exists() else CONFIG
    if is_placeholder(cfg.get("server_url")):
        print(f"{FAIL} 部署配置尚未填写：{cfg_path}")
        print("     · 填好 server_url / admin_url / public_keys，或")
        print("     · 新建 config.local.json 只覆盖需要的字段（已加入 .gitignore）")
        return 2

    base = cfg["server_url"].rstrip("/")

    print(f"Skill 配置：{cfg_path}")
    print(f"服务地址  ：{base}")
    print()

    failures = 0

    # ---------- 1. 连通性 ----------
    print("[1/3] 连通性检查  GET /health")
    health = None
    try:
        status, body = http_json(f"{base}/health", timeout=args.timeout)
        if status == 200 and isinstance(body, dict) and body.get("service") == "license-guard":
            health = body
            print(f"  {OK} Worker 在线，服务端时间 {body.get('time')}")
        else:
            failures += 1
            print(f"  {FAIL} 响应异常：HTTP {status}  {str(body)[:200]}")
    except Exception as e:
        failures += 1
        print(f"  {FAIL} 连不上：{type(e).__name__}: {e}")
        print("      · 若本机在中国内地，workers.dev 常被 DNS 污染/阻断，这是网络问题不是配置问题")
        print("      · 换网络或用代理再试；客户端侧若也连不上，需要绑自定义域名")

    # ---------- 2. 产品 + 3. 公钥 ----------
    if args.app_id:
        print(f"\n[2/3] 产品检查  GET /v1/meta?app_id={args.app_id}")
        alg = cfg.get("default_sign_alg", "ed25519")
        try:
            status, body = http_json(f"{base}/v1/meta?app_id={args.app_id}", timeout=args.timeout)
            if status == 200 and isinstance(body, dict):
                alg = body.get("sign_alg", alg)
                print(f"  {OK} 产品存在：{body.get('name')}  签名算法={alg}")
                print(f"      后端策略：{json.dumps(body.get('policy', {}), ensure_ascii=False)}")
            elif status == 404:
                failures += 1
                print(f"  {FAIL} 该 app_id 不存在（APP_UNKNOWN）—— 检查拼写，或先在后台建这个产品")
                print(f"      后台：{cfg.get('admin_url')}")
            else:
                failures += 1
                print(f"  {FAIL} 响应异常：HTTP {status}  {str(body)[:200]}")
        except Exception as e:
            failures += 1
            print(f"  {FAIL} 请求失败：{type(e).__name__}: {e}")

        print(f"\n[3/3] 公钥验签  GET /v1/time?app_id={args.app_id}")
        try:
            status, body = http_json(f"{base}/v1/time?app_id={args.app_id}", timeout=args.timeout)
            if status == 200 and isinstance(body, dict) and body.get("token"):
                alg = body.get("sign_alg", alg)
                pk = pick_pubkey(cfg, alg)
                if not pk:
                    failures += 1
                    print(f"  {FAIL} 部署配置里没有 {alg} 的公钥（或仍是占位符）")
                else:
                    sdk = load_sdk()
                    try:
                        payload = sdk._Token.verify(body["token"], pk, alg)
                        print(f"  {OK} 公钥与服务端私钥匹配（算法 {alg}）")
                        print(f"      令牌载荷：{json.dumps(payload, ensure_ascii=False)}")
                        print("      -> 内嵌到客户端的就是这把公钥，可以放心接入")
                    except Exception as e:
                        failures += 1
                        print(f"  {FAIL} 验签失败：{e}")
                        print("      -> 说明部署配置里的公钥与线上服务端的私钥不是同一对！")
                        print("         客户端接入后会出现 BAD_SIGNATURE，务必先修正公钥")
            else:
                failures += 1
                print(f"  {FAIL} 响应异常：HTTP {status}  {str(body)[:200]}")
        except Exception as e:
            failures += 1
            print(f"  {FAIL} 请求失败：{type(e).__name__}: {e}")
    else:
        print("\n[2/3] 产品检查  已跳过（未传 --app-id）")
        print("[3/3] 公钥验签  已跳过（未传 --app-id）")

    print()
    if failures == 0:
        print(f"{OK} 全部通过。配置可用，可以放心接入新项目。")
        return 0
    print(f"{FAIL} 有 {failures} 项未通过，见上面的提示。")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
