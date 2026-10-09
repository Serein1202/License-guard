#!/usr/bin/env node
/**
 * 生成授权签名密钥对，并打印需要配置的内容。
 *
 *   node scripts/gen-keys.mjs
 *
 * 输出：
 *   · Worker 端要写入的 secret（LICENSE_KEY_ED25519 / LICENSE_KEY_ES256）
 *   · 客户端要内嵌的公钥
 *   · keys.json（本地留存，切勿提交到仓库）
 *
 *   wrangler secret put LICENSE_KEY_ED25519
 *   wrangler secret put LICENSE_KEY_ES256
 */
import { generateKeyPairSync, createHash, randomBytes } from "node:crypto";
import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64 = (buf) => buf.toString("base64");

/* ---------------------------- Ed25519 ---------------------------- */
const ed = generateKeyPairSync("ed25519");
const edPrivDer = ed.privateKey.export({ type: "pkcs8", format: "der" });
const edPubDer = ed.publicKey.export({ type: "spki", format: "der" });
// SPKI 尾部 32 字节即 Ed25519 raw 公钥
const edPubRaw = edPubDer.subarray(edPubDer.length - 32);
const edFingerprint = b64url(createHash("sha256").update(edPubRaw).digest().subarray(0, 16));

/* --------------------------- ECDSA P-256 -------------------------- */
const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const ecPrivDer = ec.privateKey.export({ type: "pkcs8", format: "der" });
const ecPubDer = ec.publicKey.export({ type: "spki", format: "der" });

/* ------------------------------ 输出 ------------------------------ */
const out = {
  generated_at: new Date().toISOString(),
  ed25519: {
    secret_pkcs8_b64url: b64url(edPrivDer),
    secret_pkcs8_b64: b64(edPrivDer),
    public_raw_b64url: b64url(edPubRaw),
    public_spki_b64: b64(edPubDer),
    fingerprint: edFingerprint,
  },
  es256: {
    secret_pkcs8_b64url: b64url(ecPrivDer),
    public_spki_b64: b64(ecPubDer),
  },
};

const banner = (t) => `\n${"=".repeat(64)}\n  ${t}\n${"=".repeat(64)}`;

console.log(banner("1) Worker 端密钥（用 wrangler secret put 写入，不要提交到 Git）"));
console.log(`\n# Ed25519 —— 推荐，令牌短、验签快`);
console.log(`LICENSE_KEY_ED25519=${b64url(edPrivDer)}`);
console.log(`\n# ECDSA P-256 —— C# / .NET 客户端用这个（.NET 无内置 Ed25519）`);
console.log(`LICENSE_KEY_ES256=${b64url(ecPrivDer)}`);

console.log(banner("2) 客户端内嵌的公钥（可以公开）"));
console.log(`\n# Python / Node (Ed25519)`);
console.log(`PUBLIC_KEY_ED25519_B64URL=${b64url(edPubRaw)}`);
console.log(`\n# C# / .NET (ES256, SPKI base64)`);
console.log(`PUBLIC_KEY_ES256_SPKI_B64=${b64(ecPubDer)}`);

// 随机生成管理后台口令（绝不要用固定默认值 —— 公开仓库里的默认口令等于没有口令）
const adminToken = randomBytes(24).toString("base64url");

console.log(banner("3) 管理后台口令（随机生成，仅用于本地 wrangler dev）"));
console.log(`\nADMIN_TOKEN=${adminToken}`);
console.log(`\n# 上线时务必换成自己的强口令：wrangler secret put ADMIN_TOKEN`);

console.log(banner("4) 下一步"));
console.log(`
  wrangler secret put ADMIN_TOKEN
  wrangler secret put LICENSE_KEY_ED25519
  wrangler secret put LICENSE_KEY_ES256
  wrangler deploy
`);

const outPath = join(root, "keys.json");
if (!existsSync(root)) mkdirSync(root, { recursive: true });
writeFileSync(outPath, JSON.stringify(out, null, 2), { mode: 0o600 });

// 顺便写好本地开发用的 .dev.vars（wrangler dev 会自动读取）
const devVarsPath = join(root, ".dev.vars");
writeFileSync(
  devVarsPath,
  [
    "# 本地开发专用（wrangler dev 自动读取）—— 已加入 .gitignore，不要提交",
    "# 口令为本次随机生成，上线时请用: wrangler secret put ADMIN_TOKEN",
    "ADMIN_TOKEN=" + adminToken,
    "LICENSE_KEY_ED25519=" + b64url(edPrivDer),
    "LICENSE_KEY_ES256=" + b64url(ecPrivDer),
    "",
  ].join("\n"),
  { mode: 0o600 },
);

console.log(`密钥已保存到: ${outPath}  ← 请勿提交到仓库！`);
console.log(`本地开发变量已写入: ${devVarsPath}`);
console.log(`管理口令（本地开发用）: ${adminToken}\n`);
