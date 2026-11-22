// Runs the step-2 checks alone, against an install from `RV_E2E_SETUP_ONLY=1 bash scripts/e2e.sh`.
import { execSync } from "node:child_process";
import crypto from "node:crypto";
import { runAccounts } from "./e2e_accounts.mjs";
import { runSetupImport } from "./e2e_setup_import.mjs";
const BASE = "https://localhost:8443", DIR = new URL("../deploy/compose/", import.meta.url).pathname;
const COMPOSE = "docker compose -f docker-compose.yml -f docker-compose.e2e.yml --profile logs --profile ai --profile proxy --profile adapters --profile files";
const sh = (c) => execSync(c, { cwd: DIR, encoding: "utf8", maxBuffer: 1 << 28, stdio: ["ignore", "pipe", "pipe"] });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let passed = 0; const failures = [];
const check = (n, ok, d = "") => { if (ok) { passed++; console.log(`  ok    ${n}`); } else { failures.push(n); console.log(`  FAIL  ${n} ${String(d).slice(0, 300)}`); } };
const section = (s) => console.log(`\n${s}`);
async function req(path, { method, body, token } = {}) {
  const res = await fetch(BASE + path, { method: method ?? (body !== undefined ? "POST" : "GET"), headers: { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text };
}
const control = (p, o) => req(`/control${p}`, o);
const data = (p, o) => req(p, o);
const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const b32 = (s) => { let b = 0, v = 0; const o = []; for (const c of s) { v = (v << 5) | A.indexOf(c); b += 5; if (b >= 8) { o.push((v >>> (b - 8)) & 255); b -= 8; v &= (1 << b) - 1; } } return Buffer.from(o); };
const totp = (s, off = 0) => { const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + off)); const m = crypto.createHmac("sha1", b32(s)).update(c).digest(); return String((m.readUInt32BE(m[m.length - 1] & 15) & 0x7fffffff) % 1e6).padStart(6, "0"); };
const u = crypto.randomBytes(3).toString("hex"), adminEmail = `root-${u}@e2e.example.ng`, pw = `root-${crypto.randomBytes(9).toString("hex")}`;
const boot = process.argv[2];
await control("/v1/bootstrap", { body: { bootstrap_token: boot, organisation: "E2E Org", display_name: "Root Admin", email: adminEmail, password: pw } });
const e = await control("/v1/auth/login", { body: { email: adminEmail, password: pw } });
const ADMIN = (await control("/v1/auth/login", { body: { email: adminEmail, password: pw, totp: totp(e.json.secret) } })).json.access_token;
const r = await control("/v1/principals", { token: ADMIN, body: { kind: "user", display_name: "Eng Other", email: `eng-${u}@e2e.example.ng`, roles: ["engineer"] } });
const f = await control("/v1/auth/login", { body: { email: `eng-${u}@e2e.example.ng`, password: r.json.temporary_password } });
const OTHER = (await control("/v1/auth/login", { body: { email: `eng-${u}@e2e.example.ng`, password: r.json.temporary_password, totp: totp(f.json.secret), new_password: `own-${crypto.randomBytes(9).toString("hex")}` } })).json.access_token;
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const only = process.argv[3];
if (only !== "setup") await runAccounts({ control, check, section, totp, sleep, sh, COMPOSE, adminToken: () => ADMIN, adminEmail, otherToken: () => OTHER });
if (only !== "accounts") await runSetupImport({ control, data, check, section, sleep, sh, COMPOSE, adminToken: () => ADMIN, otherToken: () => OTHER, root: new URL("../", import.meta.url).pathname });
console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) { console.log(failures.join("\n")); process.exit(1); }
