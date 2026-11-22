// Sets up a vault on a fresh install, then runs the iOS test host on a simulator against it.
// Every identifier is synthetic. Started by scripts/test-ios-sim.sh.
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";

const BASE = "https://localhost:8443";
const { VaultClient } = await import(process.env.RV_E2E_SDK);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const { RV_IOS_PROJECT: PROJECT, RV_IOS_RESULT: RESULT, RV_IOS_DERIVED: DERIVED, RV_IOS_DEVICE: DEVICE } = process.env;

async function req(path, { method, body, token } = {}) {
  const res = await fetch(BASE + path, { method: method ?? (body !== undefined ? "POST" : "GET"), headers: { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  if (res.status >= 400) throw new Error(`${path}: ${res.status} ${text}`);
  return json;
}
const control = (p, o) => req(`/control${p}`, o);

const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function totp(secret) {
  let bits = 0, val = 0; const key = [];
  for (const c of secret) { val = (val << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { key.push((val >>> (bits - 8)) & 255); bits -= 8; val &= (1 << bits) - 1; } }
  const t = Buffer.alloc(8); t.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const m = crypto.createHmac("sha1", Buffer.from(key)).update(t).digest();
  return String((m.readUInt32BE(m[m.length - 1] & 15) & 0x7fffffff) % 1000000).padStart(6, "0");
}
async function login(email, password, newPassword) {
  const first = await control("/v1/auth/login", { body: { email, password } });
  const done = await control("/v1/auth/login", { body: { email, password, totp: totp(first.secret), ...(newPassword ? { new_password: newPassword } : {}) } });
  return done.access_token;
}

const APP = "rvapp://ng.onshore.testhost";
const VALUE = "22777766654", REVEAL = "0456789013";
// The test identities are kept with the run's results, so a rerun can skip the install.
let saved = fs.existsSync(process.env.RV_IOS_SETUP) ? JSON.parse(fs.readFileSync(process.env.RV_IOS_SETUP, "utf8")) : null;
if (!saved) {
  const boot = { organisation: "iOS Test", display_name: "Ada Admin", email: "ada@ios.example.ng", password: "correct-horse-battery-1" };
  await control("/v1/bootstrap", { body: { ...boot, bootstrap_token: process.env.RV_E2E_BOOTSTRAP } });
  const ADMIN = await login(boot.email, boot.password);
  const V = (await control("/v1/vaults", { token: ADMIN, body: { name: "Production", environment: "production", template: "wallet_psp" } })).id;
  const second = await control("/v1/principals", { token: ADMIN, body: { kind: "user", display_name: "Bola Second", email: "bola@ios.example.ng", roles: ["admin"] } });
  const BOLA = await login("bola@ios.example.ng", second.temporary_password, `own-${crypto.randomBytes(9).toString("hex")}`);
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const sa = await control("/v1/principals", { token: ADMIN, body: { kind: "service_account", display_name: "Backend", roles: ["backend_service"], public_key: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64") } });
  await control(`/v1/vaults/${V}/embed`, { token: ADMIN, method: "PATCH", body: { origins: [APP] } });
  const pol = await control("/v1/policies", { token: ADMIN, body: { name: "ios-reveal", source: { rules: [{ id: "acct", actions: ["detokenize"], who: { roles: ["backend_service"] }, what: { data_types: ["nuban"] }, when: { purpose_required: true }, returns: "plaintext" }] } } });
  await control(`/v1/policies/${pol.id}/publish`, { token: BOLA, method: "POST" });
  await sleep(6000);
  saved = { V, id: sa.id, keyId: sa.key_id, seed: privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("base64") };
  fs.writeFileSync(process.env.RV_IOS_SETUP, JSON.stringify(saved), { mode: 0o600 });
}
const V = saved.V;
const sdk = new VaultClient({ baseUrl: BASE, serviceAccountId: saved.id, keyId: saved.keyId, privateKey: saved.seed });
const [acct, bvn] = await sdk.tokenize(V, [{ field: "account_number", value: REVEAL }, { field: "bvn", value: "22777766655" }]);
const bearer = await sdk.bearer();
const mint = async (b) => (await req(`/v1/vaults/${V}/client-tokens`, { token: bearer, body: { origin: APP, ttl_seconds: 600, ...b } })).client_token;
const collect = (ref, fields = ["bvn"]) => mint({ kind: "collect", fields, subject_ref: `cust_ios_${ref}` });
const reveal = (token) => mint({ kind: "reveal", tokens: [token.token], purpose: "ios test" });

const destination = `id=${DEVICE}`;
const common = ["-project", PROJECT, "-scheme", "RVTestHost", "-destination", destination, "-derivedDataPath", DERIVED, "-jobs", "2"];
const xcode = (args, env = {}) => execFileSync("caffeinate", ["-i", "xcodebuild", ...args], { encoding: "utf8", maxBuffer: 1 << 28, stdio: ["ignore", "pipe", "pipe"], timeout: 1200000, env: { ...process.env, ...env } });

let build = "";
try { build = xcode(["build-for-testing", ...common]); } catch (e) { console.log(`${e.stdout ?? ""}`.split("\n").filter((l) => /error:|BUILD|\*\*/.test(l)).join("\n")); throw new Error("the test host did not build"); }
console.log(build.split("\n").filter((l) => /warning: .*Onshore|\*\* /.test(l)).join("\n"));

// Tokens are short lived, so they are minted after the build, as close to the run as they can be.
const tokens = {
  RV_BASE: BASE, RV_APP_ORIGIN: APP, RV_VALUE: VALUE, RV_REVEAL_VALUE: REVEAL,
  RV_COLLECT: await collect("form"), RV_TRAITS: await collect("traits", ["bvn", "email"]), RV_COVER: await collect("cover"), RV_CLIENT: await collect("client"),
  RV_REVEAL_TIMED: await reveal(acct), RV_REVEAL_BG: await reveal(acct), RV_DENIED: await reveal(bvn),
};
const testEnv = Object.fromEntries(Object.entries(tokens).map(([k, v]) => [`TEST_RUNNER_${k}`, v]));
let out = "", ok = true;
try { out = xcode(["test-without-building", ...common, "-resultBundlePath", RESULT, "-parallel-testing-enabled", "NO", ...(process.env.RV_IOS_ONLY ? [`-only-testing:RVTestHostUITests/SDKUITests/${process.env.RV_IOS_ONLY}`] : [])], testEnv); } catch (e) { out = `${e.stdout ?? ""}\n${e.stderr ?? ""}`; ok = false; }
console.log(out.split("\n").filter((l) => /Test Case .*(passed|failed)|error:|RV_TRAITS_READ|\*\* TEST|Executed \d+ test/.test(l)).join("\n"));
process.exit(ok ? 0 : 1);
