// Fills a fresh local install with synthetic data, for looking around the console.
// Every identifier is made up. Writes the sign-in details to the file named by RV_DEMO_LOGIN,
// readable only by you. Never run this against an install that holds real data.
import crypto from "node:crypto";
import { execSync } from "node:child_process";
import fs from "node:fs";

const BASE = process.env.RV_BASE ?? "https://localhost:8443";
const { VaultClient } = await import(process.env.RV_E2E_SDK);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function req(path, { method, body, token } = {}) {
  const res = await fetch(BASE + path, { method: method ?? (body !== undefined ? "POST" : "GET"), headers: { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  if (res.status >= 400) throw new Error(`${path}: ${res.status} ${text.slice(0, 300)}`);
  return json;
}
const control = (p, o) => req(`/control${p}`, o);
const step = async (name, f) => { try { const r = await f(); console.log(`  ok    ${name}`); return r; } catch (e) { console.log(`  SKIP  ${name}: ${e.message}`); return null; } };

const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function totp(secret) {
  let bits = 0, val = 0; const key = [];
  for (const c of secret) { val = (val << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { key.push((val >>> (bits - 8)) & 255); bits -= 8; val &= (1 << bits) - 1; } }
  const t = Buffer.alloc(8); t.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const m = crypto.createHmac("sha1", Buffer.from(key)).update(t).digest();
  return String((m.readUInt32BE(m[m.length - 1] & 15) & 0x7fffffff) % 1000000).padStart(6, "0");
}
const secrets = {};
async function login(email, password, newPassword) {
  const first = await control("/v1/auth/login", { body: { email, password } });
  secrets[email] = first.secret;
  const done = await control("/v1/auth/login", { body: { email, password, totp: totp(first.secret), ...(newPassword ? { new_password: newPassword } : {}) } });
  return done.access_token;
}

const adminPassword = `seed-${crypto.randomBytes(12).toString("hex")}`;
await control("/v1/bootstrap", { body: { organisation: "Demo Fintech", display_name: "Ada Seed", email: "ada@demo.example.ng", password: adminPassword, bootstrap_token: process.env.RV_E2E_BOOTSTRAP } });
const ADMIN = await login("ada@demo.example.ng", adminPassword);
const second = await control("/v1/principals", { token: ADMIN, body: { kind: "user", display_name: "Bola Seed", email: "bola@demo.example.ng", roles: ["admin"] } });
const BOLA = await login("bola@demo.example.ng", second.temporary_password, `own-${crypto.randomBytes(9).toString("hex")}`);
const you = await control("/v1/principals", { token: ADMIN, body: { kind: "user", display_name: "Demo Admin", email: "demo@demo.example.ng", roles: ["admin"] } });

const sandbox = await step("sandbox vault with 25 synthetic records", () => control("/v1/vaults", { token: ADMIN, body: { name: "Sandbox", environment: "sandbox", template: "wallet_psp", seed: true } }));
const prod = await control("/v1/vaults", { token: ADMIN, body: { name: "Wallet (demo data)", environment: "production", template: "wallet_psp" } });
const V = prod.id;

await step("published policies", async () => {
  const p = await control("/v1/policies", { token: ADMIN, body: { name: "support-agents-nigeria", source: { limit_per_hour: 30, rules: [
    { id: "mask-ids", actions: ["detokenize"], who: { roles: ["support_agent"] }, what: { data_types: ["bvn", "nuban"] }, when: { purpose_required: true }, returns: "masked" },
    { id: "backend-accounts", actions: ["detokenize"], who: { roles: ["backend_service"] }, what: { data_types: ["nuban"] }, when: { purpose_required: true }, returns: "plaintext" },
  ] } } });
  await control(`/v1/policies/${p.id}/publish`, { token: BOLA, method: "POST" });
  await sleep(6000);
});

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const sa = await control("/v1/principals", { token: ADMIN, body: { kind: "service_account", display_name: "Payments backend", roles: ["backend_service"], public_key: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64") } });
const sdk = new VaultClient({ baseUrl: BASE, serviceAccountId: sa.id, keyId: sa.key_id, privateKey: privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("base64") });

await step("tokenized customers, and reveals for the audit log", async () => {
  const names = ["Chidinma Okonkwo", "Tunde Bakare", "Amina Yusuf", "Emeka Obi", "Funke Adeyemi", "Ibrahim Musa"];
  const accounts = [];
  for (let i = 0; i < names.length; i++) {
    const ref = `cust_demo_${i + 1}`;
    const r = await sdk.tokenize(V, [
      { field: "bvn", value: `2298765${String(1000 + i * 7)}`, subject_ref: ref },
      { field: "full_name", value: names[i], subject_ref: ref },
      { field: "phone", value: `0803999${String(1000 + i)}`, subject_ref: ref },
      { field: "email", value: `customer${i + 1}@example.ng`, subject_ref: ref },
    ]);
    if (!r.every((t) => t.token)) throw new Error("a value was refused");
    const [acct] = await sdk.tokenize(V, [{ field: "account_number", value: "0456789013", subject_ref: ref }]);
    accounts.push(acct.token);
  }
  await sdk.detokenize(V, accounts.slice(0, 3), "repayment support");
});

const samples = (yes, no) => [...yes.map((sample) => ({ sample, expect_match: true })), ...no.map((sample) => ({ sample, expect_match: false }))];
const entity = (spec, status) => step(`custom entity: ${spec.name} (${status})`, async () => {
  const ce = (p, o) => control(`/v1/vaults/${V}/custom-entities${p}`, o);
  const c = await ce("", { token: ADMIN, body: spec });
  const r = await ce(`/${c.id}/publish-requests`, { token: ADMIN, body: {} });
  await control(`/v1/publish-requests/${r.id}/approve`, { token: BOLA, method: "POST" });
  if (status === "enforcing") await ce(`/${c.id}/status`, { token: ADMIN, body: { status } });
});
await step("custom entities turned on", () => control(`/v1/vaults/${V}/detection`, { token: ADMIN, method: "PATCH", body: { enabled: true } }));
await entity({ name: "Loan ID", slug: "c_loan_id", kind: "pattern", definition: { regex: "LN-\\d{8}" }, validator: { type: "length", value: 11 }, context_positive: ["loan", "facility", "repayment"], actions: { api: "tokenize", logs: "tokenize", ai: "tokenize", proxy: "mask" }, tests: samples(["repayment on LN-00412873 is late", "facility LN-11112222 approved", "see LN-33334444"], ["invoice INV-00412873 paid", "LN-123", "nothing here"]) }, "enforcing");
await entity({ name: "Bare 11-digit reference", slug: "c_bare_ref", kind: "pattern", definition: { regex: "\\b\\d{11}\\b" }, context_positive: ["order", "ref", "ticket", "invoice"], threshold: 0.7, actions: {}, tests: samples(["order 22555566671", "support ticket 22555566671", "invoice: 22555566671"], ["the balance was 22555566671", "order 2255556667", "no number"]) }, "shadow");

await step("log pipeline", () => control("/v1/log-pipelines", { token: ADMIN, body: { vault_id: V, name: "Application logs", source_type: "otlp", destination: "Datadog", upstream_url: "http://host.docker.internal:18999" } }));
await step("AI gateway route", () => control("/v1/ai-routes", { token: ADMIN, body: { vault_id: V, name: "Support chatbot", provider: "mock", upstream_base_url: "http://host.docker.internal:18998/v1", allowed_models: ["gpt-test"], restore_in_response: true } }));
await step("proxy route", () => control("/v1/proxy-routes", { token: ADMIN, body: { vault_id: V, name: "CRM", method: "POST", path_pattern: "/crm/**", upstream_url: "http://host.docker.internal:18998", redact_paths: [{ path: "$.customer.bvn", field: "bvn" }], dlp: true } }));
await step("secure component origins", () => control(`/v1/vaults/${V}/embed`, { token: ADMIN, method: "PATCH", body: { origins: ["https://app.example.ng", "rvapp://ng.demo.wallet"] } }));

// The residency map: a mix of statuses, each reached through the real engine.
await step("residency map", async () => {
  const COMPOSE_DIR = process.env.RV_COMPOSE_DIR ?? "deploy/compose";
  const sql = (q) => execSync(`docker compose exec -T postgres psql -U rv rv -At -c "${q}"`, { cwd: COMPOSE_DIR, encoding: "utf8" }).trim();
  await control("/v1/map/settings", { token: ADMIN, method: "PATCH", body: { vault_id: V, enabled: true } });
  const logs = await control("/v1/log-pipelines", { token: ADMIN, body: { vault_id: V, name: "Payments logs", source_type: "otlp", destination: "Datadog", upstream_url: "https://http-intake.logs.datadoghq.eu" } });
  const mobile = await control("/v1/log-pipelines", { token: ADMIN, body: { vault_id: V, name: "Mobile app errors", source_type: "otlp", destination: "Sentry", upstream_url: "https://o4501.ingest.de.sentry.io" } });
  const bot = await control("/v1/ai-routes", { token: ADMIN, body: { vault_id: V, name: "Support copilot", provider: "openai", upstream_base_url: "https://api.openai.com/v1", allowed_models: ["gpt-test"] } });
  await control(`/v1/log-pipelines/${logs.id}`, { token: ADMIN, method: "PATCH", body: { mode: "enforcing" } });
  await control(`/v1/log-pipelines/${mobile.id}`, { token: ADMIN, method: "PATCH", body: { mode: "enforcing" } });
  const events = (id, module, host, rows) => rows.map(([ent, action, n]) => `INSERT INTO events.detection_events(occurred_at,vault_id,module,source_id,destination,dest_host,entity_type,action,count) SELECT date_trunc('hour',now())-(d||' days')::interval,'${V}','${module}','${id}','demo','${host}','${ent}','${action}',${n}+d*3 FROM generate_series(0,29) d ON CONFLICT DO NOTHING;`).join(" ");
  // Thirty days of made-up counts, ending eight days ago for what already passed unchanged.
  sql(events(logs.id, "logs", "http-intake.logs.datadoghq.eu", [["bvn", "tokenized", 410], ["nuban", "tokenized", 930], ["phone_ng", "masked", 210]]));
  sql(events(mobile.id, "logs", "o4501.ingest.de.sentry.io", [["phone_ng", "passed", 42], ["email", "passed", 60], ["nuban", "tokenized", 75]]));
  sql(events(bot.id, "ai", "api.openai.com", [["bvn", "shadow", 18], ["nuban", "shadow", 33], ["person_name", "shadow", 51]]));
  sql(`UPDATE control.systems SET route_mode_since=now()-interval '40 days' WHERE source_ref->>'id' IN ('${logs.id}','${mobile.id}')`);
  await control("/v1/map/settings", { token: ADMIN, method: "PATCH", body: { vault_id: V, enabled: true } });
  const flows = (await control(`/v1/map/flows?vault_id=${V}`, { token: ADMIN })).flows;
  const dd = flows.find((f) => f.dest.vendor === "Datadog");
  if (dd) await control(`/v1/map/systems/${dd.dest.system_id}/confirm-region`, { token: ADMIN, body: { region: "eu1" } });
  const oa = flows.find((f) => f.dest.vendor === "OpenAI");
  if (oa) await control(`/v1/map/systems/${oa.dest.system_id}/confirm-region`, { token: ADMIN, body: { region: "us" } });
  const me = (await control("/v1/me", { token: ADMIN })).id;
  const ledger = await control("/v1/map/systems", { token: ADMIN, body: { vault_id: V, name: "Core ledger", kind: "database", hosting_country: "NG", hosting_facility: "Lagos data centre", entity_types: ["bvn", "nuban", "amount_ngn"], owner_id: me } });
  const crm = await control("/v1/map/systems", { token: ADMIN, body: { vault_id: V, name: "Customer data warehouse", kind: "warehouse", hosting_country: "NG", entity_types: ["bvn", "email"], owner_id: me } });
  const vendors = (await control("/v1/map/vendors", { token: ADMIN })).vendors;
  const vendor = (n) => vendors.find((v) => v.name === n)?.id;
  const snow = await control("/v1/map/flows", { token: ADMIN, body: { source_system_id: ledger.id, dest_vendor_id: vendor("Snowflake"), dest_region: "aws-eu-west-1", entity_types: ["bvn", "nuban", "amount_ngn"], owner_id: me } });
  const due = new Date(Date.now() + 45 * 86400000).toISOString().slice(0, 10);
  await control(`/v1/map/flows/${snow.id}/actions`, { token: ADMIN, body: { plan: "route_via_proxy", description: "Send the nightly load through the Onshore proxy", owner_id: me, due_date: due } });
  await control("/v1/map/flows", { token: ADMIN, body: { source_system_id: ledger.id, dest_host: "dr.lagos.example.ng", dest_country: "NG", entity_types: ["bvn", "nuban"], owner_id: me } });
  await control("/v1/map/flows", { token: ADMIN, body: { source_system_id: crm.id, dest_vendor_id: vendor("Smile ID"), entity_types: ["bvn"], owner_id: me } });
  const fresh = await control("/v1/map/flows", { token: ADMIN, body: { source_system_id: crm.id, dest_vendor_id: vendor("Zendesk"), dest_region: "us", entity_types: ["email"], owner_id: me } });
  await control(`/v1/map/flows/${fresh.id}/exceptions`, { token: ADMIN, body: { reason: "The move to a Nigerian helpdesk is contracted for next quarter", compensating_controls: "Agents see email addresses masked", expires_at: new Date(Date.now() + 60 * 86400000).toISOString().slice(0, 10) } });
  // A score history, so the sparklines have something to show. Made up, like everything here.
  sql(`INSERT INTO control.map_scores_daily(vault_id,day,flow_score,flow_score_without_exceptions,volume_score) SELECT '${V}',current_date-d,greatest(0,28-d*0.4),greatest(0,28-d*0.4),greatest(0,88-d*0.6) FROM generate_series(1,60) d ON CONFLICT DO NOTHING`);
});

const count = async (p) => { const r = await control(p, { token: ADMIN }); const list = Array.isArray(r) ? r : r.items ?? r.data ?? r.results ?? r.entities ?? r.vaults ?? r.pipelines ?? r.routes ?? r.policies ?? []; return list.length; };
for (const [name, path] of [["vaults", "/v1/vaults"], ["policies", "/v1/policies"], ["custom entities", `/v1/vaults/${V}/custom-entities`], ["log pipelines", "/v1/log-pipelines"], ["AI routes", "/v1/ai-routes"], ["proxy routes", "/v1/proxy-routes"]]) console.log(`  read back ${name}: ${await count(path).catch((e) => e.message)}`);
fs.writeFileSync(process.env.RV_DEMO_LOGIN, `Local demo sign-in. Synthetic data only. Delete when done.\n\nAddress:            ${BASE}\nEmail:              demo@demo.example.ng\nTemporary password: ${you.temporary_password}\n\nYou choose your own password and scan a QR code with an authenticator app on first sign-in.\n`, { mode: 0o600 });
// Only for scripted screenshots: the seed admin's sign-in, kept out of the project.
if (process.env.RV_DEMO_ADMIN_FILE) fs.writeFileSync(process.env.RV_DEMO_ADMIN_FILE, JSON.stringify({ email: "ada@demo.example.ng", password: adminPassword, secret: secrets["ada@demo.example.ng"], V, sandbox: sandbox?.id }), { mode: 0o600 });
console.log(`  sandbox ${sandbox?.id ?? "not created"}, wallet vault ${V}`);
