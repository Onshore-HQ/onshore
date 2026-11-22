// The scenario engine: drives Lagoon Pay like real users, seeds marked history, jumps between
// story stages, and resets everything to the same starting point before a take.
import { execSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { amount, BANKS, chatTemplates, customer, loanRef, narration, recipient, rng, SEED } from "./synth.mjs";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const STACK = path.resolve(ROOT, "../deploy/compose");
const LAGOON = path.join(ROOT, "lagoon-pay");
const STATE = path.join(ROOT, ".state");
fs.mkdirSync(STATE, { recursive: true, mode: 0o700 });
const require = createRequire(path.join(LAGOON, "package.json"));
const pg = require("pg");
const { VaultClient } = await import(path.resolve(ROOT, "../sdks/node/dist/index.js"));

const env = {};
if (fs.existsSync(path.join(ROOT, ".env"))) for (const l of fs.readFileSync(path.join(ROOT, ".env"), "utf8").split("\n")) { const m = l.match(/^([A-Z_]+)=(.*)$/); if (m && m[2]) env[m[1]] = m[2]; }
const REAL = { logs: !!env.GRAFANA_OTLP_ENDPOINT, errors: !!env.SENTRY_DSN, ai: !!env.OPENAI_BASE_URL, analytics: !!env.ANALYTICS_DATABASE_URL };
const BASE = "https://localhost:8443", APP = "http://127.0.0.1:4100", SIM = "http://127.0.0.1:4200", SIM_DOCKER = "http://host.docker.internal:4200";
const LAGOON_DB = "postgres://lagoon:lagoon-demo-only@127.0.0.1:55433/lagoon";
const COMPOSE = "docker compose -f docker-compose.yml -f docker-compose.e2e.yml --profile logs --profile ai --profile proxy --profile adapters --profile files";
const sh = (c, cwd = ROOT, opts = {}) => execSync(c, { cwd, encoding: "utf8", maxBuffer: 1 << 26, stdio: [opts.input ? "pipe" : "ignore", "pipe", "pipe"], ...opts });
const sql = (q) => sh(`${COMPOSE} exec -T postgres psql -U rv rv -v ON_ERROR_STOP=1 -At`, STACK, { input: q }).trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const say = (s) => console.log(s);
const load = (n, d = null) => { try { return JSON.parse(fs.readFileSync(path.join(STATE, n), "utf8")); } catch { return d; } };
const save = (n, v) => fs.writeFileSync(path.join(STATE, n), JSON.stringify(v, null, 1), { mode: 0o600 });
const tick = async (what, f) => { const t = Date.now(); process.stdout.write(`  ${what}... `); const r = await f(); say(`done (${((Date.now() - t) / 1000).toFixed(1)} s)`); return r; };

async function api(p, { token, method, body } = {}) {
  const r = await fetch(`${BASE}/control${p}`, { method: method ?? (body !== undefined ? "POST" : "GET"), headers: { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const t = await r.text();
  let j; try { j = JSON.parse(t); } catch { j = t; }
  if (r.status >= 400) throw new Error(`${method ?? "GET"} ${p}: ${r.status} ${t.slice(0, 300)}`);
  return j;
}
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function totp(secret, ahead = 0) {
  let bits = 0, val = 0; const key = [];
  for (const c of secret) { val = (val << 5) | B32.indexOf(c); bits += 5; if (bits >= 8) { key.push((val >>> (bits - 8)) & 255); bits -= 8; val &= (1 << bits) - 1; } }
  const t = Buffer.alloc(8); t.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + ahead));
  const m = crypto.createHmac("sha1", Buffer.from(key)).update(t).digest();
  return String((m.readUInt32BE(m[m.length - 1] & 15) & 0x7fffffff) % 1e6).padStart(6, "0");
}
let used = {};
/** The scenario signs in as its own user, so that it never competes with a person's one-time code. It keeps its session. */
async function signIn(u) {
  const saved = load("session.json");
  if (saved?.email === u.email && saved.expires > Date.now() + 60000) {
    const check = await fetch(`${BASE}/control/v1/me`, { headers: { authorization: `Bearer ${saved.token}` } }).catch(() => null);
    if (check?.ok) return saved.token;
  }
  const step = () => Math.floor(Date.now() / 30000);
  while ((load("session.json")?.step ?? 0) === step() || used[u.email] === step()) await sleep(1000);
  used[u.email] = step();
  const token = (await api("/v1/auth/login", { body: { email: u.email, password: u.password, totp: totp(u.secret) } })).access_token;
  const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
  save("session.json", { email: u.email, token, step: step(), expires: (claims.exp ?? 0) * 1000 });
  return token;
}
const appPost = async (p, body) => { const r = await fetch(`${APP}/api/${p}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body ?? {}) }); const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(`${p}: ${r.status} ${JSON.stringify(j).slice(0, 200)}`); return j; };

// ---- wiring -----------------------------------------------------------------
function collector(mode, pipeline) {
  const auth = env.GRAFANA_OTLP_AUTH ? { authorization: env.GRAFANA_OTLP_AUTH } : {};
  const direct = (env.GRAFANA_OTLP_ENDPOINT || `${SIM_DOCKER}/otlp`).replace(/\/$/, "");
  const exporter = mode === "onshore" && pipeline
    // The one line that changes: where the exporter points.
    ? { logs_endpoint: `https://host.docker.internal:8443/logs/otlp/${pipeline.id}/v1/logs`, encoding: "json", compression: "none", tls: { insecure_skip_verify: true, server_name_override: "localhost" }, headers: { Host: "localhost", "X-RV-Pipeline-Key": pipeline.key, ...auth } }
    : { logs_endpoint: `${direct}/v1/logs`, encoding: REAL.logs ? "proto" : "json", compression: "none", headers: auth };
  const cfg = { receivers: { otlp: { protocols: { http: { endpoint: "0.0.0.0:4318" } } } }, processors: { batch: { timeout: "1s" } }, exporters: { "otlphttp/out": exporter }, service: { pipelines: { logs: { receivers: ["otlp"], processors: ["batch"], exporters: ["otlphttp/out"] } }, telemetry: { logs: { level: "warn" } } } };
  fs.mkdirSync(path.join(ROOT, "collector"), { recursive: true });
  fs.writeFileSync(path.join(ROOT, "collector/config.json"), JSON.stringify(cfg, null, 2));
}
const restartCollector = () => sh("docker compose -f compose.yml restart collector");
function publish(state) {
  save("state.json", state);
  save("lagoon.json", { config: state.config, onshore: state.onshore });
}
function running(file) { const p = load(file); if (!p?.pid) return false; try { process.kill(p.pid, 0); return true; } catch { return false; } }
function background(name, cmd, args, cwd, extra = {}) {
  const out = fs.openSync(path.join(STATE, `${name}.log`), "a");
  const c = spawn(cmd, args, { cwd, detached: true, stdio: ["ignore", out, out], env: { ...process.env, ...env, ...extra } });
  c.unref();
  save(`${name}.pid.json`, { pid: c.pid });
}
function stopProc(name) { const p = load(`${name}.pid.json`); if (p?.pid) { try { process.kill(-p.pid); } catch { try { process.kill(p.pid); } catch {} } } }
async function waitFor(url, what, ms = 60000) { const t0 = Date.now(); for (;;) { try { const r = await fetch(url); if (r.status < 500) return; } catch {} if (Date.now() - t0 > ms) throw new Error(`${what} did not start`); await sleep(500); } }

async function up() {
  try { await fetch(`${BASE}/healthz`); } catch { throw new Error(`The Onshore stack is not running at ${BASE}. Start it first: see demo/README.md`); }
  if (!fs.existsSync(path.join(ROOT, "collector/config.json"))) collector("direct");
  await tick("databases and collector", async () => sh("docker compose -f compose.yml up -d --wait lagoon-db analytics-db collector"));
  if (!running("sim.pid.json")) { await tick("offshore stand-in", async () => { background("sim", "node", ["server.mjs"], path.join(ROOT, "offshore-sim")); await waitFor(`${SIM}/api/counts`, "the stand-in"); }); }
  await tick("Lagoon Pay database", async () => sh("npx prisma db push --skip-generate 2>&1 || npx prisma db push", LAGOON, { env: { ...process.env, LAGOON_DATABASE_URL: LAGOON_DB } }));
  for (const f of ["index.js", "index.d.ts"]) fs.copyFileSync(path.resolve(ROOT, "../sdks/node/dist", f), path.join(LAGOON, "src/vendor", f.replace("index", "onshore-sdk")));
  if (!fs.existsSync(path.join(LAGOON, ".next/BUILD_ID"))) await tick("building Lagoon Pay (first time only)", async () => sh("npx next build", LAGOON, { env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" } }));
  if (!running("lagoon.pid.json")) await tick("Lagoon Pay", async () => { background("lagoon", "npx", ["next", "start", "-p", "4100"], LAGOON, { NODE_TLS_REJECT_UNAUTHORIZED: "0", DEMO_STATE_FILE: path.join(STATE, "lagoon.json"), LAGOON_DATABASE_URL: LAGOON_DB }); await waitFor(`${APP}/`, "Lagoon Pay"); });
}

// ---- reset ------------------------------------------------------------------
async function wipeOnshore() {
  const stackEnv = fs.readFileSync(path.join(STACK, ".env"), "utf8");
  if (!/^RV_HOST=localhost/m.test(stackEnv)) throw new Error("demo reset only runs against a stack on localhost");
  const tables = sql(`SELECT string_agg(quote_ident(schemaname)||'.'||quote_ident(tablename), ',') FROM pg_tables WHERE schemaname IN ('control','data','events') AND tablename NOT IN ('monitor_state')`);
  sql(`BEGIN; SET LOCAL session_replication_role=replica; CREATE TEMP TABLE keep_vendors AS SELECT * FROM control.vendors WHERE tenant_id IS NULL; TRUNCATE ${tables} CASCADE; INSERT INTO control.vendors SELECT * FROM keep_vendors; COMMIT;`);
  // Services hold caches and the audit chain's head in memory.
  sh(`${COMPOSE} restart vault-api control-api log-processor ai-gateway http-proxy`, STACK);
  await waitFor(`${BASE}/healthz`, "Onshore", 90000);
  for (let i = 0; i < 90; i++) { const r = await fetch(`${BASE}/control/v1/bootstrap/status`).catch(() => null); if (r?.ok) break; await sleep(1000); }
}
const password = () => `demo-${crypto.randomBytes(12).toString("hex")}`;
function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return { pub: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64"), seed: privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("base64") };
}
async function setupOnshore() {
  const stackEnv = fs.readFileSync(path.join(STACK, ".env"), "utf8");
  const bootstrap_token = load("bootstrap.json")?.token ?? process.env.DEMO_BOOTSTRAP ?? stackEnv.match(/^RV_BOOTSTRAP_TOKEN=(.*)$/m)?.[1];
  if (!bootstrap_token) throw new Error("No bootstrap token found");
  const admin = { email: "ngozi@lagoonpay.example.ng", password: password(), name: "Ngozi Adeleke" };
  await api("/v1/bootstrap", { body: { organisation: "Lagoon Pay (demo)", display_name: admin.name, email: admin.email, password: admin.password, bootstrap_token } });
  const first = await api("/v1/auth/login", { body: { email: admin.email, password: admin.password } });
  admin.secret = first.secret;
  used[admin.email] = Math.floor(Date.now() / 30000);
  const ADMIN = (await api("/v1/auth/login", { body: { email: admin.email, password: admin.password, totp: totp(admin.secret) } })).access_token;
  const second = await api("/v1/principals", { token: ADMIN, body: { kind: "user", display_name: "Tobi Bassey", email: "tobi@lagoonpay.example.ng", roles: ["admin"] } });
  const approver = { email: "tobi@lagoonpay.example.ng", password: password(), name: "Tobi Bassey" };
  const f2 = await api("/v1/auth/login", { body: { email: approver.email, password: second.temporary_password } });
  approver.secret = f2.secret;
  used[approver.email] = Math.floor(Date.now() / 30000);
  const SECOND = (await api("/v1/auth/login", { body: { email: approver.email, password: second.temporary_password, totp: totp(approver.secret), new_password: approver.password } })).access_token;
  const robot = await api("/v1/principals", { token: ADMIN, body: { kind: "user", display_name: "Demo scenario", email: "scenario@lagoonpay.example.ng", roles: ["admin"] } });
  const scenario = { email: "scenario@lagoonpay.example.ng", password: password(), name: "Demo scenario" };
  const f3 = await api("/v1/auth/login", { body: { email: scenario.email, password: robot.temporary_password } });
  scenario.secret = f3.secret;
  await api("/v1/auth/login", { body: { email: scenario.email, password: robot.temporary_password, totp: totp(scenario.secret), new_password: scenario.password } });
  fs.rmSync(path.join(STATE, "session.json"), { force: true });
  save("session.json", { step: Math.floor(Date.now() / 30000) });
  sql(`UPDATE control.tenants SET demo_mode=true`);
  const vault = (await api("/v1/vaults", { token: ADMIN, body: { name: "Lagoon Pay", environment: "production", template: "wallet_psp" } })).id;
  await api(`/v1/vaults/${vault}/detection`, { token: ADMIN, method: "PATCH", body: { enabled: true } }).catch(() => undefined);
  const sa = async (display_name, roles) => { const k = keypair(); const r = await api("/v1/principals", { token: ADMIN, body: { kind: "service_account", display_name, roles, public_key: k.pub } }); return { id: r.id, key: r.key_id, seed: k.seed, label: display_name }; };
  const backend = await sa("Lagoon backend", ["backend_service"]);
  const staff = { support_agent: await sa("Support agent, Lagos", ["support_agent"]), ops_lead: await sa("Ops lead, Lagos", ["ops_lead"]), contractor: await sa("Contractor abroad", ["contractor"]) };
  await api("/v1/networks", { token: ADMIN, body: { name: "lagoon-lagos-office", cidrs: ["172.16.0.0/12", "127.0.0.1/32"] } });
  await api("/v1/networks", { token: ADMIN, body: { name: "lagoon-vpn", cidrs: ["10.8.0.0/16"] } });
  const pol = async (name, rules) => { const p = await api("/v1/policies", { token: ADMIN, body: { name, source: { limit_per_hour: 500, rules } } }); await api(`/v1/policies/${p.id}/publish`, { token: SECOND, method: "POST" }); };
  await pol("support-agent", [
    { id: "masked-ids", actions: ["detokenize"], who: { roles: ["support_agent"] }, what: { data_types: ["bvn", "nin", "nuban", "person_name", "email"] }, when: { purpose_required: true }, returns: "masked" },
    { id: "phone", actions: ["detokenize"], who: { roles: ["support_agent"] }, what: { data_types: ["phone_ng"] }, when: { purpose_required: true }, returns: "plaintext" },
  ]);
  await pol("ops-lead", [{ id: "plain-with-purpose", actions: ["detokenize"], who: { roles: ["ops_lead"] }, what: { data_types: ["bvn", "nin", "nuban", "phone_ng", "person_name", "email"] }, when: { purpose_required: true }, returns: "plaintext" }]);
  await pol("lagoon-backend", [{ id: "restore-for-the-customer", actions: ["tokenize", "detokenize"], who: { roles: ["backend_service"] }, what: { data_types: ["bvn", "nin", "nuban", "phone_ng", "person_name", "email", "amount_ngn"] }, when: { purpose_required: true }, returns: "plaintext" }]);
  await api("/v1/scope-definitions", { token: ADMIN, body: { body: "Lagoon Pay's working definition, for this demo: account numbers, BVNs, NINs, amounts and counterparties attached to a payment or loan. This is a made-up company's definition, not legal advice." } }).catch(() => undefined);
  await sleep(6000);
  const pipeline = await api("/v1/log-pipelines", { token: ADMIN, body: { vault_id: vault, name: "Lagoon logs", source_type: "otlp", destination: REAL.logs ? "Grafana Cloud" : "Log tool", upstream_url: env.GRAFANA_OTLP_ENDPOINT || `${SIM_DOCKER}/otlp`, action_per_type: {}, transfer_basis: "tokens_only" } });
  const aiUp = (env.OPENAI_BASE_URL || `${SIM_DOCKER}/v1`).replace(/\/$/, "");
  const ai = await api("/v1/ai-routes", { token: ADMIN, body: { vault_id: vault, name: "Lagoon support bot", provider: "openai", upstream_base_url: aiUp, allowed_models: [env.OPENAI_MODEL || "gpt-test"], restore_in_response: true, transfer_basis: "tokens_only" } });
  await api(`/v1/ai-routes/${ai.id}`, { token: ADMIN, method: "PATCH", body: { mode: "enforcing" } });
  await api("/v1/map/settings", { token: ADMIN, method: "PATCH", body: { vault_id: vault, enabled: true } });
  const logins = { console: `${BASE}`, admin, approver };
  save("logins.json", logins);
  return { vault, admin, approver, scenario, pipeline: { id: pipeline.id, key: pipeline.ingest_key }, ai: { id: ai.id, key: ai.route_key, upstream: aiUp }, backend, staff };
}

async function seedLagoon() {
  sh("npx prisma db push --force-reset --skip-generate 2>&1 || npx prisma db push --force-reset", LAGOON, { env: { ...process.env, LAGOON_DATABASE_URL: LAGOON_DB, PRISMA_USER_CONSENT_FOR_DANGEROUS_AI_ACTION: "yes, this is a throwaway demo database" } });
  const db = new pg.Client({ connectionString: LAGOON_DB });
  await db.connect();
  const r = rng(SEED);
  const now = Date.now(), DAY = 86400000;
  const when = () => new Date(now - Math.floor(r() * 30 * DAY));
  const rows = (table, cols, data) => (data.length ? db.query(`INSERT INTO "${table}" (${cols.map((c) => `"${c}"`).join(",")}) SELECT * FROM unnest(${cols.map((_, i) => `$${i + 1}`).join(",")})`, cols.map((_, i) => data.map((d) => d[i]))) : null);
  const people = Array.from({ length: 200 }, (_, i) => customer(i + 1));
  for (let i = 0; i < people.length; i++) {
    const p = people[i];
    await db.query(`INSERT INTO "Customer" (ref,"fullName",phone,email,dob,city,bvn,nin,"createdAt") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [p.ref, p.fullName, p.phone, p.email, p.dob, p.city, p.bvn, p.nin, when()]);
    await db.query(`INSERT INTO "Account" ("customerId",bank,nuban,last4,balance) VALUES ($1,$2,$3,$4,$5)`, [i + 1, p.bank, p.nuban, p.nuban.slice(-4), 50000 + Math.floor(r() * 2000000)]);
    if (r() < 0.25) { const q = recipient(r); await db.query(`INSERT INTO "Account" ("customerId",bank,nuban,last4,balance) VALUES ($1,$2,$3,$4,$5)`, [i + 1, q.bank, q.nuban, q.nuban.slice(-4), Math.floor(r() * 500000)]); }
  }
  const transfers = [], loans = [], chats = [];
  const ts = (x) => x.toISOString();
  for (let i = 0; i < 5000; i++) { const q = recipient(r); transfers.push([1 + Math.floor(r() * 200), q.bank, q.nuban, q.name, amount(r), narration(r), r() < 0.03 ? "failed" : "success", ts(when())]); }
  await db.query(`INSERT INTO "Transfer" ("customerId","toBank","toAccount","toName",amount,narration,status,"createdAt") SELECT * FROM unnest($1::int[],$2::text[],$3::text[],$4::text[],$5::int[],$6::text[],$7::text[],$8::timestamptz[])`, [0, 1, 2, 3, 4, 5, 6, 7].map((c) => transfers.map((t) => t[c])));
  for (let i = 0; i < 300; i++) { const id = 1 + Math.floor(r() * 200); loans.push([loanRef(r), id, 20000 + Math.floor(r() * 1980) * 1000, 3 + Math.floor(r() * 10), people[id - 1].income, people[id - 1].employer, r() < 0.6 ? "approved" : "in review", ts(when())]); }
  await db.query(`INSERT INTO "Loan" ("loanRef","customerId",amount,tenor,income,employer,status,"createdAt") SELECT * FROM unnest($1::text[],$2::int[],$3::int[],$4::int[],$5::int[],$6::text[],$7::text[],$8::timestamptz[]) ON CONFLICT DO NOTHING`, [0, 1, 2, 3, 4, 5, 6, 7].map((c) => loans.map((t) => t[c])));
  for (let i = 0; i < 120; i++) { const id = 1 + Math.floor(r() * 200); const t = chatTemplates[Math.floor(r() * chatTemplates.length)]; const at = when(); chats.push([id, "user", t(people[id - 1], amount(r)), ts(at)]); chats.push([id, "assistant", "Thanks for reaching out. We are looking into this for you.", ts(new Date(at.getTime() + 4000))]); }
  await db.query(`INSERT INTO "ChatMessage" ("customerId",role,content,"createdAt") SELECT * FROM unnest($1::int[],$2::text[],$3::text[],$4::timestamptz[])`, [0, 1, 2, 3].map((c) => chats.map((t) => t[c])));
  await db.end();
  void rows;
}
async function wipeAnalytics() {
  const c = new pg.Client({ connectionString: env.ANALYTICS_DATABASE_URL || "postgres://analytics:analytics-demo-only@127.0.0.1:55434/analytics" });
  await c.connect(); await c.query("DROP SCHEMA IF EXISTS analytics CASCADE"); await c.end();
}

async function reset() {
  const t0 = Date.now();
  stopProc("traffic");
  say("Resetting the demo. This wipes the Onshore install on this machine.");
  await up();
  await tick("wiping Onshore", wipeOnshore);
  const s = await tick("setting up the demo vault, policies, pipeline and AI route", setupOnshore);
  await tick("seeding Lagoon Pay: 200 customers, about 5,000 transfers", seedLagoon);
  await tick("clearing the foreign tools", async () => { await wipeAnalytics(); await fetch(`${SIM}/api/clear`, { method: "POST" }).catch(() => {}); });
  const state = { stage: "before", config: { mode: "off", sentry_hook: false, ai_gateway: false, tokenize_at_source: false, stage: "before" }, onshore: { base: BASE, vault: s.vault, ai_route: s.ai.id, ai_route_key: s.ai.key, ai_upstream: s.ai.upstream, flows: {}, backend: s.backend, staff: s.staff }, pipeline: s.pipeline, ai: s.ai, admin: s.admin, approver: s.approver, scenario: s.scenario, seed: SEED };
  publish(state);
  await tick("pointing logs straight at the log tool", async () => { collector("direct"); restartCollector(); });
  await tick("running the nightly copy to the foreign database", () => appPost("jobs/analytics-copy"));
  const secs = Math.round((Date.now() - t0) / 1000);
  say(`\nReady in ${secs} s. Stage: before.${secs >= 120 ? " That is over the 2-minute target." : ""}`);
  printLogins();
}

// ---- seeded history ---------------------------------------------------------
const ENTITY_MIX = [["bvn", 420], ["nuban", 930], ["phone_ng", 260], ["amount_ngn", 610], ["person_name", 180], ["email", 95]];
function seedEvents(sourceId, module, host, { from, to, action }) {
  // Marked seeded: true. The console shows a badge, and the story says so out loud.
  const v = load("state.json").onshore.vault;
  const rowsSql = ENTITY_MIX.map(([e, n]) => `INSERT INTO events.detection_events(occurred_at,vault_id,module,source_id,destination,dest_host,entity_type,action,count,seeded)
    SELECT date_trunc('day', now()) - (d||' days')::interval + interval '11 hours','${v}','${module}','${sourceId}','demo','${host}','${e}','${action}',${n}+(d*17)%90,true FROM generate_series(${to},${from}) d ON CONFLICT DO NOTHING;`).join("\n");
  sql(rowsSql);
}
function seedScores(days, start = 24, end = 100) {
  const v = load("state.json").onshore.vault;
  sql(`INSERT INTO control.map_scores_daily(vault_id,day,flow_score,flow_score_without_exceptions,volume_score,seeded) SELECT '${v}',current_date-d,round(${end}-(${end}-${start})*d/${days}.0,2),round(${end}-(${end}-${start})*d/${days}.0,2),round(least(100,${end}-(${end}-${start}-15)*d/${days}.0),2),true FROM generate_series(1,${days}) d ON CONFLICT (vault_id,day) DO UPDATE SET flow_score=EXCLUDED.flow_score, flow_score_without_exceptions=EXCLUDED.flow_score_without_exceptions, volume_score=EXCLUDED.volume_score, seeded=true;`);
}
const pipelineHost = () => (env.GRAFANA_OTLP_ENDPOINT ? new URL(env.GRAFANA_OTLP_ENDPOINT).hostname : "host.docker.internal").toLowerCase();
async function seedHistory(days = 30) {
  const s = load("state.json");
  seedEvents(s.pipeline.id, "logs", pipelineHost(), { from: days, to: 1, action: "shadow" });
  seedScores(days);
  sql(`INSERT INTO events.usage_daily(vault_id,date,tokenize_count,detokenize_count,denied_count,detections_by_type,p95_latency_ms) SELECT '${s.onshore.vault}',current_date-d,900+(d*31)%400,40+(d*7)%60,(d*3)%9,'{}',24 FROM generate_series(1,${days}) d ON CONFLICT DO NOTHING`);
  say(`Seeded ${days} days of history, marked as seeded.`);
}

// ---- stages -----------------------------------------------------------------
const ORDER = ["before", "shadow", "enforcing", "map", "report"];
async function admin(s) { return signIn(s.scenario); }
async function vendorByName(token, name) { return (await api(`/v1/map/vendors?q=${encodeURIComponent(name)}`, { token })).vendors.find((v) => v.name.toLowerCase() === name.toLowerCase()); }
const flowsOf = async (s, token) => (await api(`/v1/map/flows?vault_id=${s.onshore.vault}&limit=500`, { token })).flows;

async function declareFlows(s, token) {
  const sys = await api("/v1/map/systems", { token, body: { vault_id: s.onshore.vault, name: "Lagoon Pay app", kind: "service", hosting_country: "NG", hosting_facility: "Lagos", entity_types: ["bvn", "nuban", "phone_ng", "amount_ngn"], owner_id: undefined } });
  const job = await api("/v1/map/systems", { token, body: { vault_id: s.onshore.vault, name: "Nightly analytics copy", kind: "service", hosting_country: "NG", entity_types: ["bvn", "nuban", "phone_ng", "person_name"] } });
  const me = (await api("/v1/me", { token })).id;
  const add = (body) => api("/v1/map/flows", { token, body: { in_cbn_scope: true, owner_id: me, ...body } });
  const sentry = await vendorByName(token, "Sentry");
  const sf = await add({ source_system_id: sys.id, dest_vendor_id: sentry.id, dest_region: "us", entity_types: ["nuban", "amount_ngn"] });
  const openai = await vendorByName(token, "OpenAI");
  const af = await add({ source_system_id: sys.id, dest_vendor_id: openai.id, dest_region: "us", entity_types: ["bvn", "nuban", "phone_ng", "person_name"] });
  const neonHost = env.ANALYTICS_HOST || (env.ANALYTICS_DATABASE_URL ? new URL(env.ANALYTICS_DATABASE_URL).hostname : "analytics.eu.example");
  const neon = await api("/v1/map/vendors", { token, body: { name: "Neon (analytics copy)", category: "cloud", hostnames: [neonHost], regions: [{ code: "eu-central-1", name: "Frankfurt", country: "DE", hosts: [] }] } });
  const nf = await add({ source_system_id: job.id, dest_vendor_id: neon.id, dest_region: "eu-central-1", entity_types: ["bvn", "nuban", "phone_ng", "person_name"] });
  s.map = { app_system: sys.id, job_system: job.id, sentry_flow: sf.id, ai_flow: af.id, analytics_flow: nf.id };
  s.onshore.flows = { sentry: sf.id, analytics: nf.id };
}

async function toShadow(s) {
  const token = await admin(s);
  // Logs now pass through Onshore, in watch mode. A week of watch-mode history is seeded.
  collector("onshore", s.pipeline); restartCollector();
  await sleep(1000);
  seedEvents(s.pipeline.id, "logs", pipelineHost(), { from: 7, to: 0, action: "shadow" });
  await declareFlows(s, token);
  await api("/v1/map/settings", { token, method: "PATCH", body: { vault_id: s.onshore.vault, enabled: true } });
  const flows = await flowsOf(s, token);
  const logs = flows.find((f) => f.route?.id === s.pipeline.id);
  if (logs?.dest.system_id && !env.GRAFANA_OTLP_ENDPOINT) {
    // The stand-in has no catalogue entry, so its location is declared.
    await api(`/v1/map/systems/${logs.dest.system_id}`, { token, method: "PATCH", body: { name: "Log tool (stand-in)", hosting_country: "US" } });
  } else if (logs?.dest.system_id) {
    await api(`/v1/map/systems/${logs.dest.system_id}/confirm-region`, { token, body: { region: env.GRAFANA_REGION || "us" } }).catch(() => undefined);
  }
  s.map.logs_flow = logs?.id;
  s.config.mode = "on";
}
async function toEnforcing(s) {
  const token = await admin(s);
  await api(`/v1/log-pipelines/${s.pipeline.id}`, { token, method: "PATCH", body: { mode: "enforcing" } });
  s.config.sentry_hook = true;
  // The chat flow was declared; linking the route makes it one Onshore can see.
  const me = (await api("/v1/me", { token })).id;
  const act = await api(`/v1/map/flows/${s.map.ai_flow}/actions`, { token, body: { plan: "route_via_proxy", description: "Send the support bot through the AI gateway", owner_id: me, due_date: new Date(Date.now() + 14 * 86400000).toISOString().slice(0, 10) } });
  await api(`/v1/map/actions/${act.id}`, { token, method: "PATCH", body: { status: "done", evidence: { type: "route", route_id: s.ai.id } } });
  s.config.ai_gateway = true;
}
async function sourceOn(s) {
  s.config.tokenize_at_source = true;
  publish(s);
  await appPost("jobs/tokenize-existing");
  await appPost("jobs/analytics-copy");
}
async function toMap(s) {
  const token = await admin(s);
  await seedHistory(30);
  // Thirty days under watch, then a clean recent stretch, as a real rollout would look. All seeded.
  seedEvents(s.pipeline.id, "logs", pipelineHost(), { from: 8, to: 1, action: "tokenized" });
  sql(`UPDATE control.systems SET route_mode_since=now()-interval '9 days' WHERE source_ref->>'id'='${s.pipeline.id}';
       UPDATE events.detection_events SET occurred_at=occurred_at-interval '10 days' WHERE source_id='${s.pipeline.id}' AND action IN ('passed','shadow') AND occurred_at>now()-interval '9 days' AND NOT seeded;
       DELETE FROM events.detection_events WHERE source_id='${s.pipeline.id}' AND action IN ('passed','shadow') AND seeded AND occurred_at>now()-interval '9 days';`);
  await api("/v1/map/settings", { token, method: "PATCH", body: { vault_id: s.onshore.vault, enabled: true } });
}
async function toReport(s) {
  const token = await admin(s);
  if (!s.config.tokenize_at_source) await sourceOn(s);
  await api(`/v1/map/flows/${s.map.analytics_flow}`, { token }).catch(() => undefined);
  await sleep(3000);
  await seedHistory(45);
  const ids = [s.map.logs_flow, s.map.sentry_flow, s.map.ai_flow, s.map.analytics_flow].filter(Boolean);
  const list = ids.map((i) => `'${i}'`).join(",");
  // A month protected. Status history is seeded and says so, in the event's evidence.
  sql(`UPDATE control.systems SET route_mode_since=now()-interval '40 days' WHERE id IN (SELECT via_system_id FROM control.data_flows WHERE id IN (${list}));
       DELETE FROM events.detection_events WHERE source_id IN ('${s.pipeline.id}','${s.ai.id}',${list}) AND action IN ('passed','shadow') AND occurred_at>now()-interval '38 days';
       INSERT INTO control.flow_status_events(flow_id,occurred_at,from_status,to_status,cause,evidence) SELECT id, now()-interval '40 days', 'shadow','protected','no_leak_7d','{"seeded":true}'::jsonb FROM control.data_flows WHERE id IN (${list});
       UPDATE control.data_flows SET status='protected', status_since=now()-interval '40 days' WHERE id IN (${list});`);
  seedScores(45, 24, 100);
  await api("/v1/map/settings", { token, method: "PATCH", body: { vault_id: s.onshore.vault, enabled: true } });
}
const APPLY = { shadow: toShadow, enforcing: toEnforcing, map: toMap, report: toReport };

async function stage(name) {
  if (!ORDER.includes(name)) throw new Error(`Stages: ${ORDER.join(", ")}`);
  let s = load("state.json");
  if (!s) throw new Error("Run demo reset first");
  const here = ORDER.indexOf(s.stage), there = ORDER.indexOf(name);
  if (there < here) { say(`Going back needs a reset first.`); await reset(); s = load("state.json"); }
  const t0 = Date.now();
  for (let i = ORDER.indexOf(s.stage) + 1; i <= there; i++) {
    await tick(`stage ${ORDER[i]}`, () => APPLY[ORDER[i]](s));
    s.stage = ORDER[i]; s.config.stage = ORDER[i];
    publish(s);
  }
  say(`Stage: ${s.stage} (${Math.round((Date.now() - t0) / 1000)} s).`);
}

// ---- traffic ----------------------------------------------------------------
async function traffic(rate) {
  const per = 1000 / rate;
  const r = rng(Date.now() % 100000);
  let i = 1000 + Math.floor(r() * 90000), sent = 0, errs = 0;
  const cust = () => 1 + Math.floor(r() * 200);
  say(`Sending about ${rate} requests a second. Ctrl-C to stop.`);
  let lastCopy = Date.now();
  for (;;) {
    const roll = r();
    try {
      if (roll < 0.06) {
        const p = customer(i++);
        const c = await appPost("signup", { fullName: p.fullName, phone: p.phone, email: p.email, dob: p.dob, city: p.city, bvn: p.bvn, nin: p.nin, ref: p.ref });
        await appPost("accounts", { customer_id: c.id, bank: p.bank, account: p.nuban });
      } else if (roll < 0.72) {
        const q = recipient(r);
        await appPost("transfers", { customer_id: cust(), bank: q.bank, account: q.nuban, name: q.name, amount: amount(r), narration: narration(r) });
      } else if (roll < 0.88) {
        const p = customer(cust());
        await appPost("loans", { customer_id: cust(), amount: 20000 + Math.floor(r() * 1980) * 1000, tenor: 6, income: p.income, employer: p.employer });
      } else {
        const id = cust(); const p = customer(id);
        await appPost("chat", { customer_id: id, message: chatTemplates[Math.floor(r() * chatTemplates.length)](p, amount(r)) });
      }
      sent++;
    } catch (e) { if (errs++ < 3) console.error(String(e.message).slice(0, 200)); }
    if (Date.now() - lastCopy > 60000) { lastCopy = Date.now(); await appPost("jobs/analytics-copy").catch(() => undefined); }
    if (sent % 50 === 0 && sent) process.stdout.write(`\r${sent} sent, ${errs} errors   `);
    await sleep(per * (0.5 + r()));
  }
}

// ---- status -----------------------------------------------------------------
function printLogins() {
  const l = load("logins.json");
  if (!l) return;
  say(`\nConsole: ${BASE}\n  ${l.admin.name}: ${l.admin.email}\n  Sign-in details: ./demo logins`);
}
async function status() {
  const s = load("state.json");
  if (!s) return say("Not set up yet. Run: ./demo reset");
  say(`Stage:      ${s.stage}`);
  say(`Mode:       ${s.config.mode === "on" ? "on" : "off"} (Sentry hook ${s.config.sentry_hook ? "on" : "off"}, AI gateway ${s.config.ai_gateway ? "on" : "off"}, tokenize at source ${s.config.tokenize_at_source ? "on" : "off"})`);
  say(`Seed:       ${s.seed}`);
  say(`Tools:      logs ${REAL.logs ? "Grafana Cloud" : "local stand-in"}; errors ${REAL.errors ? "Sentry" : "local stand-in"}; AI ${REAL.ai ? env.OPENAI_BASE_URL : "local stand-in"}; analytics ${REAL.analytics ? "your database" : "local stand-in"}`);
  say(`Lagoon Pay: ${running("lagoon.pid.json") ? APP : "NOT RUNNING"}`);
  say(`Traffic:    ${running("traffic.pid.json") ? "running" : "stopped"}`);
  const token = await admin(s);
  const p = await api(`/v1/log-pipelines`, { token });
  for (const x of p.pipelines) say(`Pipeline:   ${x.name}, ${x.mode}`);
  const fl = await flowsOf(s, token);
  say(`Flows:      ${fl.length ? "" : "none (the map is empty)"}`);
  for (const f of fl) say(`  ${f.status.padEnd(11)} ${f.source.name} to ${f.dest.name} (${f.dest_country ?? "not confirmed"})${f.proving ? `, proving day ${f.proving.day}` : ""}`);
  const sm = await api(`/v1/map/summary?vault_id=${s.onshore.vault}`, { token });
  say(`Scores:     flow ${sm.flow_score ?? "n/a"}, volume ${sm.volume_score ?? "n/a"}`);
  const leaks = s.config.mode === "off" ? "L1, L2, L3, L4" : [!s.config.sentry_hook && "L2", !s.config.ai_gateway && "L3", !s.config.tokenize_at_source && "L4"].filter(Boolean).join(", ") || "none";
  say(`Leaks open: ${leaks}`);
}

async function logins() {
  const l = load("logins.json");
  if (!l) return say("Not set up yet. Run: ./demo reset");
  for (const u of [l.admin, l.approver]) say(`${u.name}\n  Email:    ${u.email}\n  Password: ${u.password}\n  Code now: ${totp(u.secret)} (changes every 30 seconds; run again for a new one)\n`);
  say(`These are made-up demo users on this machine only, reset each time.`);
}

/** Recovery codes don't expire, so they are the easy way to sign in on camera. Making new ones ends the old ones. */
async function codes() {
  const l = load("logins.json");
  if (!l) return say("Not set up yet. Run: ./demo reset");
  for (const u of [l.admin, l.approver]) {
    // The code the person may be typing right now is left alone: this takes the next one.
    const token = (await api("/v1/auth/login", { body: { email: u.email, password: u.password, totp: totp(u.secret, 1) } })).access_token;
    const { recovery_codes } = await api("/v1/auth/recovery-codes", { token, body: { password: u.password } });
    say(`${u.name}\n  Email:    ${u.email}\n  Password: ${u.password}\n  Recovery codes, each works once and never expires:\n    ${recovery_codes.slice(0, 4).join("\n    ")}\n`);
  }
  say(`At sign-in, after the password, choose "Use a recovery code instead". Running this again replaces these codes.`);
}

const [cmd, ...args] = process.argv.slice(2);
const flag = (n, d) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : d; };
const HELP = `demo up                   start Lagoon Pay, its databases and the stand-ins
demo reset                wipe and rebuild everything to the starting point
demo seed-history --days  write marked history, so dashboards look lived-in
demo traffic --rate 2/s   simulated customers, until stopped
demo stage <name>         ${ORDER.join(", ")}
demo source on            turn on tokenize-at-source, live, for the map beat
demo chat "<message>"     send one scripted support message
demo copy                 run the nightly analytics copy now
demo fail                 send one failed transfer, for a clean Sentry shot
demo status               the pre-take check
demo logins               console sign-in details, and a current code
demo codes                sign-in details with recovery codes that never expire
demo selftest             walk the whole story and check it, from a fresh reset
demo down                 stop the demo's own pieces`;
try {
  switch (cmd) {
    case "up": await up(); say(`\nLagoon Pay: ${APP}\nBack office: ${APP}/ops/customers\nForeign tools (stand-in): ${SIM}`); break;
    case "reset": await reset(); break;
    case "seed-history": await seedHistory(Number(flag("days", 30))); break;
    case "traffic": await traffic(Number(String(flag("rate", "2/s")).split("/")[0])); break;
    case "stage": await stage(args[0]); break;
    case "source": { const s = load("state.json"); await tick("tokenizing at source", () => sourceOn(s)); publish(s); say("Tokenize-at-source is on. The next copy holds only tokens."); break; }
    case "chat": { const c = await appPost("chat", { customer_id: 1, message: args.join(" ") }); say(c.reply); break; }
    case "copy": say(JSON.stringify(await appPost("jobs/analytics-copy"))); break;
    case "fail": { const q = recipient(rng(Date.now() % 9999)); await appPost("transfers", { customer_id: 1, bank: q.bank, account: q.nuban, name: q.name, amount: 250000, narration: "Rent", fail: true }); say(`Sent a failed transfer to ${q.nuban}.`); break; }
    case "status": await status(); break;
    case "logins": await logins(); break;
    case "codes": await codes(); break;
    case "selftest": { const { spawnSync } = await import("node:child_process"); const r = spawnSync("node", ["scenario/selftest.mjs", ...args], { cwd: ROOT, stdio: "inherit", env: process.env }); process.exit(r.status ?? 1); }
    case "down": stopProc("traffic"); stopProc("lagoon"); stopProc("sim"); sh("docker compose -f compose.yml down"); say("Stopped. The Onshore stack is untouched."); break;
    default: say(HELP);
  }
} catch (e) {
  console.error(`\n${e.message}`);
  process.exit(1);
}
process.exit(0);
