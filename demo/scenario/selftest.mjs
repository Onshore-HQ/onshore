// Walks the whole story from a fresh reset, and checks what actually arrives at the foreign tools
// at each stage. Run it with: ./demo selftest. It works with the local stand-ins only.
import { execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const require = createRequire(path.join(ROOT, "lagoon-pay/package.json"));
const pg = require("pg");
const APP = "http://127.0.0.1:4100", SIM = "http://127.0.0.1:4200", BASE = "https://localhost:8443";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let ok = 0; const bad = [];
const check = (n, c, d = "") => { if (c) { ok++; console.log(`  ok    ${n}`); } else { bad.push(n); console.log(`  FAIL  ${n} ${String(d).slice(0, 400)}`); } };
const demo = (a) => execSync(`./demo ${a}`, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const post = async (p, b) => { const r = await fetch(`${APP}/api/${p}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b ?? {}) }); const j = await r.json().catch(() => ({})); return { status: r.status, json: j, cookie: r.headers.get("set-cookie") }; };
const logs = async () => { const h = await (await fetch(`${SIM}/logs`)).text(); return h; };
const page = async (p) => (await fetch(`${SIM}${p}`)).text();
const until = async (f, ms = 25000) => { const t = Date.now(); for (;;) { const v = await f(); if (v) return v; if (Date.now() - t > ms) return null; await sleep(500); } };
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const totp = (s) => { let b = 0, v = 0; const k = []; for (const c of s) { v = (v << 5) | B32.indexOf(c); b += 5; if (b >= 8) { k.push((v >>> (b - 8)) & 255); b -= 8; v &= (1 << b) - 1; } } const t = Buffer.alloc(8); t.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000))); const m = crypto.createHmac("sha1", Buffer.from(k)).update(t).digest(); return String((m.readUInt32BE(m[m.length - 1] & 15) & 0x7fffffff) % 1e6).padStart(6, "0"); };
const state = () => JSON.parse(fs.readFileSync(path.join(ROOT, ".state/state.json")));
async function token() { demo("status"); return JSON.parse(fs.readFileSync(path.join(ROOT, ".state/session.json"))).token; }
const ctl = async (p, t, o = {}) => { const r = await fetch(`${BASE}/control${p}`, { method: o.method ?? (o.body ? "POST" : "GET"), headers: { authorization: `Bearer ${t}`, ...(o.body ? { "content-type": "application/json" } : {}) }, body: o.body ? JSON.stringify(o.body) : undefined }); const x = await r.text(); try { return { status: r.status, json: JSON.parse(x), text: x }; } catch { return { status: r.status, text: x }; } };
const analytics = async () => { const c = new pg.Client({ connectionString: "postgres://analytics:analytics-demo-only@127.0.0.1:55434/analytics" }); await c.connect(); const r = await c.query("SELECT bvn, account_number FROM analytics.customers"); await c.end(); return r.rows; };
const NEW = { fullName: "Selftest Person", phone: "+2348031112222", email: "selftest@example.ng", dob: "1990-01-01", bvn: "22333444551" };

console.log("Reset"); const t0 = Date.now(); demo("reset"); const secs = (Date.now() - t0) / 1000;
check(`reset takes under 2 minutes (${Math.round(secs)} s)`, secs < 120);
const cust = await until(async () => (await fetch(`${APP}/ops/customers`)).ok);
check("the back office answers, and shows the synthetic label", cust && (await (await fetch(`${APP}/ops/customers`)).text()).includes("fictional company, synthetic data"));
for (const p of ["/", "/signup", "/ops/customers", "/ops/log", "/ops/customers/1"]) check(`synthetic-data label on ${p}`, (await (await fetch(APP + p)).text()).includes("synthetic data"));

console.log("Stage: before. All four leaks"); 
const su = await post("signup", NEW); check("sign up works", su.status === 200, JSON.stringify(su.json));
const cid = su.json.id;
await post("accounts", { customer_id: cid, bank: "Harbour Trust Bank", account: "1234567890" });
check("L1: the BVN reaches the log tool in the clear", !!(await until(async () => (await logs()).includes(NEW.bvn))));
await post("transfers", { customer_id: cid, bank: "Delta Crest Bank", account: "2345678901", name: "A B", amount: 250000, narration: "Rent", fail: true });
check("L2: the failed transfer's account reaches the error tracker in the clear", !!(await until(async () => (await page("/errors")).includes("2345678901"))));
const chat0 = await post("chat", { customer_id: cid, message: "my transfer of 250k to 2345678901 failed, my BVN na 22333444551" });
check("L3: the provider receives the BVN and account in the clear", (await page("/ai")).includes(NEW.bvn), chat0.json.reply);
const a0 = await analytics();
check("L4: BVNs sit in the foreign database", a0.length >= 200 && a0.every((r) => /^\d{11}$/.test(r.bvn)));
let t = await token();
check("the map is empty", (await ctl(`/v1/map/flows?vault_id=${state().onshore.vault}`, t)).json.total === 0);

console.log("Stage: shadow");
demo("stage shadow");
const V = state().onshore.vault;
await sleep(1500);
await post("signup", { ...NEW, ref: "LGN-C-SHADOW", email: "s2@example.ng", bvn: "22333444552" });
check("through Onshore in watch mode, logs still arrive unchanged", !!(await until(async () => (await logs()).includes("22333444552"))));
let flows = (await ctl(`/v1/map/flows?vault_id=${V}`, t)).json.flows;
const byDest = (n) => flows.find((f) => f.dest.name.includes(n));
check("the map shows logs as watch only", flows.find((f) => f.route?.type === "log_pipeline")?.status === "shadow", JSON.stringify(flows.map((f) => [f.dest.name, f.status])));
check("the others are leaking", ["Sentry", "OpenAI", "Neon"].every((n) => byDest(n)?.status === "leaking"), JSON.stringify(flows.map((f) => [f.dest.name, f.status])));
const ov = await ctl("/v1/overview", t);
check("seeded detections exist, and are marked", execSync(`docker compose -f docker-compose.yml -f docker-compose.e2e.yml exec -T postgres psql -U rv rv -At -c "SELECT count(*) FROM events.detection_events WHERE seeded"`, { cwd: path.join(ROOT, "../deploy/compose"), encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() !== "0");
check("the console knows this is a demo tenant", (await ctl("/v1/me", t)).json.tenant.demo_mode === true);
void ov;

console.log("Live switch to protecting");
check("the switch works", (await ctl(`/v1/log-pipelines/${state().pipeline.id}`, t, { method: "PATCH", body: { mode: "enforcing" } })).status === 200);
await sleep(7000);
await post("signup", { ...NEW, ref: "LGN-C-PROTECT", email: "s3@example.ng", bvn: "22333444553" });
const prot = await until(async () => { const h = await logs(); return h.includes("LGN-C-PROTECT") ? h : null; });
const line = (prot ?? "").split("<tr>").find((x) => x.includes("LGN-C-PROTECT")) ?? "";
check("the same traffic now carries tokens", line.includes("tok_bvn") && !line.includes("22333444553"), line);

console.log("Stage: enforcing");
demo("stage enforcing");
demo("fail");
const err = await until(async () => { const h = await page("/errors"); return h.includes("tok_nuban") ? h : null; });
check("L2: the error arrives tokenized", !!err, (await page("/errors")).slice(600, 1100));
const reply = await post("chat", { customer_id: cid, message: "my transfer of 250k to 3456789012 failed, my BVN na 22333444551" });
const aiPage = await page("/ai");
const first = aiPage.split('<div class=card>')[1] ?? "";
check("L3: the provider sees placeholders", /\[(BVN|NG_11_DIGIT_ID|NUBAN)_\d+\]/.test(first) && !first.includes("22333444551") && !first.includes("3456789012"), first.slice(0, 500));
check("L3: the customer gets real values back", reply.json.reply?.includes("3456789012"), reply.json.reply);
flows = (await ctl(`/v1/map/flows?vault_id=${V}`, t)).json.flows;
check("the chat flow now counts as seen by Onshore", flows.find((f) => f.dest.name === "OpenAI")?.basis === "observed", JSON.stringify(flows.find((f) => f.dest.name === "OpenAI")));

console.log("Stage: map, then the fix live");
demo("stage map");
flows = (await ctl(`/v1/map/flows?vault_id=${V}`, t)).json.flows;
check("logs are protected after the seeded clean week", flows.find((f) => f.route?.type === "log_pipeline")?.status === "protected", JSON.stringify(flows.map((f) => [f.dest.name, f.status])));
const nf = flows.find((f) => f.dest.name.includes("Neon"));
check("the Europe copy is still leaking", nf?.status === "leaking");
check("it offers a fix", !!(await ctl(`/v1/map/flows/${nf.id}`, t)).json.fix);
const sum0 = (await ctl(`/v1/map/summary?vault_id=${V}`, t)).json;
check("scores have 30 days of history", sum0.series.length >= 30, sum0.series.length);
demo("source on");
const moved = await until(async () => { const f = (await ctl(`/v1/map/flows/${nf.id}`, t)).json; return f.status === "shadow" && f.proving ? f : null; });
check("turning on tokenize-at-source moves the flow to proving clean", !!moved, JSON.stringify((await ctl(`/v1/map/flows/${nf.id}`, t)).json.status));
check("the flow's move is logged", (await ctl(`/v1/map/flows/${nf.id}/timeline`, t)).json.events.length >= 2);
const a1 = await analytics();
check("L4: the foreign database now holds only tokens", a1.length >= 200 && a1.every((r) => r.bvn.startsWith("tok_")), JSON.stringify(a1[0]));

console.log("Reveal and deny");
const db = new pg.Client({ connectionString: "postgres://lagoon:lagoon-demo-only@127.0.0.1:55433/lagoon" }); await db.connect();
const row = (await db.query(`SELECT c.bvn, c.phone, a.nuban FROM "Customer" c JOIN "Account" a ON a."customerId"=c.id WHERE c.id=1`)).rows[0]; await db.end();
check("the ledger holds tokens", row.bvn.startsWith("tok_"));
const r1 = await post("reveal", { role: "support_agent", token: row.nuban, purpose: "Ticket 42" });
check("a support agent sees a masked account", r1.json.decision === "masked" && !/^\d{10}$/.test(r1.json.value ?? ""), JSON.stringify(r1.json));
const r2 = await post("reveal", { role: "ops_lead", token: row.bvn, purpose: "Ticket 42" });
check("an ops lead sees the real value, with a purpose", r2.json.decision === "plaintext" && /^\d{11}$/.test(r2.json.value ?? ""), JSON.stringify(r2.json));
const r3 = await post("reveal", { role: "contractor", token: row.bvn, purpose: "Ticket 42" });
check("the contractor abroad is denied", r3.json.decision === "denied" && !r3.json.value, JSON.stringify(r3.json));
check("a reveal without a purpose is refused", (await post("reveal", { role: "ops_lead", token: row.bvn, purpose: " " })).status === 400);
const verify = await ctl("/v1/audit-events?limit=5", t);
check("the audit log records it", verify.status === 200 && verify.text.includes("detokenize"), verify.text.slice(0, 200));

console.log("Custom entity");
const ent = await ctl(`/v1/vaults/${V}/custom-entities`, t, { body: { name: "Lagoon loan ID", slug: "c_lagoon_loan", kind: "pattern", definition: { regex: "LGN-LN-\\d{8}" }, actions: {}, tests: [...["loan LGN-LN-48213907 approved", "ref LGN-LN-00000001", "LGN-LN-12345678"].map((sample) => ({ sample, expect_match: true })), ...["LGN-LN-123", "loan 48213907", "no id here"].map((sample) => ({ sample, expect_match: false }))] } });
check("the loan ID pattern can be created", ent.status < 300, ent.text);

console.log("Stage: report");
demo("stage report");
flows = (await ctl(`/v1/map/flows?vault_id=${V}`, t)).json.flows;
check("everything shows protected or verified", flows.every((f) => ["protected", "verified"].includes(f.status)), JSON.stringify(flows.map((f) => [f.dest.name, f.status])));
check("logs show verified", flows.find((f) => f.route?.type === "log_pipeline")?.status === "verified");
const sum = (await ctl(`/v1/map/summary?vault_id=${V}`, t)).json;
check("the flow score is 100", sum.flow_score === 100, sum.flow_score);
const from = encodeURIComponent(new Date(Date.now() - 60 * 864e5).toISOString()), to = encodeURIComponent(new Date(Date.now() + 6e4).toISOString());
const rep = await fetch(`${BASE}/control/v1/reports/residency?format=pdf&from=${from}&to=${to}`, { headers: { authorization: `Bearer ${t}` } });
const pdf = Buffer.from(await rep.arrayBuffer());
check("the signed residency report generates", rep.status === 200 && pdf.length > 2000, rep.status);
if (process.argv[2]) fs.writeFileSync(process.argv[2], pdf);
const st = demo("status");
check("demo status prints the story", st.includes("Stage:      report") && st.includes("Leaks open: none"), st);

console.log(`\n${ok} passed, ${bad.length} failed`);
if (bad.length) { console.log(bad.map((x) => `  ${x}`).join("\n")); process.exit(1); }
