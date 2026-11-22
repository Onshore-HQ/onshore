// Takes the documentation's console screenshots from a running local install with the
// demo loaded (./demo up). Highlights are drawn only where a step needs one, as a single
// blue outline, and removed before the next shot.
//
//   PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs CHROME=/path/to/chrome node scripts/screenshots.mjs [only…]
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { execSync } from "node:child_process";

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ?? "playwright");
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const OUT = path.join(ROOT, "public/screenshots");
const REPO = path.resolve(ROOT, "..");
const BASE = process.env.RV_BASE ?? "https://localhost:8443";
const only = new Set(process.argv.slice(2));
const want = (n) => only.size === 0 || [...only].some((o) => n.startsWith(o));
const S = JSON.parse(fs.readFileSync(path.join(REPO, "demo/.state/state.json"), "utf8"));
fs.mkdirSync(OUT, { recursive: true });

const sql = (q) => execSync(`docker compose -p onshore -f docker-compose.yml -f docker-compose.e2e.yml exec -T postgres psql -U rv rv -At -v ON_ERROR_STOP=1`, { cwd: path.join(REPO, "deploy/compose"), input: q }).toString().trim();
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function totp(secret) { let bits = 0, val = 0; const key = []; for (const c of secret) { val = (val << 5) | B32.indexOf(c); bits += 5; if (bits >= 8) { key.push((val >>> (bits - 8)) & 255); bits -= 8; val &= (1 << bits) - 1; } } const t = Buffer.alloc(8); t.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000))); const m = crypto.createHmac("sha1", Buffer.from(key)).update(t).digest(); return String((m.readUInt32BE(m[m.length - 1] & 15) & 0x7fffffff) % 1e6).padStart(6, "0"); }
const freshWindow = () => new Promise((r) => setTimeout(r, 31000 - (Date.now() % 30000)));
async function api(p, { token, body, method } = {}) { const r = await fetch(`${BASE}/control${p}`, { method: method ?? (body ? "POST" : "GET"), headers: { ...(body ? { "content-type": "application/json" } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body ? JSON.stringify(body) : undefined }); return r.json().catch(() => ({})); }

const browser = await chromium.launch({ executablePath: process.env.CHROME });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: "light", locale: "en-GB" });
const page = await ctx.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));

/** One blue outline around an element, with an optional number. */
async function highlight(locator, n) {
  const box = await locator.first().boundingBox();
  if (!box) return;
  await page.evaluate(({ box, n }) => {
    const d = document.createElement("div");
    d.className = "rv-doc-hl";
    const pad = 5;
    Object.assign(d.style, { position: "fixed", left: `${box.x - pad}px`, top: `${box.y - pad}px`, width: `${box.width + pad * 2}px`, height: `${box.height + pad * 2}px`, border: "3px solid #2574de", borderRadius: "10px", boxShadow: "0 0 0 4px rgba(37,116,222,.18)", zIndex: 2147483647, pointerEvents: "none" });
    if (n) {
      const b = document.createElement("span");
      b.textContent = String(n);
      Object.assign(b.style, { position: "absolute", top: "-14px", left: "-14px", width: "24px", height: "24px", borderRadius: "50%", background: "#2574de", color: "#fff", font: "600 13px system-ui", display: "grid", placeItems: "center" });
      d.appendChild(b);
    }
    document.body.appendChild(d);
  }, { box, n });
}
const clearHighlights = () => page.evaluate(() => document.querySelectorAll(".rv-doc-hl").forEach((e) => e.remove()));

async function shot(name, url, opts = {}) {
  if (!want(name)) return;
  try {
    if (url) await page.goto(`${BASE}${url}`, { waitUntil: "networkidle" });
    if (opts.waitFor) await page.getByText(opts.waitFor, { exact: false }).first().waitFor({ timeout: 15000 });
    if (opts.before) await opts.before();
    await page.waitForTimeout(opts.settle ?? 700);
    for (const [i, h] of (opts.highlight ?? []).entries()) await highlight(typeof h === "string" ? page.getByRole("button", { name: h }) : h, opts.numbered ? i + 1 : undefined);
    await page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: !!opts.fullPage, ...(opts.clip ? { clip: opts.clip } : {}) });
    await clearHighlights();
    console.log("ok   ", name);
  } catch (e) {
    console.log("FAIL ", name, (e.message ?? "").split("\n")[0]);
  }
}

// ---- Signed out ----------------------------------------------------------------
await shot("login", "/login", { waitFor: "Welcome back" });
await shot("login-sso", "/login", { waitFor: "Welcome back", highlight: ["Continue with single sign-on"] });
await shot("forgot", "/forgot");

// ---- Sign in as the demo admin ----------------------------------------------------
await freshWindow();
await page.goto(`${BASE}/login`);
await page.fill('input[type="email"]', S.scenario.email);
await page.fill('input[type="password"]', S.scenario.password);
await page.getByRole("button", { name: "Continue", exact: true }).click();
await page.waitForSelector('input[autocomplete="one-time-code"]');
await shot("login-code", null);
await page.fill('input[autocomplete="one-time-code"]', totp(S.scenario.secret));
await page.getByRole("button", { name: "Verify and sign in" }).click();
await page.waitForURL(/overview|welcome/);
const token = (await (async () => { await freshWindow(); return api("/v1/auth/login", { body: { email: S.scenario.email, password: S.scenario.password, totp: totp(S.scenario.secret) } }); })()).access_token;
const vault = S.onshore.vault;

// ---- First-time setup, reopened briefly -------------------------------------------
if ([...Array(5)].some((_, i) => want(`setup-${i + 1}`))) {
  const t = sql("SELECT id FROM control.tenants LIMIT 1");
  const was = sql(`SELECT setup_completed_at FROM control.tenants WHERE id='${t}'`);
  sql(`UPDATE control.tenants SET setup_completed_at=NULL WHERE id='${t}'`);
  try {
    await shot("setup-1", "/welcome", { waitFor: "Your organisation" });
    const next = async () => { await page.getByRole("button", { name: "Continue" }).last().click(); await page.waitForTimeout(600); await page.evaluate(() => scrollTo(0, 0)); };
    await next(); await shot("setup-2", null, { waitFor: "Where" });
    // A vault's country is final: the screen asks for that to be confirmed.
    for (const box of await page.locator('input[type="checkbox"]').all()) if (!(await box.isChecked())) await box.check();
    await shot("setup-2-confirm", null, { before: async () => { await page.locator('input[type="checkbox"]').last().scrollIntoViewIfNeeded(); } });
    await next(); await shot("setup-3", null);
    await next(); await shot("setup-4", null);
    await next(); await shot("setup-5", null);
  } finally {
    sql(`UPDATE control.tenants SET setup_completed_at='${was}' WHERE id='${t}'`);
  }
}

// ---- Console ----------------------------------------------------------------------
await shot("overview", "/overview", { waitFor: "Home" });
await shot("search", "/overview", { before: async () => { await page.keyboard.press("Meta+K"); await page.keyboard.type("keys"); } });
await page.keyboard.press("Escape").catch(() => {});
await shot("onboarding", "/onboarding");
await shot("residency-map", "/residency-map", { waitFor: "Flow score" });
await shot("residency-flow", null, { before: async () => { await page.goto(`${BASE}/residency-map`, { waitUntil: "networkidle" }); await page.getByRole("button", { name: /^Flows/ }).click(); await page.locator('a[href*="/residency-map/flows/"], tbody tr').first().click(); await page.waitForLoadState("networkidle"); } });
await shot("residency-new", "/residency-map/new");
await shot("residency-exceptions", "/residency-map/exceptions");
await shot("connections", "/pipelines", { waitFor: "Connections" });
for (const label of ["Logs", "AI", "Web APIs", "Support tools", "Page protection"]) {
  const slug = label.toLowerCase().replace(/[^a-z]+/g, "-");
  await shot(`connections-${slug}`, "/pipelines", { waitFor: "Connections", before: async () => { await page.getByRole("button", { name: label, exact: true }).first().click(); await page.waitForLoadState("networkidle"); }, settle: 1200 });
}
await shot("connections-ai-full", "/pipelines", { waitFor: "Connections", fullPage: true, before: async () => { await page.getByRole("button", { name: "AI", exact: true }).first().click(); await page.waitForLoadState("networkidle"); }, settle: 1500 });
await shot("connect", "/connect");
await shot("page-protection", "/page-protection");
await shot("data-types", "/detection", { waitFor: "Data types" });
await shot("data-types-own", "/detection?tab=custom", { waitFor: "Data types" });
await shot("data-types-templates", "/detection?tab=templates", { waitFor: "Data types" });
await shot("data-type-new", `/detection/new?vault=${vault}`);
await shot("data-type-detail", null, { before: async () => { await page.goto(`${BASE}/detection?tab=custom`, { waitUntil: "networkidle" }); await page.locator(`a[href^="/detection/${vault}/"], tbody tr`).first().click(); await page.waitForLoadState("networkidle"); } });

// A sample country pack, removed again at the end.
let packId = null;
if (want("pack")) {
  const r = await api("/v1/packs", { token, body: { country: "ES", name: "Spain", description: "DNI numbers, and Spain's data protection law" } });
  packId = r.id;
  await api(`/v1/packs/${packId}`, { token, method: "PUT", body: {
    name: "Spain", description: "DNI numbers, and Spain's data protection law",
    data_types: [{ slug: "c_es_dni", kind: "pattern", name: "Spanish DNI", definition: { regex: "\\b\\d{8}-?[A-Z]\\b" }, validator: { type: "letter_check", values: ["TRWAGMYFPDXBNJZSQVHLCKE"], weights: [14, 6, 19, 18, 11, 8, 10, 1], check_position: 0 }, context_positive: ["DNI", "documento"],
      tests: [{ sample: "DNI 12345678Z", expect_match: true }, { sample: "mi documento es 87654321X", expect_match: true }, { sample: "00000000T", expect_match: true }, { sample: "DNI 12345678A", expect_match: false }, { sample: "87654321A", expect_match: false }, { sample: "ref 00000000R", expect_match: false }] }],
    laws: [{ name: "Ley Orgánica 3/2018 (LOPDGDD)", effect: "Spain's data protection law alongside the GDPR.", source: "https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673", checked_on: "2026-11-22" }],
  } });
  await shot("packs", "/detection?tab=packs", { waitFor: "Spain", highlight: ["New country pack"] });
  await shot("packs-new", "/detection?tab=packs", { waitFor: "Spain", before: async () => { await page.getByRole("button", { name: "New country pack" }).click(); await page.locator("select").last().selectOption("MA"); } });
  await page.keyboard.press("Escape").catch(() => {});
  await shot("pack-editor", `/detection/pack?id=${packId}`, { waitFor: "About this pack", fullPage: true });
  await shot("pack-test", `/detection/pack?id=${packId}`, { waitFor: "About this pack", before: async () => { await page.getByRole("button", { name: "Test the saved pack" }).click(); await page.getByText("Every data type passes").waitFor(); await page.getByText("Every data type passes").scrollIntoViewIfNeeded(); } });
}
await shot("vaults", "/vaults", { waitFor: "Vaults" });
await shot("vaults-components", "/vaults", { waitFor: "Vaults", before: async () => { await page.getByText("Secure components").first().scrollIntoViewIfNeeded(); } });
await shot("files", "/files");
await shot("records", "/records", { waitFor: "Customer records", highlight: [page.getByRole("link", { name: "Import existing data" })] });
await shot("record-detail", null, { before: async () => { await page.goto(`${BASE}/records`, { waitUntil: "networkidle" }); await page.locator("tbody tr").first().click(); await page.waitForLoadState("networkidle"); } });
await shot("records-import", "/records/import");
await shot("people", "/people", { waitFor: "People" });
await shot("people-add", "/people", { waitFor: "People", before: async () => { await page.getByRole("button", { name: /Add a person/ }).first().click(); } });
await page.keyboard.press("Escape").catch(() => {});
await shot("person-detail", null, { before: async () => { await page.goto(`${BASE}/people`, { waitUntil: "networkidle" }); await page.locator("tbody tr").first().click(); await page.waitForLoadState("networkidle"); } });
await shot("access-rules", "/policies", { waitFor: "Access rules" });
await shot("access-rules-full", "/policies", { waitFor: "Access rules", fullPage: true });
await shot("reports", "/reports", { waitFor: "Reports" });
await shot("audit", "/audit", { waitFor: "Audit log" });
await shot("keys", "/keys", { waitFor: "Encryption keys" });
await shot("usage", "/usage");
await shot("service-logs", "/logs");
await shot("health", "/monitoring", { waitFor: "Health" });
await shot("account", "/account");
for (const [tab, name] of [["org", "settings-org"], ["locations", "settings-locations"], ["signin", "settings-signin"], ["email", "settings-email"], ["setup", "settings-copy"], ["audit", "settings-audit"]]) {
  await shot(name, `/settings?tab=${tab}`, { waitFor: "Settings", settle: 1200 });
}
// Run with the install as Enterprise or Cloud to see single sign-on, SCIM and LDAP set up.
if (only.has("identity")) {
  await shot("identity-sso", "/settings?tab=signin", { waitFor: "Groups and roles", settle: 1500, before: async () => { await page.getByText("Single sign-on").first().scrollIntoViewIfNeeded(); await page.evaluate(() => scrollBy(0, -80)); } });
  await shot("identity-full", "/settings?tab=signin", { waitFor: "Groups and roles", settle: 1500, fullPage: true });
}
await shot("settings-locations-full", "/settings?tab=locations", { waitFor: "Settings", settle: 1200, fullPage: true });

// ---- Passkey sign-in, with a simulated authenticator -------------------------------
if (want("passkey")) {
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  try {
    await page.goto(`${BASE}/settings?tab=signin`, { waitUntil: "networkidle" });
    await shot("passkey-add", null, { before: async () => { await page.getByRole("button", { name: "Add a passkey or security key" }).click(); await page.getByRole("dialog").locator("input").first().fill("Work laptop"); } });
    const dialog = page.getByRole("dialog");
    await dialog.locator('input[type="password"]').fill(S.scenario.password);
    await dialog.getByRole("button", { name: "Continue" }).click();
    await page.getByText("Added. Next time you sign in").waitFor();
    await dialog.getByRole("button", { name: "Done" }).click();
    await page.evaluate(() => fetch("/api/session", { method: "DELETE" }));
    await page.goto(`${BASE}/login`);
    await page.fill('input[type="email"]', S.scenario.email);
    await page.fill('input[type="password"]', S.scenario.password);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.waitForSelector('input[autocomplete="one-time-code"]');
    await shot("passkey-login", null, { highlight: ["Use a passkey"] });
    await page.getByRole("button", { name: "Use a passkey" }).click();
    await page.waitForURL(/overview|welcome/);
  } finally {
    const me = sql(`SELECT id FROM control.principals WHERE email='${S.scenario.email}'`);
    sql(`DELETE FROM control.webauthn_credentials WHERE principal_id='${me}'; DELETE FROM control.auth_challenges WHERE principal_id='${me}';`);
    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  }
}

// ---- Console in French -------------------------------------------------------------
if (want("french")) {
  await api("/v1/settings/locations", { token, method: "PATCH", body: { console_language: "fr" } });
  try { await shot("french-overview", "/overview", { settle: 2000 }); } finally { await api("/v1/settings/locations", { token, method: "PATCH", body: { console_language: "en" } }); await page.evaluate(() => { try { localStorage.setItem("rv-lang", "en"); } catch {} }); }
}

if (packId) await api(`/v1/packs/${packId}`, { token, method: "DELETE" });
await browser.close();
console.log(errors.length ? `page errors: ${errors.slice(0, 5).join(" | ")}` : "no page errors");
