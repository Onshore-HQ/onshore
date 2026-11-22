import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";

process.env.VAULT_INTERNAL_URL ??= "https://unused:1";
process.env.DATABASE_URL ??= "postgres://unused:unused@127.0.0.1:1/unused";
process.env.RV_INTERNAL_TOKEN ??= "x".repeat(32);
process.env.RV_USER_TOKEN_SEED ??= Buffer.alloc(32).toString("base64");
process.env.RV_CONTROL_SECRET ??= "x".repeat(32);
const { auditPayload, classifyFailure, eventTypesFor, nextDelay, signature } = await import("../src/ee/webhooks.js");
const { renderMetrics } = await import("../src/monitoring.js");

const row = { seq: 7n, event_id: "e", occurred_at: new Date(0), vault_id: "v", principal_id: "p", principal_kind: "user", module: "api", action: "detokenize", field_id: "f", decision: "plaintext", policy_id: "pol", policy_version: 1, break_glass: false, request_id: "r" };

test("a payload is an allowlist: free text and addresses cannot leave", () => {
  const hostile = { ...row, purpose: "BVN 22333444558", detail: "secret", source_ip: "1.2.3.4", token_hash: "abc", geo_country: "NG", network: "office", record_id: "rec" };
  const out = JSON.stringify(auditPayload(hostile));
  for (const leak of ["22333444558", "secret", "1.2.3.4", "abc", "office", "rec", "purpose", "detail", "source_ip", "token_hash"]) assert.ok(!out.includes(leak), leak);
});

test("events map to subscriptions", () => {
  const t = (action: string, decision: string | null = null, break_glass = false) => eventTypesFor({ action, decision, break_glass });
  assert.deepEqual(t("detokenize", "plaintext"), ["reveal.performed"]);
  // These are the action names the vault really writes, read from a live audit log.
  assert.deepEqual(t("reveal_denied", "denied"), ["reveal.denied"]);
  assert.deepEqual(t("detokenize", "denied"), ["reveal.denied"]);
  assert.deepEqual(t("export", "denied"), ["access.denied"]);
  assert.deepEqual(t("compare", "denied"), ["access.denied"]);
  assert.deepEqual(t("export"), ["data.exported"]);
  assert.deepEqual(t("detokenize", "masked"), []);
  assert.deepEqual(t("detokenize", "plaintext", true), ["access.break_glass", "reveal.performed"]);
  assert.deepEqual(t("break_glass_request"), ["access.break_glass"]);
  assert.deepEqual(t("key_revoke"), ["key.changed"]);
  assert.deepEqual(t("principal_create"), ["identity.changed"]);
  assert.deepEqual(t("tokenize"), []);
});

test("the signature covers the time, so a replay with a new time fails", () => {
  const header = signature(["s"], "{}", 1000);
  const v1 = /v1=([0-9a-f]+)/.exec(header)![1];
  assert.equal(v1, crypto.createHmac("sha256", "s").update("1000.{}").digest("hex"));
  assert.notEqual(v1, crypto.createHmac("sha256", "s").update("2000.{}").digest("hex"));
  assert.equal(signature(["a", "b"], "{}", 1).match(/v1=/g)!.length, 2);
});

test("backoff grows, and then gives up", () => {
  assert.equal(nextDelay(1), 30);
  assert.equal(nextDelay(8), 86400);
  assert.equal(nextDelay(9), null);
});

test("a failure records a category, never the error's own text", () => {
  assert.equal(classifyFailure({ cause: { message: "destination is not public" } }), "refused: the destination is not public");
  assert.equal(classifyFailure({ name: "TimeoutError" }), "timed out");
  assert.equal(classifyFailure({ cause: { code: "ECONNREFUSED", message: "secret host" } }), "connection refused");
  assert.equal(classifyFailure(new Error("BVN 22333444558")), "connection failed");
});

test("metrics escape labels, and leave out services that are not installed", () => {
  const text = renderMetrics({
    components: [{ component: "a", status: "up", since: new Date(), checked_at: new Date() }, { component: "b", status: "down", since: new Date(), checked_at: new Date() }, { component: "c", status: "absent", since: new Date(), checked_at: new Date() }],
    activity_last_hour: [{ module: 'm"x', action: "a\nb", decision: "", count: 2 }], latency_ms: { p50: null, p95: 3 }, open_alerts: 1, webhooks_last_day: { dead: 4 }, webhook_oldest_pending_seconds: 0, siem_lag_events: null,
  });
  assert.match(text, /rv_component_up\{component="a"\} 1/);
  assert.match(text, /rv_component_up\{component="b"\} 0/);
  assert.ok(!text.includes('component="c"'));
  assert.ok(text.includes('module="m\\"x",action="a\\nb"'));
  assert.ok(!text.includes("p50") && text.includes("rv_vault_latency_p95_ms 3"));
  assert.ok(!text.includes("siem"));
});
