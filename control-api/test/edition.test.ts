import { test } from "node:test";
import assert from "node:assert/strict";

// lib.ts reads these at import; the vault is deliberately unreachable.
process.env.VAULT_INTERNAL_URL = "http://127.0.0.1:1";
process.env.DATABASE_URL ??= "postgres://unused:unused@127.0.0.1:1/unused";
process.env.RV_INTERNAL_TOKEN ??= "x".repeat(32);
process.env.RV_USER_TOKEN_SEED ??= Buffer.alloc(32).toString("base64");
process.env.RV_CONTROL_SECRET ??= "x".repeat(32);

const { default: Fastify } = await import("fastify");
const { gated, has } = await import("../src/edition.js");
const { advancedFeatures } = await import("../src/ee/advanced-rules.js");
const { sendError } = await import("../src/lib.js");

async function app() {
  const a = Fastify();
  a.setErrorHandler((err, _req, reply) => sendError(reply, err));
  await a.register(gated("business", "webhooks", async (x) => {
    x.get("/thing", async () => ({ ok: true }));
    x.post("/thing", async () => ({ ok: true }));
    x.delete("/thing", async () => ({ ok: true }));
  }));
  await a.register(gated("business", "reports", async (x) => { x.get("/report", async () => ({ ok: true })); }, { all: true }));
  return a;
}

test("levels", () => {
  assert.ok(has("enterprise", "business"));
  assert.ok(has("development", "enterprise"));
  assert.ok(has("cloud", "enterprise"));
  assert.ok(!has("business", "enterprise"));
  assert.ok(!has("free", "business"));
});

test("an unreachable vault means Community: writes refused, reads and deletes open", async () => {
  delete process.env.RV_CLOUD;
  const a = await app();
  const post = await a.inject({ method: "POST", url: "/thing", payload: {} });
  assert.equal(post.statusCode, 403);
  assert.equal(post.json().error.code, "needs_business");
  assert.equal((await a.inject({ method: "GET", url: "/thing" })).statusCode, 200);
  assert.equal((await a.inject({ method: "DELETE", url: "/thing" })).statusCode, 200);
  assert.equal((await a.inject({ method: "GET", url: "/report" })).statusCode, 403);
});

test("Onshore Cloud has every feature", async () => {
  process.env.RV_CLOUD = "1";
  try {
    const a = await app();
    assert.equal((await a.inject({ method: "POST", url: "/thing", payload: {} })).statusCode, 200);
    assert.equal((await a.inject({ method: "GET", url: "/report" })).statusCode, 200);
  } finally {
    delete process.env.RV_CLOUD;
  }
});

test("advanced rule features", () => {
  assert.deepEqual(advancedFeatures({ rules: [{ who: { roles: ["support"] }, when: {} }] }), []);
  assert.deepEqual(advancedFeatures({ limit_per_hour: 50, rules: [{ who: { networks: ["office"], require_mfa: true }, when: { purpose_required: true, hour_from: 8, hour_to: 18 } }] }).sort(),
    ["MFA conditions", "network conditions", "office hours", "required purposes", "reveal limits"]);
  assert.deepEqual(advancedFeatures(undefined), []);
});
