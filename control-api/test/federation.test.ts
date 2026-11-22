import { test } from "node:test";
import assert from "node:assert/strict";
import { reportSchema, sign } from "../src/ee/federation-protocol.js";

const report = { version: "dev", country: "GB", vaults: [{ id: "v_live_1", name: "Acme · United Kingdom", country: "GB", environment: "production", packs: ["everywhere", "gb"], fields: 9 }], detections_7d: { uk_nino: 12 }, reveals_7d: { plaintext: 1, masked: 4, denied: 0 } };

test("a report carries names, settings and counts", () => {
  assert.equal(reportSchema.parse(report).vaults[0]!.name, "Acme · United Kingdom");
});

test("a report cannot carry anything else, such as a value or a token", () => {
  assert.throws(() => reportSchema.parse({ ...report, sample: "AB 12 34 56 C" }));
  assert.throws(() => reportSchema.parse({ ...report, vaults: [{ ...report.vaults[0], tokens: ["tok_x"] }] }));
  assert.throws(() => reportSchema.parse({ ...report, detections_7d: { uk_nino: "AB 12 34 56 C" } }));
});

test("signatures bind the timestamp and the exact body", () => {
  const body = JSON.stringify(report);
  const s = sign("secret", "1000", body);
  assert.equal(s, sign("secret", "1000", body));
  assert.notEqual(s, sign("secret", "1001", body));
  assert.notEqual(s, sign("secret", "1000", body.replace("12", "13")));
  assert.notEqual(s, sign("other", "1000", body));
});
