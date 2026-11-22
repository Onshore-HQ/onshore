import assert from "node:assert/strict";
import { test } from "node:test";
import { upstreamUrlProblem } from "../src/netguard.js";

test("IP literals that reach private addresses are refused, in every spelling", () => {
  for (const url of ["https://10.0.0.1/", "https://127.0.0.1/", "https://169.254.169.254/x", "https://[::1]/", "https://[fd00::1]/", "https://[::ffff:10.0.0.1]/", "https://[::ffff:a00:1]/", "https://[::ffff:7f00:1]/", "https://[64:ff9b::a00:1]/", "https://[2002:a00:1::]/", "https://2130706433/", "https://0x7f.0.0.1/", "https://vault-api/", "https://x.internal/", "http://example.ng/", "https://u:p@example.ng/", "nonsense"]) {
    assert.notEqual(upstreamUrlProblem(url), null, url);
  }
});

test("public destinations pass", () => {
  for (const url of ["https://idp.example.ng/", "https://8.8.8.8/", "https://[2606:4700:4700::1111]/"]) assert.equal(upstreamUrlProblem(url), null, url);
});
