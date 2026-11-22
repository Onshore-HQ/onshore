import assert from "node:assert/strict";
import { test } from "node:test";

process.env.VAULT_INTERNAL_URL ??= "https://unused:1";
process.env.DATABASE_URL ??= "postgres://unused:unused@127.0.0.1:1/unused";
process.env.RV_INTERNAL_TOKEN ??= "x".repeat(32);
process.env.RV_USER_TOKEN_SEED ??= Buffer.alloc(32).toString("base64");
process.env.RV_CONTROL_SECRET ??= "x".repeat(32);
const { parseReport, sameOrigin, scriptsInHtml, scrubUrl } = await import("../src/pageprotect.js");

test("a stored address loses its query, fragment and anything that looks like a value", () => {
  assert.equal(scrubUrl("https://cdn.x.ng/a/b.js?bvn=22333444558&x=1#frag"), "https://cdn.x.ng/a/b.js");
  assert.equal(scrubUrl("https://x.ng/collect/22333444558/s.js"), "https://x.ng/collect/[removed]/s.js");
  assert.equal(scrubUrl("https://x.ng/u/2233-344-4558/s.js"), "https://x.ng/u/[removed]/s.js");
  assert.equal(scrubUrl("https://x.ng/ada%40example.ng/s.js"), "https://x.ng/[removed]/s.js");
  assert.equal(scrubUrl("https://x.ng/v1.2.3/lib-20260101.js"), "https://x.ng/v1.2.3/lib-20260101.js");
  assert.equal(scrubUrl("/app.js", "https://x.ng"), "https://x.ng/app.js");
  assert.equal(scrubUrl("inline"), "inline");
});

test("only real web addresses are kept", () => {
  for (const bad of ["javascript:alert(1)", "data:text/javascript,1", "file:///etc/passwd", "", 7, null, "x".repeat(5000)]) assert.equal(scrubUrl(bad), null, String(bad));
});

test("all three report formats parse, and other directives are ignored", () => {
  const legacy = JSON.stringify({ "csp-report": { "document-uri": "https://a.ng/kyc", "blocked-uri": "https://evil.x/s.js", "effective-directive": "script-src-elem" } });
  assert.deepEqual(parseReport(legacy), [{ document: "https://a.ng/kyc", scripts: ["https://evil.x/s.js"], source: "csp" }]);
  const api = JSON.stringify([{ type: "csp-violation", body: { documentURL: "https://a.ng/", blockedURL: "inline", effectiveDirective: "script-src" } }, { type: "deprecation", body: {} }]);
  assert.deepEqual(parseReport(api), [{ document: "https://a.ng/", scripts: ["inline"], source: "csp" }]);
  assert.deepEqual(parseReport(JSON.stringify({ page: "https://a.ng", scripts: ["https://b/c.js", 3] })), [{ document: "https://a.ng", scripts: ["https://b/c.js"], source: "watcher" }]);
  assert.deepEqual(parseReport(JSON.stringify({ "csp-report": { "document-uri": "https://a.ng", "blocked-uri": "https://f/x.png", "effective-directive": "img-src" } })), []);
  for (const junk of ["", "not json", "null", "[1,2]", '{"a":1}', '"x"']) assert.deepEqual(parseReport(junk), [], junk);
});

test("a report must come from the page's own origin", () => {
  assert.ok(sameOrigin("https://a.ng/kyc?x=1", "https://a.ng"));
  assert.ok(!sameOrigin("https://a.ng.evil.x/", "https://a.ng"));
  assert.ok(!sameOrigin("http://a.ng/", "https://a.ng"));
  assert.ok(!sameOrigin("", "https://a.ng"));
  assert.ok(!sameOrigin(null, "https://a.ng"));
});

test("script tags are read from HTML, in every quoting style", () => {
  const html = `<script src="https://a/1.js"></script><SCRIPT defer src='/2.js'></SCRIPT><script src=3.js></script><script>var s = 1</script><img src="https://a/no.png">`;
  assert.deepEqual(scriptsInHtml(html, "https://x.ng/p/"), ["https://a/1.js", "https://x.ng/2.js", "https://x.ng/p/3.js"]);
});
