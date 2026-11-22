import assert from "node:assert/strict";
import { test } from "node:test";
import { computeStatus, DAY, FlowFacts, matchVendor, resolveCountry, scores, stableUuid, suggestRegion } from "../src/map/engine.js";

const now = new Date("2026-11-05T12:00:00Z");
const ago = (days: number) => new Date(now.getTime() - days * DAY);
const base: FlowFacts = { retired: false, exceptionActive: false, destCountry: null, homeCountry: "NG", destCountrySource: "unconfirmed", routeMode: "enforcing", routeModeSince: ago(10), inScope: true, entityCount: 1, unprotected: 0, current: "shadow", statusSince: ago(10), now };
const status = (o: Partial<FlowFacts>) => computeStatus({ ...base, ...o }).status;

test("rule order: retired beats everything", () => assert.equal(status({ retired: true, exceptionActive: true, destCountry: "NG", destCountrySource: "declared" }), "retired"));
test("rule order: an exception beats location and traffic", () => assert.equal(status({ exceptionActive: true, destCountry: "NG", destCountrySource: "declared", unprotected: 5 }), "exception"));
test("rule order: the vault's own country beats traffic", () => assert.equal(status({ destCountry: "NG", destCountrySource: "vendor_region", unprotected: 5 }), "in_country"));
test("an unconfirmed guess of the vault's country is not in-country", () => assert.notEqual(status({ destCountry: "NG", destCountrySource: "unconfirmed" }), "in_country"));
test("a route in shadow is shadow, even with passes", () => assert.equal(status({ routeMode: "shadow", unprotected: 99 }), "shadow"));
test("criterion 2: enforcing for under 7 days stays amber, and says how far along", () => {
  const c = computeStatus({ ...base, routeModeSince: ago(3) });
  assert.equal(c.status, "shadow");
  assert.deepEqual(c.proving, { day: 4, of: 7 });
});
test("criterion 2: enforcing 7 clean days is protected", () => assert.equal(status({ routeModeSince: ago(7) }), "protected"));
test("a pass during the proving week is a leak at once", () => assert.equal(status({ routeModeSince: ago(1), unprotected: 1 }), "leaking"));
test("30 days protected is verified", () => assert.equal(status({ current: "protected", statusSince: ago(30) }), "verified"));
test("29 days protected is not", () => assert.equal(status({ current: "protected", statusSince: ago(29) }), "protected"));
test("verified stays verified while clean", () => assert.equal(status({ current: "verified", statusSince: ago(90) }), "verified"));
test("criterion 3: one pass drops verified to leaking", () => assert.equal(status({ current: "verified", statusSince: ago(90), unprotected: 1 }), "leaking"));
test("the 30-day clock restarts: a leak that clears is protected, not verified", () => assert.equal(status({ current: "leaking", statusSince: ago(40) }), "protected"));
test("an out-of-scope flow does not leak", () => assert.equal(status({ inScope: false, unprotected: 9 }), "protected"));
const manual = { routeMode: null, routeModeSince: null } as const;
test("manual offshore in scope leaks", () => assert.equal(status({ ...manual, destCountry: "IE", destCountrySource: "vendor_region" }), "leaking"));
test("manual with no location is unverified", () => assert.equal(status({ ...manual }), "unverified"));
test("manual offshore holding nothing in scope is unverified", () => assert.equal(status({ ...manual, destCountry: "IE", destCountrySource: "declared", inScope: false }), "unverified"));
test("manual offshore with no entity types is unverified", () => assert.equal(status({ ...manual, destCountry: "IE", destCountrySource: "declared", entityCount: 0 }), "unverified"));

test("scores: unverified counts against, retired and out-of-scope do not count", () => {
  const s = scores([
    { status: "protected", in_scope: true, protected_30d: 90, passed_30d: 0 },
    { status: "unverified", in_scope: true, protected_30d: 0, passed_30d: 0 },
    { status: "retired", in_scope: true, protected_30d: 0, passed_30d: 1000 },
    { status: "leaking", in_scope: false, protected_30d: 0, passed_30d: 1000 },
  ]);
  assert.equal(s.flow_score, 50);
  assert.equal(s.volume_score, 100);
});
test("scores: one large leak shows in volume, not in flows", () => {
  const s = scores([...Array(9).fill({ status: "protected", in_scope: true, protected_30d: 1, passed_30d: 0 }), { status: "leaking", in_scope: true, protected_30d: 0, passed_30d: 991 }]);
  assert.equal(s.flow_score, 90);
  assert.equal(s.volume_score, 0.9);
});
test("scores: exceptions are separated", () => {
  const s = scores([{ status: "exception", in_scope: true, protected_30d: 0, passed_30d: 0 }, { status: "leaking", in_scope: true, protected_30d: 0, passed_30d: 0 }]);
  assert.equal(s.flow_score, 50);
  assert.equal(s.flow_score_without_exceptions, 0);
});
test("scores: in-country traffic counts as staying", () => assert.equal(scores([{ status: "in_country", in_scope: true, protected_30d: 0, passed_30d: 10 }]).volume_score, 100));
test("scores: nothing to score is null, not 100", () => assert.equal(scores([]).flow_score, null));

const vendors = [
  { id: "dd", hostnames: ["*.datadoghq.com", "*.datadoghq.eu"], regions: [{ code: "us5", country: "US", hosts: ["us5.datadoghq.com"] }, { code: "eu1", country: "DE", hosts: ["datadoghq.eu"] }] },
  { id: "aws", hostnames: ["*.amazonaws.com"], regions: [] },
  { id: "bedrock", hostnames: ["bedrock-runtime.*.amazonaws.com"], regions: [] },
  { id: "oa", hostnames: ["api.openai.com"], regions: [] },
];
test("vendor match: subdomain and apex", () => { assert.equal(matchVendor("http-intake.logs.us5.datadoghq.com", vendors)?.id, "dd"); assert.equal(matchVendor("datadoghq.eu", vendors)?.id, "dd"); });
test("vendor match: most specific wins", () => assert.equal(matchVendor("bedrock-runtime.eu-central-1.amazonaws.com", vendors)?.id, "bedrock"));
test("vendor match: a lookalike does not match", () => { assert.equal(matchVendor("datadoghq.com.evil.example", vendors), null); assert.equal(matchVendor("notdatadoghq.com", vendors), null); assert.equal(matchVendor("api.openai.com.evil.example", vendors), null); });
test("a suggested region is only a suggestion", () => assert.equal(suggestRegion("us5.datadoghq.com", vendors[0]!.regions), "us5"));
test("country: confirmed region wins, then declaration, else unconfirmed", () => {
  const regions = [{ code: "aws-eu-west-1", country: "IE" }];
  assert.deepEqual(resolveCountry({ flowRegion: "aws-eu-west-1", systemRegion: null, hostingCountry: "NG", regions }), { country: "IE", source: "vendor_region" });
  assert.deepEqual(resolveCountry({ flowRegion: null, systemRegion: null, hostingCountry: "NG", regions }), { country: "NG", source: "declared" });
  assert.deepEqual(resolveCountry({ flowRegion: null, systemRegion: null, hostingCountry: null, regions }), { country: null, source: "unconfirmed" });
});
test("stable alert ids are valid and repeatable", () => {
  const u = stableUuid(Buffer.alloc(32, 7));
  assert.match(u, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(u, stableUuid(Buffer.alloc(32, 7)));
});

test("in-country means the vault's country, not a fixed one", () => {
  assert.equal(status({ homeCountry: "GB", destCountry: "GB", destCountrySource: "declared", unprotected: 5 }), "in_country");
  assert.notEqual(status({ homeCountry: "GB", destCountry: "NG", destCountrySource: "declared", unprotected: 5 }), "in_country");
});
