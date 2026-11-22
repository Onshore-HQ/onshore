import { test } from "node:test";
import assert from "node:assert/strict";
import { cnOf, escapeFilter, parseIdpMetadata } from "../src/identity-parse.js";

test("an email can't widen an LDAP search", () => {
  assert.equal(escapeFilter("*)(uid=*"), "\\2a\\29\\28uid=\\2a");
  assert.equal(escapeFilter("a\\b"), "a\\5cb");
  assert.equal(escapeFilter("sarah@bank.example"), "sarah@bank.example");
});

test("a group's name is read from its DN", () => {
  assert.equal(cnOf("CN=Onshore Admins,OU=Groups,DC=bank,DC=example"), "Onshore Admins");
  assert.equal(cnOf("cn=Risk\\, Fraud,ou=groups"), "Risk, Fraud");
  assert.equal(cnOf("ou=odd"), "ou=odd");
});

const META = `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/realms/onshore">
<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>ENCRYPTIONKEY</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIC
SIGNING</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example/post"/>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/redirect"/>
</md:IDPSSODescriptor></md:EntityDescriptor>`;

test("IdP metadata gives the redirect URL and the signing certificate, not the encryption one", () => {
  assert.deepEqual(parseIdpMetadata(META), { idp_sso_url: "https://idp.example/redirect", idp_cert: "MIICSIGNING", idp_entity_id: "https://idp.example/realms/onshore" });
  assert.deepEqual(parseIdpMetadata("<x/>"), { idp_sso_url: null, idp_cert: null, idp_entity_id: null });
});

import crypto from "node:crypto";
import { canonical, fingerprint, verifyFile } from "../src/ee/pack-file.js";

test("a pack file's signature covers every byte of its content", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const body = { format: "onshore-country-pack", format_version: 1, pack: { country: "MA", name: "Morocco", data_types: [{ slug: "c_ma_cin", name: "CIN" }], laws: [] }, signed_by: { organisation: "Acme", public_key: pub, fingerprint: fingerprint(pub) }, signed_at: "2026-11-22T10:00:00Z" };
  const signature = crypto.sign(null, Buffer.from(canonical(body)), privateKey).toString("base64url");
  // Key order doesn't matter: the same content verifies however it was serialised.
  const reordered = JSON.parse(JSON.stringify({ signature, signed_at: body.signed_at, signed_by: body.signed_by, pack: body.pack, format_version: 1, format: body.format }));
  const ok = verifyFile(reordered);
  assert.equal(ok.ok, true);
  assert.equal(ok.fingerprint, fingerprint(pub));
  assert.match(ok.fingerprint, /^[0-9A-F]{4}( [0-9A-F]{4}){7}$/);
  const changed = JSON.parse(JSON.stringify(reordered));
  changed.pack.data_types[0].name = "CIN (edited)";
  assert.equal(verifyFile(changed).ok, false);
  const { signature: _s, ...unsigned } = reordered;
  assert.equal(verifyFile(unsigned).ok, false);
  const other = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).toString("base64");
  assert.equal(verifyFile({ ...reordered, signed_by: { ...body.signed_by, public_key: other } }).ok, false);
});
