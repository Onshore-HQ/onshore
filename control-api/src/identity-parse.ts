// Pure helpers for single sign-on and LDAP, kept apart so tests need no database.

/** Escapes a value for an LDAP search filter (RFC 4515), so an email can't widen the search. */
export function escapeFilter(v: string) {
  return v.replace(/[\\*()\0]/g, (c) => `\\${c.charCodeAt(0).toString(16).padStart(2, "0")}`);
}

/** "CN=Onshore Admins,OU=Groups,DC=bank,DC=example" → "Onshore Admins". */
export const cnOf = (dn: string) => dn.match(/^\s*cn=((?:\\,|[^,])+)/i)?.[1]?.replace(/\\,/g, ",").trim() ?? dn;

/** The IdP's sign-in URL, signing certificate and entity ID, read from its metadata XML. */
export function parseIdpMetadata(xml: string) {
  const idp = xml.match(/<(?:\w+:)?IDPSSODescriptor[\s\S]*?<\/(?:\w+:)?IDPSSODescriptor>/)?.[0] ?? "";
  const services = [...idp.matchAll(/<(?:\w+:)?SingleSignOnService\b[^>]*>/g)].map((m) => m[0]);
  const pick = services.find((t) => /HTTP-Redirect/.test(t)) ?? services.find((t) => /HTTP-POST/.test(t));
  const url = pick?.match(/Location="([^"]+)"/)?.[1] ?? null;
  const keys = [...idp.matchAll(/<(?:\w+:)?KeyDescriptor\b([^>]*)>([\s\S]*?)<\/(?:\w+:)?KeyDescriptor>/g)];
  const signing = keys.find((k) => !/use="encryption"/.test(k[1] ?? ""));
  const cert = (signing?.[2] ?? "").match(/<(?:\w+:)?X509Certificate>([\s\S]*?)<\/(?:\w+:)?X509Certificate>/)?.[1]?.replace(/\s+/g, "") ?? null;
  const entityId = xml.match(/<(?:\w+:)?EntityDescriptor\b[^>]*entityID="([^"]+)"/)?.[1] ?? null;
  return { idp_sso_url: url, idp_cert: cert, idp_entity_id: entityId };
}
