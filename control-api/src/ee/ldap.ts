// Checks a person's password against the organisation's LDAP directory (Active
// Directory, OpenLDAP, FreeIPA…). Only encrypted connections: ldaps://, or ldap://
// upgraded with StartTLS. Onshore's own second factor still applies afterwards.

import dns from "node:dns/promises";
import { Client, type Entry } from "ldapts";
import { ApiError, db, decryptSecret, verifyPassword } from "../lib.js";
import { isPublicAddress } from "../netguard.js";
import { cnOf, escapeFilter } from "../identity-parse.js";

export interface LdapConfig {
  url: string; start_tls: boolean; ca_cert: string | null; bind_dn: string; bind_password_enc: string;
  base_dn: string; user_filter: string; group_base_dn: string | null; group_filter: string;
}
export interface DirectoryUser { dn: string; email: string; name: string; groups: string[]; externalId: string | null }


const first = (e: Entry, k: string) => { const v = e[k]; const x = Array.isArray(v) ? v[0] : v; return x === undefined ? "" : Buffer.isBuffer(x) ? x.toString("utf8") : String(x); };
const all = (e: Entry, k: string) => { const v = e[k]; return (Array.isArray(v) ? v : v === undefined ? [] : [v]).map((x) => (Buffer.isBuffer(x) ? x.toString("utf8") : String(x))); };

async function connect(cfg: LdapConfig, cloud: boolean): Promise<Client> {
  const u = new URL(cfg.url);
  // On Onshore Cloud a directory must be on the internet; self-hosted, it's usually inside the network.
  if (cloud && process.env.RV_ALLOW_PRIVATE_UPSTREAM !== "true") {
    const addrs = await dns.lookup(u.hostname, { all: true }).catch(() => []);
    if (!addrs.length || addrs.some((a) => !isPublicAddress(a.address))) throw new ApiError(400, "invalid_request", "the directory address is not public");
  }
  const tlsOptions = { ...(cfg.ca_cert ? { ca: [cfg.ca_cert] } : {}), minVersion: "TLSv1.2" as const, servername: u.hostname };
  const client = new Client({ url: cfg.url, timeout: 8000, connectTimeout: 5000, ...(u.protocol === "ldaps:" ? { tlsOptions } : {}) });
  if (u.protocol === "ldap:") {
    if (!cfg.start_tls) throw new ApiError(400, "invalid_request", "an unencrypted directory connection is refused; use ldaps:// or StartTLS");
    await client.startTLS(tlsOptions);
  }
  return client;
}

/** Finds a person by email with the service account, and reads their groups. */
async function lookup(client: Client, cfg: LdapConfig, email: string): Promise<DirectoryUser | null> {
  await client.bind(cfg.bind_dn, decryptSecret(cfg.bind_password_enc));
  const filter = cfg.user_filter.split("{email}").join(escapeFilter(email));
  const { searchEntries } = await client.search(cfg.base_dn, { scope: "sub", filter, sizeLimit: 2, attributes: ["dn", "mail", "cn", "displayName", "memberOf", "entryUUID", "objectGUID", "uid"] });
  // None, or more than one match: either way, nobody is let in.
  if (searchEntries.length !== 1) return null;
  const e = searchEntries[0]!;
  const groups = new Set(all(e, "memberOf").map(cnOf));
  if (cfg.group_base_dn) {
    const gf = cfg.group_filter.split("{dn}").join(escapeFilter(e.dn)).split("{email}").join(escapeFilter(email)).split("{uid}").join(escapeFilter(first(e, "uid")));
    const r = await client.search(cfg.group_base_dn, { scope: "sub", filter: gf, sizeLimit: 500, attributes: ["cn"] });
    for (const g of r.searchEntries) groups.add(first(g, "cn") || cnOf(g.dn));
  }
  const guid = e.objectGUID;
  return { dn: e.dn, email: (first(e, "mail") || email).toLowerCase(), name: first(e, "displayName") || first(e, "cn") || email, groups: [...groups], externalId: first(e, "entryUUID") || (Buffer.isBuffer(guid) ? guid.toString("hex") : null) };
}

/** The directory's answer for this email and password, or null if they don't match. */
export async function ldapAuthenticate(cfg: LdapConfig, email: string, password: string, cloud = false): Promise<DirectoryUser | null> {
  // An empty password makes many directories accept an unauthenticated bind.
  if (!password) return null;
  const client = await connect(cfg, cloud);
  try {
    const user = await lookup(client, cfg, email);
    if (!user) return null;
    try { await client.bind(user.dn, password); } catch { return null; }
    return user;
  } finally {
    await client.unbind().catch(() => undefined);
  }
}

/** For the settings page: can we connect and bind, and does this email resolve? */
export async function ldapTest(cfg: LdapConfig, email: string | undefined, cloud = false): Promise<{ ok: true; user: Omit<DirectoryUser, "dn"> & { dn: string } | null }> {
  let client: Client;
  try { client = await connect(cfg, cloud); } catch (e) { throw e instanceof ApiError ? e : new ApiError(400, "invalid_request", `could not connect: ${(e as Error).message.slice(0, 160)}`); }
  try {
    try { await client.bind(cfg.bind_dn, decryptSecret(cfg.bind_password_enc)); } catch (e) {
      const m = (e as Error).message;
      // With ldaps://, the connection is only made at the first bind: tell a TLS problem apart from a wrong password.
      const network = /certificate|self.signed|ssl|tls|ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EHOSTUNREACH|timeout/i.test(m);
      throw new ApiError(400, "invalid_request", `${network ? "could not connect securely" : "the service account could not sign in"}: ${m.slice(0, 160)}`);
    }
    return { ok: true, user: email ? await lookup(client, cfg, email) : null };
  } finally {
    await client.unbind().catch(() => undefined);
  }
}

/**
 * The directory that checks this person's password, if any: their domain has one,
 * and they came from it, have no password here, or are new.
 */
export async function ldapConfigFor(email: string, p: { tenant_id: string; source: string; password_hash: string | null } | null) {
  const domain = email.toLowerCase().split("@")[1] ?? "";
  const cfg = await db.ldap_configs.findFirst({ where: { email_domains: { has: domain }, ...(p ? { tenant_id: p.tenant_id } : {}) } });
  if (!cfg) return null;
  if (p && p.source !== "ldap" && p.password_hash) return null;
  return cfg;
}

/** Checks a signed-in person's password again, against the directory for directory people. */
export async function checkAnyPassword(p: { email: string | null; tenant_id: string; source: string; password_hash: string | null }, pw: string): Promise<boolean> {
  if (p.email) {
    const cfg = await ldapConfigFor(p.email, p);
    if (cfg) return !!(await ldapAuthenticate(cfg, p.email, pw).catch(() => null));
  }
  return verifyPassword(pw, p.password_hash);
}
