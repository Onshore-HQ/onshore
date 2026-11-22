import crypto from "node:crypto";
import { SAML, ValidateInResponseTo } from "@node-saml/node-saml";
import type { FastifyInstance } from "fastify";
import { createRemoteJWKSet, customFetch, jwtVerify } from "jose";
import { Agent, fetch as undiciFetch } from "undici";
import { z } from "zod";
import { ApiError, audit, checkUpstreamUrl, clientIp, db, decryptSecret, encryptSecret, issueToken, requireRole, TOKEN_TTL_SECONDS, WRITE } from "../lib.js";
import { guardedLookup } from "../netguard.js";
import { parseIdpMetadata } from "../identity-parse.js";
import { asList, provision, publicOrigin, requireIdentityEdition, rolesForGroups, setRoles } from "../identity.js";

const denied = () => new ApiError(401, "unauthenticated", "single sign-on could not be completed");
const sha = (s: string) => crypto.createHash("sha256").update(s).digest("hex");
const b64u = (b: Buffer) => b.toString("base64url");

const idpAgent = new Agent({ connect: { lookup: guardedLookup("identity provider address is not public") } });
const idpFetch = (url: string, init: Record<string, unknown> = {}) => undiciFetch(url, { ...init, dispatcher: idpAgent, redirect: "error", signal: AbortSignal.timeout(10_000) });

async function discovery(issuer: string) {
  const r = await idpFetch(`${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`);
  if (!r.ok) throw denied();
  const d = (await r.json()) as { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string };
  // The discovery document must name the issuer it was fetched from.
  if (d.issuer.replace(/\/$/, "") !== issuer.replace(/\/$/, "")) throw denied();
  for (const u of [d.authorization_endpoint, d.token_endpoint, d.jwks_uri]) checkUpstreamUrl(u);
  return d;
}

const callbackUrl = () => `${publicOrigin()}/api/session/sso`;
const spEntityId = (c: { sp_entity_id: string | null }) => c.sp_entity_id ?? publicOrigin();

function samlClient(c: { idp_sso_url: string | null; idp_cert: string | null; sp_entity_id: string | null }) {
  return new SAML({
    entryPoint: c.idp_sso_url!,
    idpCert: c.idp_cert!,
    issuer: spEntityId(c),
    callbackUrl: callbackUrl(),
    audience: spEntityId(c),
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false,
    signatureAlgorithm: "sha256",
    digestAlgorithm: "sha256",
    validateInResponseTo: ValidateInResponseTo.never, // checked by the single-use state below
    acceptedClockSkewMs: 30_000,
    disableRequestedAuthnContext: true,
  });
}

interface Identity { email: string; name?: string; groups: string[] | null; externalId?: string }
type Cfg = { tenant_id: string; email_domains: string[]; jit_provisioning: boolean };

/**
 * Maps a verified identity to a person. Groups the provider sends decide roles when
 * the organisation maps any; with "create on first sign-in" on, someone new with a
 * mapped group gets an account. Otherwise an admin must have added them first.
 */
async function finish(cfg: Cfg, who: Identity, ip: string, kind: string) {
  const lower = who.email.toLowerCase();
  const domain = lower.split("@")[1] ?? "";
  if (!cfg.email_domains.includes(domain)) throw denied();
  const tenantId = cfg.tenant_id;
  // Roles follow groups only when the provider sent a groups list at all.
  const mapped = who.groups ? await rolesForGroups(tenantId, who.groups) : null;
  let p = await db.principals.findUnique({ where: { email: lower } });
  let created = false;
  if (!p) {
    if (!cfg.jit_provisioning || !mapped?.length) throw denied();
    await provision(tenantId, { email: lower, displayName: who.name ?? lower, source: "sso", externalId: who.externalId, roles: mapped });
    p = await db.principals.findUnique({ where: { email: lower } });
    created = true;
  }
  if (!p || p.tenant_id !== tenantId || p.kind !== "user" || p.status !== "active") throw denied();
  let roles: string[] | undefined;
  if (mapped && !created) {
    const r = await setRoles(tenantId, p.id, mapped);
    roles = r.roles;
    // Someone left with no role can do nothing here, so they are not let in.
    if (!r.roles.length) throw denied();
  }
  await db.principals.update({ where: { id: p.id }, data: { mfa_enabled: true, must_change_password: false, last_active_at: new Date() } });
  await audit({ tenantId, id: p.id, ip }, "login", { detail: { via: kind, ...(created ? { created: true, roles: mapped } : {}), ...(roles ? { roles } : {}) } });
  return { step: "done", access_token: issueToken(p.id, tenantId), expires_in: TOKEN_TTL_SECONDS };
}

const SAML_EMAIL = ["email", "mail", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"];
const SAML_NAME = ["displayName", "name", "http://schemas.microsoft.com/identity/claims/displayname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"];
const SAML_GROUPS = ["groups", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", "memberOf", "Role", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"];


async function takeState(state: string) {
  const row = await db.sso_states.findUnique({ where: { state_hash: sha(state) } });
  if (!row) throw denied();
  // Single use, whether or not the rest succeeds.
  await db.sso_states.delete({ where: { state_hash: row.state_hash } });
  if (row.expires_at < new Date()) throw denied();
  const cfg = await db.sso_configs.findUnique({ where: { tenant_id: row.tenant_id } });
  if (!cfg) throw denied();
  return { row, cfg };
}

export async function ssoRoutes(app: FastifyInstance) {
  app.get("/v1/settings/sso", async (req) => {
    const a = requireRole(req, ...WRITE);
    const c = await db.sso_configs.findUnique({ where: { tenant_id: a.tenantId } });
    const sp = { callback_url: callbackUrl(), entity_id: spEntityId({ sp_entity_id: c?.sp_entity_id ?? null }), metadata_url: `${publicOrigin()}/control/v1/auth/sso/saml/metadata/${a.tenantId}` };
    if (!c) return { config: null, sp };
    const { client_secret_enc: _s, ...rest } = c;
    return { config: { ...rest, has_client_secret: !!_s }, sp };
  });

  app.put("/v1/settings/sso", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z
      .object({
        kind: z.enum(["oidc", "saml"]),
        email_domains: z.array(z.string().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/)).min(1),
        issuer: z.string().optional(),
        client_id: z.string().optional(),
        client_secret: z.string().optional(),
        idp_sso_url: z.string().optional(),
        idp_cert: z.string().optional(),
        sp_entity_id: z.string().optional(),
        idp_enforces_mfa: z.boolean(),
        sso_only: z.boolean().default(false),
        jit_provisioning: z.boolean().default(false),
        groups_attribute: z.string().max(200).nullish(),
        scopes: z.string().regex(/^openid( [\w:./-]+){0,10}$/, "scopes must start with openid").default("openid email profile"),
        provider: z.string().max(40).nullish(),
      })
      .parse(req.body);
    await requireIdentityEdition();
    const existing = await db.sso_configs.findUnique({ where: { tenant_id: a.tenantId } });
    if (b.kind === "oidc") {
      if (!b.issuer || !b.client_id || (!b.client_secret && !existing?.client_secret_enc)) throw new ApiError(400, "invalid_request", "OIDC needs an issuer, client id and client secret");
      checkUpstreamUrl(b.issuer);
    } else {
      if (!b.idp_sso_url || !b.idp_cert) throw new ApiError(400, "invalid_request", "SAML needs the IdP's sign-in URL and signing certificate");
      checkUpstreamUrl(b.idp_sso_url);
    }
    // Console access requires MFA, so an IdP that does not enforce it cannot stand in.
    if (!b.idp_enforces_mfa) throw new ApiError(400, "invalid_request", "turn on MFA at your identity provider, then confirm it here");
    const { client_secret, ...fields } = b;
    const data = { ...fields, groups_attribute: fields.groups_attribute || null, provider: fields.provider || null, client_secret_enc: client_secret ? encryptSecret(client_secret) : b.kind === "oidc" ? existing?.client_secret_enc ?? null : null };
    await db.sso_configs.upsert({ where: { tenant_id: a.tenantId }, create: { tenant_id: a.tenantId, ...data }, update: data });
    await audit(a, "sso_configure", { detail: { kind: b.kind, domains: b.email_domains, sso_only: b.sso_only, jit: b.jit_provisioning, provider: b.provider ?? null } });
    return { ok: true };
  });

  // Paste the IdP's metadata instead of copying its URL and certificate by hand.
  app.post("/v1/settings/sso/parse-metadata", async (req) => {
    requireRole(req, ...WRITE);
    const b = z.object({ xml: z.string().min(50).max(200_000) }).parse(req.body);
    const out = parseIdpMetadata(b.xml);
    if (!out.idp_sso_url || !out.idp_cert) throw new ApiError(400, "invalid_request", "no sign-in URL and signing certificate found in that metadata");
    return out;
  });

  // What the IdP needs to know about Onshore, as SAML metadata. Public, like any SP's.
  app.get<{ Params: { tenant: string } }>("/v1/auth/sso/saml/metadata/:tenant", async (req, reply) => {
    const c = await db.sso_configs.findUnique({ where: { tenant_id: req.params.tenant } });
    const xml = samlClient({ idp_sso_url: c?.idp_sso_url ?? `${publicOrigin()}/unset`, idp_cert: c?.idp_cert ?? "unset", sp_entity_id: c?.sp_entity_id ?? null }).generateServiceProviderMetadata(null, null);
    return reply.type("application/samlmetadata+xml").send(xml);
  });

  app.delete("/v1/settings/sso", async (req) => {
    const a = requireRole(req, ...WRITE);
    await db.sso_configs.deleteMany({ where: { tenant_id: a.tenantId } });
    await audit(a, "sso_remove");
    return { ok: true };
  });

  // Starts sign-in for an email's domain. It answers the same for any unknown domain.
  app.post("/v1/auth/sso/start", async (req) => {
    const b = z.object({ email: z.email() }).parse(req.body);
    const domain = b.email.toLowerCase().split("@")[1]!;
    const cfg = await db.sso_configs.findFirst({ where: { email_domains: { has: domain } } });
    if (!cfg) return { sso: false };
    const state = b64u(crypto.randomBytes(32));
    const nonce = b64u(crypto.randomBytes(32));
    const verifier = b64u(crypto.randomBytes(48));
    await db.sso_states.deleteMany({ where: { expires_at: { lt: new Date() } } });
    await db.sso_states.create({ data: { state_hash: sha(state), tenant_id: cfg.tenant_id, nonce, verifier, expires_at: new Date(Date.now() + 10 * 60_000) } });
    if (cfg.kind === "saml") {
      const url = await samlClient(cfg).getAuthorizeUrlAsync(state, undefined, {});
      return { sso: true, redirect: url };
    }
    const d = await discovery(cfg.issuer!);
    const u = new URL(d.authorization_endpoint);
    u.search = new URLSearchParams({ response_type: "code", client_id: cfg.client_id!, redirect_uri: callbackUrl(), scope: cfg.scopes, state, nonce, code_challenge: b64u(crypto.createHash("sha256").update(verifier).digest()), code_challenge_method: "S256" }).toString();
    return { sso: true, redirect: u.toString() };
  });

  app.post("/v1/auth/sso/oidc", async (req) => {
    const b = z.object({ state: z.string().max(200), code: z.string().max(4000) }).parse(req.body);
    const { row, cfg } = await takeState(b.state);
    if (cfg.kind !== "oidc") throw denied();
    const d = await discovery(cfg.issuer!);
    const res = await idpFetch(d.token_endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code: b.code, redirect_uri: callbackUrl(), client_id: cfg.client_id!, client_secret: decryptSecret(cfg.client_secret_enc!), code_verifier: row.verifier }).toString() });
    if (!res.ok) throw denied();
    const tok = (await res.json()) as { id_token?: string };
    if (!tok.id_token) throw denied();
    const jwks = createRemoteJWKSet(new URL(d.jwks_uri), { [customFetch]: ((url: string, init: Record<string, unknown>) => idpFetch(url, init)) as never });
    let claims;
    try {
      // Asymmetric only: a client-secret-signed token could be forged by anyone holding the secret.
      ({ payload: claims } = await jwtVerify(tok.id_token, jwks, { issuer: d.issuer, audience: cfg.client_id!, algorithms: ["RS256", "ES256", "PS256", "EdDSA"], clockTolerance: 30 }));
    } catch {
      throw denied();
    }
    // A named groups claim that's missing means "in no groups", as providers omit empty lists.
    // Entra puts the address in preferred_username when no email claim is configured.
    const email = typeof claims.email === "string" ? claims.email : typeof claims.preferred_username === "string" && claims.preferred_username.includes("@") ? claims.preferred_username : null;
    if (claims.nonce !== row.nonce || !email || claims.email_verified === false) throw denied();
    const gk = cfg.groups_attribute || "groups";
    const name = typeof claims.name === "string" ? claims.name : [claims.given_name, claims.family_name].filter((x) => typeof x === "string").join(" ") || undefined;
    return finish(cfg, { email, name, groups: gk in claims ? asList(claims[gk]) : cfg.groups_attribute ? [] : null, externalId: typeof claims.sub === "string" ? claims.sub : undefined }, clientIp(req), "oidc");
  });

  app.post("/v1/auth/sso/saml", async (req) => {
    const b = z.object({ SAMLResponse: z.string().max(1 << 20), RelayState: z.string().max(200) }).parse(req.body);
    const { cfg } = await takeState(b.RelayState);
    if (cfg.kind !== "saml") throw denied();
    let profile;
    try {
      ({ profile } = await samlClient(cfg).validatePostResponseAsync({ SAMLResponse: b.SAMLResponse }));
    } catch {
      throw denied();
    }
    if (!profile) throw denied();
    const attr = (keys: string[]) => { for (const k of keys) if (k in profile) return profile[k]; return undefined; };
    const nameId = typeof profile.nameID === "string" && profile.nameID.includes("@") ? profile.nameID : undefined;
    const email = nameId ?? asList(attr(SAML_EMAIL))[0];
    if (!email) throw denied();
    const gkeys = cfg.groups_attribute ? [cfg.groups_attribute] : SAML_GROUPS;
    // With a groups attribute named, a provider that leaves it out means "in no groups":
    // Keycloak and others omit an empty list rather than sending one.
    const groups = gkeys.some((k) => k in profile) ? asList(attr(gkeys)) : cfg.groups_attribute ? [] : null;
    return finish(cfg, { email, name: asList(attr(SAML_NAME))[0], groups, externalId: typeof profile.nameID === "string" ? profile.nameID : undefined }, clientIp(req), "saml");
  });
}

