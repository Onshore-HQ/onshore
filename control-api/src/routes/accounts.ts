import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { actor, ApiError, audit, badRequest, base32, clientIp, db, decryptSecret, encryptSecret, hashPassword, matchTotp, newId, notFound, READ_CONFIG, requireRole, verifyPassword, WRITE } from "../lib.js";
import { MailError, mailFor, notify, sendWith } from "../mail.js";
import { checkLock, passwordRule, recordFailure } from "./auth.js";
import { checkAnyPassword } from "../ee/ldap.js";
import { finishRegistration, registrationOptions } from "../passkeys.js";

const INVITE_DAYS = 7;
const RESET_MINUTES = 60;
export const sha = (t: string) => crypto.createHash("sha256").update(t).digest("hex");

/** A new single-use link. It replaces any earlier link of the same kind. */
export async function issueAccountToken(tenantId: string, principalId: string, kind: "invite" | "password_reset", createdBy: string | null) {
  const token = crypto.randomBytes(32).toString("base64url");
  const ms = kind === "invite" ? INVITE_DAYS * 86_400_000 : RESET_MINUTES * 60_000;
  await db.$transaction([
    db.account_tokens.updateMany({ where: { principal_id: principalId, kind, used_at: null, revoked_at: null }, data: { revoked_at: new Date() } }),
    db.account_tokens.create({ data: { id: newId("atk"), tenant_id: tenantId, principal_id: principalId, kind, token_hash: sha(token), created_by: createdBy, expires_at: new Date(Date.now() + ms) } }),
  ]);
  return token;
}

const link = (base: string, token: string) => `${base.replace(/\/+$/, "")}/account#token=${token}`;

/** Emails the link if it can. If not, the admin gets the token to pass on themselves. */
export async function deliverAccountLink(tenantId: string, to: string, kind: "invite" | "password_reset", token: string, name: string) {
  const cfg = await mailFor(tenantId);
  if (!cfg) return { emailed: false, token, reason: "not_configured" };
  const org = (await db.tenants.findUnique({ where: { id: tenantId } }))?.name ?? "your organisation";
  const url = link(cfg.console_url, token);
  const [subject, text] = kind === "invite"
    ? [`You've been invited to Onshore`, `Hello ${name},\n\nYou've been added to Onshore for ${org}. Choose a password here. The link works once, for ${INVITE_DAYS} days:\n\n${url}\n\nYou will then set up two-factor authentication.\n\nIf you weren't expecting this, ignore this email.`]
    : [`Reset your Onshore password`, `Hello ${name},\n\nUse this link to choose a new password. It works once, for ${RESET_MINUTES} minutes:\n\n${url}\n\nYou will still need your two-factor code to sign in.\n\nIf you didn't ask for this, your password hasn't changed. Tell your admin.`];
  try {
    await sendWith(cfg, to, subject, text);
    return { emailed: true };
  } catch (e) {
    return { emailed: false, token, reason: "failed", message: e instanceof MailError ? e.message : "The email could not be sent." };
  }
}

const mailBody = z.object({
  host: z.string().min(1).max(253).regex(/^[A-Za-z0-9.:_-]+$/, "use a host name or address"),
  port: z.number().int().min(1).max(65535),
  tls_mode: z.enum(["starttls", "tls", "none"]),
  username: z.string().max(254).nullish(),
  password: z.string().max(500).optional(),
  from_address: z.email(),
  from_name: z.string().min(1).max(80).regex(/^[^\r\n<>"]+$/, "use plain words").default("Onshore"),
  console_url: z.url().max(300).refine((u) => { const x = new URL(u); return x.protocol === "https:" || x.hostname === "localhost"; }, "use an https address"),
  alerts_enabled: z.boolean().default(true),
});

export async function accountRoutes(app: FastifyInstance) {
  // ---- Email settings -------------------------------------------------------------
  app.get("/v1/settings/mail", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const c = await db.mail_settings.findUnique({ where: { tenant_id: a.tenantId } });
    if (!c) return { configured: false };
    const { password_enc, ...rest } = c;
    return { configured: true, ...rest, has_password: Boolean(password_enc) };
  });

  app.put("/v1/settings/mail", async (req) => {
    const a = requireRole(req, ...WRITE);
    const { password, ...b } = mailBody.parse(req.body);
    const before = await db.mail_settings.findUnique({ where: { tenant_id: a.tenantId } });
    // An empty field keeps the saved password, unless the username was cleared too.
    const password_enc = !b.username ? null : password ? encryptSecret(password) : before?.password_enc ?? null;
    if (b.tls_mode === "none" && password_enc) throw badRequest("a password can't be sent without a secure connection");
    const data = { ...b, username: b.username || null, password_enc, verified_at: null, updated_at: new Date() };
    await db.mail_settings.upsert({ where: { tenant_id: a.tenantId }, create: { tenant_id: a.tenantId, ...data }, update: data });
    await audit(a, "mail_configure", { detail: { host: b.host, port: b.port, tls_mode: b.tls_mode, from: b.from_address } });
    return { ok: true };
  });

  app.delete("/v1/settings/mail", async (req) => {
    const a = requireRole(req, ...WRITE);
    await db.mail_settings.deleteMany({ where: { tenant_id: a.tenantId } });
    await audit(a, "mail_remove");
    return { ok: true };
  });

  app.post("/v1/settings/mail/test", async (req) => {
    const a = requireRole(req, ...WRITE);
    const cfg = await mailFor(a.tenantId);
    if (!cfg) throw badRequest("set up email first");
    const me = await db.principals.findUnique({ where: { id: a.id } });
    if (!me?.email) throw badRequest("your account has no email address");
    try {
      await sendWith(cfg, me.email, "Onshore test email", "Email from Onshore is working.\n\nThis email holds no customer data.");
    } catch (e) {
      throw new ApiError(400, "mail_failed", e instanceof MailError ? e.message : "The email could not be sent.");
    }
    await db.mail_settings.update({ where: { tenant_id: a.tenantId }, data: { verified_at: new Date() } });
    await audit(a, "mail_test");
    return { ok: true, sent_to: me.email };
  });

  // ---- Forgot password ------------------------------------------------------------
  // Always the same answer, sent before any mail work, so that it can't reveal who has an account.
  app.post("/v1/auth/forgot", async (req) => {
    const b = z.object({ email: z.email() }).parse(req.body);
    const ip = `forgot:${clientIp(req)}`;
    checkLock(ip);
    recordFailure(ip);
    const email = b.email.toLowerCase();
    void (async () => {
      const p = await db.principals.findUnique({ where: { email } });
      if (!p || p.kind !== "user" || p.status !== "active") return;
      const sso = await db.sso_configs.findUnique({ where: { tenant_id: p.tenant_id } });
      if (sso?.sso_only || !(await mailFor(p.tenant_id))) return;
      // One link every few minutes per person, so that nobody can flood an inbox.
      const recent = await db.account_tokens.count({ where: { principal_id: p.id, kind: "password_reset", created_at: { gt: new Date(Date.now() - 5 * 60_000) } } });
      if (recent) return;
      const token = await issueAccountToken(p.tenant_id, p.id, "password_reset", null);
      await deliverAccountLink(p.tenant_id, email, "password_reset", token, p.display_name);
      await audit({ tenantId: p.tenant_id, id: p.id, ip: clientIp(req) }, "password_reset_request");
    })().catch(() => req.log.warn("password reset mail failed"));
    return { ok: true };
  });

  // ---- Redeeming a link -----------------------------------------------------------
  const find = async (token: string, ip: string) => {
    checkLock(`token:${ip}`);
    const t = await db.account_tokens.findUnique({ where: { token_hash: sha(token) }, include: { principals: true } });
    if (!t || t.used_at || t.revoked_at || t.expires_at <= new Date() || t.principals.status !== "active") {
      recordFailure(`token:${ip}`);
      throw new ApiError(400, "link_invalid", "This link has expired or has already been used. Ask for a new one.");
    }
    return t;
  };
  const tokenField = z.string().min(20).max(200);

  app.post("/v1/auth/account-link/check", async (req) => {
    const b = z.object({ token: tokenField }).parse(req.body);
    const t = await find(b.token, clientIp(req));
    return { kind: t.kind, email: t.principals.email, display_name: t.principals.display_name };
  });

  app.post("/v1/auth/account-link/redeem", async (req) => {
    const b = z.object({ token: tokenField, password: passwordRule }).parse(req.body);
    const t = await find(b.token, clientIp(req));
    // Only the first of two simultaneous requests gets through.
    const claimed = await db.account_tokens.updateMany({ where: { id: t.id, used_at: null, revoked_at: null }, data: { used_at: new Date() } });
    if (!claimed.count) throw new ApiError(400, "link_invalid", "This link has expired or has already been used. Ask for a new one.");
    // A reset link does not replace two-factor. Only the operator's recovery command clears it.
    const clearMfa = t.kind === "admin_recovery";
    // Someone new has no earlier sessions to end, and may sign in within the same second.
    await db.principals.update({ where: { id: t.principal_id }, data: { password_hash: hashPassword(b.password), must_change_password: false, ...(t.kind === "invite" ? {} : { sessions_valid_after: new Date() }), ...(clearMfa ? { mfa_enabled: false, totp_secret_enc: null, totp_last_step: null, totp_pending_enc: null } : {}) } });
    if (clearMfa) await db.recovery_codes.deleteMany({ where: { principal_id: t.principal_id } });
    await audit({ tenantId: t.tenant_id, id: t.principal_id, ip: clientIp(req) }, t.kind === "invite" ? "invite_accept" : "password_reset");
    if (t.kind !== "invite") await notify(t.tenant_id, t.principals.email, "Your Onshore password was changed", "Your Onshore password was just changed. If this wasn't you, tell your admin straight away.");
    return { ok: true };
  });

  // ---- An admin acting for someone else -------------------------------------------
  const someoneElse = async (req: { params: { id: string } }, a: { tenantId: string; id: string }) => {
    const p = await db.principals.findFirst({ where: { id: req.params.id, tenant_id: a.tenantId, kind: "user" } });
    if (!p) throw notFound();
    if (p.id === a.id) throw badRequest("you can't do this to your own account. Use Settings, or ask another admin");
    return p;
  };

  app.post<{ Params: { id: string } }>("/v1/principals/:id/invite", async (req) => {
    const a = requireRole(req, ...WRITE);
    const p = await someoneElse(req, a);
    if (p.password_hash) throw badRequest("this person has already accepted");
    const token = await issueAccountToken(a.tenantId, p.id, "invite", a.id);
    await audit(a, "invite_send", { detail: { principal: p.id } });
    return deliverAccountLink(a.tenantId, p.email!, "invite", token, p.display_name);
  });

  app.post<{ Params: { id: string } }>("/v1/principals/:id/invite/revoke", async (req) => {
    const a = requireRole(req, ...WRITE);
    const p = await someoneElse(req, a);
    const r = await db.account_tokens.updateMany({ where: { principal_id: p.id, kind: "invite", used_at: null, revoked_at: null }, data: { revoked_at: new Date() } });
    if (r.count) await audit(a, "invite_revoke", { detail: { principal: p.id } });
    return { ok: true, revoked: r.count };
  });

  // The old password stops working straight away, as the usual reason is a suspected compromise.
  app.post<{ Params: { id: string } }>("/v1/principals/:id/reset-password", async (req) => {
    const a = requireRole(req, ...WRITE);
    const p = await someoneElse(req, a);
    await db.principals.update({ where: { id: p.id }, data: { password_hash: null, must_change_password: false, sessions_valid_after: new Date() } });
    const token = await issueAccountToken(a.tenantId, p.id, "password_reset", a.id);
    await audit(a, "password_reset_by_admin", { detail: { principal: p.id } });
    return deliverAccountLink(a.tenantId, p.email!, "password_reset", token, p.display_name);
  });

  app.post<{ Params: { id: string } }>("/v1/principals/:id/reset-mfa", async (req) => {
    const a = requireRole(req, ...WRITE);
    const p = await someoneElse(req, a);
    await db.principals.update({ where: { id: p.id }, data: { mfa_enabled: false, totp_secret_enc: null, totp_last_step: null, totp_pending_enc: null, sessions_valid_after: new Date() } });
    await db.recovery_codes.deleteMany({ where: { principal_id: p.id } });
    await db.webauthn_credentials.deleteMany({ where: { principal_id: p.id } });
    await audit(a, "mfa_reset_by_admin", { detail: { principal: p.id } });
    const emailed = await notify(a.tenantId, p.email, "Your Onshore two-factor was reset", `An admin reset your two-factor authentication. You'll set it up again the next time you sign in.\n\nIf you weren't expecting this, tell your security team straight away.`);
    return { ok: true, notified: emailed };
  });

  // ---- Your own two-factor --------------------------------------------------------
  app.get("/v1/auth/security", async (req) => {
    const a = actor(req);
    const p = await db.principals.findUnique({ where: { id: a.id } });
    const passkeys = await db.webauthn_credentials.findMany({ where: { principal_id: a.id }, orderBy: { created_at: "asc" } });
    return { recovery_codes_left: await db.recovery_codes.count({ where: { principal_id: a.id, used_at: null } }), source: p?.source ?? "local", passkeys: passkeys.map((k) => ({ id: k.id, name: k.name, created_at: k.created_at, last_used_at: k.last_used_at })) };
  });

  // ---- Passkeys and security keys ------------------------------------------------
  app.post("/v1/auth/passkeys/options", async (req) => {
    const a = actor(req);
    const b = z.object({ password: z.string().max(200) }).parse(req.body);
    const p = await checkPassword(a.id, b.password, clientIp(req));
    if ((await db.webauthn_credentials.count({ where: { principal_id: a.id } })) >= 10) throw badRequest("you have 10 passkeys already; remove one first");
    return registrationOptions(p);
  });

  app.post("/v1/auth/passkeys", async (req) => {
    const a = actor(req);
    const b = z.object({ name: z.string().min(1).max(60), response: z.object({ id: z.string().max(1024), type: z.literal("public-key") }).passthrough() }).parse(req.body);
    if (!(await finishRegistration(a.id, b.response as never, b.name))) throw new ApiError(400, "invalid_request", "that passkey could not be checked; try again");
    await audit(a, "passkey_add", { detail: { name: b.name } });
    const p = await db.principals.findUnique({ where: { id: a.id } });
    await notify(a.tenantId, p?.email ?? null, "A passkey was added to your Onshore account", `A passkey called "${b.name}" can now be used to sign in to your account. If this wasn't you, tell your admin straight away.`);
    return { ok: true };
  });

  app.delete<{ Params: { id: string } }>("/v1/auth/passkeys/:id", async (req) => {
    const a = actor(req);
    const gone = await db.webauthn_credentials.deleteMany({ where: { id: req.params.id, principal_id: a.id } });
    if (!gone.count) throw notFound();
    await audit(a, "passkey_remove");
    return { ok: true };
  });

  const checkPassword = async (id: string, pw: string, ip: string) => {
    const key = `reauth:${id}`;
    checkLock(key);
    const p = await db.principals.findUnique({ where: { id } });
    if (!p || !(await checkAnyPassword(p, pw))) {
      recordFailure(key);
      void ip;
      throw new ApiError(401, "unauthenticated", "that password is incorrect");
    }
    return p!;
  };

  app.post("/v1/auth/recovery-codes", async (req) => {
    const a = actor(req);
    const b = z.object({ password: z.string().max(200) }).parse(req.body);
    const p = await checkPassword(a.id, b.password, clientIp(req));
    const codes = await newRecoveryCodes(a.id);
    await audit(a, "recovery_codes_replace");
    await notify(a.tenantId, p.email, "Your Onshore recovery codes were replaced", "New recovery codes were made for your account, and the old ones stopped working. If this wasn't you, tell your admin.");
    return { recovery_codes: codes };
  });

  app.post("/v1/auth/mfa/replace", async (req) => {
    const a = actor(req);
    const b = z.object({ password: z.string().max(200) }).parse(req.body);
    const p = await checkPassword(a.id, b.password, clientIp(req));
    const secret = base32(crypto.randomBytes(20));
    await db.principals.update({ where: { id: a.id }, data: { totp_pending_enc: encryptSecret(secret) } });
    const issuer = encodeURIComponent("Onshore");
    return { secret, otpauth_uri: `otpauth://totp/${issuer}:${encodeURIComponent(p.email ?? a.id)}?secret=${secret}&issuer=${issuer}&digits=6&period=30` };
  });

  app.post("/v1/auth/mfa/replace/confirm", async (req) => {
    const a = actor(req);
    const b = z.object({ totp: z.string().regex(/^\d{6}$/) }).parse(req.body);
    const key = `reauth:${a.id}`;
    checkLock(key);
    const p = await db.principals.findUnique({ where: { id: a.id } });
    if (!p?.totp_pending_enc) throw badRequest("start again");
    const secret = decryptSecret(p.totp_pending_enc);
    const step = matchTotp(secret, b.totp, null);
    if (step === null) { recordFailure(key); throw new ApiError(401, "unauthenticated", "that code is incorrect"); }
    await db.principals.update({ where: { id: a.id }, data: { totp_secret_enc: p.totp_pending_enc, totp_pending_enc: null, totp_last_step: BigInt(step) } });
    const codes = await newRecoveryCodes(a.id);
    await audit(a, "mfa_replace");
    await notify(a.tenantId, p.email, "Your Onshore authenticator was changed", "A new authenticator app was set up for your account. If this wasn't you, tell your admin straight away.");
    return { recovery_codes: codes };
  });
}

/** Ten codes, usable once each. Random enough that a plain hash is safe to store. */
export async function newRecoveryCodes(principalId: string): Promise<string[]> {
  const codes = Array.from({ length: 10 }, () => { const c = base32(crypto.randomBytes(10)).slice(0, 16).toLowerCase(); return `${c.slice(0, 4)}-${c.slice(4, 8)}-${c.slice(8, 12)}-${c.slice(12)}`; });
  await db.$transaction([
    db.recovery_codes.deleteMany({ where: { principal_id: principalId } }),
    db.recovery_codes.createMany({ data: codes.map((c) => ({ id: newId("rc"), principal_id: principalId, code_hash: sha(`${principalId}:${c}`) })) }),
  ]);
  return codes;
}
