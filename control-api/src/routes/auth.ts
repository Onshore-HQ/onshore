import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { ApiError, audit, base32, clientIp, db, decryptSecret, encryptSecret, env, hashPassword, issueToken, matchTotp, newId, actor, SESSION_MAX_SECONDS, TOKEN_TTL_SECONDS, verifyPassword } from "../lib.js";
import { notify } from "../mail.js";
import { newRecoveryCodes, sha } from "./accounts.js";
import { ROLES } from "../templates.js";
import { ldapAuthenticate, ldapConfigFor } from "../ldap.js";
import { provision, rolesForGroups, setRoles } from "../identity.js";
import { hasPasskeys, loginOptions, verifyLogin } from "../passkeys.js";
import { edition } from "./locations.js";

const attempts = new Map<string, { count: number; until: number }>();
const MAX_ATTEMPTS = 8;
const LOCK_MS = 15 * 60 * 1000;

export function checkLock(key: string) {
  const a = attempts.get(key);
  if (a && a.count >= MAX_ATTEMPTS && a.until > Date.now()) throw new ApiError(429, "rate_limited", "too many attempts; try again later");
}
export function recordFailure(key: string) {
  const a = attempts.get(key);
  const fresh = !a || a.until <= Date.now();
  attempts.set(key, { count: fresh ? 1 : a.count + 1, until: fresh ? Date.now() + LOCK_MS : a.until });
}

export const passwordRule = z.string().min(12, "use at least 12 characters").max(200);
const password = passwordRule;

export async function authRoutes(app: FastifyInstance) {
  app.get("/v1/bootstrap/status", async () => ({ needed: (await db.tenants.count()) === 0 }));

  // First-run setup. Needs the token that `rv init` printed, so that whoever
  // reaches the console first cannot claim the installation.
  app.post("/v1/bootstrap", async (req) => {
    const b = z.object({ bootstrap_token: z.string(), organisation: z.string().min(2).max(120), display_name: z.string().min(2).max(120), email: z.email(), password, deployment: z.enum(["hosted", "self_hosted"]).default("self_hosted") }).parse(req.body);
    const want = Buffer.from(env("RV_BOOTSTRAP_TOKEN"));
    const got = Buffer.from(b.bootstrap_token);
    checkLock(`bootstrap:${clientIp(req)}`);
    if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) {
      recordFailure(`bootstrap:${clientIp(req)}`);
      throw new ApiError(401, "unauthenticated", "bad bootstrap token");
    }
    const tenantId = newId("t");
    const principalId = newId("usr");
    await db.$transaction(async (tx) => {
      // Serialise concurrent first runs; only the first one may create a tenant.
      await tx.$executeRaw`LOCK TABLE control.tenants IN EXCLUSIVE MODE`;
      if ((await tx.tenants.count()) > 0) throw new ApiError(409, "already_bootstrapped", "this installation is already set up");
      const country = (process.env.RV_COUNTRY ?? "").toUpperCase();
      await tx.tenants.create({ data: { id: tenantId, name: b.organisation, deployment: b.deployment, ...(/^[A-Z]{2}$/.test(country) ? { hosting_country: country } : {}) } });
      for (const r of ROLES) await tx.roles.create({ data: { id: `${tenantId}:${r}`, tenant_id: tenantId, name: r } });
      await tx.principals.create({ data: { id: principalId, tenant_id: tenantId, kind: "user", display_name: b.display_name, email: b.email.toLowerCase(), password_hash: hashPassword(b.password) } });
      for (const r of ["admin", "dpo"]) await tx.role_assignments.create({ data: { role_id: `${tenantId}:${r}`, principal_id: principalId } });
    });
    await audit({ tenantId, id: principalId, ip: clientIp(req) }, "bootstrap", { detail: { organisation: b.organisation } });
    return { ok: true };
  });

  // Two steps. Password alone never yields a session: MFA is mandatory, and the
  // first login enrols a TOTP secret that is only confirmed by a valid code.
  app.post("/v1/auth/login", async (req) => {
    const b = z.object({ email: z.email(), password: z.string().max(200), totp: z.string().regex(/^\d{6}$/).optional(), recovery_code: z.string().regex(/^[a-z2-7]{4}(-[a-z2-7]{4}){3}$/).optional(), new_password: password.optional(), passkey: z.object({ id: z.string().max(1024), type: z.literal("public-key") }).passthrough().optional() }).parse(req.body);
    const email = b.email.toLowerCase();
    const key = `login:${email}`;
    checkLock(key);
    checkLock(`ip:${clientIp(req)}`);
    let p = await db.principals.findUnique({ where: { email } });
    const fail = () => {
      recordFailure(key);
      recordFailure(`ip:${clientIp(req)}`);
      return new ApiError(401, "unauthenticated", "email, password or code is incorrect");
    };
    // The organisation's directory checks the password for its own people, and for
    // newcomers from its domains when it may create accounts. Local accounts, such
    // as a break-glass admin, keep their own password.
    const ldap = await ldapConfigFor(email, p);
    let ok: boolean;
    if (ldap) {
      const dir = await ldapAuthenticate(ldap, email, b.password, (await edition()) === "cloud").catch(() => null);
      ok = !!dir;
      if (dir) {
        const mapped = await rolesForGroups(ldap.tenant_id, dir.groups);
        if (!p) {
          if (!ldap.jit_provisioning || !mapped?.length) throw fail();
          await provision(ldap.tenant_id, { email, displayName: dir.name, source: "ldap", externalId: dir.externalId, roles: mapped });
          p = await db.principals.findUnique({ where: { email } });
          if (p) await audit({ tenantId: p.tenant_id, id: p.id, ip: clientIp(req) }, "account_created", { detail: { via: "ldap", roles: mapped } });
        } else if (p.tenant_id === ldap.tenant_id && mapped) {
          if (!(await setRoles(p.tenant_id, p.id, mapped)).roles.length) throw fail();
        }
        if (p && p.must_change_password) await db.principals.update({ where: { id: p.id }, data: { must_change_password: false } });
        if (p) p = { ...p, must_change_password: false };
      }
    } else {
      ok = verifyPassword(b.password, p?.password_hash ?? null);
    }
    if (!ok || !p || p.kind !== "user" || p.status !== "active") throw fail();
    // Where a tenant requires SSO, the password no longer opens the console.
    const sso = await db.sso_configs.findUnique({ where: { tenant_id: p.tenant_id } });
    if (sso?.sso_only) throw fail();

    let secret: string;
    if (p.totp_secret_enc) {
      secret = decryptSecret(p.totp_secret_enc);
    } else {
      secret = base32(crypto.randomBytes(20));
      await db.principals.update({ where: { id: p.id }, data: { totp_secret_enc: encryptSecret(secret) } });
    }
    // A lost phone: a recovery code stands in for the code, once. It can't finish a first sign-in.
    if (b.recovery_code) {
      if (!p.mfa_enabled || p.must_change_password) throw fail();
      const used = await db.recovery_codes.updateMany({ where: { principal_id: p.id, code_hash: sha(`${p.id}:${b.recovery_code}`), used_at: null }, data: { used_at: new Date() } });
      if (!used.count) throw fail();
      await db.principals.update({ where: { id: p.id }, data: { last_active_at: new Date() } });
      attempts.delete(key);
      await audit({ tenantId: p.tenant_id, id: p.id, ip: clientIp(req) }, "login", { detail: { with: "recovery_code" } });
      await notify(p.tenant_id, p.email, "A recovery code was used on your Onshore account", "Someone signed in to your account with a recovery code. If this wasn't you, tell your admin straight away.");
      return { step: "done", access_token: issueToken(p.id, p.tenant_id), expires_in: TOKEN_TTL_SECONDS, recovery_codes_left: await db.recovery_codes.count({ where: { principal_id: p.id, used_at: null } }) };
    }
    if (!p.mfa_enabled && !b.totp) {
      const issuer = encodeURIComponent("Onshore");
      return { step: "enrol_totp", secret, otpauth_uri: `otpauth://totp/${issuer}:${encodeURIComponent(email)}?secret=${secret}&issuer=${issuer}&digits=6&period=30` };
    }
    // A passkey or security key stands in for the code.
    if (b.passkey) {
      if (!p.mfa_enabled || p.must_change_password || !(await verifyLogin(p.id, b.passkey as never))) throw fail();
      await db.principals.update({ where: { id: p.id }, data: { last_active_at: new Date() } });
      attempts.delete(key);
      await audit({ tenantId: p.tenant_id, id: p.id, ip: clientIp(req) }, "login", { detail: { with: "passkey" } });
      return { step: "done", access_token: issueToken(p.id, p.tenant_id), expires_in: TOKEN_TTL_SECONDS };
    }
    if (!b.totp) return { step: "totp_required", ...(p.mfa_enabled && !p.must_change_password && (await hasPasskeys(p.id)) ? { passkey: await loginOptions(p.id) } : {}) };
    const step = matchTotp(secret, b.totp, p.totp_last_step);
    if (step === null) throw fail();
    // An admin-issued password is single-use: no session until it is replaced.
    if (p.must_change_password && (!b.new_password || b.new_password === b.password)) {
      await db.principals.update({ where: { id: p.id }, data: { mfa_enabled: true, totp_last_step: BigInt(step) } });
      return { step: "change_password" };
    }
    await db.principals.update({ where: { id: p.id }, data: { mfa_enabled: true, totp_last_step: BigInt(step), last_active_at: new Date(), ...(p.must_change_password ? { password_hash: hashPassword(b.new_password!), must_change_password: false } : {}) } });
    attempts.delete(key);
    await audit({ tenantId: p.tenant_id, id: p.id, ip: clientIp(req) }, "login");
    // Shown once, the first time someone gets in. Later sets come from Settings.
    const fresh = (await db.recovery_codes.count({ where: { principal_id: p.id } })) === 0 ? await newRecoveryCodes(p.id) : undefined;
    return { step: "done", access_token: issueToken(p.id, p.tenant_id), expires_in: TOKEN_TTL_SECONDS, ...(fresh ? { recovery_codes: fresh } : {}) };
  });

  // Sliding renewal, capped so that a session must log in again after 12 hours.
  app.post("/v1/auth/refresh", async (req) => {
    const a = actor(req);
    if (Date.now() / 1000 - a.authTime > SESSION_MAX_SECONDS) throw new ApiError(401, "unauthenticated", "session expired; log in again");
    return { access_token: issueToken(a.id, a.tenantId, a.authTime), expires_in: TOKEN_TTL_SECONDS };
  });

  app.get("/v1/me", async (req) => {
    const a = actor(req);
    const t = await db.tenants.findUnique({ where: { id: a.tenantId } });
    return { id: a.id, display_name: a.displayName, roles: a.roles, tenant: { id: t?.id, name: t?.name, deployment: t?.deployment, demo_mode: t?.demo_mode ?? false, setup_needed: !t?.setup_completed_at, console_language: t?.console_language ?? "en", console_format: t?.console_format ?? t?.home_country ?? null } };
  });

  app.post("/v1/auth/change-password", async (req) => {
    const a = actor(req);
    const b = z.object({ current: z.string().max(200), next: password }).parse(req.body);
    const p = await db.principals.findUnique({ where: { id: a.id } });
    if (!verifyPassword(b.current, p?.password_hash ?? null)) throw new ApiError(401, "unauthenticated", "current password is incorrect");
    await db.principals.update({ where: { id: a.id }, data: { password_hash: hashPassword(b.next), sessions_valid_after: new Date() } });
    await audit(a, "password_change");
    return { ok: true, sign_in_again: true };
  });
}
