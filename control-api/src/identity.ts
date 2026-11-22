// Shared by single sign-on, SCIM and LDAP: which edition may use them, how groups
// at an identity provider become roles here, and how accounts are created.

import { ApiError, db, newId } from "./lib.js";
import { ROLES } from "./templates.js";
import { edition, has, needs, type Edition, type Level } from "./edition.js";

/** Single sign-on and SCIM are Business; LDAP is Enterprise. Change here to change the offer. */
export const IDENTITY_LEVEL: Record<"sso" | "scim" | "ldap", Level> = { sso: "business", scim: "business", ldap: "enterprise" };

export async function requireIdentityEdition(feature: "sso" | "scim" | "ldap") {
  const ed = await edition();
  const level = IDENTITY_LEVEL[feature];
  if (!has(ed, level)) throw needs(level, feature === "ldap" ? "LDAP" : feature === "sso" ? "single sign-on" : "SCIM");
  return ed;
}

/** What this edition may set up, for the Sign-in settings. */
export const identityAllowed = (ed: Edition) => ({ sso: has(ed, "business"), scim: has(ed, "business"), ldap: has(ed, "enterprise") });

export const publicOrigin = () => `https://${process.env.RV_HOST ?? "localhost"}${process.env.RV_PUBLIC_PORT ? `:${process.env.RV_PUBLIC_PORT}` : ""}`;

/**
 * The roles a set of groups gives, or null when the organisation maps no groups (then
 * roles stay as an admin set them). Group names match without regard to case.
 */
export async function rolesForGroups(tenantId: string, groups: string[]): Promise<string[] | null> {
  const maps = await db.group_role_mappings.findMany({ where: { tenant_id: tenantId } });
  if (maps.length === 0) return null;
  const have = new Set(groups.map((g) => g.trim().toLowerCase()));
  const roles = new Set<string>();
  for (const m of maps) if (have.has(m.group_name)) for (const r of m.roles) if (ROLES.includes(r)) roles.add(r);
  return [...roles].sort();
}

/**
 * Replaces a person's roles. It never removes the organisation's last active admin:
 * an identity provider's mistake must not lock everyone out. Returns the roles set.
 */
export async function setRoles(tenantId: string, principalId: string, roles: string[]): Promise<{ roles: string[]; keptAdmin: boolean }> {
  return db.$transaction(async (tx) => {
    const current = (await tx.role_assignments.findMany({ where: { principal_id: principalId }, include: { roles: true } })).map((r) => r.roles.name);
    let next = [...new Set(roles.filter((r) => ROLES.includes(r)))];
    let keptAdmin = false;
    if (current.includes("admin") && !next.includes("admin")) {
      const others = await tx.role_assignments.count({ where: { roles: { tenant_id: tenantId, name: "admin" }, principal_id: { not: principalId }, principals: { status: "active", kind: "user" } } });
      if (others === 0) { next = [...next, "admin"]; keptAdmin = true; }
    }
    if (current.slice().sort().join() !== next.slice().sort().join()) {
      await tx.role_assignments.deleteMany({ where: { principal_id: principalId } });
      for (const r of next) await tx.role_assignments.create({ data: { role_id: `${tenantId}:${r}`, principal_id: principalId } });
    }
    return { roles: next.sort(), keptAdmin };
  });
}

/** Whether suspending this person would leave the organisation with no active admin. */
export async function isLastAdmin(tenantId: string, principalId: string): Promise<boolean> {
  const mine = await db.role_assignments.count({ where: { principal_id: principalId, roles: { name: "admin" } } });
  if (!mine) return false;
  const others = await db.role_assignments.count({ where: { roles: { tenant_id: tenantId, name: "admin" }, principal_id: { not: principalId }, principals: { status: "active", kind: "user" } } });
  return others === 0;
}

/** Creates a person who signs in through an identity provider: no password here. */
export async function provision(tenantId: string, p: { email: string; displayName: string; source: "sso" | "scim" | "ldap"; externalId?: string | null; roles: string[] }) {
  const id = newId("usr");
  await db.$transaction(async (tx) => {
    await tx.principals.create({ data: { id, tenant_id: tenantId, kind: "user", display_name: p.displayName.slice(0, 120) || p.email, email: p.email.toLowerCase(), source: p.source, external_id: p.externalId ?? null } });
    for (const r of new Set(p.roles.filter((x) => ROLES.includes(x)))) await tx.role_assignments.create({ data: { role_id: `${tenantId}:${r}`, principal_id: id } });
  });
  return id;
}

/** A value from a claim or attribute that may be one string or a list. */
export function asList(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string");
  if (typeof v === "string" && v) return [v];
  return [];
}
