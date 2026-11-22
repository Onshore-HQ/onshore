import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { actor, audit, badRequest, db, newId, notFound, requireRole, vault, WRITE, type Actor } from "../lib.js";
import { STARTER_POLICIES, TEMPLATES } from "../templates.js";
import { builtInPack, COUNTRY, countryName, isCountry, PACKS, fieldsForPacks } from "../catalog.js";
import { edition, installCountry } from "./locations.js";

const DATA_TYPES = ["bvn", "nin", "ng_11_digit_id", "nuban", "phone_ng", "email", "person_name", "amount_ngn", "address", "date", "free_text", "custom",
  // Country packs.
  "ghana_card", "ke_national_id", "ke_kra_pin", "za_id", "eg_national_id", "emirates_id", "sa_national_id", "qa_id", "uk_nino", "uk_nhs", "uk_bank_account",
  "iban", "eu_vat", "de_tax_id", "fr_nir", "us_ssn", "us_itin", "us_routing", "ca_sin", "br_cpf", "in_aadhaar", "in_pan", "sg_nric", "phone"] as const;
const FP_TYPES = new Set(["bvn", "nin", "ng_11_digit_id", "nuban", "phone_ng"]);

export async function ownedVault(tenantId: string, id: string) {
  const v = await db.vaults.findFirst({ where: { id, tenant_id: tenantId } });
  if (!v) throw notFound("unknown vault");
  return v;
}

const fieldBody = z.object({
  name: z.string().regex(/^[a-z][a-z0-9_]{0,62}$/, "use lower_snake_case"),
  data_type: z.enum(DATA_TYPES),
  custom_entity_id: z.string().nullish(),
  token_kind: z.enum(["deterministic", "cell", "transient"]).default("deterministic"),
  token_format: z.enum(["opaque", "format_preserving"]).default("opaque"),
  column_group_id: z.string().nullish(),
  ttl_days: z.number().int().positive().nullish(),
  searchable: z.boolean().default(true),
  unique_values: z.boolean().default(false),
  mask_rule: z.enum(["default", "full"]).default("default"),
  in_payment_scope: z.boolean().default(true),
});

function checkField(f: { data_type: string; token_format: string; token_kind: string; ttl_days?: number | null; custom_entity_id?: string | null }) {
  if ((f.data_type === "custom") !== Boolean(f.custom_entity_id)) throw badRequest("a custom field names one custom entity, and only a custom field does");
  if (f.token_format === "format_preserving" && f.data_type !== "custom" && !FP_TYPES.has(f.data_type)) throw badRequest("format-preserving tokens exist only for BVN, NIN, NUBAN and phone fields");
  if (f.token_kind === "transient" && !f.ttl_days) throw badRequest("transient fields need ttl_days");
}

async function compile(name: string, version: number, source: object) {
  return vault<{ compiled: object; readable: string }>("/internal/policy/compile", { name, version, source });
}

/** Installs the starter policies once. The admin who picks a template is their approver. */
async function ensureStarterPolicies(a: Actor) {
  for (const p of STARTER_POLICIES) {
    if (await db.policies.findFirst({ where: { tenant_id: a.tenantId, name: p.name } })) continue;
    const { compiled } = await compile(p.name, 1, p.source);
    const id = newId("pol");
    await db.policies.create({ data: { id, tenant_id: a.tenantId, name: p.name, version: 1, source: p.source, compiled_cel: compiled, status: "active", created_by: "system:template", approved_by: a.id, published_at: new Date() } });
    await audit(a, "policy_publish", { policyId: id, policyVersion: 1, detail: { name: p.name, from: "template" } });
  }
}

export interface NewVault { name: string; environment: "sandbox" | "production"; template: string; seed?: boolean; country: string; packs?: string[] }

/** Creates a vault with a template's fields. Used by the vaults API and by first-time setup. */
export async function createVault(a: Actor, b: NewVault) {
  if (!isCountry(b.country)) throw badRequest("unknown country");
  const own = builtInPack(b.country);
  const packs = [...new Set(["everywhere", ...(b.packs ?? (own ? [own] : []))])];
  if (packs.some((p) => !PACKS[p])) throw badRequest("unknown country pack");
  // "packs" builds the fields from the vault's country packs. The older templates hold
  // Nigerian identifiers, so they only apply to a vault with the Nigeria pack.
  const legacy = TEMPLATES[b.template];
  if (b.template !== "packs" && !legacy) throw badRequest("unknown template");
  if (legacy && legacy.fields.length > 0 && !packs.includes("ng")) throw badRequest("that template holds Nigerian identifiers; use the \"packs\" template for this vault");
  const tpl = b.template === "packs" ? { fields: fieldsForPacks(packs) as { name: string; data_type: string; token_kind?: string }[] } : legacy!;
  const id = newId(b.environment === "production" ? "v_live" : "v_test", 6);
  await db.$transaction(async (tx) => {
    // A country with one time zone gives the vault its zone; a country with several leaves the organisation's.
    await tx.vaults.create({ data: { id, tenant_id: a.tenantId, name: b.name, environment: b.environment, country: b.country, packs, time_zone: COUNTRY[b.country]?.zone ?? null } });
    for (const f of tpl.fields) {
      await tx.vault_fields.create({ data: { id: newId("fld"), vault_id: id, name: f.name, data_type: f.data_type, token_kind: f.token_kind ?? "deterministic", ttl_seconds: f.token_kind === "transient" ? 300 : null } });
    }
  });
  await db.$executeRaw`SELECT pg_notify('rv_rulesets', ${id})`;
  await ensureStarterPolicies(a);
  await audit(a, "vault_create", { vaultId: id, detail: { name: b.name, environment: b.environment, template: b.template, country: b.country, packs } });
  let seeded = 0;
  // Sandbox seeding makes made-up customers from the vault's own country.
  if (b.seed && b.environment === "sandbox" && tpl.fields.length > 0) {
    seeded = (await vault<{ subjects: number }>("/internal/sandbox/seed", { vault: id, count: 25 })).subjects;
  }
  return { id, seeded };
}

export async function vaultRoutes(app: FastifyInstance) {
  app.get("/v1/templates", async () => TEMPLATES);

  // Which sites may frame this vault's secure components. https only, except localhost
  // on a sandbox vault. A wildcard is refused: it would let any site host the form.
  app.patch<{ Params: { id: string } }>("/v1/vaults/:id/embed", async (req) => {
    const a = requireRole(req, ...WRITE);
    const v = await ownedVault(a.tenantId, req.params.id);
    const b = z.object({ origins: z.array(z.string().max(200)).max(20) }).parse(req.body);
    const origins = [...new Set(b.origins.map((o) => o.trim().toLowerCase()))];
    for (const o of origins) {
      const https = /^https:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$/.test(o);
      const local = v.environment === "sandbox" && /^http:\/\/localhost(:[0-9]{1,5})?$/.test(o);
      const app = /^rvapp:\/\/[a-z0-9][a-z0-9._-]{0,150}$/.test(o);
      if (!https && !local && !app) throw badRequest("an origin is https://host with an optional port, with no path or wildcard, or rvapp:// and an app's id; http://localhost is allowed on a sandbox vault");
    }
    await db.vaults.update({ where: { id: v.id }, data: { embed_origins: origins } });
    await audit(a, "embed_origins_change", { vaultId: v.id, detail: { from: v.embed_origins, to: origins } });
    return { origins };
  });

  app.get("/v1/vaults", async (req) => {
    const a = actor(req);
    const vaults = await db.vaults.findMany({ where: { tenant_id: a.tenantId }, orderBy: { created_at: "asc" }, include: { vault_fields: { orderBy: { created_at: "asc" } }, column_groups: true } });
    return { vaults };
  });

  app.post("/v1/vaults", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ name: z.string().min(1).max(80), environment: z.enum(["sandbox", "production"]).default("sandbox"), template: z.string().default("packs"), seed: z.boolean().default(false), country: z.string().regex(/^[A-Z]{2}$/).optional(), packs: z.array(z.string()).optional() }).parse(req.body);
    const install = await installCountry(a.tenantId);
    const country = b.country ?? install;
    if (!country) throw badRequest("say which country this vault keeps data in");
    // A self-hosted install keeps data in its own country; other countries need their own install.
    if (install && country !== install && (await edition()) !== "cloud") throw badRequest(`this install keeps data in ${countryName(install) ?? install}; a vault in another country needs its own install there`);
    return createVault(a, { ...b, country });
  });

  app.patch<{ Params: { id: string } }>("/v1/vaults/:id/time-zone", async (req) => {
    const a = requireRole(req, ...WRITE);
    const v = await ownedVault(a.tenantId, req.params.id);
    const b = z.object({ time_zone: z.string().max(60).nullable() }).parse(req.body);
    if (b.time_zone && (await db.$queryRaw<{ n: number }[]>`SELECT 1 AS n FROM pg_timezone_names WHERE name=${b.time_zone} LIMIT 1`).length === 0) throw badRequest(`unknown time zone ${b.time_zone}`);
    await db.vaults.update({ where: { id: v.id }, data: { time_zone: b.time_zone } });
    await audit(a, "vault_time_zone", { vaultId: v.id, detail: { from: v.time_zone, to: b.time_zone } });
    return { ok: true };
  });

  app.post<{ Params: { id: string } }>("/v1/vaults/:id/fields", async (req) => {
    const a = requireRole(req, ...WRITE);
    await ownedVault(a.tenantId, req.params.id);
    const b = fieldBody.parse(req.body);
    checkField(b);
    if (b.custom_entity_id && !(await db.custom_entities.findFirst({ where: { id: b.custom_entity_id, vault_id: req.params.id } }))) throw badRequest("that custom entity is not in this vault");
    const id = newId("fld");
    await db.vault_fields.create({ data: { ...b, id, vault_id: req.params.id, column_group_id: b.column_group_id ?? null, ttl_days: b.ttl_days ?? null } });
    await audit(a, "field_create", { vaultId: req.params.id, detail: { name: b.name, data_type: b.data_type } });
    return { id };
  });

  // Token settings are immutable once a field exists: changing kind or data type
  // would strand stored values. Only presentation and scope can change.
  app.patch<{ Params: { id: string; fid: string } }>("/v1/vaults/:id/fields/:fid", async (req) => {
    const a = requireRole(req, ...WRITE);
    await ownedVault(a.tenantId, req.params.id);
    const b = z.object({ mask_rule: z.enum(["default", "full"]).optional(), searchable: z.boolean().optional(), in_payment_scope: z.boolean().optional(), ttl_days: z.number().int().positive().nullish() }).parse(req.body);
    const r = await db.vault_fields.updateMany({ where: { id: req.params.fid, vault_id: req.params.id }, data: b });
    if (r.count === 0) throw notFound("unknown field");
    await audit(a, "field_update", { vaultId: req.params.id, detail: { field: req.params.fid, ...b } });
    return { ok: true };
  });

  app.post<{ Params: { id: string } }>("/v1/vaults/:id/column-groups", async (req) => {
    const a = requireRole(req, ...WRITE);
    await ownedVault(a.tenantId, req.params.id);
    const b = z.object({ name: z.string().min(1).max(60), token_kind: z.enum(["deterministic", "cell", "transient"]).default("deterministic"), token_format: z.enum(["opaque", "format_preserving"]).default("opaque") }).parse(req.body);
    const id = newId("grp");
    await db.column_groups.create({ data: { id, vault_id: req.params.id, ...b } });
    await audit(a, "column_group_create", { vaultId: req.params.id, detail: { name: b.name } });
    return { id };
  });

  // Live preview on a field card. Sandbox only: real values must not be typed here.
  app.post<{ Params: { id: string } }>("/v1/vaults/:id/fields/preview", async (req) => {
    const a = requireRole(req, ...WRITE, "engineer");
    const v = await ownedVault(a.tenantId, req.params.id);
    if (v.environment !== "sandbox") throw badRequest("live preview is available in sandbox vaults only");
    const b = z.object({ data_type: z.enum(DATA_TYPES), token_format: z.enum(["opaque", "format_preserving"]).default("opaque"), mask_rule: z.string().default("default"), value: z.string().max(4096) }).parse(req.body);
    return vault("/internal/fields/preview", b);
  });

  app.post<{ Params: { id: string } }>("/v1/vaults/:id/seed", async (req) => {
    const a = requireRole(req, ...WRITE);
    const v = await ownedVault(a.tenantId, req.params.id);
    if (v.environment !== "sandbox") throw badRequest("only sandbox vaults can be seeded");
    return vault("/internal/sandbox/seed", { vault: v.id, count: 25 });
  });
}
