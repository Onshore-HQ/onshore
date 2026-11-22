// An organisation's own country packs. A pack holds data types and laws for one
// country. Applying it to a vault creates the data types there as drafts and asks to
// publish them: the usual tests, benchmark and second-person approval still decide
// whether anything protects traffic. Packs move between organisations as signed files.

import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { ApiError, audit, badRequest, db, decryptSecret, encryptSecret, newId, notFound, READ_CONFIG, requireRole, vault, type Actor } from "../../lib.js";
import { countryName, isCountry } from "../../catalog.js";
import { createBody, createEntity, editEntity, requestPublish } from "./custom-entities.js";
import { ownedVault } from "../../routes/vaults.js";
import { canonical, fingerprint, verifyFile } from "../pack-file.js";

const MANAGE = ["admin", "detection_manager"];
const READ = [...READ_CONFIG, "detection_manager", "detection_approver"];
const FORMAT = "onshore-country-pack";

// A pack's data type: a custom entity's definition with its samples. Value lists stay
// out: their values are an organisation's own data, not something to share.
export const packType = createBody.refine((t) => t.kind !== "value_list", "a country pack can't hold a value list");
export const packLaw = z.object({
  name: z.string().trim().min(2).max(160),
  effect: z.string().trim().max(600).default(""),
  source: z.url().refine((u) => u.startsWith("https://"), "a source must be an https link"),
  checked_on: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "use a date such as 2026-11-22"),
});
const content = z.object({
  name: z.string().trim().min(2).max(80),
  description: z.string().trim().max(600).default(""),
  data_types: z.array(packType).max(60).default([]),
  laws: z.array(packLaw).max(30).default([]),
});
const country = z.string().regex(/^[A-Z]{2}$/).refine(isCountry, "unknown country");

type Content = z.infer<typeof content>;
type Pack = NonNullable<Awaited<ReturnType<typeof db.custom_packs.findFirst>>>;

/** Checks a pack's content: slugs once each, and every definition compiles in the engine. */
async function checkContent(c: Content) {
  const slugs = new Set<string>();
  for (const t of c.data_types) {
    if (slugs.has(t.slug)) throw badRequest(`the slug ${t.slug} is used twice`);
    slugs.add(t.slug);
    try {
      await vault("/internal/custom/check", { def: { slug: t.slug, kind: t.kind, name: t.name, definition: t.definition, validator: t.validator ?? undefined, threshold: t.threshold, status: "draft" } });
    } catch (e) {
      throw badRequest(`${t.name}: ${(e as Error).message}`);
    }
  }
}

async function ownPack(tenantId: string, id: string) {
  const p = await db.custom_packs.findFirst({ where: { id, tenant_id: tenantId, archived_at: null } });
  if (!p) throw notFound("unknown country pack");
  return p;
}

const summary = (p: Pack) => ({
  id: p.id, country: p.country, country_name: countryName(p.country), name: p.name, description: p.description, version: p.version,
  data_types: (p.data_types as unknown as Content["data_types"]).length, laws: (p.laws as unknown as Content["laws"]).length,
  origin: p.origin, imported_from: p.imported_from, updated_at: p.updated_at,
});

async function signingKey(tenantId: string) {
  const k = await db.pack_signing_keys.findUnique({ where: { tenant_id: tenantId } });
  if (k) return { publicKey: k.public_key, privateKey: crypto.createPrivateKey({ key: Buffer.from(decryptSecret(k.private_key_enc), "base64"), format: "der", type: "pkcs8" }) };
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  await db.pack_signing_keys.create({ data: { tenant_id: tenantId, public_key: pub, private_key_enc: encryptSecret(privateKey.export({ format: "der", type: "pkcs8" }).toString("base64")) } });
  return { publicKey: pub, privateKey };
}

/** Puts one pack data type into one vault, creating or updating its entity, and asks to publish. */
async function applyType(a: Actor, vaultId: string, p: Pack, t: Content["data_types"][number]) {
  const existing = await db.custom_entities.findFirst({ where: { vault_id: vaultId, slug: t.slug } });
  const tag = { id: p.id, version: p.version };
  if (existing && existing.pack_id !== p.id) return { slug: t.slug, outcome: "skipped", error: "a data type with this slug is already in this vault, and didn't come from this pack" };
  if (existing && existing.pack_version === p.version) return { slug: t.slug, outcome: "unchanged" };
  if (existing?.status === "archived") return { slug: t.slug, outcome: "skipped", error: "this data type was archived in this vault; restore it first" };
  let entity = existing;
  if (!existing) {
    const made = await createEntity(a, vaultId, t, tag);
    entity = await db.custom_entities.findUniqueOrThrow({ where: { id: made.id } });
  } else {
    const { slug: _s, kind: _k, tests: _t, ...edit } = t;
    await editEntity(a, existing, edit, tag);
    // The pack's samples replace the old ones, so the tests match this version.
    for (const old of await db.custom_entity_tests.findMany({ where: { entity_id: existing.id }, select: { id: true } })) await vault("/internal/custom/samples/delete", { entity: existing.id, sample_id: old.id });
    if (t.tests.length) await vault("/internal/custom/samples/add", { vault: vaultId, entity: existing.id, by: a.id, samples: t.tests });
    entity = await db.custom_entities.findUniqueOrThrow({ where: { id: existing.id } });
  }
  try {
    const r = await requestPublish(a, entity!);
    return { slug: t.slug, outcome: existing ? "updated" : "created", request: r.id };
  } catch (e) {
    // The draft stays, so someone can fix the samples and ask again.
    return { slug: t.slug, outcome: existing ? "updated" : "created", error: e instanceof ApiError ? e.message : "could not ask to publish" };
  }
}

export async function packRoutes(app: FastifyInstance) {
  app.get("/v1/packs", async (req) => {
    const a = requireRole(req, ...READ);
    const rows = await db.custom_packs.findMany({ where: { tenant_id: a.tenantId, archived_at: null }, orderBy: { name: "asc" } });
    return { packs: rows.map(summary) };
  });

  app.post("/v1/packs", async (req, reply) => {
    const a = requireRole(req, ...MANAGE);
    const b = z.object({ country, name: z.string().trim().min(2).max(80), description: z.string().trim().max(600).default("") }).parse(req.body);
    if (await db.custom_packs.findFirst({ where: { tenant_id: a.tenantId, archived_at: null, name: { equals: b.name, mode: "insensitive" } } })) throw new ApiError(409, "conflict", "a pack with that name already exists");
    const id = newId("pk");
    await db.custom_packs.create({ data: { id, tenant_id: a.tenantId, country: b.country, name: b.name, description: b.description, created_by: a.id } });
    await audit(a, "pack_create", { detail: { pack: id, country: b.country, name: b.name } });
    return reply.code(201).send({ id });
  });

  app.get<{ Params: { id: string } }>("/v1/packs/:id", async (req) => {
    const a = requireRole(req, ...READ);
    const p = await ownPack(a.tenantId, req.params.id);
    const used = await db.custom_entities.groupBy({ by: ["vault_id", "pack_version"], where: { pack_id: p.id, status: { not: "archived" } }, _count: true });
    const vaults = await db.vaults.findMany({ where: { id: { in: used.map((u) => u.vault_id) } }, select: { id: true, name: true, country: true } });
    return {
      pack: { ...summary(p), data_types: p.data_types, laws: p.laws },
      vaults: vaults.map((v) => ({ ...v, data_types: used.filter((u) => u.vault_id === v.id).reduce((n, u) => n + u._count, 0), up_to_date: used.filter((u) => u.vault_id === v.id).every((u) => u.pack_version === p.version) })),
    };
  });

  // Saving new content makes a new version; vaults pick it up when the pack is applied again.
  app.put<{ Params: { id: string } }>("/v1/packs/:id", async (req) => {
    const a = requireRole(req, ...MANAGE);
    const p = await ownPack(a.tenantId, req.params.id);
    const c = content.parse(req.body);
    await checkContent(c);
    if (c.name.toLowerCase() !== p.name.toLowerCase() && (await db.custom_packs.findFirst({ where: { tenant_id: a.tenantId, archived_at: null, id: { not: p.id }, name: { equals: c.name, mode: "insensitive" } } }))) throw new ApiError(409, "conflict", "a pack with that name already exists");
    const changed = canonical({ d: c.data_types, l: c.laws }) !== canonical({ d: p.data_types, l: p.laws });
    await db.custom_packs.update({ where: { id: p.id }, data: { name: c.name, description: c.description, data_types: c.data_types as object, laws: c.laws as object, version: changed ? p.version + 1 : p.version, updated_at: new Date() } });
    await audit(a, "pack_update", { detail: { pack: p.id, version: changed ? p.version + 1 : p.version, data_types: c.data_types.map((t) => t.slug), laws: c.laws.length } });
    return { ok: true, version: changed ? p.version + 1 : p.version };
  });

  // Runs each data type's samples on its own, before the pack goes near a vault.
  app.post<{ Params: { id: string } }>("/v1/packs/:id/test", async (req) => {
    const a = requireRole(req, ...READ);
    const p = await ownPack(a.tenantId, req.params.id);
    const types = p.data_types as unknown as Content["data_types"];
    const out = [];
    for (const t of types) {
      const { results } = await vault<{ results: { sample: string; expect_match: boolean; matched: boolean; passed: boolean }[] }>("/internal/custom/try", {
        def: { slug: t.slug, kind: t.kind, name: t.name, definition: t.definition, validator: t.validator ?? undefined, context_positive: t.context_positive, context_negative: t.context_negative, threshold: t.threshold, status: "draft" },
        samples: t.tests,
      });
      const must = results.filter((r) => r.expect_match).length;
      out.push({ slug: t.slug, name: t.name, passed: results.filter((r) => r.passed).length, failed: results.filter((r) => !r.passed).map((r) => ({ sample: r.sample, expect_match: r.expect_match })), enough_samples: must >= 3 && results.length - must >= 3 });
    }
    return { results: out, ready: out.length > 0 && out.every((r) => r.failed.length === 0 && r.enough_samples) };
  });

  app.post<{ Params: { id: string } }>("/v1/packs/:id/apply", async (req) => {
    const a = requireRole(req, ...MANAGE);
    const p = await ownPack(a.tenantId, req.params.id);
    const b = z.object({ vault: z.string().max(60) }).parse(req.body);
    const v = await ownedVault(a.tenantId, b.vault);
    const types = p.data_types as unknown as Content["data_types"];
    if (!types.length) throw badRequest("this pack has no data types yet");
    if (!v.custom_entities_enabled) {
      if (!a.roles.includes("admin")) throw new ApiError(403, "feature_disabled", "an admin must turn on your own data types for this vault first");
      await db.vaults.update({ where: { id: v.id }, data: { custom_entities_enabled: true } });
      await audit(a, "detection_settings_change", { vaultId: v.id, detail: { enabled: true, via: "pack" } });
    }
    const results = [];
    for (const t of types) results.push(await applyType(a, v.id, p, t));
    await audit(a, "pack_apply", { vaultId: v.id, detail: { pack: p.id, version: p.version, results: results.map((r) => ({ slug: r.slug, outcome: r.outcome })) } });
    return { results, country_matches: v.country === p.country, vault_country: countryName(v.country) };
  });

  app.delete<{ Params: { id: string } }>("/v1/packs/:id", async (req) => {
    const a = requireRole(req, ...MANAGE);
    const p = await ownPack(a.tenantId, req.params.id);
    await db.custom_packs.update({ where: { id: p.id }, data: { archived_at: new Date() } });
    await audit(a, "pack_archive", { detail: { pack: p.id } });
    return { ok: true };
  });

  // A signed file another organisation, a partner or the community can import.
  app.get<{ Params: { id: string } }>("/v1/packs/:id/export", async (req, reply) => {
    const a = requireRole(req, ...MANAGE);
    const p = await ownPack(a.tenantId, req.params.id);
    const t = await db.tenants.findUnique({ where: { id: a.tenantId } });
    const { publicKey, privateKey } = await signingKey(a.tenantId);
    const body = {
      format: FORMAT, format_version: 1,
      pack: { country: p.country, name: p.name, description: p.description, version: p.version, data_types: p.data_types, laws: p.laws },
      signed_by: { organisation: t?.name ?? "", public_key: publicKey, fingerprint: fingerprint(publicKey) },
      signed_at: new Date().toISOString(),
    };
    const signature = crypto.sign(null, Buffer.from(canonical(body)), privateKey).toString("base64url");
    await audit(a, "pack_export", { detail: { pack: p.id, version: p.version } });
    return reply.header("content-disposition", `attachment; filename="${p.country.toLowerCase()}-${p.name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-v${p.version}.onshore-pack.json"`).send({ ...body, signature });
  });

  // Reads a pack file. A changed or unsigned file is refused; the signer's fingerprint is
  // shown so it can be checked with them another way.
  app.post("/v1/packs/import", async (req, reply) => {
    const a = requireRole(req, ...MANAGE);
    const b = z.object({ file: z.record(z.string(), z.unknown()), preview: z.boolean().default(false) }).parse(req.body);
    if (b.file.format !== FORMAT || b.file.format_version !== 1) throw badRequest("this is not an Onshore country pack file");
    const check = verifyFile(b.file);
    if (!check.ok) throw new ApiError(422, "bad_signature", "this pack file has been changed since it was signed, or isn't signed; it can't be imported");
    const raw = (b.file.pack ?? {}) as Record<string, unknown>;
    const cc = country.parse(raw.country);
    const c = content.parse({ name: raw.name, description: raw.description, data_types: raw.data_types, laws: raw.laws });
    await checkContent(c);
    const by = b.file.signed_by as { organisation?: string };
    const from = { organisation: String(by.organisation ?? "").slice(0, 120), fingerprint: check.fingerprint, signed_at: String(b.file.signed_at ?? ""), version: Number(raw.version ?? 1) };
    if (b.preview) return { preview: { country: cc, country_name: countryName(cc), name: c.name, description: c.description, data_types: c.data_types.map((t) => ({ slug: t.slug, name: t.name, kind: t.kind })), laws: c.laws, signed_by: from } };
    let name = c.name;
    for (let n = 2; await db.custom_packs.findFirst({ where: { tenant_id: a.tenantId, archived_at: null, name: { equals: name, mode: "insensitive" } } }); n++) name = `${c.name} (${n})`.slice(0, 80);
    const id = newId("pk");
    await db.custom_packs.create({ data: { id, tenant_id: a.tenantId, country: cc, name, description: c.description, data_types: c.data_types as object, laws: c.laws as object, origin: "imported", imported_from: from, created_by: a.id } });
    await audit(a, "pack_import", { detail: { pack: id, country: cc, signed_by: from } });
    return reply.code(201).send({ id, signed_by: from });
  });
}
