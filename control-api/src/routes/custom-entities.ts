import multipart from "@fastify/multipart";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { ApiError, audit, badRequest, db, newId, notFound, READ_CONFIG, requireRole, vault, type Actor } from "../lib.js";
import { ownedVault } from "./vaults.js";
import { BUILT_IN_ENTITIES, ENTITY_TEMPLATES } from "../templates.js";

// The spec's detection:manage and detection:approve. Roles, as everywhere in this product.
const MANAGE = ["admin", "detection_manager"];
const APPROVE = ["admin", "detection_approver"];
const READ = [...READ_CONFIG, "detection_manager", "detection_approver"];

const MAX_ENTITIES = 200;
const MAX_PATTERNS = 50;
const MIN_SAMPLES = 3;
const MAX_MS_PER_KB = 0.3;
// The spec gives value lists their own figure: one keyed hash per candidate, "well under
// 1 ms" on a 1 KB line. At 0.3 a list with four-word entries could never be published.
// All of a vault's lists share one hashing pass, so this cost does not add up per list.
const MAX_LIST_MS_PER_KB = 1;
const MAX_MATCHED_SHARE = 0.05;
const MAX_UPLOAD = 32 << 20;

export const KIND = z.enum(["keyword_list", "pattern", "after_keyword", "value_list", "json_path"]);
const ACTION = z.enum(["tokenize", "mask", "drop", "pass"]);
const maskRule = z.discriminatedUnion("type", [
  z.object({ type: z.literal("last_n"), n: z.number().int().min(0).max(32) }),
  z.object({ type: z.literal("first_n"), n: z.number().int().min(0).max(32) }),
  z.object({ type: z.literal("fixed"), text: z.string().min(1).max(40) }),
  z.object({ type: z.literal("full") }),
]);
const definition = z.object({
  terms: z.array(z.string()).optional(),
  case_sensitive: z.boolean().optional(),
  whole_word: z.boolean().optional(),
  regex: z.string().optional(),
  cues: z.array(z.string()).optional(),
  max_length: z.number().int().positive().optional(),
  stop_chars: z.string().max(40).optional(),
  paths: z.array(z.string()).optional(),
});
const validator = z.object({
  type: z.enum(["length", "prefix_list", "luhn", "mod11", "custom_checksum", "mod11_weighted", "mod97", "letter_check", "date_embedded"]),
  value: z.number().int().optional(),
  values: z.array(z.string()).optional(),
  weights: z.array(z.number().int()).optional(),
  modulus: z.number().int().optional(),
  check_position: z.number().int().optional(),
});
const actions = z.object({ api: ACTION, logs: ACTION, ai: ACTION, proxy: ACTION }).partial();
const sample = z.object({ sample: z.string().min(1).max(20000), expect_match: z.boolean() });

const editable = z.object({
  name: z.string().min(1).max(120),
  definition,
  validator: validator.nullish(),
  context_positive: z.array(z.string().min(1).max(60)).max(50).default([]),
  context_negative: z.array(z.string().min(1).max(60)).max(50).default([]),
  threshold: z.number().min(0).max(1).default(0.7),
  token_kind: z.enum(["deterministic", "cell", "transient"]).default("deterministic"),
  token_format: z.enum(["opaque", "format_preserving"]).default("opaque"),
  mask_rule: maskRule.default({ type: "last_n", n: 4 }),
  actions: actions.default({}),
});
export const createBody = editable.extend({
  slug: z.string().regex(/^c_[a-z0-9_]{2,40}$/, "a slug is c_ then 2 to 40 lower-case letters, digits or underscores"),
  kind: KIND,
  tests: z.array(sample).max(200).default([]),
});
const patchBody = editable.partial().extend({ slug: z.string().regex(/^c_[a-z0-9_]{2,40}$/).optional() });

type Entity = NonNullable<Awaited<ReturnType<typeof db.custom_entities.findFirst>>>;
interface Def extends z.infer<typeof editable> { slug: string; kind: string }

const fullActions = (a: z.infer<typeof actions>) => ({ api: a.api ?? "tokenize", logs: a.logs ?? "tokenize", ai: a.ai ?? "tokenize", proxy: a.proxy ?? "tokenize" });

/** Value lists and JSON paths are certain when they match, so the spec fixes their threshold. */
const thresholdFor = (kind: string, t: number) => (kind === "value_list" || kind === "json_path" ? 1 : t);

/** What the row says now: the pending edit if one is waiting, else the row itself. */
function pendingDef(e: Entity): Def {
  if (e.draft) return { ...(e.draft as unknown as Def), slug: e.slug, kind: e.kind };
  return {
    slug: e.slug,
    kind: e.kind,
    name: e.name,
    definition: e.definition as Def["definition"],
    validator: e.validator as Def["validator"],
    context_positive: e.context_positive,
    context_negative: e.context_negative,
    threshold: Number(e.threshold),
    token_kind: e.token_kind as Def["token_kind"],
    token_format: e.token_format as Def["token_format"],
    mask_rule: e.mask_rule as Def["mask_rule"],
    actions: e.actions as Def["actions"],
  };
}

/** The form the vault compiles. validator null must be absent for Go's pointer. */
const toVaultDef = (d: Def) => ({
  slug: d.slug, name: d.name, kind: d.kind, definition: d.definition, validator: d.validator ?? undefined, context_positive: d.context_positive, context_negative: d.context_negative,
  threshold: thresholdFor(d.kind, d.threshold), token_kind: d.token_kind, token_format: d.token_format, mask_rule: d.mask_rule, actions: fullActions(d.actions), status: "draft",
});

const maskString = (m: Def["mask_rule"]) => (m.type === "fixed" ? `fixed:${m.text}` : m.type === "full" ? "full" : `${m.type}:${m.n}`);

async function enabledVault(tenantId: string, id: string) {
  const v = await ownedVault(tenantId, id);
  if (!v.custom_entities_enabled) throw new ApiError(403, "feature_disabled", "custom entities are not turned on for this vault");
  return v;
}

async function loadEntity(tenantId: string, vaultId: string, id: string) {
  const e = await db.custom_entities.findFirst({ where: { id, vault_id: vaultId, tenant_id: tenantId } });
  if (!e) throw notFound("unknown entity");
  return e;
}

/** A new version tells every data-plane service to fetch; delivery happens at commit. */
async function bumpRuleset(tx: { $executeRaw: typeof db.$executeRaw }, vaultId: string) {
  await tx.$executeRaw`INSERT INTO control.ruleset_versions(vault_id,version) VALUES (${vaultId},1) ON CONFLICT (vault_id) DO UPDATE SET version=control.ruleset_versions.version+1`;
  await tx.$executeRaw`SELECT pg_notify('rv_rulesets', ${vaultId})`;
}

/** A definition's staged list or its samples changed, so an open request no longer holds. */
async function supersede(entityId: string) {
  await db.custom_entity_publish_requests.updateMany({ where: { entity_id: entityId, status: "pending" }, data: { status: "superseded", decided_at: new Date() } });
}

/** RFC 4180, enough for one column of a list. Values are never logged. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  const s = text.replace(/^﻿/, "");
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quoted) {
      if (c === '"' && s[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && s[i + 1] === "\n") i++;
      row.push(cell); rows.push(row); row = []; cell = "";
    } else cell += c;
  }
  if (cell !== "" || row.length > 0) { row.push(cell); rows.push(row); }
  return rows;
}

/** Proposes an RE2 pattern from examples: shared literal runs stay, the rest becomes a class. */
export function suggestPattern(examples: string[]): { regex: string; explanation: string } {
  const classOf = (c: string) => (/[0-9]/.test(c) ? "d" : /[A-Z]/.test(c) ? "U" : /[a-z]/.test(c) ? "l" : c);
  const groups = (s: string) => {
    const out: { cls: string; text: string }[] = [];
    for (const c of s) {
      const cls = classOf(c);
      const last = out[out.length - 1];
      if (last && last.cls === cls) last.text += c;
      else out.push({ cls, text: c });
    }
    return out;
  };
  const all = examples.map(groups);
  const shape = (g: { cls: string }[]) => g.map((x) => x.cls).join("|");
  if (new Set(all.map(shape)).size > 1) throw new ApiError(422, "no_pattern", "these examples have different shapes, so no single pattern fits them; check for a typo, or write the pattern by hand");
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\/-]/g, "\\$&");
  const parts: string[] = [];
  const words: string[] = [];
  all[0]!.forEach((g, i) => {
    const col = all.map((a) => a[i]!.text);
    const lens = col.map((t) => t.length);
    const min = Math.min(...lens), max = Math.max(...lens);
    const rep = min === max ? `{${min}}` : `{${min},${max}}`;
    if (new Set(col).size === 1 && g.cls !== "d") { parts.push(esc(g.text)); words.push(`"${g.text}"`); return; }
    if (g.cls === "d") { parts.push(`\\d${rep}`); words.push(`${min === max ? min : `${min} to ${max}`} digits`); }
    else if (g.cls === "U") { parts.push(`[A-Z]${rep}`); words.push(`${min === max ? min : `${min} to ${max}`} capital letters`); }
    else if (g.cls === "l") { parts.push(`[a-z]${rep}`); words.push(`${min === max ? min : `${min} to ${max}`} small letters`); }
    else { parts.push(esc(g.text)); words.push(`"${g.text}"`); }
  });
  return { regex: parts.join(""), explanation: `Matches ${words.join(", then ")}.` };
}

/** Published policies that name an entity directly or through one of its fields. */
async function policiesUsing(tenantId: string, e: Entity) {
  const fields = await db.vault_fields.findMany({ where: { custom_entity_id: e.id }, select: { name: true } });
  const names = new Set(fields.map((f) => f.name));
  const active = await db.policies.findMany({ where: { tenant_id: tenantId, status: "active" } });
  return active.filter((p) => ((p.source as { rules?: { what?: { data_types?: string[]; fields?: string[] } }[] }).rules ?? []).some((r) => r.what?.data_types?.includes(e.slug) || r.what?.fields?.some((f) => f === e.slug || names.has(f)))).map((p) => ({ id: p.id, name: p.name, version: p.version }));
}

async function runChecks(e: Entity, def: Def) {
  const vaultDef = toVaultDef(def);
  const { results } = await vault<{ results: { id: string; expect_match: boolean; passed: boolean; matched: boolean }[] }>("/internal/custom/samples/run", { vault: e.vault_id, entity: e.id, def: vaultDef });
  return results;
}

/** Creates a draft entity, with its samples. Used by the API and by country packs. */
export async function createEntity(a: Actor, vaultId: string, b: z.infer<typeof createBody>, pack?: { id: string; version: number }) {
  const req = { params: { vault: vaultId } };
  const count = await db.custom_entities.groupBy({ by: ["kind"], where: { vault_id: vaultId, status: { not: "archived" } }, _count: true });
  const total = count.reduce((s, c) => s + c._count, 0);
  if (total >= MAX_ENTITIES) throw new ApiError(409, "entity_limit", `a vault can hold ${MAX_ENTITIES} custom entities`);
  if (b.kind === "pattern" && (count.find((c) => c.kind === "pattern")?._count ?? 0) >= MAX_PATTERNS) throw new ApiError(409, "entity_limit", `a vault can hold ${MAX_PATTERNS} pattern entities`);
  if (await db.custom_entities.findFirst({ where: { vault_id: req.params.vault, slug: b.slug } })) throw new ApiError(409, "slug_taken", "this slug is already used in this vault");
  const def: Def = { ...b, actions: fullActions(b.actions) };
  await vault("/internal/custom/check", { def: toVaultDef(def) });
  const id = newId("ce");
  await db.custom_entities.create({
    data: {
      id, tenant_id: a.tenantId, vault_id: req.params.vault, name: b.name, slug: b.slug, kind: b.kind, definition: b.definition, ...(b.validator ? { validator: b.validator } : {}),
      context_positive: b.context_positive, context_negative: b.context_negative, threshold: thresholdFor(b.kind, b.threshold), token_kind: b.token_kind, token_format: b.token_format,
      mask_rule: b.mask_rule, actions: fullActions(b.actions), created_by: a.id, edited_by: a.id, ...(pack ? { pack_id: pack.id, pack_version: pack.version } : {}),
    },
  });
  if (b.tests.length) await vault("/internal/custom/samples/add", { vault: req.params.vault, entity: id, by: a.id, samples: b.tests });
  await audit(a, "custom_entity_draft", { vaultId: req.params.vault, detail: { entity: id, slug: b.slug, kind: b.kind } });
  return { id, slug: b.slug, status: "draft", version: 0 };
}

/** Edits a draft, or stages an edit beside the live version. Used by the API and by country packs. */
export async function editEntity(a: Actor, e: Entity, b: z.infer<typeof patchBody>, pack?: { id: string; version: number }) {
  if (b.slug && b.slug !== e.slug) {
    if (e.version > 0) throw new ApiError(409, "conflict", "a slug cannot change after the first publish");
    if (await db.custom_entities.findFirst({ where: { vault_id: e.vault_id, slug: b.slug } })) throw new ApiError(409, "slug_taken", "this slug is already used in this vault");
  }
  const cur = pendingDef(e);
  const next: Def = { ...cur, ...b, slug: b.slug ?? e.slug, kind: e.kind };
  if (b.actions) next.actions = fullActions({ ...cur.actions, ...b.actions });
  await vault("/internal/custom/check", { def: toVaultDef(next) });
  if (e.version === 0) {
    await db.custom_entities.update({
      where: { id: e.id },
      data: {
        name: next.name, slug: next.slug, definition: next.definition, validator: next.validator ?? undefined, context_positive: next.context_positive, context_negative: next.context_negative,
        threshold: thresholdFor(e.kind, next.threshold), token_kind: next.token_kind, token_format: next.token_format, mask_rule: next.mask_rule, actions: fullActions(next.actions), edited_by: a.id, updated_at: new Date(),
      },
    });
  } else {
    // The live version keeps running; this waits beside it until approved.
    await db.custom_entities.update({ where: { id: e.id }, data: { draft: JSON.parse(JSON.stringify(next)), edited_by: a.id, updated_at: new Date() } });
  }
  if (pack) await db.custom_entities.update({ where: { id: e.id }, data: { pack_id: pack.id, pack_version: pack.version } });
  await supersede(e.id);
  await audit(a, "custom_entity_draft", { vaultId: e.vault_id, detail: { entity: e.id, slug: next.slug } });
  return { ok: true, status: e.status, version: e.version, draft_version: e.version + 1 };
}

/** Runs the samples and the benchmark, then files a request a second person approves. */
export async function requestPublish(a: Actor, e: Entity) {
  if (e.status === "archived") throw new ApiError(409, "conflict", "an archived entity cannot be published; restore it first");
  if (e.version > 0 && !e.draft && e.staged_list_version === null) throw new ApiError(409, "conflict", "nothing has changed since the live version");
  const def = pendingDef(e);
  if (e.kind === "value_list" && e.staged_list_version === null && e.list_version === 0) throw new ApiError(422, "entity_test_failed", "upload a value list before asking to publish");
  const results = await runChecks(e, def);
  const must = results.filter((r) => r.expect_match).length;
  const mustNot = results.length - must;
  if (must < MIN_SAMPLES || mustNot < MIN_SAMPLES) throw new ApiError(422, "entity_test_failed", `publishing needs at least ${MIN_SAMPLES} must-match and ${MIN_SAMPLES} must-not-match samples; this has ${must} and ${mustNot}`);
  const failing = results.filter((r) => !r.passed);
  if (failing.length) throw new ApiError(422, "entity_test_failed", `${failing.length} sample${failing.length === 1 ? "" : "s"} failed`, { failing: failing.map((f) => ({ id: f.id, expect_match: f.expect_match, matched: f.matched })) });
  const bench = await vault<{ bytes: number; lines: number; matched_lines: number; matched_share: number; ms_per_kb: number }>("/internal/custom/benchmark", { vault: e.vault_id, entity: e.id, def: toVaultDef(def) }, 5 * 60_000);
  if (bench.matched_share > MAX_MATCHED_SHARE) throw new ApiError(422, "entity_too_broad", `this matches ${(bench.matched_share * 100).toFixed(1)}% of benchmark lines; the limit is ${MAX_MATCHED_SHARE * 100}%`, { benchmark: bench });
  const limit = e.kind === "value_list" ? MAX_LIST_MS_PER_KB : MAX_MS_PER_KB;
  if (bench.ms_per_kb > limit) throw new ApiError(422, "entity_too_slow", `this adds ${bench.ms_per_kb.toFixed(3)} ms per KB; the limit is ${limit}`, { benchmark: bench });
  await supersede(e.id);
  const id = newId("cepr");
  await db.custom_entity_publish_requests.create({ data: { id, tenant_id: a.tenantId, vault_id: e.vault_id, entity_id: e.id, version: e.version + 1, snapshot: JSON.parse(JSON.stringify(toVaultDef(def))), benchmark: bench, requested_by: a.id } });
  return { id, version: e.version + 1, status: "pending", benchmark: bench, tests: { passed: results.length } };
}

export async function customEntityRoutes(app: FastifyInstance) {
  await app.register(multipart, { limits: { fileSize: MAX_UPLOAD, files: 1, fields: 4 } });

  app.get("/v1/custom-entity-templates", async (req) => {
    requireRole(req, ...READ);
    return { templates: ENTITY_TEMPLATES };
  });

  app.post("/v1/custom-entities/suggest-pattern", async (req) => {
    requireRole(req, ...MANAGE);
    const b = z.object({ examples: z.array(z.string().min(1).max(200)).min(3).max(50) }).parse(req.body);
    return suggestPattern(b.examples);
  });

  // For pickers elsewhere: the policy builder and the vault designer.
  app.get("/v1/custom-entities/slugs", async (req) => {
    const a = requireRole(req, ...READ);
    const rows = await db.custom_entities.findMany({ where: { tenant_id: a.tenantId, version: { gt: 0 }, status: { not: "archived" } }, orderBy: { name: "asc" }, select: { id: true, slug: true, name: true, vault_id: true } });
    return { entities: rows };
  });

  // Live checking for the builder: a definition's errors, with nothing stored.
  app.post("/v1/custom-entities/check", async (req) => {
    requireRole(req, ...MANAGE);
    const b = z.object({ kind: KIND, definition, validator: validator.nullish() }).parse(req.body);
    return vault("/internal/custom/check", { def: { kind: b.kind, slug: "c_check", definition: b.definition, validator: b.validator ?? undefined, threshold: 0.7, status: "draft" } });
  });

  // The Detection screen's header: whether the feature is on, and the built-in catalogue.
  app.get<{ Params: { vault: string } }>("/v1/vaults/:vault/detection", async (req) => {
    const a = requireRole(req, ...READ);
    const v = await ownedVault(a.tenantId, req.params.vault);
    const version = await db.ruleset_versions.findUnique({ where: { vault_id: v.id } });
    return { enabled: v.custom_entities_enabled, thresholds: v.detection_thresholds, built_in: BUILT_IN_ENTITIES, ruleset_version: Number(version?.version ?? 0) };
  });

  app.patch<{ Params: { vault: string } }>("/v1/vaults/:vault/detection", async (req) => {
    const a = requireRole(req, "admin");
    const v = await ownedVault(a.tenantId, req.params.vault);
    const known = new Set(BUILT_IN_ENTITIES.map((b) => b.slug));
    const b = z.object({ enabled: z.boolean().optional(), thresholds: z.record(z.string(), z.number().min(0.3).max(0.99)).optional() }).parse(req.body);
    for (const k of Object.keys(b.thresholds ?? {})) if (!known.has(k)) throw badRequest("unknown built-in entity");
    await db.$transaction(async (tx) => {
      await tx.vaults.update({ where: { id: v.id }, data: { ...(b.enabled === undefined ? {} : { custom_entities_enabled: b.enabled }), ...(b.thresholds ? { detection_thresholds: b.thresholds } : {}) } });
      await bumpRuleset(tx, v.id);
    });
    await audit(a, "detection_settings_change", { vaultId: v.id, detail: b });
    return { ok: true };
  });

  app.get<{ Params: { vault: string }; Querystring: { status?: string; kind?: string; q?: string; sort?: string } }>("/v1/vaults/:vault/custom-entities", async (req) => {
    const a = requireRole(req, ...READ);
    await enabledVault(a.tenantId, req.params.vault);
    const q = z.object({ status: z.string().max(20).optional(), kind: z.string().max(20).optional(), q: z.string().max(100).optional(), sort: z.enum(["name", "hits", "updated"]).default("name") }).parse(req.query);
    const rows = await db.custom_entities.findMany({
      where: { vault_id: req.params.vault, tenant_id: a.tenantId, ...(q.status ? { status: q.status } : {}), ...(q.kind ? { kind: q.kind } : {}), ...(q.q ? { OR: [{ name: { contains: q.q, mode: "insensitive" } }, { slug: { contains: q.q, mode: "insensitive" } }] } : {}) },
      orderBy: { name: "asc" },
    });
    const days = await db.$queryRaw<{ entity_type: string; day: Date; action: string; n: bigint }[]>`
      SELECT entity_type, date_trunc('day', occurred_at AT TIME ZONE control.vault_tz(vault_id)) AS day, action, sum(count)::bigint AS n FROM events.detection_events
      WHERE vault_id=${req.params.vault} AND entity_type LIKE 'c\_%' AND occurred_at>now()-interval '30 days' GROUP BY 1,2,3`;
    const pending = await db.custom_entity_publish_requests.findMany({ where: { vault_id: req.params.vault, status: "pending" } });
    const editors = await db.principals.findMany({ where: { id: { in: rows.map((r) => r.edited_by) } }, select: { id: true, display_name: true } });
    const name = new Map(editors.map((p) => [p.id, p.display_name]));
    const weekAgo = Date.now() - 7 * 86400_000;
    const entities = rows.map((e) => {
      const mine = days.filter((d) => d.entity_type === e.slug);
      const recent = mine.filter((d) => d.day.getTime() >= weekAgo);
      const req0 = pending.find((p) => p.entity_id === e.id);
      return {
        id: e.id, name: e.name, slug: e.slug, kind: e.kind, status: e.status, version: e.version, actions: e.actions,
        draft_version: e.draft || e.version === 0 ? e.version + 1 : null,
        pending_request: req0 ? { id: req0.id, requested_by: req0.requested_by, version: req0.version } : null,
        hits_7d: recent.filter((d) => d.action !== "shadow").reduce((s, d) => s + Number(d.n), 0),
        shadow_hits_7d: recent.filter((d) => d.action === "shadow").reduce((s, d) => s + Number(d.n), 0),
        hits_30d: mine.reduce((s, d) => s + Number(d.n), 0),
        spark: Array.from({ length: 7 }, (_, i) => {
          const from = weekAgo + i * 86400_000;
          return recent.filter((d) => d.day.getTime() >= from && d.day.getTime() < from + 86400_000).reduce((s, d) => s + Number(d.n), 0);
        }),
        published_at: e.published_at, updated_at: e.updated_at, edited_by: name.get(e.edited_by) ?? e.edited_by,
      };
    });
    if (q.sort === "hits") entities.sort((x, y) => y.hits_7d + y.shadow_hits_7d - (x.hits_7d + x.shadow_hits_7d));
    if (q.sort === "updated") entities.sort((x, y) => y.updated_at.getTime() - x.updated_at.getTime());
    return { entities };
  });

  // Definitions only, for copying between sandbox and production. No samples or list values.
  app.get<{ Params: { vault: string } }>("/v1/vaults/:vault/custom-entities/export", async (req) => {
    const a = requireRole(req, ...MANAGE);
    await enabledVault(a.tenantId, req.params.vault);
    const rows = await db.custom_entities.findMany({ where: { vault_id: req.params.vault, tenant_id: a.tenantId }, orderBy: { slug: "asc" } });
    return { entities: rows.map(pendingDef) };
  });

  app.post<{ Params: { vault: string } }>("/v1/vaults/:vault/custom-entities", async (req, reply) => {
    const a = requireRole(req, ...MANAGE);
    await enabledVault(a.tenantId, req.params.vault);
    const out = await createEntity(a, req.params.vault, createBody.parse(req.body));
    return reply.code(201).send(out);
  });

  app.get<{ Params: { vault: string; id: string } }>("/v1/vaults/:vault/custom-entities/:id", async (req) => {
    const a = requireRole(req, ...READ);
    await enabledVault(a.tenantId, req.params.vault);
    const e = await loadEntity(a.tenantId, req.params.vault, req.params.id);
    const fields = await db.vault_fields.findMany({ where: { custom_entity_id: e.id }, select: { id: true, name: true } });
    const list = await db.custom_entity_lists.findFirst({ where: { entity_id: e.id, list_version: e.staged_list_version ?? e.list_version } });
    const pending = await db.custom_entity_publish_requests.findFirst({ where: { entity_id: e.id, status: "pending" } });
    return {
      entity: { ...e, threshold: Number(e.threshold) }, pending_definition: e.draft, fields, policies: await policiesUsing(a.tenantId, e),
      list: list ? { values: list.value_count, staged: e.staged_list_version === list.list_version } : null,
      pending_request: pending ? { id: pending.id, requested_by: pending.requested_by, version: pending.version, benchmark: pending.benchmark } : null,
    };
  });

  app.patch<{ Params: { vault: string; id: string } }>("/v1/vaults/:vault/custom-entities/:id", async (req) => {
    const a = requireRole(req, ...MANAGE);
    await enabledVault(a.tenantId, req.params.vault);
    const e = await loadEntity(a.tenantId, req.params.vault, req.params.id);
    if (e.status === "archived") throw new ApiError(409, "conflict", "an archived entity cannot be edited; restore it first");
    return editEntity(a, e, patchBody.parse(req.body));
  });

  // Stored samples when no text comes; ad-hoc text otherwise. Neither is stored or logged.
  app.post<{ Params: { vault: string; id: string } }>("/v1/vaults/:vault/custom-entities/:id/test", async (req) => {
    const a = requireRole(req, ...MANAGE);
    await enabledVault(a.tenantId, req.params.vault);
    const e = await loadEntity(a.tenantId, req.params.vault, req.params.id);
    const b = z.object({ text: z.string().max(1 << 20).optional(), definition: editable.partial().optional(), estimate: z.boolean().optional() }).parse(req.body ?? {});
    const merged: Def = { ...pendingDef(e), ...(b.definition ?? {}), slug: e.slug, kind: e.kind };
    if (b.estimate) return vault("/internal/custom/quick-bench", { vault: e.vault_id, entity: e.id, def: toVaultDef(merged) });
    if (b.text !== undefined) return vault("/internal/custom/bench", { vault: e.vault_id, entity: e.id, def: toVaultDef(merged), text: b.text });
    return vault("/internal/custom/samples/run", { vault: e.vault_id, entity: e.id, def: toVaultDef(merged) });
  });

  app.post<{ Params: { vault: string; id: string } }>("/v1/vaults/:vault/custom-entities/:id/tests", async (req) => {
    const a = requireRole(req, ...MANAGE);
    await enabledVault(a.tenantId, req.params.vault);
    const e = await loadEntity(a.tenantId, req.params.vault, req.params.id);
    const b = z.object({ samples: z.array(sample).min(1).max(200) }).parse(req.body);
    await vault("/internal/custom/samples/add", { vault: e.vault_id, entity: e.id, by: a.id, samples: b.samples });
    await supersede(e.id);
    return { ok: true };
  });

  app.delete<{ Params: { vault: string; id: string; tid: string } }>("/v1/vaults/:vault/custom-entities/:id/tests/:tid", async (req) => {
    const a = requireRole(req, ...MANAGE);
    await enabledVault(a.tenantId, req.params.vault);
    const e = await loadEntity(a.tenantId, req.params.vault, req.params.id);
    await vault("/internal/custom/samples/delete", { entity: e.id, sample_id: req.params.tid });
    await supersede(e.id);
    return { ok: true };
  });

  // Multipart, file=list.csv and column=name. The file is held in memory only.
  app.post<{ Params: { vault: string; id: string } }>("/v1/vaults/:vault/custom-entities/:id/values", async (req: FastifyRequest<{ Params: { vault: string; id: string } }>) => {
    const a = requireRole(req, ...MANAGE);
    await enabledVault(a.tenantId, req.params.vault);
    const e = await loadEntity(a.tenantId, req.params.vault, req.params.id);
    if (e.kind !== "value_list") throw badRequest("only a value list takes uploads");
    let text = "";
    let column: string | undefined;
    try {
      for await (const part of req.parts()) {
        if (part.type === "file") text = (await part.toBuffer()).toString("utf8");
        else if (part.fieldname === "column") column = String(part.value);
      }
    } catch (err) {
      if ((err as { code?: string }).code === "FST_REQ_FILE_TOO_LARGE") throw new ApiError(413, "value_list_too_large", "this file is over 32 MB");
      throw badRequest("send a multipart form with a CSV file");
    }
    if (!text) throw badRequest("send a multipart form with a CSV file");
    const rows = parseCsv(text);
    const header = rows[0] ?? [];
    let index = 0;
    let dataRows = rows;
    if (column !== undefined) {
      index = header.findIndex((h) => h.trim().toLowerCase() === column!.trim().toLowerCase());
      if (index < 0) throw badRequest("that column is not in the file's first row");
      dataRows = rows.slice(1);
    }
    const res = await vault<{ received: number; hashed: number; duplicates: number; rejected: number; rejected_rows: unknown[]; list_version: number }>("/internal/custom/values", { vault: e.vault_id, entity: e.id, values: dataRows.map((r) => r[index] ?? "") });
    await supersede(e.id);
    await audit(a, "value_list_upload", { vaultId: e.vault_id, detail: { entity: e.id, slug: e.slug, received: res.received, hashed: res.hashed, duplicates: res.duplicates, rejected: res.rejected } });
    return res;
  });

  // The author asks to publish. Tests and the benchmark run here, so an approver only
  // ever sees a definition that has passed them.
  app.post<{ Params: { vault: string; id: string } }>("/v1/vaults/:vault/custom-entities/:id/publish-requests", async (req, reply) => {
    const a = requireRole(req, ...MANAGE);
    await enabledVault(a.tenantId, req.params.vault);
    const e = await loadEntity(a.tenantId, req.params.vault, req.params.id);
    return reply.code(201).send(await requestPublish(a, e));
  });

  app.get("/v1/publish-requests", async (req) => {
    const a = requireRole(req, ...READ);
    const rows = await db.custom_entity_publish_requests.findMany({ where: { tenant_id: a.tenantId, status: "pending" }, orderBy: { created_at: "asc" } });
    return { requests: rows.map((r) => ({ ...r, can_approve: a.roles.some((x) => APPROVE.includes(x)) && r.requested_by !== a.id })) };
  });

  async function pendingRequest(a: Actor, rid: string) {
    const r = await db.custom_entity_publish_requests.findFirst({ where: { id: rid, tenant_id: a.tenantId } });
    if (!r) throw notFound("unknown request");
    if (r.status !== "pending") throw new ApiError(409, "conflict", "this request is no longer pending");
    return r;
  }

  app.post<{ Params: { rid: string } }>("/v1/publish-requests/:rid/approve", async (req) => {
    const a = requireRole(req, ...APPROVE);
    const r = await pendingRequest(a, req.params.rid);
    const e = await db.custom_entities.findUniqueOrThrow({ where: { id: r.entity_id } });
    // Someone who wrote the pending change is an author too, whoever filed the request.
    if (r.requested_by === a.id || e.edited_by === a.id) throw new ApiError(403, "approval_required", "publishing needs a second person: you wrote this change");
    const snap = r.snapshot as unknown as Def;
    const firstPublish = e.version === 0;
    // A new entity starts in shadow. An edit keeps its status: moving a live, enforcing
    // entity to shadow would quietly stop protecting data the moment a typo was fixed.
    const status = e.status === "draft" ? "shadow" : e.status;
    const now = new Date();
    await db.$transaction(async (tx) => {
      await tx.custom_entity_versions.create({ data: { entity_id: e.id, version: r.version, snapshot: r.snapshot as object, published_by: r.requested_by, approved_by: a.id, benchmark: r.benchmark as object } });
      await tx.custom_entities.update({
        where: { id: e.id },
        data: {
          name: snap.name, definition: snap.definition, validator: snap.validator ?? undefined, context_positive: snap.context_positive, context_negative: snap.context_negative, threshold: snap.threshold,
          token_kind: snap.token_kind, token_format: snap.token_format, mask_rule: snap.mask_rule, actions: snap.actions, status, version: r.version, draft: null as never, approved_by: a.id, published_at: now, updated_at: now,
          list_version: e.staged_list_version ?? e.list_version, staged_list_version: null,
        },
      });
      await tx.custom_entity_publish_requests.update({ where: { id: r.id }, data: { status: "approved", decided_by: a.id, decided_at: now } });
      // Tokens need a field to live in. An existing field keeps its id, so tokens stay valid.
      const field = await tx.vault_fields.findFirst({ where: { vault_id: e.vault_id, custom_entity_id: e.id, name: e.slug } });
      if (field) await tx.vault_fields.update({ where: { id: field.id }, data: { mask_rule: maskString(snap.mask_rule) } });
      else await tx.vault_fields.create({ data: { id: newId("fld"), vault_id: e.vault_id, name: e.slug, data_type: "custom", custom_entity_id: e.id, token_kind: snap.token_kind, token_format: snap.token_format, mask_rule: maskString(snap.mask_rule), in_payment_scope: false, ...(snap.token_kind === "transient" ? { ttl_days: 30 } : {}) } });
      await bumpRuleset(tx, e.vault_id);
    });
    await audit(a, "custom_entity_publish", { vaultId: e.vault_id, detail: { entity: e.id, slug: e.slug, version: r.version, author: r.requested_by, approver: a.id, benchmark: r.benchmark } });
    return { ok: true, version: r.version, status, first_publish: firstPublish };
  });

  app.post<{ Params: { rid: string } }>("/v1/publish-requests/:rid/reject", async (req) => {
    const a = requireRole(req, ...APPROVE);
    const r = await pendingRequest(a, req.params.rid);
    await db.custom_entity_publish_requests.update({ where: { id: r.id }, data: { status: "rejected", decided_by: a.id, decided_at: new Date() } });
    return { ok: true };
  });

  app.post<{ Params: { vault: string; id: string } }>("/v1/vaults/:vault/custom-entities/:id/status", async (req) => {
    const a = requireRole(req, ...MANAGE);
    await enabledVault(a.tenantId, req.params.vault);
    const e = await loadEntity(a.tenantId, req.params.vault, req.params.id);
    const b = z.object({ status: z.enum(["shadow", "enforcing", "archived"]) }).parse(req.body);
    if (e.version === 0) throw new ApiError(409, "conflict", "publish this entity before changing its status");
    if (b.status === "archived") {
      const used = await policiesUsing(a.tenantId, e);
      if (used.length) throw new ApiError(409, "entity_in_use", "published policies reference this entity; update them first", { policies: used });
    }
    if (b.status !== e.status) {
      await db.$transaction(async (tx) => {
        await tx.custom_entities.update({ where: { id: e.id }, data: { status: b.status, updated_at: new Date() } });
        await bumpRuleset(tx, e.vault_id);
      });
      await audit(a, "custom_entity_status_change", { vaultId: e.vault_id, detail: { entity: e.id, slug: e.slug, from: e.status, to: b.status } });
    }
    return { ok: true, status: b.status };
  });

  app.get<{ Params: { vault: string; id: string } }>("/v1/vaults/:vault/custom-entities/:id/versions", async (req) => {
    const a = requireRole(req, ...READ);
    await enabledVault(a.tenantId, req.params.vault);
    const e = await loadEntity(a.tenantId, req.params.vault, req.params.id);
    const versions = await db.custom_entity_versions.findMany({ where: { entity_id: e.id }, orderBy: { version: "desc" } });
    return { versions };
  });

  // Counts only. The matched text is never recorded anywhere, so it cannot come back.
  app.get<{ Params: { vault: string; id: string } }>("/v1/vaults/:vault/custom-entities/:id/stats", async (req) => {
    const a = requireRole(req, ...READ);
    await enabledVault(a.tenantId, req.params.vault);
    const e = await loadEntity(a.tenantId, req.params.vault, req.params.id);
    const rows = await db.$queryRaw<{ day: Date; module: string; source_id: string; action: string; entity_version: number | null; n: bigint }[]>`
      SELECT date_trunc('day', occurred_at AT TIME ZONE control.vault_tz(vault_id)) AS day, module, source_id, action, entity_version, sum(count)::bigint AS n FROM events.detection_events
      WHERE vault_id=${e.vault_id} AND entity_type=${e.slug} AND occurred_at>now()-interval '30 days' GROUP BY 1,2,3,4,5 ORDER BY 1`;
    return { rows: rows.map((r) => ({ ...r, n: Number(r.n) })) };
  });
}
