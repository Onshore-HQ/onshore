// AI routes: the settings of the AI gateway. Community edition (AGPL).
//
// Each route has its own cloak settings: how each kind of data is hidden before a
// prompt leaves. Two extras stay under the Onshore Commercial Licence (Business, or
// any sandbox vault): cloak profiles shared across routes (ee/routes/gateways.ts),
// and keeping each request's map as a digital twin for the cloak API.
// Language-model detection is set per vault (ee/routes/detection-models.ts).

import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { DEFAULT_ENTITY_TYPES, ENTITY_TYPES } from "../catalog.js";
import { audit, badRequest, checkUpstreamUrl, db, newId, notFound, READ_CONFIG, requireRole, vault, WRITE } from "../lib.js";
import { edition, has, needs } from "../edition.js";
import { ownedVault } from "./vaults.js";
import { mapChanged } from "../ee/map/run.js";

const newKey = () => `rvr_${crypto.randomBytes(24).toString("base64url")}`;
const hashKey = (k: string) => crypto.createHash("sha256").update(k).digest("hex");

const AI_ENTITIES = ENTITY_TYPES as [string, ...string[]];

/** Where a transfer abroad rests in law; shared with log pipelines and the proxy. */
export const TRANSFER_BASIS = z.enum(["not_assessed", "adequacy", "approved_instrument", "section_43", "tokens_only"]);

// ---- cloak settings ------------------------------------------------------------
// The kinds of data and their choices live in the data plane, so the grid and the
// gateway can never disagree. Fetched once per process.
interface CloakCategory { key: string; label: string; default: string; choices: { value: string; label: string; example: string }[] }
let cloakCategories: Promise<CloakCategory[]> | null = null;
export function categories(): Promise<CloakCategory[]> {
  cloakCategories ??= vault<{ categories: CloakCategory[] }>("/internal/cloak/options", {}).then((r) => r.categories).catch((e) => { cloakCategories = null; throw e; });
  return cloakCategories;
}
export const cloakOptions = z.record(z.string(), z.string()).default({});
export async function checkOptions(opts: Record<string, string>) {
  const cats = await categories();
  for (const [k, v] of Object.entries(opts)) {
    const c = cats.find((x) => x.key === k);
    if (!c) throw badRequest(`unknown kind of data "${k}"`);
    if (!c.choices.some((ch) => ch.value === v)) throw badRequest(`${c.label} cannot use "${v}"`);
  }
}
export async function ownedProfile(tenantId: string, id: string) {
  const p = await db.cloak_profiles.findFirst({ where: { id, vaults: { tenant_id: tenantId } } });
  if (!p) throw notFound("no such cloak setting");
  return p;
}
const twinDays = z.number().int().min(0).max(365);

/**
 * Shared cloak profiles and digital twins are Business features, free on sandbox
 * vaults. Turning either off is always allowed, so a lapsed subscription can undo it.
 */
async function checkPaidExtras(vaultId: string, b: { cloak_profile_id?: string | null; twin_days?: number }) {
  const wantsProfile = !!b.cloak_profile_id;
  const wantsTwin = (b.twin_days ?? 0) > 0;
  if (!wantsProfile && !wantsTwin) return;
  const v = await db.vaults.findUnique({ where: { id: vaultId }, select: { environment: true } });
  if (v?.environment === "sandbox" || has(await edition(), "business")) return;
  throw needs("business", wantsProfile ? "shared cloak settings" : "digital twins");
}

function aiView<T extends { route_key_hash: string; id: string }>(r: T) {
  const { route_key_hash: _h, ...rest } = r;
  return { ...rest, setup: aiSetup(r.id, null) };
}

function aiSetup(id: string, key: string | null) {
  const host = process.env.RV_HOST ?? "vault.example.com";
  return `# Change one line in your OpenAI-compatible client: the base URL.
client = OpenAI(
    base_url="https://${host}/ai/${id}/v1",
    default_headers={
        "X-RV-Route-Key": "${key ?? "<your-route-key>"}",
        # Optional. Without it, values come back masked. With a token whose policy
        # allows plaintext, and a route that allows restoring, they come back in full.
        "X-RV-Caller-Token": caller_token,
    },
)`;
}

export async function aiRoutes(app: FastifyInstance) {
  app.get("/v1/ai-routes", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const rows = await db.ai_routes.findMany({ where: { vaults: { tenant_id: a.tenantId } }, orderBy: { created_at: "asc" } });
    return { routes: rows.map(aiView) };
  });

  app.post("/v1/ai-routes", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z
      .object({
        vault_id: z.string(),
        name: z.string().min(1).max(80),
        upstream_base_url: z.string(),
        provider: z.string().min(1).max(40),
        allowed_models: z.array(z.string().min(1).max(100)).min(1, "allow at least one model"),
        entity_types: z.array(z.enum(AI_ENTITIES)).min(1).default(DEFAULT_ENTITY_TYPES),
        restore_in_response: z.boolean().default(false),
        transfer_basis: TRANSFER_BASIS.default("not_assessed"),
        cloak_options: cloakOptions,
        cloak_profile_id: z.string().nullable().default(null),
        twin_days: twinDays.default(0),
      })
      .parse(req.body);
    await ownedVault(a.tenantId, b.vault_id);
    checkUpstreamUrl(b.upstream_base_url);
    await checkOptions(b.cloak_options);
    await checkPaidExtras(b.vault_id, b);
    if (b.cloak_profile_id && (await ownedProfile(a.tenantId, b.cloak_profile_id)).vault_id !== b.vault_id) throw badRequest("that cloak setting belongs to another vault");
    const id = newId("air");
    const key = newKey();
    await db.ai_routes.create({ data: { id, ...b, mode: "shadow", route_key_hash: hashKey(key) } });
    await audit(a, "ai_route_create", { vaultId: b.vault_id, detail: { route: id, provider: b.provider, models: b.allowed_models } });
    return { id, route_key: key, setup: aiSetup(id, key) };
  });

  app.patch<{ Params: { id: string } }>("/v1/ai-routes/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z
      .object({
        mode: z.enum(["shadow", "enforcing"]).optional(),
        allowed_models: z.array(z.string().min(1).max(100)).min(1).optional(),
        entity_types: z.array(z.enum(AI_ENTITIES)).min(1).optional(),
        restore_in_response: z.boolean().optional(),
        upstream_base_url: z.string().optional(),
        transfer_basis: TRANSFER_BASIS.optional(),
        cloak_options: z.record(z.string(), z.string()).optional(),
        cloak_profile_id: z.string().nullable().optional(),
        twin_days: twinDays.optional(),
      })
      .parse(req.body);
    if (b.upstream_base_url) checkUpstreamUrl(b.upstream_base_url);
    const r = await db.ai_routes.findFirst({ where: { id: req.params.id, vaults: { tenant_id: a.tenantId } } });
    if (!r) throw notFound();
    if (b.cloak_options) await checkOptions(b.cloak_options);
    // Only a change that turns a paid extra on is checked; keeping what is there is not.
    await checkPaidExtras(r.vault_id, {
      cloak_profile_id: b.cloak_profile_id !== undefined && b.cloak_profile_id !== r.cloak_profile_id ? b.cloak_profile_id : null,
      twin_days: b.twin_days !== undefined && b.twin_days > r.twin_days ? b.twin_days : 0,
    });
    if (b.cloak_profile_id && (await ownedProfile(a.tenantId, b.cloak_profile_id)).vault_id !== r.vault_id) throw badRequest("that cloak setting belongs to another vault");
    await db.ai_routes.update({ where: { id: r.id }, data: b });
    await audit(a, "ai_route_update", { vaultId: r.vault_id, detail: { route: r.id, ...b } });
    if (b.mode) await mapChanged(r.vault_id, { cause: b.mode === "enforcing" ? "route_enforcing" : undefined });
    return { ok: true };
  });

  app.post("/v1/ai-routes/preview", async (req) => {
    const a = requireRole(req, ...WRITE, "engineer");
    const b = z.object({ prompt: z.string().max(65536), reply: z.string().max(65536).default(""), vault_id: z.string().optional(), profile_id: z.string().optional(), options: z.record(z.string(), z.string()).optional() }).parse(req.body);
    if (b.vault_id) await ownedVault(a.tenantId, b.vault_id);
    let options = b.options ?? {};
    if (b.profile_id) options = (await ownedProfile(a.tenantId, b.profile_id)).options as Record<string, string>;
    await checkOptions(options);
    return vault("/internal/gateway/ai-preview", { prompt: b.prompt, reply: b.reply, vault_id: b.vault_id, options });
  });

  app.get("/v1/cloak-options", async (req) => {
    requireRole(req, ...READ_CONFIG);
    return { categories: await categories() };
  });
}
