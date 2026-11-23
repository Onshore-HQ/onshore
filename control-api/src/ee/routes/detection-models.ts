// Language-model detection: which modules of a vault also ask spaCy, transformers or
// Stanza for names and places, on top of the patterns, checksums and name lists.
// Onshore Commercial Licence (ee/LICENSE): Business, or any sandbox vault.

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { audit, db, READ_CONFIG, requireRole, WRITE } from "../../lib.js";
import { ownedVault } from "../../routes/vaults.js";
import { edition, has, needs } from "../../edition.js";

export const MODEL_MODULES = ["ai", "api", "logs", "proxy"] as const;

async function modulesOf(vaultId: string): Promise<string[]> {
  const rows = await db.$queryRaw<{ model_modules: string[] }[]>`SELECT model_modules FROM control.vaults WHERE id=${vaultId}`;
  return rows[0]?.model_modules ?? [];
}

export async function detectionModelRoutes(app: FastifyInstance) {
  app.get<{ Params: { id: string } }>("/v1/vaults/:id/detection-models", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const v = await ownedVault(a.tenantId, req.params.id);
    const ed = await edition();
    return { modules: await modulesOf(v.id), available: MODEL_MODULES, allowed: has(ed, "business") || v.environment === "sandbox" };
  });

  app.put<{ Params: { id: string } }>("/v1/vaults/:id/detection-models", async (req) => {
    const a = requireRole(req, ...WRITE);
    const v = await ownedVault(a.tenantId, req.params.id);
    const b = z.object({ modules: z.array(z.enum(MODEL_MODULES)).max(MODEL_MODULES.length) }).strict().parse(req.body);
    const modules = [...new Set(b.modules)].sort();
    // Switching off is always allowed, so a lapsed subscription can still turn it off.
    if (modules.length > 0 && v.environment !== "sandbox" && !has(await edition(), "business")) throw needs("business", "language-model detection");
    const before = await modulesOf(v.id);
    await db.$transaction(async (tx) => {
      await tx.$executeRaw`UPDATE control.vaults SET model_modules=${modules}::text[] WHERE id=${v.id}`;
      // Services recompile this vault's detectors on the next notification.
      await tx.$executeRaw`INSERT INTO control.ruleset_versions(vault_id,version) VALUES (${v.id},1) ON CONFLICT (vault_id) DO UPDATE SET version=control.ruleset_versions.version+1`;
      await tx.$executeRaw`SELECT pg_notify('rv_rulesets', ${v.id})`;
    });
    await audit(a, "vault_detection_models_update", { vaultId: v.id, detail: { from: before, to: modules } });
    return { modules };
  });
}
