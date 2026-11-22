import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { audit, db, newId, notFound, READ_CONFIG, requireRole } from "../lib.js";

/** A record of each data import. The browser or `rv import` does the work, in small batches
 *  through the normal vault API, so that access rules and the audit log apply to every value. */
export async function importRoutes(app: FastifyInstance) {
  app.get<{ Params: { vault: string } }>("/v1/vaults/:vault/imports", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    return { imports: await db.import_jobs.findMany({ where: { tenant_id: a.tenantId, vault_id: req.params.vault }, orderBy: { created_at: "desc" }, take: 50 }) };
  });

  app.post<{ Params: { vault: string } }>("/v1/vaults/:vault/imports", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const v = await db.vaults.findFirst({ where: { id: req.params.vault, tenant_id: a.tenantId } });
    if (!v) throw notFound();
    const b = z.object({ file_name: z.string().min(1).max(200), mapping: z.record(z.string().max(200), z.string().max(100)), ref_column: z.string().max(200).nullish() }).parse(req.body);
    const id = newId("imp");
    await db.import_jobs.create({ data: { id, tenant_id: a.tenantId, vault_id: v.id, file_name: b.file_name, mapping: b.mapping, ref_column: b.ref_column ?? null, created_by: a.id } });
    await audit(a, "import_start", { vaultId: v.id, detail: { import: id, file_name: b.file_name, columns: Object.keys(b.mapping).length } });
    return { id };
  });

  app.patch<{ Params: { id: string } }>("/v1/imports/:id", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const b = z.object({ status: z.enum(["running", "paused", "done", "cancelled"]).optional(), rows_done: z.number().int().min(0).optional(), rows_failed: z.number().int().min(0).optional(), values_new: z.number().int().min(0).optional(), values_existing: z.number().int().min(0).optional() }).parse(req.body);
    const j = await db.import_jobs.findFirst({ where: { id: req.params.id, tenant_id: a.tenantId, created_by: a.id } });
    if (!j) throw notFound();
    const ended = b.status === "done" || b.status === "cancelled";
    await db.import_jobs.update({ where: { id: j.id }, data: { ...b, updated_at: new Date(), ...(ended ? { finished_at: new Date() } : {}) } });
    if (ended) await audit(a, "import_finish", { vaultId: j.vault_id, detail: { import: j.id, status: b.status, rows_done: b.rows_done, rows_failed: b.rows_failed } });
    return { ok: true };
  });
}
