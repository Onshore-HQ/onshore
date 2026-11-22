import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { audit, checkUpstreamUrl, db, env, newId, notFound, READ_CONFIG, requireRole, WRITE } from "../lib.js";
import { TRANSFER_BASIS } from "./pipelines.js";
import { ownedVault } from "./vaults.js";

// Sealed with a key only the control plane and the adapters service hold.
const key = crypto.hkdfSync("sha256", Buffer.from(env("RV_ADAPTER_SECRET")), Buffer.alloc(0), "rv-adapter", 32);
function seal(plain: string): string {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", Buffer.from(key), iv);
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64");
}

const view = <T extends { api_credential_enc: string; webhook_secret_enc: string; webhook_secret_hash: string }>(a: T) => {
  const { api_credential_enc: _a, webhook_secret_enc: _b, webhook_secret_hash: _c, ...rest } = a;
  return rest;
};

export async function adapterRoutes(app: FastifyInstance) {
  app.get("/v1/adapters", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    return { adapters: (await db.adapters.findMany({ where: { vaults: { tenant_id: a.tenantId } }, orderBy: { created_at: "asc" } })).map(view) };
  });

  app.post("/v1/adapters", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z
      .object({
        vault_id: z.string(),
        name: z.string().min(1).max(80),
        kind: z.enum(["freshdesk", "intercom", "zoho_desk", "salesforce"]),
        base_url: z.string(),
        token: z.string().min(1).max(4000),
        // Intercom signs webhooks with the app's client secret.
        client_secret: z.string().max(400).optional(),
        admin_id: z.string().max(60).optional(),
        org_id: z.string().max(60).optional(),
        transfer_basis: TRANSFER_BASIS.default("not_assessed"),
      })
      .parse(req.body);
    await ownedVault(a.tenantId, b.vault_id);
    checkUpstreamUrl(b.base_url);
    const secret = b.client_secret ?? `rvw_${crypto.randomBytes(24).toString("base64url")}`;
    const id = newId("adp");
    await db.adapters.create({ data: { id, vault_id: b.vault_id, name: b.name, kind: b.kind, base_url: b.base_url, api_credential_enc: seal(JSON.stringify({ token: b.token, admin_id: b.admin_id ?? "", org_id: b.org_id ?? "" })), webhook_secret_hash: crypto.createHash("sha256").update(secret).digest("hex"), webhook_secret_enc: seal(secret), transfer_basis: b.transfer_basis } });
    await audit(a, "adapter_create", { vaultId: b.vault_id, detail: { adapter: id, kind: b.kind } });
    return { id, webhook_url: `https://${process.env.RV_HOST ?? "vault.example.com"}/support/${id}/webhook`, webhook_secret: b.client_secret ? undefined : secret };
  });

  app.patch<{ Params: { id: string } }>("/v1/adapters/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ mode: z.enum(["shadow", "enforcing"]).optional(), transfer_basis: TRANSFER_BASIS.optional() }).parse(req.body);
    const r = await db.adapters.findFirst({ where: { id: req.params.id, vaults: { tenant_id: a.tenantId } } });
    if (!r) throw notFound();
    await db.adapters.update({ where: { id: r.id }, data: b });
    await audit(a, "adapter_update", { vaultId: r.vault_id, detail: { adapter: r.id, ...b } });
    return { ok: true };
  });

  app.delete<{ Params: { id: string } }>("/v1/adapters/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const r = await db.adapters.findFirst({ where: { id: req.params.id, vaults: { tenant_id: a.tenantId } } });
    if (!r) throw notFound();
    await db.adapters.delete({ where: { id: r.id } });
    await audit(a, "adapter_delete", { vaultId: r.vault_id, detail: { adapter: r.id } });
    return { ok: true };
  });
}
