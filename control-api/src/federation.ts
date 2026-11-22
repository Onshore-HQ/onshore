// Linked installs: one organisation, an install in each country.
//
// The primary install holds the console people use. A member install in another
// country keeps its own vaults, keys and customer data there, and reports to the
// primary every minute: vault names, packs and counts, never a value or a token.
// The member always calls out; the primary never reaches into another country.
// Each report is signed with a secret agreed when the member joined, and the reply
// carries any instructions waiting for it, such as "create this vault".
//
// Onshore Cloud uses the same mechanism: each cloud region is an install Onshore
// runs in that country, linked to the cloud console.

import crypto from "node:crypto";
import { Readable } from "node:stream";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { ApiError, audit, badRequest, db, decryptSecret, encryptSecret, newId, notFound, requireRole, WRITE, type Actor } from "./lib.js";
import { cloudRegions, countryName, isCountry } from "./catalog.js";
import { hash, reportSchema, sign, type Instruction, type Report } from "./federation-protocol.js";
export { sign, reportSchema, type Instruction, type Report } from "./federation-protocol.js";

export const JOIN_TTL_MS = 24 * 3600 * 1000;
export const REPORT_EVERY_MS = 60 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;

function joinCommand(code: string, country: string) {
  const host = process.env.RV_HOST ?? "vault.example.com";
  return `./rv init --country ${country.toLowerCase()} --join ${code} --primary https://${host} --host vault.${country.toLowerCase()}.example.com`;
}

/** A pending link for a country, with a fresh join code. Reuses a pending link if there is one. */
export async function planInstall(a: Actor, country: string, opts: { name?: string; vaults?: Omit<Instruction, "id" | "type">[] } = {}) {
  if (!isCountry(country)) throw badRequest("unknown country");
  const code = `rvj_${crypto.randomBytes(24).toString("base64url")}`;
  const existing = await db.linked_installs.findFirst({ where: { tenant_id: a.tenantId, country, status: "pending" } });
  const pending: Instruction[] = [...((existing?.summary as { pending?: Instruction[] })?.pending ?? []), ...(opts.vaults ?? []).map((v) => ({ id: newId("ins"), type: "create_vault" as const, ...v }))];
  const data = { join_code_hash: hash(code), join_expires_at: new Date(Date.now() + JOIN_TTL_MS), summary: { pending } as unknown as object };
  const row = existing
    ? await db.linked_installs.update({ where: { id: existing.id }, data })
    : await db.linked_installs.create({ data: { id: newId("ins"), tenant_id: a.tenantId, country, name: opts.name ?? `${countryName(country)} install`, created_by: a.id, ...data } });
  await audit(a, "install_plan", { detail: { install: row.id, country, vaults: pending.length } });
  return { id: row.id, join_code: code, command: joinCommand(code, country), expires_at: row.join_expires_at };
}

function view(r: { id: string; country: string; name: string; status: string; base_url: string | null; version: string | null; summary: unknown; last_seen_at: Date | null; joined_at: Date | null; join_expires_at: Date | null; created_at: Date }) {
  const s = (r.summary ?? {}) as { pending?: Instruction[]; report?: Report; failed?: { id: string; error: string }[] };
  const stale = r.status === "active" && (!r.last_seen_at || Date.now() - r.last_seen_at.getTime() > 5 * REPORT_EVERY_MS);
  return {
    id: r.id, country: r.country, name: r.name, status: stale ? "unreachable" : r.status, base_url: r.base_url, version: r.version,
    last_seen_at: r.last_seen_at, joined_at: r.joined_at, created_at: r.created_at,
    join_expired: r.status === "pending" && !!r.join_expires_at && r.join_expires_at.getTime() < Date.now(),
    pending: s.pending ?? [], failed: s.failed ?? [],
    vaults: s.report?.vaults ?? [], detections_7d: s.report?.detections_7d ?? {}, reveals_7d: s.report?.reveals_7d ?? null,
  };
}

async function rawBody(req: FastifyRequest, payload: NodeJS.ReadableStream) {
  const chunks: Buffer[] = [];
  for await (const c of payload) chunks.push(Buffer.from(c as Buffer));
  const buf = Buffer.concat(chunks);
  (req as FastifyRequest & { rawBody?: string }).rawBody = buf.toString("utf8");
  return Readable.from(buf);
}

export async function federationRoutes(app: FastifyInstance, edition: () => Promise<string>) {
  const needLinking = async () => {
    const ed = await edition();
    if (ed !== "enterprise" && ed !== "cloud") throw new ApiError(403, "needs_enterprise", "linking installs in other countries needs Enterprise or Onshore Cloud");
  };

  // ---- on the primary: people ------------------------------------------------
  app.get("/v1/installs", async (req) => {
    const a = requireRole(req, ...WRITE, "compliance", "dpo", "engineer");
    const rows = await db.linked_installs.findMany({ where: { tenant_id: a.tenantId, status: { not: "revoked" } }, orderBy: { created_at: "asc" } });
    return { installs: rows.map(view), cloud_regions: cloudRegions() };
  });

  app.post("/v1/installs", async (req) => {
    const a = requireRole(req, ...WRITE);
    await needLinking();
    const b = z.object({ country: z.string().regex(/^[A-Z]{2}$/), name: z.string().trim().min(2).max(80).optional() }).parse(req.body);
    return planInstall(a, b.country, { name: b.name });
  });

  // A new join code for a link that has not joined yet; the old one stops working.
  app.post<{ Params: { id: string } }>("/v1/installs/:id/join-code", async (req) => {
    const a = requireRole(req, ...WRITE);
    await needLinking();
    const r = await db.linked_installs.findFirst({ where: { id: req.params.id, tenant_id: a.tenantId, status: "pending" } });
    if (!r) throw notFound("no install waiting to join");
    return planInstall(a, r.country);
  });

  app.delete<{ Params: { id: string } }>("/v1/installs/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const r = await db.linked_installs.findFirst({ where: { id: req.params.id, tenant_id: a.tenantId } });
    if (!r) throw notFound();
    await db.linked_installs.update({ where: { id: r.id }, data: { status: "revoked", revoked_at: new Date(), secret_enc: null, join_code_hash: null } });
    await audit(a, "install_revoke", { detail: { install: r.id, country: r.country } });
    return { ok: true };
  });

  // ---- on the primary: member installs ------------------------------------------
  app.post("/v1/federation/join", async (req) => {
    const b = z.object({ code: z.string().regex(/^rvj_[A-Za-z0-9_-]{20,64}$/), country: z.string().regex(/^[A-Z]{2}$/), base_url: z.string().url().max(200), version: z.string().max(40) }).strict().parse(req.body);
    const r = await db.linked_installs.findFirst({ where: { join_code_hash: hash(b.code), status: "pending" } });
    if (!r || !r.join_expires_at || r.join_expires_at.getTime() < Date.now()) throw new ApiError(401, "unauthenticated", "this join code is wrong, used or expired");
    if (r.country !== b.country) throw badRequest(`this join code is for an install in ${countryName(r.country)}`);
    const secret = crypto.randomBytes(32).toString("base64url");
    await db.linked_installs.update({ where: { id: r.id }, data: { status: "active", join_code_hash: null, secret_enc: encryptSecret(secret), base_url: b.base_url, version: b.version, joined_at: new Date(), last_seen_at: new Date() } });
    const t = await db.tenants.findUnique({ where: { id: r.tenant_id } });
    await audit({ tenantId: r.tenant_id, id: `install:${r.id}`, ip: req.ip }, "install_join", { detail: { install: r.id, country: r.country, base_url: b.base_url } });
    return { install_id: r.id, secret, organisation: t?.name ?? "", time_zone: t?.time_zone ?? "UTC", report_every_ms: REPORT_EVERY_MS };
  });

  app.post("/v1/federation/report", { preParsing: async (req, _reply, payload) => rawBody(req, payload) }, async (req) => {
    const id = String(req.headers["x-rv-install"] ?? "");
    const ts = String(req.headers["x-rv-timestamp"] ?? "");
    const sig = String(req.headers["x-rv-signature"] ?? "");
    const r = id ? await db.linked_installs.findFirst({ where: { id, status: "active" } }) : null;
    const raw = (req as FastifyRequest & { rawBody?: string }).rawBody ?? "";
    const fresh = Math.abs(Date.now() - Number(ts)) < CLOCK_SKEW_MS;
    const want = r?.secret_enc ? sign(decryptSecret(r.secret_enc), ts, raw) : "";
    if (!r || !fresh || !want || sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) throw new ApiError(401, "unauthenticated", "report not signed by a linked install");
    const report = reportSchema.parse(req.body);
    if (report.country !== r.country) throw badRequest("this install reports from the wrong country");
    const prev = (r.summary ?? {}) as { pending?: Instruction[] };
    const done = new Set([...report.done, ...report.failed.map((f) => f.id)]);
    const pending = (prev.pending ?? []).filter((p) => !done.has(p.id));
    await db.linked_installs.update({ where: { id: r.id }, data: { last_seen_at: new Date(), version: report.version, summary: { pending, report, failed: report.failed } as object } });
    return { instructions: pending };
  });
}
