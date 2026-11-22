import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { ApiError, audit, checkUpstreamUrl, db, newId, notFound, READ_CONFIG, redactText, requireRole, WRITE } from "../lib.js";
import { hashScript, ingest, parseReport, sameOrigin, scanPage } from "../pageprotect.js";

const MAX_PAGES = 50;
const REPORTS_PER_MINUTE = 6000;
const buckets = new Map<string, { minute: number; n: number }>();

/** Takes reports from browsers, on anyone's site. A separate plugin, so that its loose
 *  body handling applies to this one route. Answers the same whatever the key, so that
 *  it says nothing about which keys exist. */
export async function pageReportRoute(app: FastifyInstance) {
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("*", { parseAs: "string", bodyLimit: 64 << 10 }, (_req, body, done) => done(null, body));
  app.post<{ Params: { key: string } }>("/v1/page-protection/report/:key", async (req, reply) => {
    reply.code(204);
    const minute = Math.floor(Date.now() / 60_000);
    const b = buckets.get(req.params.key);
    if (!b || b.minute !== minute) {
      if (buckets.size > 10_000) buckets.clear();
      buckets.set(req.params.key, { minute, n: 1 });
    } else if (++b.n > REPORTS_PER_MINUTE) {
      reply.code(429);
      return;
    }
    if (!/^rvp_[\w-]{20,64}$/.test(req.params.key)) return;
    const page = await db.protected_pages.findUnique({ where: { report_key: req.params.key } });
    if (!page) return;
    const origin = req.headers.origin;
    if (origin && origin !== "null" && origin !== page.origin) return;
    const reports = parseReport(typeof req.body === "string" ? req.body : "");
    for (const r of reports) {
      if (!sameOrigin(r.document, page.origin)) continue;
      await ingest(page, r.scripts, r.source);
    }
    if (reports.length) await db.protected_pages.update({ where: { id: page.id }, data: { last_report_at: new Date() } });
  });
}

export async function pageProtectionRoutes(app: FastifyInstance) {
  async function owned(tenantId: string, id: string) {
    const p = await db.protected_pages.findFirst({ where: { id, tenant_id: tenantId } });
    if (!p) throw notFound("unknown page");
    return p;
  }

  app.get("/v1/page-protection/pages", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const pages = await db.protected_pages.findMany({ where: { tenant_id: a.tenantId }, orderBy: { created_at: "desc" } });
    const counts = await db.page_scripts.groupBy({ by: ["page_id", "status"], where: { tenant_id: a.tenantId }, _count: true });
    return { pages: pages.map((p) => ({ ...p, scripts: Object.fromEntries(counts.filter((c) => c.page_id === p.id).map((c) => [c.status, c._count])) })) };
  });

  app.post("/v1/page-protection/pages", async (req, reply) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ name: z.string().trim().min(1).max(120), page_url: z.string().max(2000) }).strict().parse(req.body);
    checkUpstreamUrl(b.page_url);
    if ((await db.protected_pages.count({ where: { tenant_id: a.tenantId } })) >= MAX_PAGES) throw new ApiError(409, "too_many_pages", `up to ${MAX_PAGES} pages`);
    const u = new URL(b.page_url);
    const p = await db.protected_pages.create({ data: { id: newId("pg"), tenant_id: a.tenantId, name: b.name, page_url: u.origin + u.pathname, origin: u.origin, report_key: `rvp_${crypto.randomBytes(24).toString("base64url")}`, created_by: a.id } });
    await audit(a, "page_protect_create", { detail: { page: p.id, origin: p.origin } });
    reply.code(201);
    return p;
  });

  app.delete<{ Params: { id: string } }>("/v1/page-protection/pages/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const p = await owned(a.tenantId, req.params.id);
    await db.protected_pages.delete({ where: { id: p.id } });
    await audit(a, "page_protect_delete", { detail: { page: p.id, origin: p.origin } });
    return { ok: true };
  });

  app.get<{ Params: { id: string } }>("/v1/page-protection/pages/:id", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const p = await owned(a.tenantId, req.params.id);
    const scripts = await db.page_scripts.findMany({ where: { page_id: p.id }, orderBy: { first_seen: "desc" } });
    return { page: p, scripts, approved_sources: [...new Set(scripts.filter((s) => s.status === "approved" && s.script_url.startsWith("http")).map((s) => s.script_url))] };
  });

  app.post<{ Params: { id: string } }>("/v1/page-protection/pages/:id/scan", async (req) => {
    const a = requireRole(req, ...WRITE);
    const p = await owned(a.tenantId, req.params.id);
    await scanPage(p.id);
    return { ok: true };
  });

  // PCI DSS 6.4.3 asks that each script is authorised, with a written reason.
  app.post<{ Params: { id: string; script: string } }>("/v1/page-protection/pages/:id/scripts/:script/decision", async (req) => {
    const a = requireRole(req, ...WRITE);
    const p = await owned(a.tenantId, req.params.id);
    const b = z.object({ decision: z.enum(["approve", "reject"]), justification: z.string().trim().min(3).max(500) }).strict().parse(req.body);
    const s = await db.page_scripts.findFirst({ where: { id: req.params.script, page_id: p.id } });
    if (!s) throw notFound("unknown script");
    let hash = s.content_hash;
    let hashError: string | null = null;
    if (b.decision === "approve" && s.script_url.startsWith("http")) {
      // The baseline is what the file holds when someone looks at it.
      try { hash = await hashScript(s.script_url); } catch { hash = null; hashError = "could not fetch it to record a baseline"; }
    }
    const justification = await redactText(b.justification);
    const u = await db.page_scripts.update({ where: { id: s.id }, data: { status: b.decision === "approve" ? "approved" : "rejected", justification, decided_by: a.id, decided_at: new Date(), content_hash: hash, hash_error: hashError } });
    await audit(a, "page_script_decision", { detail: { page: p.id, script: s.id, script_url: s.script_url, decision: b.decision, justification } });
    return u;
  });
}
