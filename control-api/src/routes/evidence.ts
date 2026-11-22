import fs from "node:fs";
import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import PDFDocument from "pdfkit";
import { z } from "zod";
import { Prisma } from "../generated/prisma/client.js";
import { actor, audit, badRequest, checkUpstreamUrl, db, encryptSecret, newId, notFound, READ_AUDIT, READ_CONFIG, requireRole, vault, WRITE } from "../lib.js";
import { mapReport, MapReport, mapReportCsv, mapReportPdf } from "../map/report.js";

const mapping = JSON.parse(fs.readFileSync(new URL("../../config/report-mapping.json", import.meta.url), "utf8")) as {
  version: string;
  note: string;
  questions: { question: string; rule: string; sections: string[] }[];
};

// A cell beginning with these can run as a formula in a spreadsheet.
function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? "" : v instanceof Date ? v.toISOString() : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

const AUDIT_COLUMNS = ["seq", "occurred_at", "principal_id", "principal_kind", "module", "action", "vault_id", "field_id", "decision", "policy_id", "policy_version", "purpose", "source_ip", "network", "break_glass", "request_id", "hash"] as const;

const auditFilter = z.object({
  from: z.iso.datetime({ offset: true }).optional(),
  to: z.iso.datetime({ offset: true }).optional(),
  principal: z.string().optional(),
  action: z.string().optional(),
  decision: z.string().optional(),
  module: z.string().optional(),
  field: z.string().optional(),
  vault: z.string().optional(),
  network: z.string().optional(),
  request: z.string().max(100).optional(),
  records: z.string().regex(/^[0-9a-f-]{36}(,[0-9a-f-]{36})*$/, "must be record ids").optional(),
  before_seq: z.coerce.number().int().positive().optional(),
  after_seq: z.coerce.number().int().positive().optional(),
  order: z.enum(["newest", "oldest"]).default("newest"),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});

function auditWhere(tenantId: string, q: z.infer<typeof auditFilter>): Prisma.audit_eventsWhereInput {
  const when: Prisma.DateTimeFilter = {};
  if (q.from) when.gte = new Date(q.from);
  if (q.to) when.lte = new Date(q.to);
  return {
    tenant_id: tenantId,
    ...(q.from || q.to ? { occurred_at: when } : {}),
    ...(q.principal ? { principal_id: q.principal } : {}),
    ...(q.action ? { action: q.action } : {}),
    ...(q.decision ? { decision: q.decision } : {}),
    ...(q.module ? { module: q.module } : {}),
    ...(q.field ? { field_id: q.field } : {}),
    ...(q.vault ? { vault_id: q.vault } : {}),
    ...(q.network ? { network: q.network } : {}),
    ...(q.request ? { request_id: q.request } : {}),
    ...(q.records ? { record_id: { in: q.records.split(",") } } : {}),
    ...(q.before_seq || q.after_seq ? { seq: { ...(q.before_seq ? { lt: BigInt(q.before_seq) } : {}), ...(q.after_seq ? { gt: BigInt(q.after_seq) } : {}) } } : {}),
  };
}

interface Report {
  title: string;
  disclaimer: string;
  mapping_version: string;
  cover: Record<string, unknown>;
  data_location: Record<string, unknown>;
  protected: unknown;
  outbound_flows: unknown[];
  shadow_share: Record<string, number>;
  custom_entities: { name: string; slug: string; kind: string; status: string; hits_in_period: number; shadow_hits_in_period: number; versions: { version: number; published_by: string; approved_by: string; published_at: Date }[] }[];
  access: Record<string, unknown>;
  changes: Record<string, unknown>;
  integrity: unknown;
  data_subject_requests: Record<string, unknown>;
  alerts: unknown[];
  scope_definition: unknown;
  questions: typeof mapping.questions;
  residency_map: MapReport | null;
}

async function buildReport(tenantId: string, from: Date, to: Date, generatedBy: string): Promise<Report> {
  const tenant = await db.tenants.findUnique({ where: { id: tenantId } });
  const keys = await vault<{ backend: string; health: string; data_keys: { status: string; created_at: string; kek_ref: string }[] }>("/internal/keys/status", { tenant_id: tenantId });
  const stats = await vault("/internal/stats", { tenant_id: tenantId });
  const integrity = await vault("/internal/audit/verify", { tenant_id: tenantId });
  const outbound = await db.$queryRaw<{ module: string; source_id: string; name: string | null; transfer_basis: string | null; destination: string; entity_type: string; action: string; count: bigint }[]>`
    SELECT d.module, d.source_id, coalesce(p.name,ai.name,px.name,ad.name) AS name, coalesce(p.transfer_basis,ai.transfer_basis,px.transfer_basis,ad.transfer_basis) AS transfer_basis, d.destination, d.entity_type, d.action, sum(d.count)::bigint AS count
    FROM events.detection_events d JOIN control.vaults v ON v.id=d.vault_id
    LEFT JOIN control.log_pipelines p ON p.id=d.source_id LEFT JOIN control.ai_routes ai ON ai.id=d.source_id LEFT JOIN control.proxy_routes px ON px.id=d.source_id LEFT JOIN control.adapters ad ON ad.id=d.source_id
    WHERE v.tenant_id=${tenantId} AND d.occurred_at BETWEEN ${from} AND ${to} GROUP BY 1,2,3,4,5,6,7 ORDER BY 5,6,7`;
  const passed = outbound.filter((o) => o.action === "passed").reduce((s, o) => s + Number(o.count), 0);
  const enforced = outbound.filter((o) => o.action !== "passed" && o.action !== "shadow").reduce((s, o) => s + Number(o.count), 0);
  const shadowHits = outbound.filter((o) => o.action === "shadow").reduce((s, o) => s + Number(o.count), 0);
  // The register: every custom entity active in the period, with who approved what.
  const customRows = await db.custom_entities.findMany({ where: { tenant_id: tenantId, version: { gt: 0 }, published_at: { lte: to } }, orderBy: { slug: "asc" } });
  const customVersions = await db.custom_entity_versions.findMany({ where: { entity_id: { in: customRows.map((e) => e.id) } }, orderBy: { version: "asc" } });
  const customEntities = customRows.map((e) => ({
    name: e.name, slug: e.slug, kind: e.kind, status: e.status,
    hits_in_period: outbound.filter((o) => o.entity_type === e.slug && o.action !== "shadow").reduce((s, o) => s + Number(o.count), 0),
    shadow_hits_in_period: outbound.filter((o) => o.entity_type === e.slug && o.action === "shadow").reduce((s, o) => s + Number(o.count), 0),
    versions: customVersions.filter((v) => v.entity_id === e.id).map((v) => ({ version: v.version, published_by: v.published_by, approved_by: v.approved_by, published_at: v.published_at })),
  }));
  const revealBy = (col: "network" | "geo_country") =>
    db.$queryRawUnsafe<{ key: string | null; decision: string | null; n: bigint }[]>(
      `SELECT ${col} AS key, decision, count(*)::bigint AS n FROM events.audit_events WHERE tenant_id=$1 AND occurred_at BETWEEN $2 AND $3 AND action IN ('detokenize','reveal_denied') GROUP BY 1,2 ORDER BY 3 DESC`,
      tenantId,
      from,
      to,
    );
  const byRole = await db.$queryRaw<{ role: string | null; decision: string | null; n: bigint }[]>`
    SELECT r.name AS role, a.decision, count(*)::bigint AS n
    FROM events.audit_events a LEFT JOIN control.role_assignments ra ON ra.principal_id=a.principal_id LEFT JOIN control.roles r ON r.id=ra.role_id
    WHERE a.tenant_id=${tenantId} AND a.occurred_at BETWEEN ${from} AND ${to} AND a.action IN ('detokenize','reveal_denied') GROUP BY 1,2 ORDER BY 3 DESC`;
  const inPeriod = { tenant_id: tenantId, occurred_at: { gte: from, lte: to } };
  const denied = await db.audit_events.count({ where: { ...inPeriod, action: "reveal_denied" } });
  const breakGlass = await db.audit_events.findMany({ where: { ...inPeriod, break_glass: true }, orderBy: { seq: "asc" }, take: 500 });
  const policies = await db.policies.findMany({ where: { tenant_id: tenantId, published_at: { gte: from, lte: to } }, orderBy: { published_at: "asc" }, select: { name: true, version: true, created_by: true, approved_by: true, published_at: true } });
  const rotations = await db.audit_events.findMany({ where: { ...inPeriod, action: "key_rotate" }, orderBy: { seq: "asc" }, select: { occurred_at: true, principal_id: true, detail: true } });
  const exportsDone = await db.audit_events.count({ where: { ...inPeriod, action: "export", NOT: { decision: "denied" } } });
  const erasures = await db.$queryRaw<{ n: bigint }[]>`SELECT count(*)::bigint AS n FROM events.audit_events WHERE tenant_id=${tenantId} AND occurred_at BETWEEN ${from} AND ${to} AND action='delete' AND detail LIKE '%erased_subject%'`;
  const alerts = await db.alerts.findMany({ where: { tenant_id: tenantId, raised_at: { gte: from, lte: to } }, orderBy: { raised_at: "asc" } });
  const scope = await db.scope_definitions.findFirst({ where: { tenant_id: tenantId }, orderBy: { version: "desc" } });
  const fieldsInScope = await db.vault_fields.findMany({ where: { in_payment_scope: true, vaults: { tenant_id: tenantId } }, select: { name: true, data_type: true, vault_id: true } });

  return {
    title: "Residency report",
    disclaimer: "Audit evidence for a compliance officer. This pack does not by itself establish compliance with any law.",
    mapping_version: mapping.version,
    cover: { tenant: tenant?.name, tenant_id: tenantId, period_from: from.toISOString(), period_to: to.toISOString(), generated_by: generatedBy, generated_at: new Date().toISOString() },
    data_location: { deployment: tenant?.deployment, facility: tenant?.hosting_facility ?? "not recorded: set this in Settings", country: tenant?.hosting_country, key_backend: keys.backend, key_service_health: keys.health, active_data_keys: keys.data_keys.filter((k) => k.status === "active").length },
    protected: stats,
    outbound_flows: outbound,
    shadow_share: { detections_passed_unredacted: passed, detections_enforced: enforced, custom_entity_shadow_hits: shadowHits },
    custom_entities: customEntities,
    access: { by_network: await revealBy("network"), by_country: await revealBy("geo_country"), by_role: byRole, denied_attempts: denied, break_glass_events: breakGlass.map((b) => ({ at: b.occurred_at, principal: b.principal_id, action: b.action, purpose: b.purpose })) },
    changes: { policy_versions: policies, key_rotations: rotations },
    integrity,
    data_subject_requests: { exports_completed: exportsDone, erasures_completed: Number(erasures[0]?.n ?? 0) },
    alerts,
    scope_definition: { adopted: scope ? { version: scope.version, body: scope.body, created_by: scope.created_by, created_at: scope.created_at } : null, fields_in_scope: fieldsInScope },
    questions: mapping.questions,
    residency_map: await mapReport(tenantId, from, to),
  };
}

function reportJson(r: Report): string {
  return JSON.stringify(r, (_k, v) => (typeof v === "bigint" ? Number(v) : v));
}

function reportCsv(r: Report, sig: string): string {
  const rows: unknown[][] = [["section", "key", "value", "count"]];
  const add = (section: string, key: unknown, value: unknown, count?: unknown) => rows.push([section, key, value, count ?? ""]);
  for (const [k, v] of Object.entries(r.cover)) add("cover", k, v);
  add("cover", "signature", sig);
  add("cover", "disclaimer", r.disclaimer);
  for (const [k, v] of Object.entries(r.data_location)) add("data_location", k, v);
  for (const f of (r.protected as { by_field: { field: string; data_type: string; count: number }[] }).by_field) add("protected", f.field, f.data_type, f.count);
  for (const o of r.outbound_flows as { destination: string; entity_type: string; action: string; count: bigint }[]) add("outbound_flows", o.destination, `${o.entity_type}:${o.action}`, Number(o.count));
  for (const [k, v] of Object.entries(r.shadow_share)) add("outbound_flows", k, "", v);
  for (const e of r.custom_entities) add("custom_entities", e.slug, `${e.name}, ${e.kind}, ${e.status}, versions ${e.versions.map((v) => v.version).join(" ")}`, e.hits_in_period);
  const access = r.access as { by_network: { key: string | null; decision: string; n: bigint }[]; by_role: { role: string | null; decision: string; n: bigint }[]; denied_attempts: number };
  for (const a of access.by_network) add("access_by_network", a.key ?? "unapproved", a.decision, Number(a.n));
  for (const a of access.by_role) add("access_by_role", a.role ?? "none", a.decision, Number(a.n));
  add("access", "denied_attempts", "", access.denied_attempts);
  const integ = r.integrity as { ok: boolean; events_checked: number };
  add("integrity", "chain_ok", integ.ok);
  add("integrity", "events_checked", integ.events_checked);
  for (const [k, v] of Object.entries(r.data_subject_requests)) add("data_subject_requests", k, "", v);
  if (r.residency_map) mapReportCsv(add, r.residency_map);
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

function reportPdf(r: Report, sig: string, fingerprint: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: "A4", margin: 50, info: { Title: "Residency report", Author: "Onshore" } });
    const chunks: Buffer[] = [];
    doc.on("data", (c: Buffer) => chunks.push(c));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
    const h = (t: string) => doc.moveDown(0.8).font("Helvetica-Bold").fontSize(13).fillColor("#111").text(t).moveDown(0.3).font("Helvetica").fontSize(10).fillColor("#222");
    const kv = (k: string, v: unknown) => doc.font("Helvetica-Bold").text(`${k}: `, { continued: true }).font("Helvetica").text(v === null || v === undefined ? "none recorded" : String(v));
    const line = (t: string) => doc.text(t);

    doc.font("Helvetica-Bold").fontSize(22).text("Residency report");
    doc.moveDown(0.3).font("Helvetica").fontSize(10).fillColor("#555").text(r.disclaimer).fillColor("#222").moveDown();
    h("1. Cover");
    for (const [k, v] of Object.entries(r.cover)) kv(k.replaceAll("_", " "), v);
    kv("signature fingerprint", fingerprint);
    kv("evidence mapping version", r.mapping_version);

    h("2. Data location");
    for (const [k, v] of Object.entries(r.data_location)) kv(k.replaceAll("_", " "), v);

    h("3. What is protected");
    const prot = r.protected as { records: number; subjects: number; by_field: { field: string; data_type: string; count: number; deterministic: number; cell: number; transient: number }[] };
    kv("records", prot.records);
    kv("subjects", prot.subjects);
    for (const f of prot.by_field) line(`${f.field} (${f.data_type}): ${f.count} tokens; ${f.deterministic} deterministic, ${f.cell} cell, ${f.transient} transient`);

    if (r.custom_entities.length > 0) {
      line("Custom entities defined by this organisation:");
      for (const e of r.custom_entities) line(`${e.name} (${e.slug}): ${e.kind.replaceAll("_", " ")}, ${e.status}`);
    }

    h("4. Outbound flows");
    kv("detections passed unredacted (shadow mode)", r.shadow_share.detections_passed_unredacted);
    kv("detections enforced", r.shadow_share.detections_enforced);
    if (r.custom_entities.length > 0) kv("custom entity hits in shadow, passed unchanged", r.shadow_share.custom_entity_shadow_hits);
    const flows = r.outbound_flows as { module: string; name: string | null; transfer_basis: string | null; destination: string; entity_type: string; action: string; count: bigint }[];
    if (flows.length === 0) line("No detections were recorded in this period.");
    for (const o of flows) line(`${o.module}: ${o.name ?? "source"} to ${o.destination}: ${o.entity_type}, ${o.action}: ${Number(o.count)} (ground: ${(o.transfer_basis ?? "not assessed").replaceAll("_", " ")})`);

    h("5. Access");
    const access = r.access as { by_network: { key: string | null; decision: string; n: bigint }[]; by_role: { role: string | null; decision: string; n: bigint }[]; denied_attempts: number; break_glass_events: unknown[] };
    kv("denied attempts", access.denied_attempts);
    kv("break-glass events", access.break_glass_events.length);
    for (const a of access.by_network) line(`network ${a.key ?? "(not on an approved network)"}, ${a.decision}: ${Number(a.n)}`);
    if (access.by_role.length > 0) line("By role (someone with two roles counts under both):");
    for (const a of access.by_role) line(`role ${a.role ?? "(none)"}, ${a.decision}: ${Number(a.n)}`);

    h("6. Changes");
    const ch = r.changes as { policy_versions: { name: string; version: number; created_by: string; approved_by: string | null; published_at: Date | null }[]; key_rotations: { occurred_at: Date; principal_id: string | null; detail: string | null }[] };
    if (ch.policy_versions.length === 0) line("No policies were published in this period.");
    for (const p of ch.policy_versions) line(`policy ${p.name} v${p.version}: written by ${p.created_by}, approved by ${p.approved_by}, ${p.published_at?.toISOString()}`);
    for (const k of ch.key_rotations) line(`key rotation ${k.occurred_at.toISOString()} by ${k.principal_id} ${k.detail ?? ""}`);

    h("7. Integrity");
    const integ = r.integrity as { ok: boolean; events_checked: number; checkpoints_checked: number; verified_to?: string; reason?: string };
    kv("chain verified", integ.ok ? "yes" : `NO: ${integ.reason}`);
    kv("events checked", integ.events_checked);
    kv("signed checkpoints checked", integ.checkpoints_checked);
    kv("verified to", integ.verified_to);

    h("8. Data subject requests");
    for (const [k, v] of Object.entries(r.data_subject_requests)) kv(k.replaceAll("_", " "), v);

    h("9. Appendix: adopted scope of payment transaction data");
    const scope = r.scope_definition as { adopted: { version: number; body: string; created_by: string } | null; fields_in_scope: { name: string; data_type: string }[] };
    if (scope.adopted) {
      kv("version", scope.adopted.version);
      kv("adopted by", scope.adopted.created_by);
      line(scope.adopted.body);
    } else {
      line("No scope definition has been adopted. Record one in Reports.");
    }
    doc.moveDown(0.4);
    line(`Fields marked in scope: ${scope.fields_in_scope.map((f) => f.name).join(", ") || "none"}`);

    if (r.custom_entities.length > 0) {
      h("Appendix: custom entity register");
      line("Every custom entity active in this period, its published versions and who approved them.");
      for (const e of r.custom_entities) {
        line(`${e.name} (${e.slug}), ${e.kind.replaceAll("_", " ")}, ${e.status}. Hits: ${e.hits_in_period} enforced, ${e.shadow_hits_in_period} in shadow.`);
        for (const v of e.versions) line(`  version ${v.version}: published by ${v.published_by}, approved by ${v.approved_by}, ${new Date(v.published_at).toISOString()}`);
      }
    }

    h("Auditor questions and where this pack answers them");
    for (const q of r.questions) line(`${q.question} (${q.rule}): see ${q.sections.join(", ").replaceAll("_", " ")}.`);

    if (r.residency_map) mapReportPdf(doc, r.residency_map);

    h("Signature");
    doc.font("Courier").fontSize(8).text(sig);
    doc.end();
  });
}

export async function evidenceRoutes(app: FastifyInstance) {
  app.get("/v1/audit-events", async (req) => {
    const a = requireRole(req, ...READ_AUDIT);
    const q = auditFilter.parse(req.query);
    const events = await db.audit_events.findMany({ where: auditWhere(a.tenantId, q), orderBy: { seq: q.order === "oldest" ? "asc" : "desc" }, take: q.limit });
    return { events };
  });

  // How many events match, and which values exist, so filters offer only what can match.
  app.get("/v1/audit-events/summary", async (req) => {
    const a = requireRole(req, ...READ_AUDIT);
    const q = auditFilter.parse(req.query);
    const tenant = { tenant_id: a.tenantId };
    const [total, actions, modules, networks, principals] = await Promise.all([
      db.audit_events.count({ where: auditWhere(a.tenantId, q) }),
      db.audit_events.findMany({ where: tenant, distinct: ["action"], select: { action: true }, orderBy: { action: "asc" } }),
      db.audit_events.findMany({ where: tenant, distinct: ["module"], select: { module: true }, orderBy: { module: "asc" } }),
      db.audit_events.findMany({ where: { ...tenant, network: { not: null } }, distinct: ["network"], select: { network: true }, orderBy: { network: "asc" } }),
      db.audit_events.findMany({ where: { ...tenant, principal_id: { not: null } }, distinct: ["principal_id"], select: { principal_id: true } }),
    ]);
    return { total, actions: actions.map((x) => x.action), modules: modules.map((x) => x.module), networks: networks.map((x) => x.network), principals: principals.map((x) => x.principal_id) };
  });

  app.get("/v1/audit-events/export", async (req, reply) => {
    const a = requireRole(req, ...READ_AUDIT);
    const q = auditFilter.parse(req.query);
    const events = await db.audit_events.findMany({ where: auditWhere(a.tenantId, q), orderBy: { seq: "desc" }, take: 100_000 });
    await audit(a, "export", { detail: { what: "audit_events", rows: events.length } });
    const csv = [AUDIT_COLUMNS.join(","), ...events.map((e) => AUDIT_COLUMNS.map((c) => csvCell(e[c] as unknown)).join(","))].join("\r\n");
    return reply.header("content-type", "text/csv; charset=utf-8").header("content-disposition", 'attachment; filename="audit-events.csv"').send(csv);
  });

  // A signed PDF of a filtered audit view, for an auditor. Capped: use the CSV for bulk.
  app.get("/v1/audit-events/export.pdf", async (req, reply) => {
    const a = requireRole(req, ...READ_AUDIT);
    const q = auditFilter.parse(req.query);
    const events = await db.audit_events.findMany({ where: auditWhere(a.tenantId, q), orderBy: { seq: "desc" }, take: 2000 });
    const chain = await vault<{ ok: boolean; events_checked: number; reason?: string }>("/internal/audit/verify", { tenant_id: a.tenantId });
    const digest = crypto.createHash("sha256").update(events.map((e) => e.hash).join("\n")).digest();
    const { signature, public_key } = await vault<{ signature: string; public_key: string }>("/internal/audit/sign", { tenant_id: a.tenantId, message_b64: digest.toString("base64") });
    await audit(a, "export", { detail: { what: "audit_events_pdf", rows: events.length } });
    const pdf = await new Promise<Buffer>((resolve, reject) => {
      const doc = new PDFDocument({ size: "A4", margin: 40, info: { Title: "Audit extract", Author: "Onshore" } });
      const chunks: Buffer[] = [];
      doc.on("data", (c: Buffer) => chunks.push(c));
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.on("error", reject);
      doc.font("Helvetica-Bold").fontSize(18).text("Audit extract");
      doc.font("Helvetica").fontSize(9).text(`Generated ${new Date().toISOString()} by ${a.displayName}. ${events.length} events, newest first.`);
      doc.text(`Chain ${chain.ok ? "verified" : `BROKEN: ${chain.reason}`}, ${chain.events_checked} events checked.`).moveDown();
      doc.fontSize(7.5);
      for (const e of events) doc.text(`${e.seq}  ${e.occurred_at.toISOString()}  ${e.principal_id ?? "system"}  ${e.module}  ${e.action}  ${e.decision ?? ""}  ${e.field_id ?? ""}  ${e.network ?? ""}  ${e.geo_country ?? ""}  ${e.purpose ?? ""}`);
      doc.moveDown().font("Courier").fontSize(7).text(`SHA-256 of the listed event hashes, signed with the audit key.\nDigest ${digest.toString("hex")}\nSignature ${signature}\nPublic key ${public_key}`);
      doc.end();
    });
    return reply.header("content-type", "application/pdf").header("content-disposition", 'attachment; filename="audit-extract.pdf"').send(pdf);
  });

  app.post("/v1/audit-events/verify", async (req) => {
    const a = requireRole(req, ...READ_AUDIT);
    return vault("/internal/audit/verify", { tenant_id: a.tenantId });
  });

  app.get("/v1/alerts", async (req) => {
    const a = requireRole(req, ...READ_AUDIT);
    return { alerts: await db.alerts.findMany({ where: { tenant_id: a.tenantId }, orderBy: { raised_at: "desc" }, take: 100 }) };
  });

  app.post<{ Params: { id: string } }>("/v1/alerts/:id/acknowledge", async (req) => {
    const a = requireRole(req, ...READ_AUDIT);
    const r = await db.alerts.updateMany({ where: { id: req.params.id, tenant_id: a.tenantId }, data: { acknowledged_at: new Date() } });
    if (r.count === 0) throw notFound();
    await audit(a, "alert_acknowledge", { detail: { alert: req.params.id } });
    return { ok: true };
  });

  app.get("/v1/overview", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const pipelines = await db.log_pipelines.findMany({ where: { vaults: { tenant_id: a.tenantId } }, select: { mode: true } });
    const daily = await db.$queryRaw<{ day: Date; entity_type: string; destination: string; n: bigint }[]>`
      SELECT date_trunc('day', d.occurred_at AT TIME ZONE control.vault_tz(d.vault_id)) AS day, d.entity_type, d.destination, sum(d.count)::bigint AS n
      FROM events.detection_events d JOIN control.vaults v ON v.id=d.vault_id
      WHERE v.tenant_id=${a.tenantId} AND d.occurred_at>now()-interval '14 days' GROUP BY 1,2,3 ORDER BY 1`;
    const reveals = await db.$queryRaw<{ decision: string | null; n: bigint }[]>`
      SELECT decision, count(*)::bigint AS n FROM events.audit_events
      WHERE tenant_id=${a.tenantId} AND occurred_at>now()-interval '7 days' AND action IN ('detokenize','reveal_denied') GROUP BY 1`;
    const top = await db.$queryRaw<{ principal_id: string; display_name: string | null; n: bigint }[]>`
      SELECT e.principal_id, p.display_name, count(*)::bigint AS n FROM events.audit_events e LEFT JOIN control.principals p ON p.id=e.principal_id
      WHERE e.tenant_id=${a.tenantId} AND e.occurred_at>now()-interval '7 days' AND e.action='detokenize' AND e.decision='plaintext'
      GROUP BY 1,2 ORDER BY 3 DESC LIMIT 5`;
    const p95 = await db.$queryRaw<{ p95: number | null }[]>`
      SELECT percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95 FROM events.audit_events
      WHERE tenant_id=${a.tenantId} AND occurred_at>now()-interval '1 hour' AND action IN ('tokenize','detokenize')`;
    const keys = await vault<{ backend: string; health: string }>("/internal/keys/status", { tenant_id: a.tenantId });
    // Map alerts are reviewed on the map. This number sends people to the anomaly list.
    const openAlerts = await db.alerts.count({ where: { tenant_id: a.tenantId, acknowledged_at: null, NOT: { kind: { startsWith: "map_" } } } });
    const stats = await vault<{ records: number; subjects: number }>("/internal/stats", { tenant_id: a.tenantId });
    // What the home page's checklist and problem list are worked out from. Nothing here is ticked by hand.
    const [setup] = await db.$queryRaw<Record<string, bigint | boolean>[]>`
      SELECT
        (SELECT count(*) FROM control.vaults v WHERE v.tenant_id=${a.tenantId}) AS vaults,
        (SELECT count(*) FROM control.ai_routes r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${a.tenantId}) AS ai,
        (SELECT count(*) FROM control.ai_routes r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${a.tenantId} AND r.mode='enforcing') AS ai_on,
        (SELECT count(*) FROM control.proxy_routes r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${a.tenantId}) AS proxy,
        (SELECT count(*) FROM control.adapters r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${a.tenantId}) AS adapters,
        (SELECT count(*) FROM control.adapters r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${a.tenantId} AND r.mode='enforcing') AS adapters_on,
        (SELECT count(*) FROM control.protected_pages r WHERE r.tenant_id=${a.tenantId}) AS pages,
        EXISTS (SELECT 1 FROM events.detection_events d JOIN control.vaults v ON v.id=d.vault_id WHERE v.tenant_id=${a.tenantId}) AS detected,
        (SELECT count(*) FROM control.data_flows f JOIN control.vaults v ON v.id=f.vault_id WHERE v.tenant_id=${a.tenantId} AND f.retired_at IS NULL) AS flows,
        (SELECT count(*) FROM control.data_flows f JOIN control.vaults v ON v.id=f.vault_id WHERE v.tenant_id=${a.tenantId} AND f.retired_at IS NULL AND f.status='leaking') AS leaking,
        (SELECT count(*) FROM control.data_flows f JOIN control.vaults v ON v.id=f.vault_id WHERE v.tenant_id=${a.tenantId} AND f.retired_at IS NULL AND f.status='unverified') AS unverified,
        (SELECT count(*) FROM events.alerts x WHERE x.tenant_id=${a.tenantId} AND x.acknowledged_at IS NULL AND x.kind LIKE 'map\_%') AS map_alerts,
        (SELECT count(*) FROM control.policies p WHERE p.tenant_id=${a.tenantId} AND p.status='active' AND p.name NOT IN ('backend-services','console-access')) AS own_rules,
        EXISTS (SELECT 1 FROM events.audit_events e WHERE e.tenant_id=${a.tenantId} AND e.action='export' AND e.detail LIKE '%residency_report%' AND e.detail NOT LIKE '%json%') AS report_generated`;
    const num = (k: string) => Number(setup![k] ?? 0);
    const enforcing = pipelines.filter((p) => p.mode === "enforcing").length;
    const watching = pipelines.filter((p) => p.mode === "shadow").length;
    return {
      setup: {
        vaults: num("vaults"), connections: pipelines.length + num("ai") + num("proxy") + num("adapters") + num("pages"),
        // Proxy routes have no watch mode: a route either applies its rules or doesn't exist.
        protecting: enforcing + num("ai_on") + num("proxy") + num("adapters_on"),
        watching: watching + (num("ai") - num("ai_on")) + (num("adapters") - num("adapters_on")),
        detected: Boolean(setup!.detected), flows: num("flows"), leaking: num("leaking"), unverified: num("unverified"),
        map_alerts: num("map_alerts"), own_rules: num("own_rules"), report_generated: Boolean(setup!.report_generated),
      },
      residency: { connected: pipelines.length, shadow: pipelines.filter((p) => p.mode === "shadow").length, enforcing: pipelines.filter((p) => p.mode === "enforcing").length },
      caught: daily,
      custom_names: Object.fromEntries((await db.custom_entities.findMany({ where: { tenant_id: a.tenantId, version: { gt: 0 } }, select: { slug: true, name: true } })).map((e) => [e.slug, e.name])),
      reveals,
      top_revealers: top,
      health: { api_p95_ms: p95[0]?.p95 ?? null, key_backend: keys.backend, key_service: keys.health },
      open_alerts: openAlerts,
      protected: stats,
    };
  });

  app.get("/v1/scope-definitions", async (req) => {
    const a = actor(req);
    return { definitions: await db.scope_definitions.findMany({ where: { tenant_id: a.tenantId }, orderBy: { version: "desc" } }) };
  });

  // Lawyers advise fixing this definition in writing; each change is a new version.
  app.post("/v1/scope-definitions", async (req) => {
    const a = requireRole(req, ...WRITE, "compliance", "dpo");
    const b = z.object({ body: z.string().min(10).max(20000) }).parse(req.body);
    const latest = await db.scope_definitions.findFirst({ where: { tenant_id: a.tenantId }, orderBy: { version: "desc" } });
    const version = (latest?.version ?? 0) + 1;
    await db.scope_definitions.create({ data: { id: newId("scope"), tenant_id: a.tenantId, version, body: b.body, created_by: a.id } });
    await audit(a, "scope_definition", { detail: { version } });
    return { version };
  });

  app.get("/v1/reports/residency", async (req, reply) => {
    const a = requireRole(req, ...READ_AUDIT);
    const q = z.object({ from: z.string(), to: z.string(), format: z.enum(["json", "pdf", "csv"]).default("json") }).parse(req.query);
    const from = new Date(q.from);
    const to = new Date(q.to);
    if (Number.isNaN(+from) || Number.isNaN(+to) || from >= to) throw badRequest("pick a valid period");
    const r = await buildReport(a.tenantId, from, to, a.displayName);
    const body = reportJson(r);
    const digest = crypto.createHash("sha256").update(body).digest();
    const { signature, public_key } = await vault<{ signature: string; public_key: string }>("/internal/audit/sign", { tenant_id: a.tenantId, message_b64: digest.toString("base64") });
    const fingerprint = crypto.createHash("sha256").update(Buffer.from(public_key, "base64")).digest("hex").slice(0, 24);
    await audit(a, "export", { detail: { what: "residency_report", format: q.format, from: q.from, to: q.to } });
    if (q.format === "pdf") {
      return reply.header("content-type", "application/pdf").header("content-disposition", 'attachment; filename="residency-report.pdf"').send(await reportPdf(r, signature, fingerprint));
    }
    if (q.format === "csv") {
      return reply.header("content-type", "text/csv; charset=utf-8").header("content-disposition", 'attachment; filename="residency-report.csv"').send(reportCsv(r, signature));
    }
    return reply.header("content-type", "application/json").send(`{"report":${body},"signature":${JSON.stringify(signature)},"public_key":${JSON.stringify(public_key)},"fingerprint":${JSON.stringify(fingerprint)},"digest_sha256":${JSON.stringify(digest.toString("hex"))}}`);
  });

  app.get("/v1/keys", async (req) => {
    const a = requireRole(req, ...WRITE, "compliance", "dpo");
    const status = await vault("/internal/keys/status", { tenant_id: a.tenantId });
    const rotations = await db.audit_events.findMany({ where: { tenant_id: a.tenantId, action: "key_rotate" }, orderBy: { seq: "desc" }, take: 20, select: { occurred_at: true, principal_id: true, detail: true, vault_id: true } });
    return { ...status, rotations };
  });

  app.post("/v1/keys/rotate", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ kind: z.enum(["kek", "dek"]), vault_id: z.string().optional(), reencrypt: z.boolean().default(false) }).parse(req.body);
    if (b.kind === "dek") {
      if (!b.vault_id) throw badRequest("vault_id is required for a data key");
      if (!(await db.vaults.findFirst({ where: { id: b.vault_id, tenant_id: a.tenantId } }))) throw notFound("unknown vault");
    }
    return vault("/internal/keys/rotate", { tenant_id: a.tenantId, principal_id: a.id, kind: b.kind, vault_id: b.vault_id ?? "", reencrypt: b.reencrypt });
  });

  app.get("/v1/settings", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const t = await db.tenants.findUnique({ where: { id: a.tenantId } });
    const lic = await vault<{ installed: boolean; valid?: boolean; expires_at?: string; modules?: string[]; seats?: number; expired?: boolean; customer?: string }>("/internal/licence", {});
    const { siem_secret_enc: _s, ...tenant } = t!;
    return { tenant, licence: lic.installed ? lic : null };
  });

  app.patch("/v1/settings", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z.object({ name: z.string().min(2).max(120).optional(), hosting_facility: z.string().max(200).optional(), hosting_country: z.string().length(2).optional(), kek_rotation_days: z.union([z.literal(30), z.literal(60), z.literal(180), z.literal(360), z.null()]).optional(), audit_retention_days: z.number().int().min(365).max(36500).optional(), siem_url: z.string().nullish() }).parse(req.body);
    // The install's country is where every vault on it keeps data; once a vault exists it is fixed.
    if (b.hosting_country) {
      const t = await db.tenants.findUnique({ where: { id: a.tenantId } });
      if (b.hosting_country.toUpperCase() !== t?.hosting_country && (await db.vaults.count({ where: { tenant_id: a.tenantId } })) > 0) throw badRequest("this install's country is fixed once a vault exists");
      b.hosting_country = b.hosting_country.toUpperCase();
    }
    const data: Record<string, unknown> = { ...b };
    let siemSecret: string | undefined;
    if (b.siem_url) {
      checkUpstreamUrl(b.siem_url);
      siemSecret = `rvs_${crypto.randomBytes(24).toString("base64url")}`;
      data.siem_secret_enc = encryptSecret(siemSecret);
    }
    await db.tenants.update({ where: { id: a.tenantId }, data });
    await audit(a, "settings_update", { detail: { ...b, siem_url: b.siem_url ? "set" : b.siem_url } });
    return { ok: true, siem_secret: siemSecret };
  });
}
