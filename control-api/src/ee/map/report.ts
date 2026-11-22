// The residency report's three new pages. Every number comes from the flow tables and the
// status event log; nothing is counted twice or kept in a separate tally.
import { db } from "../../lib.js";

const q = <T = Record<string, any>>(sql: string, ...args: unknown[]) => db.$queryRawUnsafe<T[]>(sql, ...args);

export interface RegisterRow { id: string; source: string; destination: string; country: string; entity_types: string[]; status: string; owner: string | null; origin: string; basis: "observed by Onshore" | "declared by the customer" }

export async function mapReport(tenantId: string, from: Date, to: Date) {
  const enabled = await q<{ n: bigint }>(`SELECT count(*) AS n FROM control.vaults WHERE tenant_id=$1 AND residency_map_enabled`, tenantId);
  if (Number(enabled[0]?.n ?? 0) === 0) return null;
  // Status at the end of the period is the last event up to that moment, not today's status.
  const flows = await q<Record<string, any>>(`
    SELECT f.id, src.name AS source, coalesce(ven.name,ds.name,f.dest_host) AS destination, coalesce(f.dest_country,'unconfirmed') AS country, f.dest_country_source, f.entity_types, f.origin, f.via_system_id, own.display_name AS owner, f.in_scope,
      e.to_status AS status,
      (SELECT a.plan FROM control.remediation_actions a WHERE a.flow_id=f.id AND a.status IN ('open','in_progress') ORDER BY a.due_date LIMIT 1) AS planned_action,
      (SELECT a.due_date FROM control.remediation_actions a WHERE a.flow_id=f.id AND a.status IN ('open','in_progress') ORDER BY a.due_date LIMIT 1) AS planned_due
    FROM control.data_flows f JOIN control.vaults v ON v.id=f.vault_id AND v.residency_map_enabled
    JOIN control.systems src ON src.id=f.source_system_id LEFT JOIN control.systems ds ON ds.id=f.dest_system_id LEFT JOIN control.vendors ven ON ven.id=coalesce(f.dest_vendor_id,ds.vendor_id) LEFT JOIN control.principals own ON own.id=f.owner_id
    JOIN LATERAL (SELECT to_status FROM control.flow_status_events ev WHERE ev.flow_id=f.id AND ev.occurred_at<=$2 ORDER BY ev.seq DESC LIMIT 1) e ON true
    WHERE f.tenant_id=$1 AND f.in_scope ORDER BY src.name, destination`, tenantId, to);
  const live = flows.filter((f) => f.status !== "retired");
  const basis = (f: Record<string, any>): RegisterRow["basis"] => (f.via_system_id && f.status !== "in_country" ? "observed by Onshore" : "declared by the customer");
  const register: RegisterRow[] = live.map((f) => ({ id: f.id, source: f.source, destination: f.destination, country: f.country, entity_types: f.entity_types, status: f.status, owner: f.owner, origin: f.origin, basis: basis(f) }));
  const changes = await q<Record<string, any>>(`
    SELECT ev.seq::text AS seq, ev.flow_id, ev.occurred_at, ev.from_status, ev.to_status, ev.cause, src.name AS source, coalesce(ven.name,ds.name,f.dest_host) AS destination, f.via_system_id
    FROM control.flow_status_events ev JOIN control.data_flows f ON f.id=ev.flow_id JOIN control.vaults v ON v.id=f.vault_id AND v.residency_map_enabled
    JOIN control.systems src ON src.id=f.source_system_id LEFT JOIN control.systems ds ON ds.id=f.dest_system_id LEFT JOIN control.vendors ven ON ven.id=coalesce(f.dest_vendor_id,ds.vendor_id)
    WHERE f.tenant_id=$1 AND ev.occurred_at BETWEEN $2 AND $3 ORDER BY ev.seq`, tenantId, from, to);
  const series = await q<{ day: Date; flow_score: number | null; flow_score_without_exceptions: number | null; volume_score: number | null }>(`
    SELECT m.day, avg(m.flow_score)::float8 AS flow_score, avg(m.flow_score_without_exceptions)::float8 AS flow_score_without_exceptions, avg(m.volume_score)::float8 AS volume_score
    FROM control.map_scores_daily m JOIN control.vaults v ON v.id=m.vault_id WHERE v.tenant_id=$1 AND m.day BETWEEN $2::date AND $3::date GROUP BY 1 ORDER BY 1`, tenantId, from, to);
  const actions = await q<Record<string, any>>(`
    SELECT a.id, a.flow_id, a.plan, a.status, a.due_date, a.completed_at, own.display_name AS owner FROM control.remediation_actions a JOIN control.data_flows f ON f.id=a.flow_id LEFT JOIN control.principals own ON own.id=a.owner_id
    WHERE f.tenant_id=$1 AND ((a.completed_at BETWEEN $2 AND $3) OR (a.status IN ('open','in_progress') AND a.due_date<=$3::date))`, tenantId, from, to);
  const exceptions = await q<Record<string, any>>(`
    SELECT e.id, e.flow_id, e.reason, e.compensating_controls, e.expires_at, e.approved_at, app.display_name AS approver, src.name AS source, coalesce(ven.name,ds.name,f.dest_host) AS destination
    FROM control.flow_exceptions e JOIN control.data_flows f ON f.id=e.flow_id JOIN control.systems src ON src.id=f.source_system_id LEFT JOIN control.systems ds ON ds.id=f.dest_system_id LEFT JOIN control.vendors ven ON ven.id=coalesce(f.dest_vendor_id,ds.vendor_id) LEFT JOIN control.principals app ON app.id=e.approved_by
    WHERE f.tenant_id=$1 AND e.approved_at<=$2 AND e.expires_at>=$2::date AND e.status IN ('active','expired')`, tenantId, to);
  return {
    note: "Each row says whether Onshore observed this flow or the customer declared it. A declared status is a declaration, not verified evidence.",
    data_flow_register: register,
    remediation_timeline: {
      scores: series,
      status_changes: changes.map((c) => ({ seq: c.seq, flow_id: c.flow_id, at: c.occurred_at, from: c.from_status, to: c.to_status, cause: c.cause, source: c.source, destination: c.destination, basis: c.via_system_id ? "observed by Onshore" : "declared by the customer" })),
      actions_completed: actions.filter((a) => a.status === "done"),
      actions_overdue: actions.filter((a) => a.status !== "done"),
    },
    exceptions_and_open_risk: {
      active_exceptions: exceptions,
      open_flows: live.filter((f) => f.status === "leaking" || f.status === "unverified").map((f) => ({ id: f.id, source: f.source, destination: f.destination, status: f.status, owner: f.owner, planned_action: f.planned_action, planned_due: f.planned_due, basis: basis(f) })),
    },
  };
}
export type MapReport = NonNullable<Awaited<ReturnType<typeof mapReport>>>;

const d = (v: unknown) => (v ? new Date(v as string).toISOString().slice(0, 10) : "");

export function mapReportPdf(doc: PDFKit.PDFDocument, m: MapReport) {
  const h = (t: string) => doc.addPage().font("Helvetica-Bold").fontSize(13).fillColor("#111").text(t).moveDown(0.3).font("Helvetica").fontSize(10).fillColor("#222");
  const line = (t: string) => doc.text(t);
  h("Data flow register");
  line(m.note);
  doc.moveDown(0.4);
  if (m.data_flow_register.length === 0) line("No in-scope flows at the end of this period.");
  for (const f of m.data_flow_register) line(`${f.source} to ${f.destination} (${f.country}): ${f.status}. ${f.entity_types.join(", ") || "no data types recorded"}. Owner: ${f.owner ?? "none"}. ${f.basis[0]!.toUpperCase()}${f.basis.slice(1)}.`);
  h("Remediation timeline");
  const t = m.remediation_timeline;
  const first = t.scores[0], last = t.scores[t.scores.length - 1];
  if (first && last) line(`Flow score: ${first.flow_score ?? "n/a"} to ${last.flow_score ?? "n/a"} (without exceptions: ${last.flow_score_without_exceptions ?? "n/a"}). Volume score: ${first.volume_score ?? "n/a"} to ${last.volume_score ?? "n/a"}.`);
  else line("No scores were recorded in this period.");
  doc.moveDown(0.4);
  if (t.status_changes.length === 0) line("No flow changed status in this period.");
  for (const c of t.status_changes) line(`${d(c.at)} ${c.source} to ${c.destination}: ${c.from ?? "new"} to ${c.to}, because ${String(c.cause).replaceAll("_", " ")} (${c.basis}).`);
  doc.moveDown(0.4);
  line(`Actions completed: ${t.actions_completed.length}. Actions overdue: ${t.actions_overdue.length}.`);
  for (const a of t.actions_completed) line(`Done ${d(a.completed_at)}: ${String(a.plan).replaceAll("_", " ")}, owner ${a.owner ?? "none"}.`);
  for (const a of t.actions_overdue) line(`Overdue since ${d(a.due_date)}: ${String(a.plan).replaceAll("_", " ")}, owner ${a.owner ?? "none"}.`);
  h("Exceptions and open risk");
  const r = m.exceptions_and_open_risk;
  if (r.active_exceptions.length === 0) line("No exception was in force at the end of this period.");
  for (const e of r.active_exceptions) line(`${e.source} to ${e.destination}: accepted by ${e.approver ?? "unknown"} until ${d(e.expires_at)}. Reason: ${e.reason}${e.compensating_controls ? `. Controls: ${e.compensating_controls}` : ""}.`);
  doc.moveDown(0.4);
  if (r.open_flows.length === 0) line("No flow was leaking or unverified at the end of this period.");
  for (const f of r.open_flows) line(`${f.source} to ${f.destination}: ${f.status}, owner ${f.owner ?? "none"}, ${f.planned_action ? `planned: ${String(f.planned_action).replaceAll("_", " ")} by ${d(f.planned_due)}` : "no planned action"} (${f.basis}).`);
}

export function mapReportCsv(add: (section: string, key: unknown, value: unknown, count?: unknown) => void, m: MapReport) {
  for (const f of m.data_flow_register) add("data_flow_register", `${f.source} to ${f.destination}`, `${f.country}; ${f.status}; ${f.entity_types.join(" ")}; owner ${f.owner ?? "none"}; ${f.origin}; ${f.basis}`);
  for (const c of m.remediation_timeline.status_changes) add("remediation_timeline", new Date(c.at).toISOString(), `${c.source} to ${c.destination}: ${c.from ?? "new"} to ${c.to}; ${c.cause}; ${c.basis}`);
  for (const s of m.remediation_timeline.scores) add("residency_score", d(s.day), `flow ${s.flow_score ?? ""}; without exceptions ${s.flow_score_without_exceptions ?? ""}; volume ${s.volume_score ?? ""}`);
  for (const e of m.exceptions_and_open_risk.active_exceptions) add("active_exception", `${e.source} to ${e.destination}`, `until ${d(e.expires_at)}; approved by ${e.approver ?? "unknown"}`);
  for (const f of m.exceptions_and_open_risk.open_flows) add("open_risk", `${f.source} to ${f.destination}`, `${f.status}; owner ${f.owner ?? "none"}; ${f.planned_action ?? "no planned action"}; ${f.basis}`);
}
