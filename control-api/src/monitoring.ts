import { fetch as tlsFetch } from "undici";
import { db, internalAgent, vault } from "./lib.js";
import { broadcast } from "./ee/webhooks.js";

/** Every service this API can reach. Services answer on /healthz over the internal network. */
const COMPONENTS: Record<string, string> = {
  "vault-api": process.env.VAULT_INTERNAL_URL ?? "https://vault-api:8080",
  "log-processor": process.env.RV_LOG_PROCESSOR_URL ?? "https://log-processor:8090",
  "ai-gateway": process.env.RV_AI_GATEWAY_URL ?? "https://ai-gateway:8091",
  "http-proxy": process.env.RV_HTTP_PROXY_URL ?? "https://http-proxy:8092",
  adapters: process.env.RV_ADAPTERS_URL ?? "https://adapters:8093",
  "file-redactor": process.env.RV_FILE_REDACTOR_URL ?? "https://file-redactor:8094",
};
const DOWN_AFTER = 2; // one missed answer during a restart is not worth waking anyone

async function answers(base: string): Promise<boolean> {
  try {
    const r = await tlsFetch(`${base}/healthz`, { ...(internalAgent ? { dispatcher: internalAgent } : {}), signal: AbortSignal.timeout(5000) });
    await r.body?.cancel().catch(() => undefined);
    return r.ok;
  } catch {
    return false;
  }
}

async function keyServiceUp(): Promise<boolean | null> {
  const tenant = await db.tenants.findFirst({ select: { id: true } });
  if (!tenant) return null;
  try {
    const k = await vault<{ health: string }>("/internal/keys/status", { tenant_id: tenant.id }, 5000);
    return k.health === "ok";
  } catch {
    return null; // the vault itself is not answering, which its own check reports
  }
}

/** Records each service's state, and announces a change once. */
export async function checkComponents(): Promise<void> {
  const results = await Promise.all(Object.entries(COMPONENTS).map(async ([name, url]) => [name, await answers(url)] as const));
  const keys = await keyServiceUp();
  if (keys !== null) results.push(["key-service", keys]);
  for (const [component, up] of results) await record(component, up);
}

/** Optional services may not be installed at all. One that has never answered is `absent`,
 *  which alarms nobody; only a service that was up can go down. */
export async function record(component: string, up: boolean): Promise<void> {
  // One statement, so that two replicas cannot both see the change.
  const rows = await db.$queryRaw<{ status: string; was: string | null; since: Date }[]>`
    WITH old AS (SELECT status FROM control.monitor_state WHERE component = ${component}),
    next AS (
      SELECT CASE WHEN ${up}::boolean THEN 'up' WHEN m.status = 'absent' THEN 'absent' WHEN m.failures + 1 >= ${DOWN_AFTER}::int THEN 'down' ELSE m.status END AS status
      FROM control.monitor_state m WHERE m.component = ${component}
    )
    INSERT INTO control.monitor_state AS m (component, status, failures)
      VALUES (${component}, ${up ? "up" : "absent"}, 0)
    ON CONFLICT (component) DO UPDATE SET
      failures = CASE WHEN ${up}::boolean THEN 0 ELSE m.failures + 1 END,
      status = (SELECT status FROM next),
      since = CASE WHEN m.status <> (SELECT status FROM next) THEN now() ELSE m.since END,
      checked_at = now()
    RETURNING m.status, (SELECT status FROM old) AS was, m.since`;
  const r = rows[0]!;
  if (r.was === r.status || r.was === null || r.was === "absent") return;
  const type = r.status === "down" ? "monitor.component_down" : "monitor.component_recovered";
  await broadcast(null, `monitor_${component}_${r.status}_${r.since.getTime()}`, type, { component, since: r.since.toISOString() });
}

/** The numbers behind the console screen and the metrics endpoint, for one tenant. */
export async function snapshot(tenantId: string) {
  const [components, activity, latency, alerts, deliveries, oldest, tenant] = await Promise.all([
    db.monitor_state.findMany({ orderBy: { component: "asc" } }),
    db.$queryRaw<{ module: string; action: string; decision: string; n: bigint }[]>`
      SELECT module, action, coalesce(decision,'') AS decision, count(*)::bigint AS n FROM events.audit_events
      WHERE tenant_id=${tenantId} AND occurred_at>now()-interval '1 hour' GROUP BY 1,2,3 ORDER BY 4 DESC LIMIT 200`,
    db.$queryRaw<{ p50: number | null; p95: number | null }[]>`
      SELECT percentile_disc(0.5) WITHIN GROUP (ORDER BY latency_ms) AS p50, percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95 FROM events.audit_events
      WHERE tenant_id=${tenantId} AND occurred_at>now()-interval '1 hour' AND action IN ('tokenize','detokenize')`,
    db.alerts.count({ where: { tenant_id: tenantId, acknowledged_at: null } }),
    db.$queryRaw<{ status: string; n: bigint }[]>`SELECT status, count(*)::bigint AS n FROM control.webhook_deliveries WHERE tenant_id=${tenantId} AND created_at>now()-interval '24 hours' GROUP BY 1`,
    db.$queryRaw<{ age: number | null }[]>`SELECT extract(epoch FROM now()-min(created_at))::float8 AS age FROM control.webhook_deliveries WHERE tenant_id=${tenantId} AND status='pending'`,
    db.tenants.findUnique({ where: { id: tenantId }, select: { siem_url: true, siem_cursor: true } }),
  ]);
  const lag = tenant?.siem_url ? await db.audit_events.count({ where: { tenant_id: tenantId, seq: { gt: tenant.siem_cursor } } }) : null;
  return {
    components: components.map((c) => ({ component: c.component, status: c.status, since: c.since, checked_at: c.checked_at })),
    activity_last_hour: activity.map((a) => ({ module: a.module, action: a.action, decision: a.decision, count: Number(a.n) })),
    latency_ms: { p50: latency[0]?.p50 ?? null, p95: latency[0]?.p95 ?? null },
    open_alerts: alerts,
    webhooks_last_day: Object.fromEntries(deliveries.map((d) => [d.status, Number(d.n)])),
    webhook_oldest_pending_seconds: oldest[0]?.age ?? 0,
    siem_lag_events: lag,
  };
}

const label = (v: string) => v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");

/** Prometheus text format, which Grafana and Datadog's OpenMetrics check can both read. */
export function renderMetrics(s: Awaited<ReturnType<typeof snapshot>>): string {
  const out: string[] = [];
  const metric = (name: string, help: string, rows: [Record<string, string>, number][]) => {
    out.push(`# HELP ${name} ${help}`, `# TYPE ${name} gauge`);
    for (const [labels, v] of rows) {
      const l = Object.entries(labels).map(([k, x]) => `${k}="${label(x)}"`).join(",");
      out.push(`${name}${l ? `{${l}}` : ""} ${v}`);
    }
  };
  metric("rv_component_up", "1 if the service answered its last health checks", s.components.filter((c) => c.status !== "absent").map((c) => [{ component: c.component }, c.status === "up" ? 1 : 0]));
  metric("rv_audit_events_last_hour", "Audited operations in the last hour", s.activity_last_hour.map((a) => [{ module: a.module, action: a.action, decision: a.decision }, a.count]));
  if (s.latency_ms.p50 !== null) metric("rv_vault_latency_p50_ms", "Median tokenize and detokenize time, last hour", [[{}, s.latency_ms.p50]]);
  if (s.latency_ms.p95 !== null) metric("rv_vault_latency_p95_ms", "95th percentile tokenize and detokenize time, last hour", [[{}, s.latency_ms.p95]]);
  metric("rv_open_alerts", "Alerts nobody has acknowledged", [[{}, s.open_alerts]]);
  metric("rv_webhook_deliveries_last_day", "Webhook deliveries by outcome, last 24 hours", Object.entries(s.webhooks_last_day).map(([status, n]) => [{ status }, n as number]));
  metric("rv_webhook_oldest_pending_seconds", "Age of the oldest undelivered webhook", [[{}, s.webhook_oldest_pending_seconds]]);
  if (s.siem_lag_events !== null) metric("rv_siem_lag_events", "Audit events not yet sent to the SIEM", [[{}, s.siem_lag_events]]);
  return out.join("\n") + "\n";
}
