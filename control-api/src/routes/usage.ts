import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { db, READ_CONFIG, requireRole, vault } from "../lib.js";

// Usage and connection summaries. Both are worked out from the audit log and detection counts,
// which already record every operation, so nothing here is tracked twice.

const range = z.object({
  from: z.iso.datetime({ offset: true }).optional(),
  to: z.iso.datetime({ offset: true }).optional(),
});

const big = (v: unknown) => Number(v ?? 0);

export async function usageRoutes(app: FastifyInstance) {
  /** Every connection of every kind on one list, with how much it caught. */
  app.get("/v1/connections/summary", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const t = a.tenantId;
    const [logs, ai, proxy, adapters, pages, checks] = await Promise.all([
      db.$queryRaw<{ id: string; name: string; destination: string; mode: string; created_at: Date }[]>`
        SELECT p.id, p.name, p.destination, p.mode, p.created_at FROM control.log_pipelines p JOIN control.vaults v ON v.id=p.vault_id WHERE v.tenant_id=${t}`,
      db.$queryRaw<{ id: string; name: string; provider: string; mode: string; created_at: Date }[]>`
        SELECT r.id, r.name, r.provider, r.mode, r.created_at FROM control.ai_routes r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${t}`,
      db.$queryRaw<{ id: string; name: string; method: string; upstream_url: string; created_at: Date }[]>`
        SELECT r.id, r.name, r.method, r.upstream_url, r.created_at FROM control.proxy_routes r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${t}`,
      db.$queryRaw<{ id: string; name: string; mode: string; created_at: Date }[]>`
        SELECT r.id, r.name, r.mode, r.created_at FROM control.adapters r JOIN control.vaults v ON v.id=r.vault_id WHERE v.tenant_id=${t}`,
      db.$queryRaw<{ id: string; name: string; origin: string; last_report_at: Date | null; created_at: Date }[]>`
        SELECT id, name, origin, last_report_at, created_at FROM control.protected_pages WHERE tenant_id=${t}`,
      // Jobs that report each batch for a flow check, such as a nightly copy. They prove themselves rather than pass through.
      db.$queryRaw<{ id: string; source: string; dest: string | null; status: string }[]>`
        SELECT f.id, src.name AS source, coalesce(ven.name, ds.name, f.dest_host) AS dest, f.status
        FROM control.data_flows f JOIN control.vaults v ON v.id=f.vault_id JOIN control.systems src ON src.id=f.source_system_id
        LEFT JOIN control.systems ds ON ds.id=f.dest_system_id LEFT JOIN control.vendors ven ON ven.id=coalesce(f.dest_vendor_id, ds.vendor_id)
        WHERE v.tenant_id=${t} AND f.retired_at IS NULL AND EXISTS (SELECT 1 FROM events.detection_events d WHERE d.module='check' AND d.source_id=f.id)`,
    ]);
    const counts = await db.$queryRaw<{ source_id: string; day: Date; n: bigint }[]>`
      SELECT d.source_id, date_trunc('day', d.occurred_at AT TIME ZONE control.vault_tz(d.vault_id)) AS day, sum(d.count)::bigint AS n
      FROM events.detection_events d JOIN control.vaults v ON v.id=d.vault_id
      WHERE v.tenant_id=${t} AND d.occurred_at>now()-interval '30 days' GROUP BY 1,2`;
    const last = await db.$queryRaw<{ source_id: string; at: Date }[]>`
      SELECT d.source_id, max(d.occurred_at) AS at FROM events.detection_events d JOIN control.vaults v ON v.id=d.vault_id
      WHERE v.tenant_id=${t} GROUP BY 1`;
    // Fourteen days, gap-filled, so every sparkline has the same shape.
    const days = [...Array(14)].map((_, i) => { const d = new Date(); d.setUTCHours(0, 0, 0, 0); d.setUTCDate(d.getUTCDate() - 13 + i); return d.toISOString().slice(0, 10); });
    const stats = (id: string) => {
      const mine = counts.filter((c) => c.source_id === id);
      const byDay = new Map(mine.map((c) => [new Date(c.day).toISOString().slice(0, 10), big(c.n)]));
      return {
        caught_30d: mine.reduce((s, c) => s + big(c.n), 0),
        sparkline: days.map((day) => ({ day, count: byDay.get(day) ?? 0 })),
        last_seen: last.find((l) => l.source_id === id)?.at ?? null,
      };
    };
    const connections = [
      ...logs.map((p) => ({ id: p.id, kind: "logs", name: p.name, detail: `To ${p.destination}`, state: p.mode === "enforcing" ? "protecting" : "watching", created_at: p.created_at, href: "/pipelines?tab=logs", ...stats(p.id) })),
      ...ai.map((r) => ({ id: r.id, kind: "ai", name: r.name, detail: `To ${r.provider}`, state: r.mode === "enforcing" ? "protecting" : "watching", created_at: r.created_at, href: "/pipelines?tab=ai", ...stats(r.id) })),
      ...proxy.map((r) => ({ id: r.id, kind: "proxy", name: r.name, detail: `${r.method} ${r.upstream_url}`, state: "protecting", created_at: r.created_at, href: "/pipelines?tab=proxy", ...stats(r.id) })),
      ...adapters.map((r) => ({ id: r.id, kind: "support", name: r.name, detail: "Support tool", state: r.mode === "enforcing" ? "protecting" : "watching", created_at: r.created_at, href: "/pipelines?tab=support", ...stats(r.id) })),
      ...pages.map((p) => ({ id: p.id, kind: "page", name: p.name, detail: p.origin, state: p.last_report_at ? "protecting" : "waiting", created_at: p.created_at, href: "/page-protection", ...stats(p.id), last_seen: p.last_report_at })),
      ...checks.map((f) => ({ id: f.id, kind: "check", name: `${f.source} to ${f.dest ?? "its destination"}`, detail: "each batch is checked before it leaves", state: f.status === "leaking" ? "leaking" : f.status === "shadow" ? "proving" : f.status === "unverified" ? "waiting" : "checked", created_at: null, href: `/residency-map/flows/${f.id}`, ...stats(f.id) })),
    ];
    const [map] = await db.$queryRaw<{ flows: bigint; leaking: bigint; outside: bigint }[]>`
      SELECT count(*) AS flows, count(*) FILTER (WHERE f.status='leaking') AS leaking,
        count(*) FILTER (WHERE f.status IN ('leaking','unverified','accepted_risk')) AS outside
      FROM control.data_flows f JOIN control.vaults v ON v.id=f.vault_id WHERE v.tenant_id=${t} AND f.retired_at IS NULL`;
    return { connections, map: { flows: big(map?.flows), leaking: big(map?.leaking), not_protected: big(map?.outside) } };
  });

  /** What Onshore did over a period: the numbers a buyer asks about and a bill is based on. */
  app.get("/v1/usage", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const q = range.parse(req.query);
    const to = q.to ? new Date(q.to) : new Date();
    const from = q.from ? new Date(q.from) : new Date(to.getTime() - 30 * 86400_000);
    if (from >= to) return { error: "from must be before to" };
    const t = a.tenantId;
    const kinds = await db.$queryRaw<{ kind: string; n: bigint }[]>`
      SELECT CASE
          WHEN action='tokenize' THEN 'protected'
          WHEN action='detokenize' AND decision='plaintext' THEN 'revealed'
          WHEN action='detokenize' AND decision='masked' THEN 'masked'
          WHEN decision='denied' OR action='reveal_denied' THEN 'refused'
          WHEN module='console' THEN 'admin'
          ELSE 'other' END AS kind, count(*)::bigint AS n
      FROM events.audit_events WHERE tenant_id=${t} AND occurred_at>=${from} AND occurred_at<${to} GROUP BY 1`;
    const daily = await db.$queryRaw<{ day: Date; protected: bigint; revealed: bigint; refused: bigint }[]>`
      SELECT date_trunc('day', occurred_at AT TIME ZONE control.tenant_tz(tenant_id)) AS day,
        count(*) FILTER (WHERE action='tokenize')::bigint AS protected,
        count(*) FILTER (WHERE action='detokenize' AND decision IN ('plaintext','masked'))::bigint AS revealed,
        count(*) FILTER (WHERE decision='denied' OR action='reveal_denied')::bigint AS refused
      FROM events.audit_events WHERE tenant_id=${t} AND occurred_at>=${from} AND occurred_at<${to} GROUP BY 1 ORDER BY 1`;
    const services = await db.$queryRaw<{ module: string; n: bigint; p50: number | null; p95: number | null }[]>`
      SELECT module, count(*)::bigint AS n,
        percentile_disc(0.5) WITHIN GROUP (ORDER BY latency_ms) AS p50, percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95
      FROM events.audit_events WHERE tenant_id=${t} AND occurred_at>=${from} AND occurred_at<${to} GROUP BY 1 ORDER BY 2 DESC`;
    const caught = await db.$queryRaw<{ module: string; entity_type: string; n: bigint }[]>`
      SELECT d.module, d.entity_type, sum(d.count)::bigint AS n FROM events.detection_events d JOIN control.vaults v ON v.id=d.vault_id
      WHERE v.tenant_id=${t} AND d.occurred_at>=${from} AND d.occurred_at<${to} GROUP BY 1,2 ORDER BY 3 DESC`;
    const [lat] = await db.$queryRaw<{ p50: number | null; p95: number | null }[]>`
      SELECT percentile_disc(0.5) WITHIN GROUP (ORDER BY latency_ms) AS p50, percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95
      FROM events.audit_events WHERE tenant_id=${t} AND occurred_at>=${from} AND occurred_at<${to} AND action IN ('tokenize','detokenize')`;
    const held = await vault<{ records: number; subjects: number }>("/internal/stats", { tenant_id: t });
    const total = (k: string) => big(kinds.find((x) => x.kind === k)?.n);
    return {
      from, to,
      operations: { protected: total("protected"), revealed: total("revealed"), masked: total("masked"), refused: total("refused"), admin: total("admin"), other: total("other") },
      daily: daily.map((d) => ({ day: d.day, protected: big(d.protected), revealed: big(d.revealed), refused: big(d.refused) })),
      services: services.map((s) => ({ module: s.module, n: big(s.n), p50: s.p50, p95: s.p95 })),
      caught: caught.map((c) => ({ module: c.module, entity_type: c.entity_type, n: big(c.n) })),
      latency: { p50: lat?.p50 ?? null, p95: lat?.p95 ?? null },
      held,
    };
  });
}
