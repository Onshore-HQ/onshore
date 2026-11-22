"use client";
import { tr } from "@/lib/i18n";
import { useState } from "react";
import { Badge, Checks, Copy, Empty, ErrorLine, Loading, Modal, Page, TypedConfirm } from "@/components/ui";
import { control, n, useLoad, when } from "@/lib/api";
import Link from "next/link";
import { actionLabel, decisionLabel, serviceLabel } from "@/lib/labels";

interface Component { component: string; status: string; since: string; checked_at: string }
interface Endpoint { id: string; url: string; description: string; event_types: string[]; enabled: boolean; disabled_reason: string | null; consecutive_failures: number; last_success_at: string | null; last_failure_at: string | null }
interface Delivery { id: string; event_id: string; event_type: string; status: string; attempts: number; last_status: number | null; last_error: string | null; created_at: string; next_attempt_at: string; delivered_at: string | null }

const COMPONENT_TONE: Record<string, "good" | "bad" | ""> = { up: "good", down: "bad", absent: "" };
const COMPONENT_WORD: Record<string, string> = { up: "Answering", down: "Not answering", absent: "Not running here" };

export default function Monitoring() {
  const mon = useLoad(() => control("/v1/monitoring"));
  const hooks = useLoad<{ endpoints: Endpoint[] }>(() => control("/v1/webhooks"));
  const [adding, setAdding] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [metricsKey, setMetricsKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [removing, setRemoving] = useState<Endpoint | null>(null);
  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try { await fn(); mon.reload(); hooks.reload(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
  };
  const m = mon.value;
  const down = (m?.components ?? []).filter((c: Component) => c.status === "down");
  const host = typeof window === "undefined" ? "" : window.location.origin;
  return (
    <Page title={tr("Health & alerts")} sub={tr("Whether each service is answering, what the product did in the last hour, and where alerts go.")} actions={<button className="primary" onClick={() => setAdding(true)}>{tr("New webhook")}</button>}>
      <div className="stack">
        <Loading error={mon.error} loading={mon.loading && !m} />
        <ErrorLine error={error} />
        {down.length > 0 && <div className="note bad">{down.map((c: Component) => c.component).join(", ")} {down.length === 1 ? "is" : tr("are")} {tr("not answering.")}</div>}
        {secret && <div className="note good"><b>{tr("Signing secret, shown once.")}</b> <code>{secret}</code> <Copy text={secret} /></div>}
        {m && (
          <div className="card">
            <h2>{tr("Services")}</h2>
            <table>
              <thead><tr><th>{tr("Service")}</th><th>{tr("State")}</th><th>{tr("Since")}</th></tr></thead>
              <tbody>{m.components.map((c: Component) => <tr key={c.component}><td><div className="font-medium">{serviceLabel(c.component)}</div><code className="text-xs text-muted-foreground">{c.component}</code></td><td><Badge tone={COMPONENT_TONE[c.status] ?? ""}>{COMPONENT_WORD[c.status] ?? c.status}</Badge></td><td className="small muted">{when(c.since)}</td></tr>)}</tbody>
            </table>
            {m.components.length === 0 && <p className="small muted">{tr("The first check runs within 30 seconds.")}</p>}
            <p className="small muted">{tr("This screen runs on the service that does the checking, so it cannot report that service's own failure. Watch")} <code>{host}/healthz</code> {tr("from outside the install as well.")}</p>
          </div>
        )}
        {m && (
          <div className="card">
            <h2>{tr("Last hour")}</h2>
            <div className="row" style={{ gap: 24, flexWrap: "wrap" }}>
              <div><div className="small muted">{tr("95% of vault requests took under")}</div><b>{m.latency_ms.p95 === null ? tr("No traffic") : `${m.latency_ms.p95} ms`}</b></div>
              <div><div className="small muted">{tr("Open alerts")}</div><b>{n(m.open_alerts)}</b></div>
              <div><div className="small muted">{tr("Webhooks delivered, 24 h")}</div><b>{n(m.webhooks_last_day.delivered)}</b></div>
              <div><div className="small muted">{tr("Webhooks given up on, 24 h")}</div><b>{n(m.webhooks_last_day.dead)}</b></div>
              {m.siem_lag_events !== null && <div><div className="small muted">{tr("Events waiting for the SIEM")}</div><b>{n(m.siem_lag_events)}</b></div>}
            </div>
            {m.activity_last_hour.length > 0 && (
              <table style={{ marginTop: 12 }}>
                <thead><tr><th>{tr("Service")}</th><th>{tr("Action")}</th><th>{tr("Result")}</th><th>{tr("Count")}</th></tr></thead>
                <tbody>{m.activity_last_hour.slice(0, 12).map((a: { module: string; action: string; decision: string; count: number }) => <tr key={`${a.module}${a.action}${a.decision}`}><td><Link href={`/logs?service=${a.module}`}>{serviceLabel(a.module)}</Link></td><td>{actionLabel(a.action, a.decision)}</td><td>{a.decision ? decisionLabel(a.decision) : "—"}</td><td>{n(a.count)}</td></tr>)}</tbody>
              </table>
            )}
          </div>
        )}
        <div className="card">
          <h2>{tr("Webhooks")}</h2>
          <p className="small muted">{tr("Events carry what happened and who did it, and never a value, a purpose or an address. Each one is signed, and retried for about two days.")}</p>
          <Loading error={hooks.error} loading={hooks.loading && !hooks.value} />
          {hooks.value?.endpoints.length === 0 && <Empty title={tr("No webhooks yet")}>{tr("Send reveals, policy changes and service failures to your own systems.")}</Empty>}
          <div className="stack">
            {hooks.value?.endpoints.map((e) => (
              <div key={e.id} style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
                <div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap" }}>
                  <div>
                    <code style={{ wordBreak: "break-all" }}>{e.url}</code> {e.enabled ? <Badge tone="good">{tr("On")}</Badge> : <Badge tone="warn">{tr("Off")}</Badge>}
                    {e.description && <div className="small muted">{e.description}</div>}
                    <div className="small muted">{e.event_types.length} {tr("event type")}{e.event_types.length === 1 ? "" : "s"}{e.last_success_at ? tr(", last delivered {0}", { 0: when(e.last_success_at) }) : tr(", nothing delivered yet")}{e.consecutive_failures > 0 ? tr(", {0} failures in a row", { 0: e.consecutive_failures }) : ""}</div>
                    {e.disabled_reason && <div className="small muted">{e.disabled_reason[0]!.toUpperCase() + e.disabled_reason.slice(1)}.</div>}
                  </div>
                  <div className="row" style={{ flexWrap: "wrap" }}>
                    <button className="small" onClick={() => setOpen(open === e.id ? null : e.id)}>{tr("Deliveries")}</button>
                    <button className="small" onClick={() => act(() => control(`/v1/webhooks/${e.id}/test`, { method: "POST" }))}>{tr("Send test")}</button>
                    <button className="small" onClick={() => act(() => control(`/v1/webhooks/${e.id}`, { method: "PATCH", body: { enabled: !e.enabled } }))}>{e.enabled ? tr("Turn off") : tr("Turn on")}</button>
                    <button className="small" onClick={() => act(async () => setSecret((await control(`/v1/webhooks/${e.id}/rotate-secret`, { method: "POST" })).secret))}>{tr("Rotate secret")}</button>
                    <button className="small" onClick={() => setRemoving(e)}>{tr("Delete")}</button>
                  </div>
                </div>
                {open === e.id && <Deliveries endpoint={e.id} />}
              </div>
            ))}
          </div>
        </div>
        {m && (
          <div className="card">
            <h2>{tr("Metrics for Grafana or Datadog")}</h2>
            <p className="small muted">{tr("Prometheus text format. The key reads these numbers and does nothing else.")}</p>
            {metricsKey && <div className="note good"><b>{tr("Metrics key, shown once.")}</b> <code>{metricsKey}</code> <Copy text={metricsKey} /></div>}
            <pre className="pre small">{`curl -H "Authorization: Bearer <key>" ${host}/control/v1/monitoring/metrics`}</pre>
            <div className="row">
              <button onClick={() => act(async () => setMetricsKey((await control("/v1/monitoring/metrics-key", { method: "POST" })).key))}>{m.metrics_key_set ? tr("Replace key") : tr("Create key")}</button>
              {m.metrics_key_set && <button onClick={() => act(async () => { await control("/v1/monitoring/metrics-key", { method: "DELETE" }); setMetricsKey(null); })}>{tr("Revoke key")}</button>}
            </div>
          </div>
        )}
      </div>
      {adding && <AddEndpoint onClose={() => setAdding(false)} onDone={(s) => { setAdding(false); setSecret(s); hooks.reload(); }} />}
      {removing && <TypedConfirm title={tr("Delete this webhook?")} word="delete" onClose={() => setRemoving(null)} onConfirm={async () => { await control(`/v1/webhooks/${removing.id}`, { method: "DELETE" }); setRemoving(null); hooks.reload(); }}>{tr("Its delivery history goes with it.")} <code>{removing.url}</code></TypedConfirm>}
    </Page>
  );
}

function Deliveries({ endpoint }: { endpoint: string }) {
  const { value, error, loading, reload } = useLoad<{ deliveries: Delivery[] }>(() => control(`/v1/webhooks/${endpoint}/deliveries?limit=20`));
  const [err, setErr] = useState<string | null>(null);
  return (
    <div style={{ marginTop: 8, overflowX: "auto" }}>
      <Loading error={error} loading={loading && !value} />
      <ErrorLine error={err} />
      {value?.deliveries.length === 0 && <p className="small muted">{tr("Nothing sent yet.")}</p>}
      {value && value.deliveries.length > 0 && (
        <table>
          <thead><tr><th>{tr("Event")}</th><th>{tr("Outcome")}</th><th>{tr("Tries")}</th><th>{tr("Result")}</th><th>{tr("When")}</th><th /></tr></thead>
          <tbody>{value.deliveries.map((d) => (
            <tr key={d.id}>
              <td><code>{d.event_type}</code></td>
              <td><Badge tone={d.status === "delivered" ? "good" : d.status === "dead" ? "bad" : "warn"}>{d.status === "dead" ? tr("Gave up") : d.status === "delivered" ? tr("Delivered") : d.attempts === 0 ? tr("Waiting") : tr("Retrying")}</Badge></td>
              <td>{d.attempts}</td>
              <td className="small">{d.last_error ?? (d.last_status ? tr("answered {0}", { 0: d.last_status }) : "—")}</td>
              <td className="small muted">{when(d.created_at)}</td>
              <td><button className="small" onClick={async () => { try { await control(`/v1/webhooks/${endpoint}/deliveries/${d.id}/redeliver`, { method: "POST" }); reload(); } catch (e) { setErr(e instanceof Error ? e.message : "failed"); } }}>{tr("Send again")}</button></td>
            </tr>
          ))}</tbody>
        </table>
      )}
    </div>
  );
}

function AddEndpoint({ onClose, onDone }: { onClose: () => void; onDone: (secret: string) => void }) {
  const types = useLoad<{ event_types: { type: string; description: string }[] }>(() => control("/v1/webhooks/event-types"));
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [chosen, setChosen] = useState<string[]>(["reveal.denied", "access.break_glass", "alert.raised", "monitor.component_down", "monitor.component_recovered"]);
  const [error, setError] = useState<string | null>(null);
  return (
    <Modal title={tr("New webhook")} onClose={onClose}>
      <div className="stack">
        <label className="field"><span>{tr("Destination, https")}</span><input value={url} placeholder="https://hooks.example.com/residency" onChange={(e) => setUrl(e.target.value)} /></label>
        <label className="field"><span>{tr("Description, optional")}</span><input value={description} onChange={(e) => setDescription(e.target.value)} /></label>
        <div className="field">
          <span>{tr("Send these events")}</span>
          <Checks options={(types.value?.event_types ?? []).filter((t) => t.type !== "test.ping").map((t) => t.type)} value={chosen} onChange={setChosen} />
        </div>
        <ErrorLine error={error} />
        <div className="row">
          <button className="primary" disabled={!url || chosen.length === 0} onClick={async () => {
            try { const r = await control("/v1/webhooks", { method: "POST", body: { url, description, event_types: chosen } }); onDone(r.secret); } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
          }}>{tr("Create webhook")}</button>
          <button onClick={onClose}>{tr("Cancel")}</button>
        </div>
      </div>
    </Modal>
  );
}
