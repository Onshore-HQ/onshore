"use client";
import { tr } from "@/lib/i18n";
import Link from "next/link";
import { use, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useMe } from "@/components/Shell";
import { Badge, ErrorLine, Loading, Page, TypedConfirm } from "@/components/ui";
import { ApiErr, control, day, n, useLoad, when } from "@/lib/api";
import { describe, kindLabel, MODULES, StatusBadge } from "../../shared";
import { Person } from "@/lib/people";

const TABS = ["Overview", "Hits", "Tests", "Versions", "Policies", "Settings"];
const NAMES: Record<string, string> = { logs: "Logs", ai: "AI gateway", proxy: "Proxy", support: "Support tools" };

function Overview({ r, onChange, vault, canManage, canApprove, meId }: { r: any; onChange: () => void; vault: string; canManage: boolean; canApprove: boolean; meId?: string }) {
  const e = r.entity;
  const [error, setError] = useState<string | null>(null);
  const versions = useLoad<{ versions: any[] }>(() => control(`/v1/vaults/${vault}/custom-entities/${e.id}/versions`), [e.id, e.version]);
  const status = async (to: string) => {
    try { await control(`/v1/vaults/${vault}/custom-entities/${e.id}/status`, { body: { status: to } }); setError(null); onChange(); } catch (err) { setError(err instanceof Error ? err.message : "failed"); }
  };
  const pending = r.pending_request;
  return (
    <div className="stack">
      {e.status === "shadow" && <div className="note small">{tr("This rule is watch only: matches are counted, and nothing changes in traffic. Once the matches look right, turn protection on.")}{canManage && <> <button className="link small" onClick={() => status("enforcing")}>{tr("Turn protection on")}</button></>}</div>}
      {pending && (
        <div className="note warn small">
          {tr("Version")} {pending.version} {tr("is waiting for approval. Benchmark:")} {Number(pending.benchmark?.ms_per_kb ?? 0).toFixed(4)} {tr("ms per KB,")} {(Number(pending.benchmark?.matched_share ?? 0) * 100).toFixed(2)}{tr("% of lines.")}
          {canApprove && pending.requested_by !== meId && e.edited_by !== meId && (
            <div className="row" style={{ marginTop: 6 }}>
              <button className="primary" onClick={async () => { try { await control(`/v1/publish-requests/${pending.id}/approve`, { method: "POST" }); onChange(); } catch (err) { setError(err instanceof Error ? err.message : "failed"); } }}>{tr("Approve")}</button>
              <button onClick={async () => { await control(`/v1/publish-requests/${pending.id}/reject`, { method: "POST" }); onChange(); }}>{tr("Reject")}</button>
            </div>
          )}
          {(pending.requested_by === meId || e.edited_by === meId) && <div>{tr("You wrote this change, so someone else must approve it.")}</div>}
        </div>
      )}
      {r.pending_definition && !pending && <div className="note small">{tr("An edit is waiting beside the live version.")} <Link href={`/detection/new?vault=${vault}&id=${e.id}`}>{tr("Continue it")}</Link></div>}
      <div className="card">
        <h2>{tr("What it matches")}</h2>
        <p>{describe(e.kind, e.definition, e.context_positive)}.</p>
        {e.context_negative.length > 0 && <p className="small muted">{tr("Less likely near")} {e.context_negative.map((w: string) => `"${w}"`).join(", ")}.</p>}
        {r.list && <p className="small muted">{n(r.list.values)} values{r.list.staged ? tr(", waiting for approval") : ""}.</p>}
        <p className="small muted">{tr("Threshold")} {Number(e.threshold).toFixed(2)}. {e.token_kind}, {e.token_format} tokens.</p>
      </div>
      <div className="card">
        <h2>{tr("Status")}</h2>
        <div className="timeline small">
          <div>{tr("Created")} {when(e.created_at)}</div>
          {(versions.value?.versions ?? []).slice().reverse().map((v) => <div key={v.version}>{tr("Version")} {v.version} published {when(v.published_at)}{tr(", approved by")} <Person id={v.approved_by} /></div>)}
        </div>
        {canManage && e.version > 0 && (
          <div className="row">
            {e.status !== "enforcing" && e.status !== "archived" && <button className="primary" onClick={() => status("enforcing")}>{tr("Turn protection on")}</button>}
            {e.status === "enforcing" && <button onClick={() => status("shadow")}>{tr("Back to watch only")}</button>}
            {e.status === "archived" && <button onClick={() => status("shadow")}>{tr("Restore as watch only")}</button>}
          </div>
        )}
        <ErrorLine error={error} />
      </div>
    </div>
  );
}

function Hits({ vault, id }: { vault: string; id: string }) {
  const { value, error, loading } = useLoad<{ rows: { day: string; module: string; source_id: string; action: string; n: number }[] }>(() => control(`/v1/vaults/${vault}/custom-entities/${id}/stats`), [id]);
  const byDay = useMemo(() => {
    const m = new Map<string, { hits: number; shadow: number }>();
    for (const r of value?.rows ?? []) {
      const k = day(r.day);
      const c = m.get(k) ?? { hits: 0, shadow: 0 };
      if (r.action === "shadow") c.shadow += r.n; else c.hits += r.n;
      m.set(k, c);
    }
    return [...m.entries()];
  }, [value]);
  const sources = useMemo(() => {
    const m = new Map<string, { module: string; source: string; n: number; shadow: number }>();
    for (const r of value?.rows ?? []) {
      const k = `${r.module}|${r.source_id}`;
      const c = m.get(k) ?? { module: r.module, source: r.source_id, n: 0, shadow: 0 };
      if (r.action === "shadow") c.shadow += r.n; else c.n += r.n;
      m.set(k, c);
    }
    return [...m.values()].sort((a, b) => b.n + b.shadow - a.n - a.shadow);
  }, [value]);
  if (loading || error) return <Loading loading={loading} error={error} />;
  if (byDay.length === 0) return <p className="muted">{tr("No hits in the last 30 days.")}</p>;
  const max = Math.max(1, ...byDay.map(([, c]) => c.hits + c.shadow));
  return (
    <div className="stack">
      <p className="small muted">{tr("Counts only. The matched text is never recorded, so it cannot be shown here.")}</p>
      <div className="card">
        <svg viewBox={`0 0 ${Math.max(120, byDay.length * 26)} 90`} role="img" aria-label={tr("Hits by day")} style={{ width: "100%", maxHeight: 180 }}>
          {byDay.map(([d, c], i) => {
            const hH = (c.hits / max) * 70, sH = (c.shadow / max) * 70;
            return (
              <g key={d}>
                <title>{tr("{0}: {1} protected, {2} watch only", { 0: d, 1: c.hits, 2: c.shadow })}</title>
                <rect x={i * 26 + 3} y={76 - hH} width={20} height={hH} fill="var(--primary)" rx={1} />
                <rect x={i * 26 + 3} y={76 - hH - sH} width={20} height={sH} fill="var(--primary)" opacity={0.4} rx={1} />
                <text x={i * 26 + 13} y={88} fontSize={6} textAnchor="middle" fill="var(--muted-foreground)">{d.slice(0, 6)}</text>
              </g>
            );
          })}
        </svg>
        <div className="legend"><span><i style={{ background: "var(--primary)" }} />{tr("Protected")}</span><span><i style={{ background: "var(--primary)", opacity: 0.4 }} />{tr("Watch only")}</span></div>
      </div>
      <div className="tablewrap"><table>
        <thead><tr><th>{tr("Module")}</th><th>{tr("Source")}</th><th>{tr("Protected")}</th><th>{tr("Watch only")}</th></tr></thead>
        <tbody>{sources.map((s) => <tr key={`${s.module}${s.source}`}><td>{NAMES[s.module] ?? s.module}</td><td><code className="small">{s.source}</code></td><td>{n(s.n)}</td><td>{n(s.shadow)}</td></tr>)}</tbody>
      </table></div>
    </div>
  );
}

function Tests({ vault, id, canManage }: { vault: string; id: string; canManage: boolean }) {
  const { value, error, loading, reload } = useLoad<{ results: { id: string; sample: string; expect_match: boolean; matched: boolean; passed: boolean }[] }>(() => control(`/v1/vaults/${vault}/custom-entities/${id}/test`, { body: {} }), [id]);
  const [text, setText] = useState("");
  const [err, setErr] = useState<string | null>(null);
  if (!canManage) return <p className="muted">{tr("Samples are visible to people who manage detection.")}</p>;
  if (loading || error) return <Loading loading={loading} error={error} />;
  const add = async (expect: boolean) => {
    try { await control(`/v1/vaults/${vault}/custom-entities/${id}/tests`, { body: { samples: [{ sample: text, expect_match: expect }] } }); setText(""); setErr(null); reload(); } catch (e) { setErr(e instanceof Error ? e.message : "failed"); }
  };
  return (
    <div className="stack">
      <label className="field"><span>{tr("Add a sample. Use synthetic data; samples are stored encrypted.")}</span><input value={text} onChange={(e) => setText(e.target.value)} /></label>
      <div className="row"><button disabled={!text} onClick={() => add(true)}>{tr("Must match")}</button><button disabled={!text} onClick={() => add(false)}>{tr("Must not match")}</button></div>
      <ErrorLine error={err} />
      <div className="tablewrap"><table>
        <thead><tr><th>{tr("Result")}</th><th>{tr("Expected")}</th><th>{tr("Sample")}</th><th /></tr></thead>
        <tbody>{value!.results.map((s) => (
          <tr key={s.id}>
            <td><Badge tone={s.passed ? "good" : "bad"}>{s.passed ? tr("pass") : tr("fail")}</Badge></td>
            <td className="small">{s.expect_match ? tr("must match") : tr("must not match")}</td>
            <td><code className="small">{s.sample}</code></td>
            <td><button className="link small" onClick={async () => { await control(`/v1/vaults/${vault}/custom-entities/${id}/tests/${s.id}`, { method: "DELETE" }); reload(); }}>{tr("Remove")}</button></td>
          </tr>
        ))}</tbody>
      </table></div>
    </div>
  );
}

function Versions({ vault, id }: { vault: string; id: string }) {
  const { value, error, loading } = useLoad<{ versions: { version: number; snapshot: unknown; published_by: string; approved_by: string; published_at: string; benchmark: { ms_per_kb: number; matched_share: number } | null }[] }>(() => control(`/v1/vaults/${vault}/custom-entities/${id}/versions`), [id]);
  if (loading || error) return <Loading loading={loading} error={error} />;
  if (value!.versions.length === 0) return <p className="muted">{tr("Nothing published yet.")}</p>;
  const lines = (x: unknown) => JSON.stringify(x, null, 2).split("\n");
  return (
    <div className="stack">
      {value!.versions.map((v, i) => {
        const older = value!.versions[i + 1];
        const oldLines = older ? lines(older.snapshot) : [];
        const newLines = lines(v.snapshot);
        return (
          <div className="card" key={v.version}>
            <div className="spread"><b>{tr("Version")} {v.version}</b><span className="small muted">{when(v.published_at)}</span></div>
            <p className="small">{tr("Written by")} <Person id={v.published_by} />{tr(", approved by")} <Person id={v.approved_by} />.{v.benchmark ? tr(" {0} ms per KB.", { 0: Number(v.benchmark.ms_per_kb).toFixed(4) }) : ""}</p>
            {older ? (
              <div className="split">
                <div><span className="small muted">{tr("Version")} {older.version}</span><pre className="pre small">{oldLines.map((l, j) => <div key={j} style={newLines.includes(l) ? undefined : { background: "var(--bad-soft)" }}>{l}</div>)}</pre></div>
                <div><span className="small muted">{tr("Version")} {v.version}</span><pre className="pre small">{newLines.map((l, j) => <div key={j} className={oldLines.includes(l) ? undefined : "diff-add"}>{l}</div>)}</pre></div>
              </div>
            ) : <pre className="pre small">{newLines.join("\n")}</pre>}
          </div>
        );
      })}
    </div>
  );
}

function Policies({ r }: { r: any }) {
  return (
    <div className="stack">
      {r.policies.length === 0 ? <p className="muted">{tr("No published access rule mentions this data type, so everyone gets the default: tokens only, and plaintext is denied.")}</p> : (
        <div className="tablewrap"><table>
          <thead><tr><th>{tr("Policy")}</th><th>{tr("Version")}</th></tr></thead>
          <tbody>{r.policies.map((p: any) => <tr key={p.id}><td><Link href="/policies">{p.name}</Link></td><td>v{p.version}</td></tr>)}</tbody>
        </table></div>
      )}
      <p className="small muted">{tr("To choose what each role sees, add")} <code>{r.entity.slug}</code> {tr("to a rule's data types in the policy builder, then use its simulator.")}</p>
    </div>
  );
}

function Settings({ r, vault, canManage, onChange }: { r: any; vault: string; canManage: boolean; onChange: () => void }) {
  const e = r.entity;
  const [archiving, setArchiving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();
  return (
    <div className="stack">
      <div className="card">
        <h2>{tr("Tokens and masking")}</h2>
        <p className="small">{e.token_kind}, {e.token_format}{tr(". Masked:")} <code>{JSON.stringify(e.mask_rule)}</code></p>
        <div className="row small">{MODULES.map(([k, l]) => <Badge key={k}>{l}: {e.actions[k] ?? "tokenize"}</Badge>)}</div>
        <p className="small muted">{tr("Fields:")} {r.fields.map((f: any) => f.name).join(", ") || tr("created at first publish")}.</p>
        {canManage && e.status !== "archived" && <div className="row"><button onClick={() => router.push(`/detection/new?vault=${vault}&id=${e.id}`)}>{tr("Edit")}</button></div>}
      </div>
      {canManage && e.version > 0 && e.status !== "archived" && (
        <div className="card">
          <h2>{tr("Archive")}</h2>
          <p className="small muted">{tr("An archived data type stops being detected and its counts are kept. Existing tokens still resolve. A published policy that names it blocks this.")}</p>
          <div className="row"><button className="danger" onClick={() => setArchiving(true)}>{tr("Archive")}</button></div>
          <ErrorLine error={error} />
        </div>
      )}
      {archiving && (
        <TypedConfirm title={tr("Archive {0}?", { 0: e.name })} word="archive" onClose={() => setArchiving(false)} onConfirm={async () => {
          try { await control(`/v1/vaults/${vault}/custom-entities/${e.id}/status`, { body: { status: "archived" } }); setArchiving(false); onChange(); }
          catch (err) { setArchiving(false); setError(err instanceof ApiErr && err.code === "entity_in_use" ? tr("{0}. See the Policies tab.", { 0: err.message }) : err instanceof Error ? err.message : "failed"); }
        }}>
          {tr("Detection stops within seconds in every module, so this data will pass through unprotected.")}
        </TypedConfirm>
      )}
    </div>
  );
}

export default function EntityDetail({ params }: { params: Promise<{ vault: string; id: string }> }) {
  const { vault, id } = use(params);
  const me = useMe();
  const [tab, setTab] = useState("Overview");
  const { value, error, loading, reload } = useLoad<any>(() => control(`/v1/vaults/${vault}/custom-entities/${id}`), [vault, id]);
  const roles = me?.roles ?? [];
  const canManage = roles.some((r) => r === "admin" || r === "detection_manager");
  const canApprove = roles.some((r) => r === "admin" || r === "detection_approver");
  return (
    <Page
      title={value?.entity.name ?? tr("Entity")}
      sub={value && <><code>{value.entity.slug}</code> · {kindLabel(value.entity.kind)} · {value.entity.version > 0 ? tr("version {0}", { 0: value.entity.version }) : tr("never published")}</>}
      actions={value && <StatusBadge status={value.entity.status} pending={Boolean(value.pending_request)} />}
    >
      <Loading loading={loading && !value} error={error} />
      {value && (
        <>
          <div className="tabs" role="tablist">{TABS.map((t) => <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? "on" : ""} onClick={() => setTab(t)}>{t}</button>)}</div>
          {tab === "Overview" && <Overview r={value} vault={vault} onChange={reload} canManage={canManage} canApprove={canApprove} meId={me?.id} />}
          {tab === "Hits" && <Hits vault={vault} id={id} />}
          {tab === "Tests" && <Tests vault={vault} id={id} canManage={canManage} />}
          {tab === "Versions" && <Versions vault={vault} id={id} />}
          {tab === "Policies" && <Policies r={value} />}
          {tab === "Settings" && <Settings r={value} vault={vault} canManage={canManage} onChange={reload} />}
        </>
      )}
    </Page>
  );
}
