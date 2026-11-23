"use client";
import { CountryPacks } from "./packs";
import { LanguageModels } from "./models";
import { tr } from "@/lib/i18n";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useMe } from "@/components/Shell";
import { Badge, Empty, ErrorLine, Loading, Page, rowKeys } from "@/components/ui";
import { control, day, n, useLoad } from "@/lib/api";
import { ApproveButton, kindIcon, kindLabel, KINDS, MODULES, Spark, StatusBadge } from "./shared";
import { modeLabel } from "@/lib/labels";
import { Person } from "@/lib/people";

interface Row {
  id: string; name: string; slug: string; kind: string; status: string; version: number; actions: Record<string, string>; draft_version: number | null;
  pending_request: { id: string; requested_by: string; version: number } | null;
  hits_7d: number; shadow_hits_7d: number; hits_30d: number; spark: number[]; published_at: string | null; updated_at: string; edited_by: string;
}
interface Template { id: string; name: string; issuer: string; confirmed: boolean; kind: string; slug: string }
const MANAGE = ["admin", "detection_manager"];
const APPROVE = ["admin", "detection_approver"];

function modulesEnforcing(r: Row) {
  if (r.status !== "enforcing") return [];
  return MODULES.filter(([k]) => (r.actions[k] ?? "tokenize") !== "pass");
}

function Custom({ vault, canManage, canApprove, meId }: { vault: string; canManage: boolean; canApprove: boolean; meId?: string }) {
  const router = useRouter();
  const { value, error, loading, reload } = useLoad<{ entities: Row[] }>(() => control(`/v1/vaults/${vault}/custom-entities`), [vault]);
  const templates = useLoad<{ templates: Template[] }>(() => control("/v1/custom-entity-templates"));
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("");
  const [status, setStatus] = useState("");
  const [module, setModule] = useState("");
  const [view, setView] = useState("");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [bulkError, setBulkError] = useState<string | null>(null);
  const rows = useMemo(() => {
    const weekAgo = Date.now() - 7 * 86400_000;
    return (value?.entities ?? []).filter((r) => {
      if (q && !`${r.name} ${r.slug}`.toLowerCase().includes(q.toLowerCase())) return false;
      if (kind && r.kind !== kind) return false;
      if (status && r.status !== status) return false;
      if (module && !modulesEnforcing(r).some(([k]) => k === module)) return false;
      if (view === "pending" && !(r.pending_request && r.pending_request.requested_by !== meId)) return false;
      if (view === "shadow" && !(r.status === "shadow" && r.published_at && new Date(r.published_at).getTime() < weekAgo)) return false;
      if (view === "quiet" && !(r.version > 0 && r.status !== "archived" && r.hits_30d === 0)) return false;
      return true;
    });
  }, [value, q, kind, status, module, view, meId]);
  const pickedRows = rows.filter((r) => picked.has(r.id));
  const toggle = (id: string) => { const next = new Set(picked); if (next.has(id)) next.delete(id); else next.add(id); setPicked(next); };

  const bulkStatus = async (to: string) => {
    setBulkError(null);
    const failed: string[] = [];
    for (const r of pickedRows) {
      try { await control(`/v1/vaults/${vault}/custom-entities/${r.id}/status`, { body: { status: to } }); }
      catch (e) { failed.push(`${r.name}: ${e instanceof Error ? e.message : "failed"}`); }
    }
    if (failed.length) setBulkError(failed.join("; "));
    setPicked(new Set());
    reload();
  };
  const exportJson = async () => {
    const res = await control(`/v1/vaults/${vault}/custom-entities/export`);
    const wanted = new Set(pickedRows.map((r) => r.slug));
    const body = JSON.stringify({ entities: res.entities.filter((e: { slug: string }) => wanted.size === 0 || wanted.has(e.slug)) }, null, 2);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([body], { type: "application/json" }));
    a.download = `custom-entities-${vault}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  if (loading || error) return <Loading loading={loading} error={error} />;
  if (value!.entities.length === 0) {
    return (
      <Empty title={tr("No data types of your own yet")}>
        <p>{tr("Add what is sensitive in your business: loan IDs, wallet IDs, staff numbers, VIP names. They are detected, tokenized, masked and reported like the built-in ones.")}</p>
        {canManage && (
          <div className="cards" style={{ marginTop: 12, textAlign: "left" }}>
            {(templates.value?.templates ?? []).slice(0, 3).map((t) => (
              <Link key={t.id} href={`/detection/new?vault=${vault}&template=${t.id}`} className="card" style={{ color: "inherit" }}>
                <h3>{t.name}</h3>
                <span className="small muted">{tr("Starter pattern, format not confirmed")}</span>
              </Link>
            ))}
            <Link href={`/detection/new?vault=${vault}`} className="card" style={{ color: "inherit" }}><h3>{tr("Create from scratch")}</h3><span className="small muted">{tr("Choose from five kinds")}</span></Link>
          </div>
        )}
      </Empty>
    );
  }
  return (
    <div className="stack">
      <div className="row" style={{ flexWrap: "wrap" }}>
        <input aria-label={tr("Search by name or slug")} placeholder={tr("Search name or slug")} value={q} onChange={(e) => setQ(e.target.value)} />
        <select aria-label={tr("Kind")} value={kind} onChange={(e) => setKind(e.target.value)}><option value="">{tr("All kinds")}</option>{KINDS.map((k) => <option key={k.kind} value={k.kind}>{k.label}</option>)}</select>
        <select aria-label={tr("Status")} value={status} onChange={(e) => setStatus(e.target.value)}><option value="">{tr("All statuses")}</option>{["draft", "shadow", "enforcing", "archived"].map((s) => <option key={s} value={s}>{modeLabel(s)}</option>)}</select>
        <select aria-label={tr("Protecting in")} value={module} onChange={(e) => setModule(e.target.value)}><option value="">{tr("Protecting anywhere")}</option>{MODULES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
        <select aria-label={tr("Saved view")} value={view} onChange={(e) => setView(e.target.value)}>
          <option value="">{tr("All data types")}</option>
          <option value="pending">{tr("Pending my approval")}</option>
          <option value="shadow">{tr("Watch only for over 7 days")}</option>
          <option value="quiet">{tr("No hits in 30 days")}</option>
        </select>
      </div>
      {canManage && (
        <div className="row small">
          <span className="muted">{pickedRows.length} selected</span>
          <button disabled={pickedRows.length === 0} onClick={() => bulkStatus("enforcing")}>{tr("Turn protection on")}</button>
          <button disabled={pickedRows.length === 0} onClick={() => bulkStatus("archived")}>{tr("Archive")}</button>
          <button onClick={exportJson}>{tr("Export definitions as JSON")}</button>
        </div>
      )}
      <ErrorLine error={bulkError} />
      <div className="tablewrap">
        <table>
          <thead><tr>{canManage && <th><span className="sr-only">{tr("Select")}</span></th>}<th>{tr("Name")}</th><th>{tr("Kind")}</th><th>{tr("Status")}</th><th>{tr("Hits (7 days)")}</th><th>{tr("Protecting in")}</th><th>{tr("Version")}</th><th>{tr("Last edited")}</th>{canApprove && <th><span className="sr-only">{tr("Approve")}</span></th>}</tr></thead>
          <tbody>
            {rows.map((r) => {
              const open = () => router.push(`/detection/${vault}/${r.id}`);
              const total = r.hits_7d + r.shadow_hits_7d;
              return (
                <tr key={r.id} className="click" tabIndex={0} onClick={open} onKeyDown={(e) => rowKeys(e, open)}>
                  {canManage && <td onClick={(e) => e.stopPropagation()}><input type="checkbox" aria-label={tr("Select {0}", { 0: r.name })} checked={picked.has(r.id)} onChange={() => toggle(r.id)} /></td>}
                  <td><b>{r.name}</b><br /><code className="small">{r.slug}</code></td>
                  <td><span aria-hidden className="mono">{kindIcon(r.kind)}</span> {kindLabel(r.kind)}</td>
                  <td><StatusBadge status={r.status} pending={Boolean(r.pending_request)} /></td>
                  <td><Spark values={r.spark} light={r.status === "shadow"} /> {n(total)}{r.shadow_hits_7d > 0 && <span className="small muted"> ({n(r.shadow_hits_7d)} {tr("watch only)")}</span>}</td>
                  <td>{modulesEnforcing(r).length ? modulesEnforcing(r).map(([k, l]) => <Badge key={k}>{l}</Badge>) : <span className="muted">{tr("None")}</span>}</td>
                  <td>{r.version > 0 ? `v${r.version}` : tr("Never published")}{r.draft_version !== null && r.version > 0 && <><br /><span className="small muted">{tr("draft v")}{r.draft_version} waiting</span></>}</td>
                  <td className="small"><Person id={r.edited_by} /><br /><span className="muted">{day(r.updated_at)}</span></td>
                  {canApprove && <td onClick={(e) => e.stopPropagation()}>{r.pending_request && r.pending_request.requested_by !== meId && <ApproveButton id={r.pending_request.id} onDone={reload} />}</td>}
                </tr>
              );
            })}
            {rows.length === 0 && <tr><td colSpan={9} className="muted">{tr("Nothing matches these filters.")}</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function BuiltIn({ vault, builtIn, thresholds, canTune, onChange }: { vault: string; builtIn: { slug: string; name: string }[]; thresholds: Record<string, number>; canTune: boolean; onChange: () => void }) {
  const [error, setError] = useState<string | null>(null);
  return (
    <div className="stack">
      <p className="muted small">{tr("The catalogue every vault starts with. These cannot be edited, but you can raise or lower how sure the engine must be. Lowering a threshold catches more and flags more that is not sensitive. The default is 0.50.")}</p>
      <ErrorLine error={error} />
      <div className="tablewrap"><table>
        <thead><tr><th>{tr("Data type")}</th><th>{tr("ID")}</th><th>{tr("Threshold")}</th></tr></thead>
        <tbody>
          {builtIn.map((b) => (
            <tr key={b.slug}>
              <td>{b.name}</td><td><code className="small">{b.slug}</code></td>
              <td><input type="number" aria-label={tr("Threshold for {0}", { 0: b.name })} step={0.05} min={0.3} max={0.99} disabled={!canTune} defaultValue={thresholds[b.slug] ?? 0.5} onBlur={async (e) => {
                const v = Number(e.target.value);
                if (v === (thresholds[b.slug] ?? 0.5)) return;
                try { await control(`/v1/vaults/${vault}/detection`, { method: "PATCH", body: { thresholds: { ...thresholds, [b.slug]: v } } }); setError(null); onChange(); } catch (err) { setError(err instanceof Error ? err.message : "failed"); }
              }} /></td>
            </tr>
          ))}
        </tbody>
      </table></div>
    </div>
  );
}

function Templates({ vault, canManage }: { vault: string; canManage: boolean }) {
  const { value, error, loading } = useLoad<{ templates: Template[] }>(() => control("/v1/custom-entity-templates"));
  if (loading || error) return <Loading loading={loading} error={error} />;
  return (
    <div className="stack">
      <div className="note warn small">{tr("None of these formats has been confirmed with its issuing body. They are starting points: check each against real documents, and edit the pattern and samples before you rely on it.")}</div>
      <div className="cards">
        {value!.templates.map((t) => (
          <div className="card" key={t.id}>
            <div className="spread"><h3>{t.name}</h3><Badge tone="warn">{tr("Unconfirmed")}</Badge></div>
            <span className="small muted">{tr("Issued by")} {t.issuer}</span>
            {canManage && <Link href={`/detection/new?vault=${vault}&template=${t.id}`}>{tr("Adopt and edit")}</Link>}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Detection() {
  const me = useMe();
  const vaults = useLoad<{ vaults: { id: string; name: string; environment: string }[] }>(() => control("/v1/vaults"));
  const [picked, setPicked] = useState("");
  const [tab, setTab] = useState("built-in");
  useEffect(() => { const t = new URLSearchParams(window.location.search).get("tab"); if (t === "packs" || t === "custom" || t === "templates" || t === "models") setTab(t); }, []);
  const vault = picked || vaults.value?.vaults[0]?.id || "";
  const det = useLoad<{ enabled: boolean; thresholds: Record<string, number>; built_in: { slug: string; name: string }[]; ruleset_version: number }>(() => (vault ? control(`/v1/vaults/${vault}/detection`) : Promise.resolve(null as never)), [vault]);
  const [error, setError] = useState<string | null>(null);
  const roles = me?.roles ?? [];
  const canManage = roles.some((r) => MANAGE.includes(r));
  const canApprove = roles.some((r) => APPROVE.includes(r));
  const isAdmin = roles.includes("admin");
  return (
    <Page
      title={tr("Data types")}
      sub={tr("What Onshore looks for in everything that passes through it. Identifiers for each of your vaults' countries come from their country packs, and you can add your own.")}
      actions={
        <>
          <select aria-label={tr("Vault")} value={vault} onChange={(e) => setPicked(e.target.value)}>{(vaults.value?.vaults ?? []).map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select>
          {canManage && det.value?.enabled && tab === "custom" && <Link className="btn primary" href={`/detection/new?vault=${vault}`}>{tr("New data type")}</Link>}
        </>
      }
    >
      <Loading loading={vaults.loading || det.loading} error={vaults.error ?? det.error} />
      {det.value && (
        <>
          <div className="tabs" role="tablist">
            {[["built-in", tr("Built-in")], ["custom", tr("Your own")], ["packs", tr("Country packs")], ["models", tr("Language models")], ["templates", tr("Templates")]].map(([k, l]) => <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "on" : ""} onClick={() => setTab(k!)}>{l}</button>)}
          </div>
          {tab === "built-in" && <BuiltIn vault={vault} builtIn={det.value.built_in} thresholds={det.value.thresholds} canTune={isAdmin} onChange={det.reload} />}
          {tab !== "built-in" && tab !== "packs" && tab !== "models" && !det.value.enabled && (
            <Empty title={tr("Custom entities are off for this vault")}>
              <p>{tr("Turn them on to define your own sensitive data types. Nothing changes in traffic until a data type has been tested, approved by a second person and published.")}</p>
              {isAdmin && <button className="primary" style={{ marginTop: 10 }} onClick={async () => { try { await control(`/v1/vaults/${vault}/detection`, { method: "PATCH", body: { enabled: true } }); det.reload(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } }}>{tr("Turn on for this vault")}</button>}
              {!isAdmin && <p className="small">{tr("An admin can turn them on.")}</p>}
              <ErrorLine error={error} />
            </Empty>
          )}
          {tab === "custom" && det.value.enabled && <Custom vault={vault} canManage={canManage} canApprove={canApprove} meId={me?.id} />}
          {tab === "templates" && det.value.enabled && <Templates vault={vault} canManage={canManage} />}
          {tab === "packs" && <CountryPacks canManage={canManage} />}
          {tab === "models" && <LanguageModels vault={vault} canManage={isAdmin} />}
        </>
      )}
    </Page>
  );
}
