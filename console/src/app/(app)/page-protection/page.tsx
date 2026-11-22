"use client";
import { tr } from "@/lib/i18n";
import { useState } from "react";
import { Badge, Copy, Empty, ErrorLine, Loading, Modal, Page, TypedConfirm } from "@/components/ui";
import { control, n, useLoad, when } from "@/lib/api";

interface PageRow { id: string; name: string; page_url: string; origin: string; report_key: string; last_report_at: string | null; last_scan_at: string | null; last_scan_error: string | null; scripts?: Record<string, number> }
interface Script { id: string; script_url: string; source: string; status: string; justification: string | null; first_seen: string; last_seen: string; seen_count: number; hash_changed_at: string | null; hash_error: string | null }

const STATUS: Record<string, { word: string; tone: "good" | "bad" | "warn" | "" }> = {
  pending: { word: "Needs a decision", tone: "warn" },
  approved: { word: "Approved", tone: "good" },
  rejected: { word: "Rejected", tone: "bad" },
  changed: { word: "Changed since approval", tone: "bad" },
};
const SOURCE: Record<string, string> = { csp: "Browser report", watcher: "Watcher", scan: "Server scan" };

export default function PageProtection() {
  const pages = useLoad<{ pages: PageRow[] }>(() => control("/v1/page-protection/pages"));
  const [adding, setAdding] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Page title={tr("Page protection")} sub={tr("Which scripts run on pages where customers type sensitive details, and who approved each one. This is how card skimmers get caught.")} actions={<button className="primary" onClick={() => setAdding(true)}>{tr("Protect a page")}</button>}>
      <div className="stack">
        <Loading error={pages.error} loading={pages.loading && !pages.value} />
        {pages.value?.pages.length === 0 && <Empty title={tr("No protected pages yet")}>{tr("Add a page that collects a BVN, NIN or card details. You will be told when a new script appears on it, or when an approved one changes.")}</Empty>}
        {pages.value?.pages.map((p) => (
          <div className="card" key={p.id}>
            <div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap" }}>
              <div>
                <button className="link" style={{ font: "inherit", fontWeight: 600 }} onClick={() => setOpen(open === p.id ? null : p.id)}>{p.name}</button>
                <div className="small muted" style={{ wordBreak: "break-all" }}>{p.page_url}</div>
              </div>
              <div className="row" style={{ flexWrap: "wrap" }}>
                {(p.scripts?.pending ?? 0) > 0 && <Badge tone="warn">{n(p.scripts!.pending)} {tr("need a decision")}</Badge>}
                {(p.scripts?.changed ?? 0) > 0 && <Badge tone="bad">{n(p.scripts!.changed)} changed</Badge>}
                <Badge tone="good">{n(p.scripts?.approved)} approved</Badge>
              </div>
            </div>
            {open === p.id && <Detail page={p} onChange={pages.reload} onGone={() => { setOpen(null); pages.reload(); }} />}
          </div>
        ))}
      </div>
      {adding && <AddPage onClose={() => setAdding(false)} onDone={(id) => { setAdding(false); setOpen(id); pages.reload(); }} />}
    </Page>
  );
}

function Detail({ page, onChange, onGone }: { page: PageRow; onChange: () => void; onGone: () => void }) {
  const { value, error, loading, reload } = useLoad<{ scripts: Script[]; approved_sources: string[] }>(() => control(`/v1/page-protection/pages/${page.id}`), [page.id]);
  const [deciding, setDeciding] = useState<Script | null>(null);
  const [removing, setRemoving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const host = typeof window === "undefined" ? "" : window.location.origin;
  const report = `${host}/control/v1/page-protection/report/${page.report_key}`;
  const watch = `<script src="${host}/embed/rv-watch.js" data-page="${page.report_key}"></script>`;
  const learn = tr("Content-Security-Policy-Report-Only: script-src 'none'; report-uri {0}", { 0: report });
  const enforce = tr("Content-Security-Policy: script-src {0}; report-uri {1}", { 0: (value?.approved_sources ?? []).join(" ") || "'none'", 1: report });
  return (
    <div className="stack" style={{ marginTop: 12 }}>
      <ErrorLine error={err} />
      <Loading error={error} loading={loading && !value} />
      {value?.scripts.length === 0 && <p className="small muted">{tr("Nothing seen yet. Add one of the snippets below, or run a scan.")}</p>}
      {value && value.scripts.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead><tr><th>{tr("Script")}</th><th>{tr("State")}</th><th>{tr("Seen by")}</th><th>{tr("First seen")}</th><th>{tr("Reason")}</th><th /></tr></thead>
            <tbody>{value.scripts.map((s) => (
              <tr key={s.id}>
                <td style={{ wordBreak: "break-all" }}><code>{s.script_url}</code>{s.hash_error && <div className="small muted">{tr("Not checked:")} {s.hash_error}</div>}</td>
                <td><Badge tone={STATUS[s.status]?.tone ?? ""}>{STATUS[s.status]?.word ?? s.status}</Badge></td>
                <td className="small">{SOURCE[s.source] ?? s.source}</td>
                <td className="small muted">{when(s.first_seen)}</td>
                <td className="small">{s.justification ?? "—"}</td>
                <td><button className="small" onClick={() => setDeciding(s)}>{tr("Decide")}</button></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      <div className="small muted">
        {tr("Last browser report:")} {page.last_report_at ? when(page.last_report_at) : tr("none yet")}{tr(". Last server scan:")} {page.last_scan_at ? when(page.last_scan_at) : tr("none yet")}{page.last_scan_error ? ` (${page.last_scan_error})` : ""}.
      </div>
      <details>
        <summary><b>{tr("Set it up")}</b></summary>
        <div className="stack" style={{ marginTop: 8 }}>
          <p className="small muted"><b>{tr("1. Report only.")}</b> {tr("Send this header on the page. Browsers report every script, and nothing is blocked.")}</p>
          <pre className="pre small" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{learn}</pre><Copy text={learn} />
          <p className="small muted"><b>{tr("2. Watcher, for scripts added after the page loads.")}</b> {tr("A hostile script could interfere with this one, which is why the header comes first.")}</p>
          <pre className="pre small" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{watch}</pre><Copy text={watch} />
          <p className="small muted"><b>{tr("3. Enforce, once the list is right.")}</b> {tr("This header blocks anything not approved. Your own inline code would need a nonce, so test it in report-only mode first.")}</p>
          <pre className="pre small" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{enforce}</pre><Copy text={enforce} />
        </div>
      </details>
      <div className="row">
        <button onClick={async () => { setErr(null); try { await control(`/v1/page-protection/pages/${page.id}/scan`, { method: "POST" }); reload(); onChange(); } catch (e) { setErr(e instanceof Error ? e.message : "failed"); } }}>{tr("Scan now")}</button>
        <button onClick={() => setRemoving(true)}>{tr("Remove this page")}</button>
      </div>
      {deciding && <Decide page={page.id} script={deciding} onClose={() => setDeciding(null)} onDone={() => { setDeciding(null); reload(); onChange(); }} />}
      {removing && <TypedConfirm title={tr("Stop protecting this page?")} word="remove" onClose={() => setRemoving(false)} onConfirm={async () => { await control(`/v1/page-protection/pages/${page.id}`, { method: "DELETE" }); onGone(); }}>{tr("Its script list and decisions go with it. The audit log keeps the decisions.")}</TypedConfirm>}
    </div>
  );
}

function Decide({ page, script, onClose, onDone }: { page: string; script: Script; onClose: () => void; onDone: () => void }) {
  const [justification, setJustification] = useState(script.justification ?? "");
  const [error, setError] = useState<string | null>(null);
  const send = async (decision: "approve" | "reject") => {
    try { await control(`/v1/page-protection/pages/${page}/scripts/${script.id}/decision`, { method: "POST", body: { decision, justification } }); onDone(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
  };
  return (
    <Modal title={tr("Decide on this script")} onClose={onClose}>
      <div className="stack">
        <code style={{ wordBreak: "break-all" }}>{script.script_url}</code>
        {script.status === "changed" && <div className="note bad">{tr("This file changed after it was approved. Check what changed before approving it again.")}</div>}
        {script.script_url === "inline" && <p className="small muted">{tr("This is code written into the page itself, so it cannot be told apart by address, and no file is checked.")}</p>}
        <label className="field"><span>{tr("Reason, kept with the decision")}</span><textarea rows={3} value={justification} placeholder={tr("What it does, and who asked for it")} onChange={(e) => setJustification(e.target.value)} /></label>
        <ErrorLine error={error} />
        <div className="row">
          <button className="primary" disabled={justification.trim().length < 3} onClick={() => send("approve")}>{tr("Approve")}</button>
          <button disabled={justification.trim().length < 3} onClick={() => send("reject")}>{tr("Reject")}</button>
          <button onClick={onClose}>{tr("Cancel")}</button>
        </div>
      </div>
    </Modal>
  );
}

function AddPage({ onClose, onDone }: { onClose: () => void; onDone: (id: string) => void }) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  return (
    <Modal title={tr("Protect a page")} onClose={onClose}>
      <div className="stack">
        <label className="field"><span>{tr("Name")}</span><input value={name} placeholder={tr("KYC form")} onChange={(e) => setName(e.target.value)} /></label>
        <label className="field"><span>{tr("Page address, https")}</span><input value={url} placeholder="https://app.example.com/kyc" onChange={(e) => setUrl(e.target.value)} /></label>
        <p className="small muted">{tr("The address must be reachable without signing in for the server scan to work. Browser reports work either way.")}</p>
        <ErrorLine error={error} />
        <div className="row">
          <button className="primary" disabled={!name || !url} onClick={async () => { try { const r = await control("/v1/page-protection/pages", { method: "POST", body: { name, page_url: url } }); onDone(r.id); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } }}>{tr("Protect page")}</button>
          <button onClick={onClose}>{tr("Cancel")}</button>
        </div>
      </div>
    </Modal>
  );
}
