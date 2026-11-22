"use client";
import { tr } from "@/lib/i18n";
import { useEffect, useMemo, useRef, useState } from "react";
import { Badge, Empty, ErrorLine, Loading, ShownOnce } from "@/components/ui";
import { control, useLoad } from "@/lib/api";

interface Rule { path: string }
type Side = "request" | "response";

const SAMPLE_REQ = JSON.stringify({ customer: { name: "Chioma Okafor", bvn: "22123456789", tier: "gold" }, accounts: [{ number: "0123456789", bank: "058" }] }, null, 2);
const SAMPLE_RES = JSON.stringify({ status: "ok", customer: { bvn: "tok_bvn_example", verified: true } }, null, 2);

/** The JSON renders as a tree, and clicking a value marks its path. */
function Tree({ value, path, marked, onToggle }: { value: unknown; path: string; marked: Set<string>; onToggle: (p: string) => void }) {
  if (Array.isArray(value)) {
    return <div style={{ marginLeft: 12 }}>{value.slice(0, 1).map((v, i) => <Tree key={i} value={v} path={`${path}[*]`} marked={marked} onToggle={onToggle} />)}</div>;
  }
  if (value && typeof value === "object") {
    return (
      <div style={{ marginLeft: 12 }}>
        {Object.entries(value).map(([k, v]) => {
          const p = `${path}.${k}`;
          const leaf = v === null || typeof v !== "object";
          return (
            <div key={k} className="mono small">
              <span className="muted">{k}: </span>
              {leaf ? (
                <button type="button" className={marked.has(p) ? "primary" : ""} style={{ padding: "0 6px", fontSize: 12 }} aria-pressed={marked.has(p)} onClick={() => onToggle(p)}>{String(v)}</button>
              ) : (
                <Tree value={v} path={Array.isArray(v) ? p : p} marked={marked} onToggle={onToggle} />
              )}
            </div>
          );
        })}
      </div>
    );
  }
  return null;
}

function parse(s: string): unknown {
  try { return JSON.parse(s); } catch { return null; }
}

function Builder({ onSaved }: { onSaved: () => void }) {
  const vaults = useLoad<{ vaults: { id: string; name: string }[] }>(() => control("/v1/vaults"));
  const [f, setF] = useState({ vault_id: "", name: "", direction: "inbound", method: "POST", path_pattern: "/v1/**", upstream_url: "", mode: "process_and_store" });
  const [reqText, setReqText] = useState(SAMPLE_REQ);
  const [resText, setResText] = useState(SAMPLE_RES);
  const [reqPaths, setReqPaths] = useState<Set<string>>(new Set(["$.customer.bvn"]));
  const [resPaths, setResPaths] = useState<Set<string>>(new Set());
  const [resMode, setResMode] = useState<"unredact" | "redact">("unredact");
  const [dlp, setDlp] = useState(true);
  const [filePolicy, setFilePolicy] = useState("refuse");
  const [reqHeaders, setReqHeaders] = useState("");
  const headerRules = (text: string) => text.split(/[\n,]/).map((h) => h.trim()).filter(Boolean).map((header) => ({ header }));
  const [preview, setPreview] = useState<{ request?: string; response?: string; request_error?: string; response_error?: string } | null>(null);
  const [created, setCreated] = useState<{ route_key: string; url: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const toRules = (s: Set<string>): Rule[] => [...s].map((path) => ({ path }));
  const route = useMemo(() => ({
    ...f,
    redact_paths: f.direction === "inbound" ? toRules(reqPaths) : [],
    unredact_paths: f.direction === "outbound" ? toRules(reqPaths) : [],
    response_redact_paths: resMode === "redact" ? toRules(resPaths) : [],
    response_unredact_paths: resMode === "unredact" ? toRules(resPaths) : [],
    dlp,
    file_policy: filePolicy,
    redact_headers: f.direction === "inbound" ? headerRules(reqHeaders) : [],
    unredact_headers: f.direction === "outbound" ? headerRules(reqHeaders) : [],
  }), [f, reqPaths, resPaths, resMode, dlp, filePolicy, reqHeaders]);
  const toggle = (set: Set<string>, update: (s: Set<string>) => void) => (p: string) => { const n = new Set(set); if (n.has(p)) n.delete(p); else n.add(p); update(n); };

  useEffect(() => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      control("/v1/proxy-routes/preview", { body: { route: { ...route, name: "preview", upstream_url: "" }, request: reqText, response: resText, ...(f.vault_id ? { vault_id: f.vault_id } : {}) } }).then(setPreview).catch(() => setPreview(null));
    }, 300);
    return () => clearTimeout(timer.current);
  }, [route, reqText, resText]);

  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });
  const reqDoc = parse(reqText), resDoc = parse(resText);
  return (
    <div className="stack">
      <div className="card">
        <h2>{tr("New proxy route")}</h2>
        <div className="slots">
          <label className="field"><span>{tr("Vault")}</span><select value={f.vault_id} onChange={set("vault_id")}><option value="">{tr("Choose a vault")}</option>{vaults.value?.vaults.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label>
          <label className="field"><span>{tr("Name")}</span><input value={f.name} onChange={set("name")} /></label>
          <label className="field"><span>{tr("Direction")}</span><select value={f.direction} onChange={set("direction")}><option value="inbound">{tr("Inbound: tokenize before your server or vendor")}</option><option value="outbound">{tr("Outbound: restore for a third party that needs real values")}</option></select></label>
          <label className="field"><span>{tr("Method")}</span><select value={f.method} onChange={set("method")}>{[tr("GET"), tr("POST"), tr("PUT"), tr("PATCH"), tr("DELETE")].map((m) => <option key={m}>{m}</option>)}</select></label>
          <label className="field"><span>{tr("Path")}</span><input value={f.path_pattern} onChange={set("path_pattern")} /></label>
          <label className="field"><span>{tr("Destination URL")}</span><input placeholder={tr("https://…")} value={f.upstream_url} onChange={set("upstream_url")} /></label>
          <label className="field"><span>{tr("Mode")}</span><select value={f.mode} onChange={set("mode")}><option value="process_and_store">{tr("Process and store: value vaulted, token forwarded")}</option><option value="process_only">{tr("Process only: token forwarded, nothing stored")}</option></select></label>
        </div>
        <div className="slots">
          <label className="field"><span>{tr("Headers to")} {f.direction === "inbound" ? tr("tokenize") : tr("restore")}</span><input placeholder={tr("X-Customer-BVN, X-Account")} value={reqHeaders} onChange={(e) => setReqHeaders(e.target.value)} /></label>
          <label className="field"><span>{tr("PDFs, images and other files")}</span><select value={filePolicy} onChange={(e) => setFilePolicy(e.target.value)}><option value="refuse">{tr("Refuse them")}</option><option value="redact">{tr("Redact PDFs and images, refuse the rest")}</option><option value="pass">{tr("Send them unread")}</option></select></label>
        </div>
        {filePolicy === "pass" && <div className="note warn small">{tr("Files on this route reach the destination unread, and may hold anything. Each one is counted as uninspected.")}</div>}
        <p className="small muted">{tr("Forms, XML and SOAP, multipart uploads and plain text are read as well as JSON. Rules use the same paths:")} <code>{tr("$.bvn")}</code> {tr("for a form field or upload field, and")} <code>{tr("$.Envelope.Body.Check.BVN")}</code> or <code>{tr("$.Check.@id")}</code> {tr("for XML. A body that cannot be read in full is not forwarded.")}</p>
        <label className="row small"><input type="checkbox" checked={dlp} onChange={(e) => setDlp(e.target.checked)} />{tr("Also catch identifiers no rule names")}</label>
      </div>
      <div className="cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))" }}>
        <div className="card">
          <h2>{tr("Sample request")}</h2>
          <textarea className="code" aria-label={tr("Sample request")} value={reqText} onChange={(e) => setReqText(e.target.value)} />
          <span className="small muted">{tr("Click values to")} {f.direction === "inbound" ? tr("tokenize") : tr("restore")}{tr(". Use synthetic data.")}</span>
          {reqDoc ? <Tree value={reqDoc} path="$" marked={reqPaths} onToggle={toggle(reqPaths, setReqPaths)} /> : <div className="err">{tr("Not valid JSON.")}</div>}
          <div className="slot"><b>{tr("Sent on to the destination")}</b>{preview?.request_error ? <div className="err">{preview.request_error}</div> : <pre className="pre">{preview?.request}</pre>}</div>
        </div>
        <div className="card">
          <h2>{tr("Sample response")}</h2>
          <textarea className="code" aria-label={tr("Sample response")} value={resText} onChange={(e) => setResText(e.target.value)} />
          <label className="field"><span>{tr("Clicked values are")}</span><select value={resMode} onChange={(e) => setResMode(e.target.value as "unredact" | "redact")}><option value="unredact">{tr("Restored, for a caller whose policy allows it")}</option><option value="redact">{tr("Tokenized")}</option></select></label>
          {resDoc ? <Tree value={resDoc} path="$" marked={resPaths} onToggle={toggle(resPaths, setResPaths)} /> : <div className="err">{tr("Not valid JSON.")}</div>}
          <div className="slot"><b>{tr("Returned, in preview with no caller")}</b>{preview?.response_error ? <div className="err">{preview.response_error}</div> : <pre className="pre">{preview?.response}</pre>}</div>
        </div>
      </div>
      <ErrorLine error={error} />
      {created ? (
        <div className="grid gap-2">
          <ShownOnce items={[{ label: tr("Route key"), value: created.route_key }, { label: tr("Address to call"), value: created.url }]}><p className="small muted">{tr("Send the route key in the")} <code>{tr("X-RV-Route-Key")}</code> header.</p></ShownOnce>
          <div className="row" style={{ marginTop: 6 }}><button onClick={onSaved}>{tr("Done")}</button></div>
        </div>
      ) : (
        <div className="row"><button className="primary" disabled={!f.vault_id || !f.name || !f.upstream_url} onClick={async () => {
          setError(null);
          try { setCreated(await control("/v1/proxy-routes", { body: route })); } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
        }}>{tr("Create route")}</button></div>
      )}
    </div>
  );
}

interface Route { id: string; name: string; direction: string; method: string; path_pattern: string; upstream_url: string; mode: string; redact_paths: Rule[]; unredact_paths: Rule[] }

export function ProxyRoutes({ startNew = false }: { startNew?: boolean }) {
  const { value, error, loading, reload } = useLoad<{ routes: Route[] }>(() => control("/v1/proxy-routes"));
  const [building, setBuilding] = useState(startNew);
  return (
    <div className="stack">
      <div className="row"><button className="primary" onClick={() => setBuilding(!building)}>{building ? tr("Close") : tr("Connect a web API")}</button></div>
      {building && <Builder onSaved={() => { setBuilding(false); reload(); }} />}
      <Loading error={error} loading={loading && !value} />
      {value?.routes.length === 0 && !building && <Empty title={tr("No web APIs connected yet")}>{tr("A route replaces sensitive fields on the way to a vendor, and restores them for callers who are allowed.")}</Empty>}
      {value && value.routes.length > 0 && (
        <div className="tablewrap">
          <table>
            <thead><tr><th>{tr("Name")}</th><th>{tr("Direction")}</th><th>{tr("Route")}</th><th>{tr("Destination")}</th><th>{tr("Mode")}</th><th className="num">{tr("Rules")}</th><th></th></tr></thead>
            <tbody>
              {value.routes.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td><td><Badge>{r.direction}</Badge></td><td className="mono small">{r.method} {r.path_pattern}</td><td className="small">{r.upstream_url}</td><td className="small">{r.mode.replaceAll("_", " ")}</td><td className="num">{r.redact_paths.length + r.unredact_paths.length}</td>
                  <td><button className="link" onClick={async () => { await control(`/v1/proxy-routes/${r.id}`, { method: "DELETE" }); reload(); }}>{tr("Remove")}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
