"use client";
import { tr } from "@/lib/i18n";
import { EmergencyAccess, Networks } from "./safeguards";
import { useEffect, useMemo, useRef, useState } from "react";
import { useMe } from "@/components/Shell";
import { Badge, Checks, DecisionBadge, ErrorLine, Loading, Modal, Page } from "@/components/ui";
import { control, useLoad, when } from "@/lib/api";
import { Person } from "@/lib/people";

const ACTIONS = ["detokenize", "tokenize", "insert", "search", "compare", "file_redact", "export", "delete"];
const DATA_TYPES = ["bvn", "nin", "vnin", "ng_11_digit_id", "nuban", "phone_ng", "email", "person_name", "amount_ngn", "payment_ref", "address", "date", "free_text"];

interface Rule { id: string; actions: string[]; who: { roles?: string[]; principals?: string[]; networks?: string[]; require_mfa?: boolean }; what: { fields?: string[]; data_types?: string[] }; when: { purpose_required?: boolean; hour_from?: number; hour_to?: number }; returns: string }
interface Source { rules: Rule[]; limit_per_hour?: number }
interface Policy { id: string; name: string; version: number; status: string; source: Source; created_by: string; approved_by: string | null; created_at: string; published_at: string | null }

const blankRule = (i: number): Rule => ({ id: `rule-${i}`, actions: ["detokenize"], who: { roles: ["support_agent"] }, what: {}, when: { purpose_required: true }, returns: "masked" });

function RuleCard({ rule, roles, networks, customTypes, onChange, onRemove }: { rule: Rule; roles: string[]; networks: string[]; customTypes: string[]; onChange: (r: Rule) => void; onRemove: () => void }) {
  const isReveal = rule.actions.includes("detokenize");
  return (
    <div className="card">
      <div className="spread">
        <input aria-label={tr("Rule name")} value={rule.id} onChange={(e) => onChange({ ...rule, id: e.target.value })} className="mono" />
        <button className="link small" onClick={onRemove}>{tr("Remove")}</button>
      </div>
      <div className="slot"><b>{tr("Action")}</b><Checks options={ACTIONS} value={rule.actions} onChange={(actions) => onChange({ ...rule, actions, returns: actions.includes("detokenize") && rule.returns === "allow" ? "masked" : rule.returns })} /></div>
      <div className="slots">
        <div className="slot">
          <b>{tr("Who")}</b>
          <Checks options={roles} value={rule.who.roles ?? []} onChange={(r) => onChange({ ...rule, who: { ...rule.who, roles: r } })} />
          {networks.length > 0 && <><span className="small muted">{tr("Only from networks")}</span><Checks options={networks} value={rule.who.networks ?? []} onChange={(n) => onChange({ ...rule, who: { ...rule.who, networks: n } })} /></>}
          <label className="row small"><input type="checkbox" checked={Boolean(rule.who.require_mfa)} onChange={(e) => onChange({ ...rule, who: { ...rule.who, require_mfa: e.target.checked } })} />{tr("Require MFA")}</label>
        </div>
        <div className="slot">
          <b>{tr("What")}</b>
          <span className="small muted">{tr("Data types; none means all fields")}</span>
          <Checks options={[...DATA_TYPES, ...customTypes]} value={rule.what.data_types ?? []} onChange={(d) => onChange({ ...rule, what: { ...rule.what, data_types: d } })} />
          <label className="field"><span>{tr("Field names, comma-separated")}</span><input value={(rule.what.fields ?? []).join(", ")} onChange={(e) => onChange({ ...rule, what: { ...rule.what, fields: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) } })} /></label>
        </div>
        <div className="slot">
          <b>{tr("When")}</b>
          <label className="row small"><input type="checkbox" checked={Boolean(rule.when.purpose_required)} onChange={(e) => onChange({ ...rule, when: { ...rule.when, purpose_required: e.target.checked } })} />{tr("Purpose required")}</label>
          <label className="row small"><input type="checkbox" checked={rule.when.hour_from !== undefined} onChange={(e) => { const { hour_from: _f, hour_to: _t, ...rest } = rule.when; onChange({ ...rule, when: e.target.checked ? { ...rest, hour_from: 8, hour_to: 18 } : rest }); }} />{tr("Office hours only (organisation's zone)")}</label>
          {rule.when.hour_from !== undefined && (
            <div className="row small">
              <input aria-label={tr("From hour")} type="number" min={0} max={23} style={{ width: 60 }} value={rule.when.hour_from} onChange={(e) => onChange({ ...rule, when: { ...rule.when, hour_from: Number(e.target.value) } })} /> to
              <input aria-label={tr("To hour")} type="number" min={1} max={24} style={{ width: 60 }} value={rule.when.hour_to} onChange={(e) => onChange({ ...rule, when: { ...rule.when, hour_to: Number(e.target.value) } })} />
            </div>
          )}
        </div>
        <div className="slot">
          <b>{tr("Returns")}</b>
          <select aria-label={tr("Returns")} value={rule.returns} onChange={(e) => onChange({ ...rule, returns: e.target.value })}>
            {isReveal ? <><option value="plaintext">{tr("Plaintext")}</option><option value="masked">{tr("Masked")}</option><option value="token_only">{tr("Token only")}</option><option value="denied">{tr("Deny")}</option></> : <><option value="allow">{tr("Allow")}</option><option value="denied">{tr("Deny")}</option></>}
          </select>
        </div>
      </div>
    </div>
  );
}

function Simulator({ name, version, source, roles, networks }: { name: string; version: number; source: Source; roles: string[]; networks: string[] }) {
  const people = useLoad<{ principals: { id: string; display_name: string }[] }>(() => control("/v1/principals"));
  const [s, setS] = useState({ who: `role:${roles[0] ?? ""}`, action: "detokenize", data_type: "bvn", field_name: "bvn", purpose: "Ticket 1", network: "", hour: 10 });
  const [res, setRes] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setError(null);
    try {
      const whoBody = s.who.startsWith("role:") ? { roles: [s.who.slice(5)] } : { principal_id: s.who.slice(7) };
      setRes(await control("/v1/policies/preview", { body: { ...whoBody, action: s.action, data_type: s.data_type, field_name: s.field_name, purpose: s.purpose, networks: s.network ? [s.network] : [], hour: s.hour, draft: { name, version, source } } }));
    } catch (e) { setError(e instanceof Error ? e.message : "failed"); setRes(null); }
  };
  return (
    <div className="card">
      <h2>{tr("Simulator")}</h2>
      <label className="field"><span>{tr("Who")}</span>
        <select value={s.who} onChange={(e) => setS({ ...s, who: e.target.value })}>
          <optgroup label={tr("Role")}>{roles.map((r) => <option key={r} value={`role:${r}`}>{r}</option>)}</optgroup>
          <optgroup label={tr("Person")}>{people.value?.principals.map((p) => <option key={p.id} value={`person:${p.id}`}>{p.display_name}</option>)}</optgroup>
        </select>
      </label>
      <label className="field"><span>{tr("Action")}</span><select value={s.action} onChange={(e) => setS({ ...s, action: e.target.value })}>{ACTIONS.map((a) => <option key={a}>{a}</option>)}</select></label>
      <label className="field"><span>{tr("Data type")}</span><select value={s.data_type} onChange={(e) => setS({ ...s, data_type: e.target.value, field_name: e.target.value })}>{DATA_TYPES.map((a) => <option key={a}>{a}</option>)}</select></label>
      <label className="field"><span>{tr("Purpose")}</span><input value={s.purpose} onChange={(e) => setS({ ...s, purpose: e.target.value })} /></label>
      <label className="field"><span>{tr("Network")}</span><select value={s.network} onChange={(e) => setS({ ...s, network: e.target.value })}><option value="">{tr("Not on an approved network")}</option>{networks.map((x) => <option key={x}>{x}</option>)}</select></label>
      <label className="field"><span>{tr("Hour, organisation's time zone")}</span><input type="number" min={0} max={23} value={s.hour} onChange={(e) => setS({ ...s, hour: Number(e.target.value) })} /></label>
      <button className="primary" onClick={run}>{tr("Run")}</button>
      <ErrorLine error={error} />
      {res && (
        <div className="stack" style={{ gap: 6 }}>
          <div className="row"><DecisionBadge value={res.decision} />{res.rule ? <span className="small muted">by <code>{res.policy}@v{res.policy_version}</code> rule <code>{res.rule}</code></span> : <span className="small muted">{tr("No rule matched, so default deny applies.")}</span>}</div>
          {(res.trace ?? []).map((t: any, i: number) => (
            <div key={i} className="small muted">
              <code>{t.policy}/{t.rule}</code>: {t.won ? tr("decided") : t.matched ? tr("matched, but returns {0}, less restrictive", { 0: t.returns }) : tr("did not match ({0})", { 0: t.failed_slot })}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Builder({ initial, name: initialName, version, roles, networks, onSaved, onCancel }: { initial: Source; name: string; version: number; roles: string[]; networks: string[]; onSaved: () => void; onCancel: () => void }) {
  const customSlugs = useLoad<{ entities: { slug: string; name: string }[] }>(() => control("/v1/custom-entities/slugs"));
  const [name, setName] = useState(initialName);
  const [source, setSource] = useState<Source>(initial);
  const [readable, setReadable] = useState("");
  const [compileError, setCompileError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const json = useMemo(() => JSON.stringify(source), [source]);
  useEffect(() => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      control("/v1/policies/compile", { body: { name: name || "draft", version, source } })
        .then((r) => { setReadable(r.readable); setCompileError(null); })
        .catch((e) => setCompileError(e.message));
    }, 250);
    return () => clearTimeout(timer.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [json, name, version]);
  const setRule = (i: number, r: Rule) => setSource({ ...source, rules: source.rules.map((x, j) => (j === i ? r : x)) });
  return (
    <div className="split">
      <div className="stack">
        <div className="card">
          <div className="row">
            <label className="field" style={{ flex: 1, minWidth: 220 }}><span>{tr("Policy name")}</span><input disabled={Boolean(initialName)} value={name} onChange={(e) => setName(e.target.value)} placeholder="support-agents-nigeria" /></label>
            <label className="field" style={{ width: 170 }}><span>{tr("Reveals per user per hour")}</span><input type="number" min={0} value={source.limit_per_hour ?? 0} onChange={(e) => setSource({ ...source, limit_per_hour: Number(e.target.value) })} /></label>
            <span className="small muted">{tr("Version")} {version}</span>
          </div>
        </div>
        {source.rules.map((r, i) => <RuleCard key={i} rule={r} roles={roles} networks={networks} customTypes={(customSlugs.value?.entities ?? []).map((e) => e.slug)} onChange={(x) => setRule(i, x)} onRemove={() => setSource({ ...source, rules: source.rules.filter((_, j) => j !== i) })} />)}
        <div className="row"><button onClick={() => setSource({ ...source, rules: [...source.rules, blankRule(source.rules.length + 1)] })}>{tr("Add rule")}</button></div>
        <div className="card">
          <h2>{tr("Readable policy")}</h2>
          {compileError ? <div className="note bad">{compileError}</div> : <pre className="pre">{readable}</pre>}
        </div>
        <ErrorLine error={saveError} />
        <div className="row">
          <button onClick={onCancel}>{tr("Cancel")}</button>
          <button className="primary" disabled={!name || Boolean(compileError)} onClick={async () => {
            try {
              await control("/v1/policies", { body: { name, source } });
              onSaved();
            } catch (e) { setSaveError(e instanceof Error ? e.message : "failed"); }
          }}>{tr("Save draft")}</button>
          <span className="small muted">{tr("A second admin publishes it.")}</span>
        </div>
      </div>
      <Simulator name={name || "draft"} version={version} source={source} roles={roles} networks={networks} />
    </div>
  );
}

function diffLines(a: string, b: string) {
  const left = a.split("\n"), right = b.split("\n");
  const inLeft = new Set(left), inRight = new Set(right);
  return [...left.filter((l) => !inRight.has(l)).map((l) => ({ t: "del", l })), ...right.map((l) => ({ t: inLeft.has(l) ? "same" : "add", l }))];
}

function PublishDialog({ policy, me, onClose, onDone }: { policy: Policy; me: string; onClose: () => void; onDone: () => void }) {
  const { value, error, loading } = useLoad<{ readable: string; previous_readable: string | null; previous_version: number | null }>(() => control(`/v1/policies/${policy.id}`), [policy.id]);
  const [err, setErr] = useState<string | null>(null);
  const own = policy.created_by === me;
  return (
    <Modal title={tr("Publish {0} v{1}", { 0: policy.name, 1: policy.version })} onClose={onClose}>
      <Loading error={error} loading={loading} />
      {value && (
        <pre className="pre">
          {diffLines(value.previous_readable ?? "", value.readable).filter((d) => d.l).map((d, i) => (
            <div key={i} className={d.t === "add" ? "diff-add" : d.t === "del" ? "diff-del" : ""}>{d.t === "add" ? "+ " : d.t === "del" ? "- " : "  "}{d.l}</div>
          ))}
        </pre>
      )}
      {own && <div className="note warn">{tr("You wrote this draft. Publishing needs a second admin.")}</div>}
      <ErrorLine error={err} />
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button onClick={onClose}>{tr("Cancel")}</button>
        <button className="primary" disabled={own} onClick={async () => {
          try {
            await control(`/v1/policies/${policy.id}/publish`, { method: "POST" });
            onDone();
          } catch (e) { setErr(e instanceof Error ? e.message : "failed"); }
        }}>{tr("Publish")}</button>
      </div>
    </Modal>
  );
}

export default function Policies() {
  const me = useMe();
  const { value, error, loading, reload } = useLoad<{ policies: Policy[] }>(() => control("/v1/policies"));
  const rolesRes = useLoad<{ roles: string[] }>(() => control("/v1/roles"));
  const netsRes = useLoad<{ networks: { name: string }[] }>(() => control("/v1/networks"));
  const [editing, setEditing] = useState<{ source: Source; name: string; version: number } | null>(null);
  const [publishing, setPublishing] = useState<Policy | null>(null);
  const [tab, setTab] = useState<"rules" | "networks" | "emergency">("rules");
  const roles = rolesRes.value?.roles ?? [];
  const networks = netsRes.value?.networks.map((n) => n.name) ?? [];
  const nextVersion = (name: string) => Math.max(0, ...(value?.policies.filter((p) => p.name === name).map((p) => p.version) ?? [0])) + 1;

  if (editing) {
    return (
      <Page title={editing.name ? tr("Edit {0}", { 0: editing.name }) : tr("New access rule")} sub={tr("Each rule is one card. Nothing changes until a second admin publishes this draft.")}>
        <Builder initial={editing.source} name={editing.name} version={editing.version} roles={roles} networks={networks} onCancel={() => setEditing(null)} onSaved={() => { setEditing(null); reload(); }} />
      </Page>
    );
  }
  return (
    <Page title={tr("Access rules")} sub={tr("Nobody sees a real value until a published rule says so. If several rules match, the strictest one wins.")} actions={<button className="primary" onClick={() => setEditing({ source: { rules: [blankRule(1)], limit_per_hour: 200 }, name: "", version: 1 })}>{tr("New access rule")}</button>}>
      <div className="tabs" role="tablist">
        {([["rules", tr("Rules")], ["networks", tr("Approved networks")], ["emergency", tr("Emergency access")]] as const).map(([k, l]) => <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{l}</button>)}
      </div>
      {tab === "networks" && <Networks />}
      {tab === "emergency" && <EmergencyAccess />}
      {tab === "rules" && <Loading error={error} loading={loading && !value} />}
      {tab === "rules" && value && (
        <div className="tablewrap">
          <table>
            <thead><tr><th>{tr("Name")}</th><th className="num">{tr("Version")}</th><th>{tr("Status")}</th><th className="num">{tr("Rules")}</th><th>{tr("Written by")}</th><th>{tr("Approved by")}</th><th>{tr("Published")}</th><th></th></tr></thead>
            <tbody>
              {value.policies.map((p) => (
                <tr key={p.id}>
                  <td><code>{p.name}</code></td><td className="num">v{p.version}</td>
                  <td><Badge tone={p.status === "active" ? "good" : p.status === "draft" ? "warn" : ""}>{p.status[0]!.toUpperCase() + p.status.slice(1)}</Badge></td>
                  <td className="num">{p.source.rules?.length ?? 0}</td>
                  <td className="small"><Person id={p.created_by} /></td><td className="small">{p.approved_by ? <Person id={p.approved_by} /> : tr("Pending")}</td><td className="small">{p.published_at ? when(p.published_at) : tr("not yet")}</td>
                  <td>
                    <div className="row">
                      {p.status === "active" && <button onClick={() => setEditing({ source: p.source, name: p.name, version: nextVersion(p.name) })}>{tr("Edit as draft")}</button>}
                      {p.status === "draft" && <button className="primary" onClick={() => setPublishing(p)}>{tr("Review and publish")}</button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {publishing && <PublishDialog policy={publishing} me={me?.id ?? ""} onClose={() => setPublishing(null)} onDone={() => { setPublishing(null); reload(); }} />}
    </Page>
  );
}
