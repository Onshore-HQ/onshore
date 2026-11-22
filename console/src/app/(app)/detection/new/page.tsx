"use client";
import { tr } from "@/lib/i18n";
import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useMe } from "@/components/Shell";
import { Badge, ErrorLine, Page } from "@/components/ui";
import { ApiErr, control, n, useLoad } from "@/lib/api";
import { ACTIONS, Chips, ValidatorFields, describe, explainRegex, Highlighted, KINDS, kindLabel, maskPreview, MaskRule, MODULES, type Definition, type Validator } from "../shared";

const STEPS = ["Kind", "Define", "Context", "Token and mask", "Test bench", "Review"];
const SAMPLE_PAYLOAD = '{\n  "loan": { "collateral_ref": "synthetic-ref", "amount": 250000 },\n  "staffId": "S-1001"\n}';

interface Draft {
  kind: string; name: string; slug: string; definition: Definition; validator: Validator | null;
  context_positive: string[]; context_negative: string[]; threshold: number;
  token_kind: string; token_format: string; mask_rule: MaskRule; actions: Record<string, string>;
}
const blank: Draft = {
  kind: "", name: "", slug: "", definition: {}, validator: null, context_positive: [], context_negative: [], threshold: 0.7,
  token_kind: "deterministic", token_format: "opaque", mask_rule: { type: "last_n", n: 4 }, actions: { api: "tokenize", logs: "tokenize", ai: "tokenize", proxy: "tokenize" },
};
const slugify = (s: string) => `c_${s.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "").slice(0, 40)}`;

function JsonTree({ value, path, onPick, picked }: { value: unknown; path: string; onPick: (p: string) => void; picked: string[] }) {
  if (Array.isArray(value)) return <>{value.slice(0, 3).map((v, i) => <JsonTree key={i} value={v} path={`${path}[*]`} onPick={onPick} picked={picked} />)}</>;
  if (value && typeof value === "object") {
    return (
      <ul style={{ listStyle: "none", paddingLeft: 14, margin: 0 }}>
        {Object.entries(value as Record<string, unknown>).map(([k, v]) => {
          const p = `${path}.${k}`;
          const leaf = v === null || typeof v !== "object";
          return (
            <li key={k}>
              {leaf ? <button className="link small mono" onClick={() => onPick(p)} aria-pressed={picked.includes(p)}>{picked.includes(p) ? "✓ " : ""}{k}</button> : <span className="small mono">{k}</span>}
              {leaf ? <span className="small muted"> {String(v).slice(0, 30)}</span> : <JsonTree value={v} path={p} onPick={onPick} picked={picked} />}
            </li>
          );
        })}
      </ul>
    );
  }
  return null;
}

function ValueUpload({ ensureSaved, vault }: { ensureSaved: () => Promise<string | null>; vault: string }) {
  const [file, setFile] = useState<File | null>(null);
  const [rows, setRows] = useState<string[][]>([]);
  const [column, setColumn] = useState("");
  const [result, setResult] = useState<{ received: number; hashed: number; duplicates: number; rejected: number; rejected_rows: { row: number; reason: string }[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const pick = async (f: File | undefined) => {
    if (!f) return;
    setFile(f); setResult(null);
    // Only the first few rows are read here, and only to show their shape, masked.
    const head = await f.slice(0, 8192).text();
    const lines = head.split(/\r?\n/).slice(0, 6).map((l) => l.split(","));
    setRows(lines);
    setColumn(lines[0]?.[0]?.trim() ?? "");
  };
  const index = rows[0]?.findIndex((h) => h.trim() === column) ?? 0;
  return (
    <div className="stack">
      <label className="field"
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => { e.preventDefault(); pick(e.dataTransfer.files[0]); }}>
        <span>{tr("CSV file, up to 100,000 values. Drop it here or choose one.")}</span>
        <input type="file" accept=".csv,text/csv" onChange={(e) => pick(e.target.files?.[0])} />
      </label>
      {rows.length > 0 && (
        <>
          <label className="field"><span>{tr("Which column holds the values?")}</span><select value={column} onChange={(e) => setColumn(e.target.value)}>{rows[0]!.map((h) => <option key={h}>{h.trim()}</option>)}</select></label>
          <div className="small muted">{tr("First rows, masked:")}</div>
          <div className="pre small">{rows.slice(1, 5).map((r, i) => <div key={i}>{maskPreview({ type: "last_n", n: 2 }, r[index]?.trim() ?? "")}</div>)}</div>
          <div className="row"><button className="primary" disabled={busy || !file} onClick={async () => {
            setBusy(true); setError(null);
            try {
              const id = await ensureSaved();
              if (!id) return;
              const form = new FormData();
              form.append("column", column);
              form.append("file", file!);
              const res = await fetch(`/api/proxy/control/v1/vaults/${vault}/custom-entities/${id}/values`, { method: "POST", headers: { "x-rv-console": "1" }, body: form });
              const data = await res.json();
              if (!res.ok) throw new Error(data.error?.message ?? "upload failed");
              setResult(data);
            } catch (e) { setError(e instanceof Error ? e.message : "upload failed"); } finally { setBusy(false); }
          }}>{busy ? tr("Hashing…") : tr("Hash and store")}</button></div>
        </>
      )}
      <ErrorLine error={error} />
      {result && (
        <div className="note good small">
          {n(result.received)} {tr("received,")} <b>{n(result.hashed)} added</b>, {n(result.duplicates)} {tr("duplicates,")} {n(result.rejected)} rejected.
          {result.rejected_rows.slice(0, 5).map((r) => <div key={r.row}>{tr("Row")} {r.row}: {r.reason}</div>)}
        </div>
      )}
      <p className="small muted">{tr("Values are stored only as secure fingerprints, which cannot be read back. The original is kept encrypted for 30 days so the list can be reprocessed, then deleted. This list goes live only after a second person approves.")}</p>
    </div>
  );
}

function Builder() {
  const router = useRouter();
  const params = useSearchParams();
  const me = useMe();
  const vault = params.get("vault") ?? "";
  const editId = params.get("id");
  const templateId = params.get("template");
  const [step, setStep] = useState(0);
  const [d, setD] = useState<Draft>(blank);
  const [slugEdited, setSlugEdited] = useState(false);
  const [id, setId] = useState<string | null>(editId);
  const [published, setPublished] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [defError, setDefError] = useState<string | null>(null);
  const [examples, setExamples] = useState("");
  const [suggestion, setSuggestion] = useState<{ regex: string; explanation: string } | null>(null);
  const [payload, setPayload] = useState(SAMPLE_PAYLOAD);
  const [bench, setBench] = useState("repayment on LN-00412873 is late, BVN 22123456789");
  const [matches, setMatches] = useState<{ type: string; start: number; end: number; score: number; custom: boolean }[]>([]);
  const [samples, setSamples] = useState<{ id: string; sample: string; expect_match: boolean; matched: boolean; passed: boolean }[]>([]);
  const [newSample, setNewSample] = useState("");
  const [estimate, setEstimate] = useState<{ ms_per_kb: number; matched_share: number } | null>(null);
  const [requested, setRequested] = useState<{ id: string; version: number; benchmark: { ms_per_kb: number; matched_share: number } } | null>(null);
  const people = useLoad<{ principals: { id: string; display_name: string; roles: string[]; kind: string; status: string }[] }>(() => control("/v1/principals"));
  const templates = useLoad<{ templates: { id: string; name: string; kind: string; slug: string; definition: Definition; context_positive: string[]; confirmed: boolean; issuer: string }[] }>(() => control("/v1/custom-entity-templates"));
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const set = (patch: Partial<Draft>) => setD((x) => ({ ...x, ...patch }));
  const defn = (patch: Partial<Definition>) => setD((x) => ({ ...x, definition: { ...x.definition, ...patch } }));
  const certain = d.kind === "value_list" || d.kind === "json_path";
  const unconfirmed = templates.value?.templates.find((t) => t.id === templateId);

  useEffect(() => {
    if (editId) {
      control(`/v1/vaults/${vault}/custom-entities/${editId}`).then((r) => {
        const e = r.pending_definition ?? r.entity;
        setD({ ...blank, ...e, kind: r.entity.kind, slug: r.entity.slug, threshold: Number(e.threshold) });
        setPublished(r.entity.version > 0);
        setStep(1);
      }).catch((err) => setError(err.message));
    }
  }, [editId, vault]);
  useEffect(() => {
    if (unconfirmed && !d.kind) {
      setD({ ...blank, kind: unconfirmed.kind, name: unconfirmed.name, slug: unconfirmed.slug, definition: unconfirmed.definition, context_positive: unconfirmed.context_positive });
      setSlugEdited(true);
      setStep(1);
    }
  }, [unconfirmed, d.kind]);

  // Syntax errors show as the pattern is typed.
  useEffect(() => {
    // An empty form is unfinished, not wrong, so it gets no error yet.
    const x = d.definition;
    const started = d.kind === "value_list" || x.regex || x.terms?.length || x.cues?.length || x.paths?.length;
    if (!d.kind || !started) { setDefError(null); return; }
    clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      control("/v1/custom-entities/check", { body: { kind: d.kind, definition: d.definition, validator: d.validator } }).then(() => setDefError(null)).catch((e) => setDefError(e.message));
    }, 300);
    return () => clearTimeout(timer.current);
  }, [d.kind, d.definition, d.validator]);

  const body = () => ({ name: d.name, definition: d.definition, validator: d.validator, context_positive: d.context_positive, context_negative: d.context_negative, threshold: d.threshold, token_kind: d.token_kind, token_format: d.token_format, mask_rule: d.mask_rule, actions: d.actions });

  /** A draft must exist before lists or samples can be stored against it. */
  const ensureSaved = async (): Promise<string | null> => {
    setError(null);
    try {
      if (id) {
        await control(`/v1/vaults/${vault}/custom-entities/${id}`, { method: "PATCH", body: { ...body(), ...(published ? {} : { slug: d.slug }) } });
        return id;
      }
      const r = await control(`/v1/vaults/${vault}/custom-entities`, { body: { ...body(), slug: d.slug, kind: d.kind, tests: [] } });
      setId(r.id);
      return r.id;
    } catch (e) {
      setError(e instanceof Error ? e.message : "could not save");
      return null;
    }
  };

  const runSamples = async (eid: string | null = id) => {
    if (!eid) return;
    const r = await control(`/v1/vaults/${vault}/custom-entities/${eid}/test`, { body: { definition: body() } });
    setSamples(r.results);
  };
  // The bench re-runs as text or definition changes, so a threshold move shows at once.
  useEffect(() => {
    if (!id || (step !== 4 && step !== 2)) return;
    const t = setTimeout(() => {
      control(`/v1/vaults/${vault}/custom-entities/${id}/test`, { body: { text: bench, definition: body() } }).then((r) => setMatches(r.matches)).catch((e) => setError(e.message));
      runSamples().catch(() => {});
      control(`/v1/vaults/${vault}/custom-entities/${id}/test`, { body: { estimate: true, definition: body() } }).then(setEstimate).catch(() => {});
    }, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, step, bench, d.threshold, d.context_positive, d.context_negative, d.definition, d.validator]);

  const next = async () => {
    if (step >= 1 && step < 5) { const saved = await ensureSaved(); if (!saved) return; }
    setStep(step + 1);
  };
  const approvers = (people.value?.principals ?? []).filter((p) => p.kind === "user" && p.status === "active" && p.id !== me?.id && p.roles.some((r) => r === "admin" || r === "detection_approver"));
  const mustMatch = samples.filter((s) => s.expect_match).length;
  const mustNot = samples.length - mustMatch;
  const ready = mustMatch >= 3 && mustNot >= 3 && samples.every((s) => s.passed);
  const previewValue = d.kind === "pattern" ? "LN-00412873" : "sample-value";
  const token = `tok_${d.slug || "c_entity"}_7Hq2xP9LmA4cRt5YzX0a1b`;

  return (
    <Page title={editId ? tr("Edit {0}", { 0: d.name }) : tr("New custom entity")} sub={published ? tr("The live version keeps running until this edit is approved.") : tr("Nothing here affects traffic until it is tested, approved and published.")}>
      <div className="steps">{STEPS.map((s, i) => <span key={s} className={i === step ? "on" : ""}>{i + 1}. {s}</span>)}</div>
      {unconfirmed && <div className="note warn small">{tr("This template's format has not been confirmed with")} {unconfirmed.issuer}{tr(". Check it against real documents and edit it before relying on it.")}</div>}
      <div className="card">
        {step === 0 && (
          <>
            <h2>{tr("Choose a kind")}</h2>
            <div className="cards">
              {KINDS.map((k) => (
                <button key={k.kind} className={`card pick ${d.kind === k.kind ? "on" : ""}`} aria-pressed={d.kind === k.kind} onClick={() => { set({ kind: k.kind, threshold: k.kind === "value_list" || k.kind === "json_path" ? 1 : 0.7 }); setStep(1); }}>
                  <b><span aria-hidden className="mono">{k.icon}</span> {k.label}</b>
                  <span className="small muted">{k.example}</span>
                </button>
              ))}
            </div>
          </>
        )}
        {step === 1 && (
          <>
            <h2>{tr("Define it:")} {kindLabel(d.kind)}</h2>
            <label className="field"><span>{tr("Name")}</span><input value={d.name} onChange={(e) => set({ name: e.target.value, ...(slugEdited || published ? {} : { slug: slugify(e.target.value) }) })} placeholder={tr("Loan ID")} /></label>
            <label className="field"><span>{tr("Slug")}{published ? tr(", fixed after the first publish") : ""}</span><input className="mono" disabled={published} value={d.slug} onChange={(e) => { setSlugEdited(true); set({ slug: e.target.value }); }} /></label>

            {d.kind === "keyword_list" && (
              <>
                <Chips label={tr("Words or phrases")} value={d.definition.terms ?? []} onChange={(terms) => defn({ terms })} />
                <label className="row small"><input type="checkbox" checked={Boolean(d.definition.case_sensitive)} onChange={(e) => defn({ case_sensitive: e.target.checked })} />{tr("Case sensitive")}</label>
                <label className="row small"><input type="checkbox" checked={d.definition.whole_word ?? true} onChange={(e) => defn({ whole_word: e.target.checked })} />{tr("Whole words only")}</label>
              </>
            )}
            {d.kind === "pattern" && (
              <>
                <label className="field"><span>{tr("Pattern")}</span><input className="mono" value={d.definition.regex ?? ""} onChange={(e) => defn({ regex: e.target.value })} placeholder={tr("LN-\\d{8}")} aria-invalid={Boolean(defError)} /></label>
                {defError ? <div className="err small">{defError}</div> : <p className="small muted">{explainRegex(d.definition.regex ?? "")}</p>}
                <details>
                  <summary className="small">{tr("Build from examples")}</summary>
                  <div className="stack" style={{ marginTop: 6 }}>
                    <label className="field"><span>{tr("Three or more examples, one per line. Use synthetic ones.")}</span><textarea className="code" value={examples} onChange={(e) => setExamples(e.target.value)} /></label>
                    <div className="row"><button onClick={async () => {
                      setError(null);
                      try { setSuggestion(await control("/v1/custom-entities/suggest-pattern", { body: { examples: examples.split("\n").map((s) => s.trim()).filter(Boolean) } })); }
                      catch (e) { setSuggestion(null); setError(e instanceof Error ? e.message : "failed"); }
                    }}>{tr("Propose a pattern")}</button></div>
                    {suggestion && <div className="note small"><code>{suggestion.regex}</code><br />{suggestion.explanation} <button className="link small" onClick={() => defn({ regex: suggestion.regex })}>{tr("Use this")}</button></div>}
                  </div>
                </details>
                <ValidatorFields value={d.validator} onChange={(validator) => set({ validator })} />
                {!d.validator && <div className="note small">{tr("Without a validator a pattern scores 0.6, below the default threshold of 0.7, so it matches only with a positive context word nearby or a lower threshold.")}</div>}
              </>
            )}
            {d.kind === "after_keyword" && (
              <>
                <Chips label={tr("Cue words")} value={d.definition.cues ?? []} onChange={(cues) => defn({ cues })} placeholder={tr("PIN, OTP, password")} />
                <label className="field"><span>{tr("Maximum length:")} {d.definition.max_length ?? 64} characters</span><input type="range" min={1} max={512} value={d.definition.max_length ?? 64} onChange={(e) => defn({ max_length: Number(e.target.value) })} /></label>
                <label className="field"><span>{tr("Stop characters. Empty means whitespace, comma, semicolon, ampersand and quotes.")}</span><input className="mono" value={d.definition.stop_chars ?? ""} onChange={(e) => defn({ stop_chars: e.target.value })} /></label>
              </>
            )}
            {d.kind === "value_list" && (d.name && d.slug ? <ValueUpload ensureSaved={ensureSaved} vault={vault} /> : <p className="small muted">{tr("Name this entity to upload its list.")}</p>)}
            {d.kind === "json_path" && (
              <>
                <label className="field"><span>{tr("Paste a sample payload, then click the fields to protect. Use synthetic data.")}</span><textarea className="code" value={payload} onChange={(e) => setPayload(e.target.value)} /></label>
                {(() => { try { return <div className="pre"><JsonTree value={JSON.parse(payload)} path="$" picked={d.definition.paths ?? []} onPick={(p) => { const cur = d.definition.paths ?? []; defn({ paths: cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p] }); }} /></div>; } catch { return <div className="err small">{tr("This is not valid JSON yet.")}</div>; } })()}
                <Chips label={tr("Paths. $..name matches at any depth.")} value={d.definition.paths ?? []} onChange={(paths) => defn({ paths })} placeholder={tr("$..staffId")} />
              </>
            )}
            {d.kind !== "pattern" && defError && <div className="err small">{defError}</div>}
          </>
        )}
        {step === 2 && (
          <>
            <h2>{tr("Add context")}</h2>
            {certain ? <p className="muted small">A {kindLabel(d.kind).toLowerCase()} {tr("match is always certain, so it uses no context and its threshold is fixed at 1.0.")}</p> : (
              <>
                <Chips label={tr("Words that raise confidence when nearby")} value={d.context_positive} onChange={(context_positive) => set({ context_positive })} placeholder={tr("loan, repayment")} />
                <Chips label={tr("Words that lower confidence")} value={d.context_negative} onChange={(context_negative) => set({ context_negative })} placeholder="invoice" />
                <label className="field"><span>{tr("Threshold:")} {d.threshold.toFixed(2)}</span><input type="range" min={0} max={1} step={0.05} value={d.threshold} onChange={(e) => set({ threshold: Number(e.target.value) })} /></label>
                <label className="field"><span>{tr("Try it on some text")}</span><textarea className="code" value={bench} onChange={(e) => setBench(e.target.value)} /></label>
                <Highlighted text={bench} matches={matches.filter((m) => m.custom)} />
                <p className="small muted">{matches.filter((m) => m.custom).length} match{matches.filter((m) => m.custom).length === 1 ? "" : "es"} {tr("above the line.")}</p>
              </>
            )}
          </>
        )}
        {step === 3 && (
          <>
            <h2>{tr("Token and mask")}</h2>
            <label className="field"><span>{tr("When the same value comes in again")}</span><select value={d.token_kind} disabled={published} onChange={(e) => set({ token_kind: e.target.value })}><option value="deterministic">{tr("Give it the same token, so records can be matched up")}</option><option value="cell">{tr("Give it a new token each time")}</option><option value="transient">{tr("Give it a token that expires after 30 days")}</option></select></label>
            {d.token_kind !== "deterministic" && <div className="note warn small">{tr("Logs need the same token each time to stay searchable, so with this choice they mask the value instead.")}</div>}
            <label className="field"><span>{tr("What the token looks like")}</span><select value={d.token_format} disabled={published} onChange={(e) => set({ token_format: e.target.value })}><option value="opaque">{tr("Clearly a token (tok_…)")}</option><option value="format_preserving">{tr("Looks like the real value")}</option></select></label>
            {d.token_format === "format_preserving" && <div className="note warn small">{tr("A token like this looks like a real value, so other systems can mistake it for one. Values too short to vary safely get a tok_… token instead.")}</div>}
            {published && <p className="small muted">{tr("Token settings cannot change after the first publish, because stored values depend on them.")}</p>}
            <label className="field"><span>{tr("Mask rule")}</span>
              <select value={d.mask_rule.type} onChange={(e) => set({ mask_rule: e.target.value === "fixed" ? { type: "fixed", text: "[hidden]" } : e.target.value === "full" ? { type: "full" } : { type: e.target.value, n: 4 } })}>
                <option value="last_n">{tr("Show the last few characters")}</option><option value="first_n">{tr("Show the first few characters")}</option><option value="fixed">{tr("Fixed text")}</option><option value="full">{tr("Full mask")}</option>
              </select>
            </label>
            {(d.mask_rule.type === "last_n" || d.mask_rule.type === "first_n") && <label className="field"><span>{tr("How many characters")}</span><input type="number" min={0} max={32} value={d.mask_rule.n ?? 4} onChange={(e) => set({ mask_rule: { ...d.mask_rule, n: Number(e.target.value) } })} /></label>}
            {d.mask_rule.type === "fixed" && <label className="field"><span>{tr("Text")}</span><input value={d.mask_rule.text ?? ""} onChange={(e) => set({ mask_rule: { ...d.mask_rule, text: e.target.value } })} /></label>}
            <div className="card">
              <div className="small"><span className="muted">{tr("Value")}</span> <code>{previewValue}</code></div>
              <div className="small"><span className="muted">{tr("Token")}</span> <code>{d.token_format === "format_preserving" ? tr("same shape, random contents") : token}</code></div>
              <div className="small"><span className="muted">{tr("Masked")}</span> <code>{maskPreview(d.mask_rule, previewValue)}</code></div>
            </div>
            <h3>{tr("What each module does")}</h3>
            <div className="cards">
              {MODULES.map(([k, l]) => (
                <label className="field" key={k}><span>{l}</span><select value={d.actions[k] ?? "tokenize"} onChange={(e) => set({ actions: { ...d.actions, [k]: e.target.value } })}>{ACTIONS.map(([v, t]) => <option key={v} value={v}>{t}</option>)}</select></label>
              ))}
            </div>
          </>
        )}
        {step === 4 && (
          <>
            <h2>{tr("Test bench")}</h2>
            <div className="split" style={{ alignItems: "start" }}>
              <div className="stack">
                <label className="field"><span>{tr("Paste any text: a log line, a ticket, a prompt or JSON. Use synthetic data. Nothing is stored.")}</span><textarea className="code" rows={6} value={bench} onChange={(e) => setBench(e.target.value)} /></label>
                <Highlighted text={bench} matches={matches} />
                <div className="row small"><Badge tone="good">{tr("Solid outline: this data type")}</Badge><Badge tone="warn">{tr("Dashed: built-in")}</Badge><span className="muted">{tr("Hover for the score.")}</span></div>
              </div>
              <div className="stack">
                <h3>{tr("Samples")}</h3>
                <label className="field"><span>{tr("Add a sample. Stored encrypted.")}</span><input value={newSample} onChange={(e) => setNewSample(e.target.value)} /></label>
                <div className="row">
                  {[[true, tr("Must match")], [false, tr("Must not match")]].map(([expect, label]) => (
                    <button key={String(label)} disabled={!newSample} onClick={async () => {
                      try { await control(`/v1/vaults/${vault}/custom-entities/${id}/tests`, { body: { samples: [{ sample: newSample, expect_match: expect }] } }); setNewSample(""); await runSamples(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
                    }}>{label as string}</button>
                  ))}
                </div>
                {samples.map((s) => (
                  <div className="spread small" key={s.id}>
                    <span><Badge tone={s.passed ? "good" : "bad"}>{s.passed ? tr("pass") : tr("fail")}</Badge> <span className="muted">{s.expect_match ? tr("must match") : tr("must not match")}</span> <code>{s.sample.slice(0, 44)}</code></span>
                    <button className="link small" onClick={async () => { await control(`/v1/vaults/${vault}/custom-entities/${id}/tests/${s.id}`, { method: "DELETE" }); await runSamples(); }}>{tr("Remove")}</button>
                  </div>
                ))}
                <p className="small muted">{mustMatch} {tr("must match and")} {mustNot} {tr("must not match. Publishing needs at least 3 of each, all passing.")}</p>
              </div>
            </div>
            {estimate && <p className="small muted">{tr("Estimated cost:")} {estimate.ms_per_kb.toFixed(4)} {tr("ms per KB (limit")} {d.kind === "value_list" ? "1" : "0.3"}{tr("), matching")} {(estimate.matched_share * 100).toFixed(1)}{tr("% of sample lines (limit 5%). From a small sample; the publish check uses 50 MB.")}</p>}
          </>
        )}
        {step === 5 && (
          <>
            <h2>{tr("Review and request publish")}</h2>
            <div className="card">
              <b>{d.name}</b> <code className="small">{d.slug}</code>
              <p>{describe(d.kind, d.definition, d.context_positive)}.</p>
              <p className="small muted">{tr("Threshold")} {certain ? "1.00" : d.threshold.toFixed(2)}. {d.token_kind} {d.token_format} {tr("tokens. Masked as")} <code>{maskPreview(d.mask_rule, previewValue)}</code>.</p>
              <div className="row small">{MODULES.map(([k, l]) => <Badge key={k}>{l}: {d.actions[k] ?? "tokenize"}</Badge>)}</div>
            </div>
            {!ready && !requested && <div className="note warn small">{tr("Samples are not ready:")} {mustMatch} {tr("must match,")} {mustNot} {tr("must not match")}{samples.some((s) => !s.passed) ? tr(", and some are failing") : ""}{tr(". Go back to the test bench.")}</div>}
            {requested ? (
              <div className="note good small">
                {tr("Request filed for version")} {requested.version}{tr(". Benchmark:")} {requested.benchmark.ms_per_kb.toFixed(4)} {tr("ms per KB,")} {(requested.benchmark.matched_share * 100).toFixed(2)}{tr("% of lines.")}
                {approvers.length > 0 ? tr(" {0} can approve it.", { 0: approvers.map((p) => p.display_name).join(" or ") }) : tr(" Nobody else can approve it yet: add a second admin or detection approver.")}
                <div className="row" style={{ marginTop: 8 }}><button onClick={() => router.push(`/detection/${vault}/${id}`)}>{tr("Open this entity")}</button></div>
              </div>
            ) : (
              <>
                <p className="small muted">{approvers.length > 0 ? tr("{0} can approve this.", { 0: approvers.map((p) => p.display_name).join(" or ") }) : tr("Nobody else can approve this yet: add a second admin or detection approver.")} {published ? tr("An edit keeps the entity's current status once approved.") : tr("After approval it starts as watch only: matches are counted and nothing changes in traffic.")}</p>
                <div className="row"><button className="primary" disabled={busy || !ready} onClick={async () => {
                  setBusy(true); setError(null);
                  try { setRequested(await control(`/v1/vaults/${vault}/custom-entities/${id}/publish-requests`, { body: {} })); }
                  catch (e) { setError(e instanceof ApiErr ? `${e.code}: ${e.message}` : "failed"); } finally { setBusy(false); }
                }}>{busy ? tr("Testing and benchmarking…") : tr("Request approval")}</button></div>
              </>
            )}
          </>
        )}
        <ErrorLine error={error} />
      </div>
      <div className="row" style={{ justifyContent: "space-between", marginTop: 12 }}>
        <button disabled={step === 0} onClick={() => setStep(step - 1)}>{tr("Back")}</button>
        {step > 0 && step < 5 && <button className="primary" disabled={!d.name || !/^c_[a-z0-9_]{2,40}$/.test(d.slug) || Boolean(defError)} onClick={next}>{tr("Continue")}</button>}
      </div>
    </Page>
  );
}

export default function NewEntity() {
  return <Suspense fallback={null}><Builder /></Suspense>;
}
