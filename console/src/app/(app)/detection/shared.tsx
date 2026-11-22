"use client";
import { tr } from "@/lib/i18n";
import { useState } from "react";
import { Badge, ErrorLine } from "@/components/ui";
import { control } from "@/lib/api";
import { modeLabel } from "@/lib/labels";

export const KINDS: { kind: string; label: string; icon: string; example: string }[] = [
  { kind: "keyword_list", label: "Keyword list", icon: "≡", example: "Exact words or phrases, such as \"Project Ember\"" },
  { kind: "pattern", label: "Pattern", icon: "#", example: "IDs with a known shape, such as LN- then 8 digits" },
  { kind: "after_keyword", label: "After a keyword", icon: "→", example: "Whatever follows a cue, such as text after \"PIN:\"" },
  { kind: "value_list", label: "Value list", icon: "▤", example: "A fixed set of known values, such as VIP customer names" },
  { kind: "json_path", label: "JSON path", icon: "{}", example: "Fields in payloads that are always sensitive" },
];
export const kindLabel = (k: string) => KINDS.find((x) => x.kind === k)?.label ?? k;
export const kindIcon = (k: string) => KINDS.find((x) => x.kind === k)?.icon ?? "";
export const MODULES: [string, string][] = [["api", "API"], ["logs", "Logs"], ["ai", "AI"], ["proxy", "Proxy"]];
export const ACTIONS: [string, string][] = [["tokenize", "Tokenize"], ["mask", "Mask"], ["drop", "Drop"], ["pass", "Pass and count"]];

export interface Definition { terms?: string[]; case_sensitive?: boolean; whole_word?: boolean; regex?: string; cues?: string[]; max_length?: number; stop_chars?: string; paths?: string[] }
export interface Validator { type: string; value?: number; values?: string[]; weights?: number[]; modulus?: number; check_position?: number }
export interface MaskRule { type: string; n?: number; text?: string }

export function StatusBadge({ status, pending }: { status: string; pending?: boolean }) {
  const tone = status === "enforcing" ? "good" : status === "shadow" ? "info" : status === "archived" ? "" : "warn";
  return <span className="row" style={{ gap: 4 }}><Badge tone={tone}>{modeLabel(status)}</Badge>{pending && <Badge tone="warn">{tr("Pending approval")}</Badge>}</span>;
}

/** Bars, not a line: a day with no hits is zero, and should look like it. */
export function Spark({ values, light }: { values: number[]; light?: boolean }) {
  const max = Math.max(1, ...values);
  return (
    <svg width={56} height={18} role="img" aria-label={tr("Hits by day, last 7 days: {0}", { 0: values.join(", ") })} style={{ verticalAlign: "middle" }}>
      {values.map((v, i) => {
        const h = v === 0 ? 1 : Math.max(2, (v / max) * 18);
        return <rect key={i} x={i * 8} y={18 - h} width={6} height={h} rx={1} fill="var(--primary)" opacity={light ? 0.45 : 1} />;
      })}
    </svg>
  );
}

/** A definition in plain words, for the overview and the review step. */
export function describe(kind: string, d: Definition, contextPositive: string[] = []): string {
  const near = contextPositive.length ? tr(", near {0}", { 0: contextPositive.map((w) => `"${w}"`).join(" or ") }) : "";
  switch (kind) {
    case "keyword_list": return tr("Matches {0} word{1} or phrase{2}{3}{4}{5}", { 0: (d.terms ?? []).length, 1: (d.terms ?? []).length === 1 ? "" : "s", 2: (d.terms ?? []).length === 1 ? "" : "s", 3: d.terms?.length ? tr(", such as \"{0}\"", { 0: d.terms[0] }) : "", 4: d.case_sensitive ? tr(", exact case") : "", 5: near });
    case "pattern": return `${explainRegex(d.regex ?? "")}${near}`;
    case "after_keyword": return tr("Matches up to {0} characters after {1}{2}", { 0: d.max_length ?? 64, 1: (d.cues ?? []).map((c) => `"${c}"`).join(tr(" or ")), 2: near });
    case "value_list": return "Matches members of an uploaded list, compared by secure fingerprint";
    case "json_path": return tr("Matches the fields {0} in structured payloads", { 0: (d.paths ?? []).join(", ") });
  }
  return "";
}

/** Reads the common parts of a pattern. Anything else is admitted rather than guessed at. */
export function explainRegex(re: string): string {
  if (!re) return "No pattern yet";
  const parts: string[] = [];
  let i = 0;
  const count = (rest: string): [string, number] => {
    const m = rest.match(/^\{(\d+)(?:,(\d+))?\}/);
    if (m) return [m[2] ? `${m[1]} to ${m[2]}` : m[1]!, m[0].length];
    if (rest[0] === "+") return ["one or more", 1];
    if (rest[0] === "*") return ["any number of", 1];
    if (rest[0] === "?") return ["an optional", 1];
    return ["1", 0];
  };
  while (i < re.length) {
    const rest = re.slice(i);
    const cls = rest.match(/^(\\d|\\w|\[A-Z\]|\[a-z\]|\[0-9\]|\[0-9A-Z\]|\[A-Z0-9\])/);
    if (cls) {
      const names: Record<string, string> = { "\\d": "digits", "\\w": "word characters", "[A-Z]": "capital letters", "[a-z]": "small letters", "[0-9]": "digits", "[0-9A-Z]": "capitals or digits", "[A-Z0-9]": "capitals or digits" };
      const [c, len] = count(rest.slice(cls[0].length));
      parts.push(`${c} ${names[cls[0]]}`);
      i += cls[0].length + len;
      continue;
    }
    if (rest.startsWith("\\b")) { i += 2; continue; }
    const lit = rest.match(/^(?:\\[-.\/]|[A-Za-z0-9_ :-])+/);
    if (!lit) return tr("Custom pattern: {0}", { 0: re });
    parts.push(`"${lit[0].replace(/\\/g, "")}"`);
    i += lit[0].length;
  }
  return tr("Matches {0}", { 0: parts.join(", then ") });
}

export function maskPreview(rule: MaskRule, value: string): string {
  const r = [...value];
  if (rule.type === "full") return "********";
  if (rule.type === "fixed") return rule.text ?? "";
  const n = rule.n ?? 4;
  if (n >= r.length) return "*".repeat(r.length);
  if (rule.type === "first_n") return r.slice(0, n).join("") + "*".repeat(r.length - n);
  return "*".repeat(r.length - n) + r.slice(r.length - n).join("");
}

/** A chip input. Pasting a list splits it. */
export function Chips({ label, value, onChange, placeholder }: { label: string; value: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const add = (raw: string) => {
    const parts = raw.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    if (parts.length) onChange([...new Set([...value, ...parts])]);
  };
  return (
    <label className="field">
      <span>{label}</span>
      <input
        aria-label={label}
        placeholder={placeholder ?? tr("Type and press Enter, or paste a list")}
        onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(e.currentTarget.value); e.currentTarget.value = ""; } }}
        onPaste={(e) => { const t = e.clipboardData.getData("text"); if (/[\n,]/.test(t)) { e.preventDefault(); add(t); } }}
        onBlur={(e) => { add(e.currentTarget.value); e.currentTarget.value = ""; }}
      />
      {value.length > 0 && (
        <div className="row" style={{ flexWrap: "wrap", gap: 4 }}>
          {value.map((v) => <button type="button" key={v} className="small" title={tr("Remove")} onClick={(e) => { e.preventDefault(); onChange(value.filter((x) => x !== v)); }}>{v} ✕</button>)}
        </div>
      )}
    </label>
  );
}

/** Highlights matches in text. Built-in matches stay visible, so overlaps can be seen. */
export function Highlighted({ text, matches }: { text: string; matches: { type: string; start: number; end: number; score: number; custom: boolean }[] }) {
  const sorted = [...matches].sort((a, b) => a.start - b.start);
  const out: React.ReactNode[] = [];
  const bytes = new TextEncoder().encode(text);
  const dec = new TextDecoder();
  let pos = 0;
  sorted.forEach((m, i) => {
    if (m.start < pos) return;
    out.push(<span key={`t${i}`}>{dec.decode(bytes.slice(pos, m.start))}</span>);
    out.push(<mark key={`m${i}`} title={tr("{0}, score {1}", { 0: m.type, 1: m.score.toFixed(2) })} style={{ background: m.custom ? "var(--accent)" : "var(--warn-soft)", color: "inherit", borderRadius: 3, padding: "0 2px", outline: m.custom ? "1px solid var(--primary)" : "1px dashed var(--warn)" }}>{dec.decode(bytes.slice(m.start, m.end))}</mark>);
    pos = m.end;
  });
  out.push(<span key="end">{dec.decode(bytes.slice(pos))}</span>);
  return <div className="pre" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{out}</div>;
}

export function ApproveButton({ id, onDone }: { id: string; onDone: () => void }) {
  const [error, setError] = useState<string | null>(null);
  return (
    <>
      <button className="small" onClick={async () => { try { await control(`/v1/publish-requests/${id}/approve`, { method: "POST" }); onDone(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); } }}>{tr("Approve")}</button>
      <ErrorLine error={error} />
    </>
  );
}


// Date layouts are codes the engine reads, not text to translate.
const LAYOUTS = ["YYMMDD", "YYYYMMDD", "DDMMYY", "DDMMYYYY", "MMDDYY"];
const nums = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean).map(Number).filter((x) => !Number.isNaN(x));

/** The check a pattern's match must pass, from a fixed menu. Customers never supply code. */
export function ValidatorFields({ value, onChange }: { value: Validator | null | undefined; onChange: (v: Validator | null) => void }) {
  const v = value ?? null;
  const set = (patch: Partial<Validator>) => onChange({ ...(v ?? { type: "length" }), ...patch } as Validator);
  return (
    <>
      <label className="field"><span>{tr("Validator")}</span>
        <select value={v?.type ?? ""} onChange={(e) => onChange(e.target.value ? { type: e.target.value } : null)}>
          <option value="">{tr("None")}</option>
          <option value="length">{tr("Exact length")}</option>
          <option value="prefix_list">{tr("Prefix list")}</option>
          <option value="luhn">{tr("Luhn")}</option>
          <option value="mod11">{tr("Mod 11")}</option>
          <option value="mod11_weighted">{tr("Mod 11 with your weights (X stands for 10)")}</option>
          <option value="custom_checksum">{tr("Custom checksum")}</option>
          <option value="mod97">{tr("Mod 97, as IBANs use")}</option>
          <option value="letter_check">{tr("Check letter")}</option>
          <option value="date_embedded">{tr("A real date inside the number")}</option>
        </select>
      </label>
      {v?.type === "length" && <label className="field"><span>{tr("Length")}</span><input type="number" min={1} value={v.value ?? ""} onChange={(e) => set({ value: Number(e.target.value) })} /></label>}
      {v?.type === "prefix_list" && <Chips label={tr("Prefixes")} value={v.values ?? []} onChange={(values) => set({ values })} />}
      {(v?.type === "custom_checksum" || v?.type === "mod11_weighted" || v?.type === "letter_check") && (
        <label className="field"><span>{tr("Weights, comma-separated")}</span><input className="mono" defaultValue={(v.weights ?? []).join(",")} onBlur={(e) => set({ weights: nums(e.target.value) })} placeholder="2,7,6,5,4,3,2" /></label>
      )}
      {v?.type === "custom_checksum" && <label className="field"><span>{tr("Modulus")}</span><input type="number" value={v.modulus ?? ""} onChange={(e) => set({ modulus: Number(e.target.value) })} /></label>}
      {(v?.type === "custom_checksum" || v?.type === "mod11_weighted" || v?.type === "letter_check") && (
        <label className="field"><span>{v.type === "letter_check" ? tr("Position of the check letter, from 1; 0 or -1 is the last") : tr("Check digit position, from 1; -1 is the last")}</span><input type="number" value={v.check_position ?? -1} onChange={(e) => set({ check_position: Number(e.target.value) })} /></label>
      )}
      {v?.type === "mod11_weighted" && (
        <label className="field"><span>{tr("The check is")}</span>
          <select value={v.value ?? 0} onChange={(e) => set({ value: Number(e.target.value) })}><option value={0}>{tr("11 minus the remainder (most schemes)")}</option><option value={1}>{tr("The remainder itself")}</option></select>
        </label>
      )}
      {v?.type === "mod97" && <label className="field"><span>{tr("Characters to move from the start to the end first (4 for an IBAN)")}</span><input type="number" min={0} max={10} value={v.value ?? 0} onChange={(e) => set({ value: Number(e.target.value) })} /></label>}
      {v?.type === "letter_check" && (
        <>
          <label className="field"><span>{tr("Check letters, in order (the remainder picks one)")}</span><input className="mono" value={v.values?.[0] ?? ""} onChange={(e) => set({ values: [e.target.value.toUpperCase().replace(/[^A-Z]/g, "")] })} placeholder={tr("TRWAGMYFPDXBNJZSQVHLCKE")} /></label>
          <label className="field"><span>{tr("Number added before dividing (often 0)")}</span><input type="number" value={v.value ?? 0} onChange={(e) => set({ value: Number(e.target.value) })} /></label>
        </>
      )}
      {v?.type === "date_embedded" && (
        <>
          <label className="field"><span>{tr("Date layout")}</span>
            <select value={v.values?.[0] ?? "YYMMDD"} onChange={(e) => set({ values: [e.target.value] })}>{LAYOUTS.map((l) => <option key={l} value={l}>{l}</option>)}</select>
          </label>
          <label className="field"><span>{tr("Where the date starts, counting digits only, from 1")}</span><input type="number" min={1} value={v.value || 1} onChange={(e) => set({ value: Number(e.target.value), values: v.values ?? ["YYMMDD"] })} /></label>
        </>
      )}
    </>
  );
}
