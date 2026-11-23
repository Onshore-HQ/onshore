"use client";
import { tr } from "@/lib/i18n";
import { BrainCircuit } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge, ErrorLine, Loading } from "@/components/ui";
import { control, useLoad } from "@/lib/api";

const WHERE: [string, string, string][] = [
  ["ai", "AI gateway", "Prompts to AI models. Usually worth it: prompts are free text, and the model's time is small next to the AI's."],
  ["api", "Files, support tickets and the detect API", "Documents, scans, recordings and tickets, where names sit in prose."],
  ["proxy", "HTTP proxy", "Calls to outside vendors. Adds time to each call."],
  ["logs", "Log pipelines", "Every log line. Only for low volumes: a model reads a few hundred lines a second, the patterns thousands."],
];

/** Language-model detection: spaCy, transformers or Stanza on top of the patterns. */
export function LanguageModels({ vault, canManage }: { vault: string; canManage: boolean }) {
  const cur = useLoad<{ modules: string[]; allowed: boolean }>(() => control(`/v1/vaults/${vault}/detection-models`), [vault]);
  const [on, setOn] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => { if (cur.value) setOn(cur.value.modules); }, [cur.value]);
  if (cur.loading || cur.error) return <Loading loading={cur.loading} error={cur.error} />;
  const changed = [...on].sort().join() !== [...cur.value!.modules].sort().join();
  const save = async () => {
    setErr(null); setSaved(false);
    try { await control(`/v1/vaults/${vault}/detection-models`, { method: "PUT", body: { modules: on } }); setSaved(true); cur.reload(); }
    catch (e) { setErr(e instanceof Error ? e.message : "failed"); }
  };
  return (
    <div className="stack">
      <div className="card">
        <div className="spread">
          <div>
            <h2 className="m-0 flex items-center gap-2"><BrainCircuit size={18} aria-hidden /> {tr("Language models")} <Badge>{tr("Business")}</Badge></h2>
            <p className="small muted m-0">{tr("Patterns, checksums and name lists find most identifiers. A language model also reads the sentence, so it finds names and places they miss: unusual names, nicknames, a street mentioned in passing. It runs inside this install with spaCy, Hugging Face transformers or Stanza; text never leaves it.")}</p>
          </div>
        </div>
        {!cur.value!.allowed && <div className="note small">{tr("Language-model detection needs Onshore Business. It's free on sandbox vaults, to try it.")}</div>}
      </div>
      <div className="card">
        <h3 className="m-0">{tr("Use it for")}</h3>
        {WHERE.map(([k, name, why]) => (
          <label key={k} className="row" style={{ alignItems: "flex-start", gap: 10, padding: "8px 0" }}>
            <input type="checkbox" checked={on.includes(k)} disabled={!canManage || (!cur.value!.allowed && !on.includes(k))} onChange={(e) => setOn(e.target.checked ? [...on, k] : on.filter((x) => x !== k))} />
            <span><b>{tr(name)}</b><br /><span className="small muted">{tr(why)}</span></span>
          </label>
        ))}
        <p className="small muted">{tr("The model service has to be running: start it with --profile nlp and set RV_NLP_URL=https://nlp:8095 in .env. If it can't be reached, detection carries on with the patterns alone.")}</p>
        <ErrorLine error={err} />
        {canManage && <div className="row" style={{ justifyContent: "flex-end", gap: 10 }}>{saved && !changed && <span className="small">{tr("Saved. Services pick it up within a few seconds.")}</span>}<button className="primary" disabled={!changed} onClick={save}>{tr("Save")}</button></div>}
        {!canManage && <p className="small">{tr("An admin can change this.")}</p>}
      </div>
    </div>
  );
}
