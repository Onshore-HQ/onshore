"use client";
import { tr } from "@/lib/i18n";
import { ArrowLeft, Check, FileUp } from "lucide-react";
import Link from "next/link";
import { useRef, useState } from "react";
import { Badge, Empty, ErrorLine, Loading, Page } from "@/components/ui";
import { Progress } from "@/components/ui/progress";
import { control, data, n, useLoad, when } from "@/lib/api";
import { csvLine, csvRows, saveFile } from "@/lib/csv";
import { entityLabel } from "@/lib/labels";

interface Field { id: string; name: string; data_type: string; token_kind: string }
interface Vault { id: string; name: string; environment: string; vault_fields: Field[] }
interface Problem { row: number; column: string; code: string }
interface Tally { rows: number; failed: number; created: number; existing: number; problems: Problem[]; byCode: Record<string, number> }
const BATCH = 450;
const LARGE = 100 * 1024 * 1024;
const REASONS: Record<string, string> = { validation_failed: "Not a valid value for this field", policy_denied: "An access rule doesn't let you store this" };
const reason = (c: string) => REASONS[c] ?? c;
const blank = (): Tally => ({ rows: 0, failed: 0, created: 0, existing: 0, problems: [], byCode: {} });

/** Suggests a field from a column's name. Only a suggestion: the person confirms it. */
function suggest(column: string, fields: Field[]): string {
  const c = column.toLowerCase().replace(/[^a-z0-9]/g, "");
  const hit = (...w: string[]) => w.some((x) => c.includes(x));
  const type = hit("bvn") ? "bvn" : hit("vnin") ? "vnin" : hit("nin") ? "nin" : hit("account", "nuban") ? "nuban" : hit("phone", "mobile", "msisdn") ? "phone_ng" : hit("email") ? "email" : hit("fullname", "customername", "name") ? "person_name" : hit("amount", "balance") ? "amount_ngn" : hit("dob", "birth") ? "date_of_birth" : "";
  return fields.find((f) => f.name.toLowerCase().replace(/[^a-z0-9]/g, "") === c)?.name ?? fields.find((f) => f.data_type === type)?.name ?? "";
}
const looksLikeRef = (c: string) => /(^|_|\b)(customer|cust|client|user|member)?_?(id|ref|reference|no|number)$/i.test(c) && !/bvn|nin|account|phone/i.test(c);
const hide = (v: string) => (v.length <= 2 ? "•".repeat(v.length) : "•".repeat(Math.min(v.length - 2, 10)) + v.slice(-2));

export default function ImportData() {
  const vaults = useLoad<{ vaults: Vault[] }>(() => control("/v1/vaults"));
  const [vaultId, setVaultId] = useState("");
  const list = vaults.value?.vaults ?? [];
  const vault = list.find((v) => v.id === vaultId) ?? list[0];
  const history = useLoad<{ imports: any[] }>(() => (vault ? control(`/v1/vaults/${vault.id}/imports`) : Promise.resolve({ imports: [] })), [vault?.id]);
  const [file, setFile] = useState<File | null>(null);
  const [header, setHeader] = useState<string[]>([]);
  const [sample, setSample] = useState<string[][]>([]);
  const [mapping, setMapping] = useState<Record<string, string>>({});
  const [ref, setRef] = useState("");
  const [stage, setStage] = useState<"pick" | "map" | "checking" | "checked" | "running" | "paused" | "done" | "stopped">("pick");
  const [tally, setTally] = useState<Tally>(blank());
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const control$ = useRef<{ pause: boolean; stop: boolean; resume?: () => void }>({ pause: false, stop: false });
  const output = useRef<string[]>([]);

  const reset = () => { setFile(null); setHeader([]); setSample([]); setMapping({}); setRef(""); setStage("pick"); setTally(blank()); setTotal(0); setError(null); output.current = []; history.reload(); };

  const open = async (f: File) => {
    setError(null);
    const rows: string[][] = [];
    try { for await (const r of csvRows(f)) { rows.push(r); if (rows.length > 6) break; } } catch { setError("That file can't be read as text. Save it as CSV and try again."); return; }
    if (rows.length < 2) { setError("That file needs a header line and at least one row."); return; }
    const head = rows[0]!;
    if (new Set(head).size !== head.length || head.some((h) => !h.trim())) { setError("Every column needs its own name in the first line. Fix the file and try again."); return; }
    setFile(f); setHeader(head); setSample(rows.slice(1, 4));
    setMapping(Object.fromEntries(head.map((h) => [h, suggest(h, vault?.vault_fields ?? [])])));
    setRef(head.find((h) => looksLikeRef(h) && !suggest(h, vault?.vault_fields ?? [])) ?? "");
    setStage("map");
  };

  const mapped = Object.entries(mapping).filter(([, f]) => f);
  const unsafeFields = mapped.filter(([, f]) => vault?.vault_fields.find((x) => x.name === f)?.token_kind !== "deterministic");

  /** One pass over the file. A check stores nothing; a real run keeps the output for download. */
  const pass = async (dry: boolean, jobId?: string) => {
    const pos = new Map(header.map((h, i) => [h, i]));
    const t = blank();
    let buf: { rec: string[]; rowNo: number }[] = [];
    let items: { field: string; value: string; subject_ref?: string }[] = [];
    let slots: { rowNo: number; column: string; rec: string[]; at: number }[] = [];
    const out = output.current;
    const flush = async () => {
      if (!buf.length) return;
      const bad = new Set<number>();
      if (items.length) {
        const r = await data<{ results: { index: number; token?: string; existing?: boolean; error?: { code: string } }[] }>(`/v1/vaults/${vault!.id}/tokenize`, { body: { items, continue_on_error: true, dry_run: dry } });
        for (const x of r.results) {
          const s = slots[x.index]!;
          if (x.error) {
            bad.add(s.rowNo); s.rec[s.at] = "";
            t.problems.push({ row: s.rowNo, column: s.column, code: x.error.code });
            t.byCode[x.error.code] = (t.byCode[x.error.code] ?? 0) + 1;
          } else if (!dry) {
            s.rec[s.at] = x.token!;
            if (x.existing) t.existing++; else t.created++;
          }
        }
      }
      for (const b of buf) { t.rows++; if (bad.has(b.rowNo)) t.failed++; if (!dry) out.push(csvLine(b.rec)); }
      buf = []; items = []; slots = [];
      setTally({ ...t, problems: t.problems });
      if (jobId) await control(`/v1/imports/${jobId}`, { method: "PATCH", body: { rows_done: t.rows - t.failed, rows_failed: t.failed, values_new: t.created, values_existing: t.existing } }).catch(() => undefined);
    };
    let rowNo = 0, firstLine = true;
    for await (const rec of csvRows(file!)) {
      if (firstLine) { firstLine = false; continue; }
      rowNo++;
      if (control$.current.stop) break;
      if (control$.current.pause) {
        await flush();
        if (jobId) await control(`/v1/imports/${jobId}`, { method: "PATCH", body: { status: "paused" } }).catch(() => undefined);
        setStage("paused");
        await new Promise<void>((resolve) => { control$.current.resume = resolve; });
        if (control$.current.stop) break;
        if (jobId) await control(`/v1/imports/${jobId}`, { method: "PATCH", body: { status: "running" } }).catch(() => undefined);
        setStage("running");
      }
      if (items.length + mapped.length > BATCH) await flush();
      buf.push({ rec, rowNo });
      for (const [column, field] of mapped) {
        const at = pos.get(column)!;
        const value = rec[at];
        if (!value) continue;
        const subject = ref ? rec[pos.get(ref)!] : undefined;
        items.push({ field, value, ...(subject ? { subject_ref: subject } : {}) });
        slots.push({ rowNo, column, rec, at });
      }
    }
    await flush();
    return t;
  };

  const check = async () => {
    setError(null); setStage("checking"); setTally(blank()); control$.current = { pause: false, stop: false };
    try { const t = await pass(true); setTotal(t.rows); setStage("checked"); }
    catch (e) { setError(e instanceof Error ? e.message : "failed"); setStage("map"); }
  };
  const start = async () => {
    setError(null); setStage("running"); setTally(blank()); control$.current = { pause: false, stop: false };
    output.current = [csvLine(header)];
    let job: string | undefined;
    try {
      job = (await control<{ id: string }>(`/v1/vaults/${vault!.id}/imports`, { body: { file_name: file!.name, mapping: Object.fromEntries(mapped), ref_column: ref || null } })).id;
      const t = await pass(false, job);
      const stopped = control$.current.stop;
      await control(`/v1/imports/${job}`, { method: "PATCH", body: { status: stopped ? "cancelled" : "done", rows_done: t.rows - t.failed, rows_failed: t.failed, values_new: t.created, values_existing: t.existing } });
      setStage(stopped ? "stopped" : "done");
    } catch (e) {
      setError(tr("The import stopped: {0}. What finished is still in the vault, and you can download it below. Running the same file again is safe for fields that give the same token each time.", { 0: e instanceof Error ? e.message : "failed" }));
      if (job) await control(`/v1/imports/${job}`, { method: "PATCH", body: { status: "cancelled" } }).catch(() => undefined);
      setStage("stopped");
    }
  };
  const errorsCsv = () => saveFile([csvLine(["row", "column", "problem"]), ...tally.problems.map((p) => csvLine([String(p.row), p.column, reason(p.code)]))], `${file?.name ?? "import"}.problems.csv`);
  const tokensCsv = () => saveFile(output.current, `${file?.name ?? "import"}.tokens.csv`);
  const pct = total ? Math.min(100, (tally.rows / total) * 100) : 0;

  return (
    <Page title={tr("Import existing data")} sub={tr("Load customers you already hold into a vault, and get a file of tokens to put back in your own database.")} actions={<Link className="btn" href="/records"><ArrowLeft className="size-4" />{tr("Customer records")}</Link>}>
      <div className="stack" style={{ maxWidth: 900 }}>
        <Loading error={vaults.error} loading={vaults.loading && !vaults.value} />
        {vaults.value && list.length === 0 && <Empty title={tr("No vault yet")} action={<Link className="btn primary" href="/onboarding">{tr("Open the setup guide")}</Link>}>{tr("You need a vault to import into.")}</Empty>}
        <ErrorLine error={error} />
        {vault && stage === "pick" && (
          <div className="card">
            <h2>{tr("1. Choose a vault and a CSV file")}</h2>
            <p className="small muted">{tr("Your file stays on this computer. It is read here and sent to the vault in small batches, the same way your own systems would. Access rules apply, and every value is recorded in the audit log.")}</p>
            {list.length > 1 && <label className="field" style={{ maxWidth: 320 }}><span>{tr("Vault")}</span><select value={vault.id} onChange={(e) => setVaultId(e.target.value)}>{list.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label>}
            <label className="field"><span>{tr("CSV file, with column names in the first line")}</span><input type="file" accept=".csv,text/csv" onChange={(e) => { const f = e.target.files?.[0]; if (f) open(f); }} /></label>
            <p className="small muted">{tr("For a very large file, or to run this on a schedule, use")} <code>{tr("rv import")}</code> {tr("on your server. It can stop and carry on.")}</p>
          </div>
        )}
        {vault && file && file.size > LARGE && stage === "map" && <div className="note warn">{tr("This is a large file. It may be slow in a browser, and the tab must stay open.")} <code>{tr("rv import")}</code> {tr("on your server handles this better.")}</div>}
        {vault && stage === "map" && (
          <div className="card">
            <div className="spread"><h2>{tr("2. Match your columns")}</h2><span className="small muted">{file?.name}</span></div>
            <p className="small muted">{tr("Choose which columns to protect. Anything left as “Keep as it is” isn't sent to Onshore, and stays in your output file unchanged.")}</p>
            <div className="tablewrap">
              <table>
                <thead><tr><th>{tr("Column")}</th><th>{tr("First values, partly hidden")}</th><th>{tr("Protect as")}</th></tr></thead>
                <tbody>
                  {header.map((h, i) => (
                    <tr key={h}>
                      <td><code>{h}</code></td>
                      <td className="small mono">{sample.map((r) => hide(r[i] ?? "")).join("  ")}</td>
                      <td><select aria-label={tr("Protect {0} as", { 0: h })} value={mapping[h] ?? ""} onChange={(e) => setMapping({ ...mapping, [h]: e.target.value })}><option value="">{tr("Keep as it is")}</option>{vault.vault_fields.map((f) => <option key={f.id} value={f.name}>{entityLabel(f.data_type)} ({f.name})</option>)}</select></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <label className="field" style={{ maxWidth: 360 }}><span>{tr("Which column is your customer reference?")}</span>
              <select value={ref} onChange={(e) => setRef(e.target.value)}><option value="">{tr("None")}</option>{header.filter((h) => !mapping[h]).map((h) => <option key={h} value={h}>{h}</option>)}</select>
            </label>
            <p className="small muted">{ref ? tr("Values are grouped by customer, so that you can find, export or erase one person's data.") : tr("Without one, values can't be grouped by customer, so finding or erasing one person's data won't work.")}</p>
            {unsafeFields.length > 0 && <div className="note warn small">{unsafeFields.map(([c]) => c).join(", ")}{tr(": these fields give a new token every time, so importing the same file twice would store the values twice.")}</div>}
            <div className="row"><button onClick={reset}>{tr("Back")}</button><button className="primary" disabled={!mapped.length} onClick={check}>{tr("Check the file")}</button></div>
          </div>
        )}
        {(stage === "checking" || stage === "checked") && (
          <div className="card">
            <h2>{tr("3. Check")}</h2>
            <p className="small muted">{tr("Every value is checked against its field and your access rules. Nothing is stored yet.")}</p>
            {stage === "checking" ? <p className="muted" role="status">{tr("Checked")} {n(tally.rows)} {tr("rows…")}</p> : (
              <>
                <div className="row">
                  <Badge tone="good">{n(tally.rows - tally.failed)} {tr("rows are fine")}</Badge>
                  {tally.failed > 0 && <Badge tone="bad">{n(tally.failed)} {tr("have problems")}</Badge>}
                </div>
                {Object.entries(tally.byCode).map(([c, k]) => <div key={c} className="small">{reason(c)}: {n(k)} value{k === 1 ? "" : "s"}</div>)}
                {tally.byCode.policy_denied ? <div className="note bad small">{tr("Your role can't store values in this vault yet.")} <Link href="/policies">{tr("Add an access rule")}</Link> {tr("that allows it, or run")} <code>{tr("rv import")}</code> {tr("with a service account.")}</div> : null}
                {tally.failed > 0 && !tally.byCode.policy_denied && <p className="small muted">{tr("Rows with problems still import, with the bad value left blank. Download the list to fix them.")}</p>}
                <div className="row">
                  <button onClick={() => setStage("map")}>{tr("Back")}</button>
                  {tally.failed > 0 && <button onClick={errorsCsv}>{tr("Download the problems")}</button>}
                  <button className="primary" disabled={Boolean(tally.byCode.policy_denied) || tally.failed === tally.rows} onClick={start}>{tr("Import")} {n(tally.rows - tally.failed)} rows</button>
                </div>
              </>
            )}
          </div>
        )}
        {(stage === "running" || stage === "paused") && (
          <div className="card">
            <h2>{tr("4. Importing")}</h2>
            <div className="row"><Progress value={pct} className="h-2 flex-1" aria-label={tr("Import progress")} /><span className="small muted">{n(tally.rows)} of {n(total)}</span></div>
            <p className="small muted">{stage === "paused" ? tr("Paused.") : tr("Keep this tab open.")} {n(tally.created)} {tr("new values,")} {n(tally.existing)} {tr("already held,")} {n(tally.failed)} {tr("rows with problems.")}</p>
            <div className="row">
              {stage === "running"
                ? <button onClick={() => { control$.current.pause = true; }}>{tr("Pause")}</button>
                : <button className="primary" onClick={() => { control$.current.pause = false; control$.current.resume?.(); }}>{tr("Carry on")}</button>}
              <button onClick={() => { control$.current.stop = true; control$.current.pause = false; control$.current.resume?.(); }}>{tr("Stop")}</button>
            </div>
          </div>
        )}
        {(stage === "done" || stage === "stopped") && (
          <div className="card">
            <div className="row"><span className="tile teal" aria-hidden><Check className="size-[18px]" /></span><h2>{stage === "done" ? tr("Import finished") : tr("Import stopped")}</h2></div>
            <p>{n(tally.rows - tally.failed)} {tr("rows imported:")} {n(tally.created)} {tr("new values, and")} {n(tally.existing)} {tr("already held.")} {tally.failed > 0 ? tr("{0} rows had problems.", { 0: n(tally.failed) }) : ""}</p>
            <div className="note warn small"><b>{tr("Download your tokens now.")}</b> {tr("They are only in this tab, and aren't saved anywhere else.")}</div>
            <div className="row"><button className="primary" onClick={tokensCsv}><FileUp className="size-4 rotate-180" />{tr("Download tokens")}</button>{tally.failed > 0 && <button onClick={errorsCsv}>{tr("Download the problems")}</button>}</div>
            <h3>{tr("What to do next")}</h3>
            <ol className="list-decimal pl-5 text-muted-foreground">
              <li>{tr("Replace the real values in your own database with the tokens from this file.")}</li>
              <li>{tr("Check your systems still work.")}</li>
              <li>{tr("Delete the original file, and any copies of the real values you no longer need.")}</li>
            </ol>
            <div className="row"><Link className="btn" href="/records">{tr("See the customers")}</Link><button onClick={reset}>{tr("Import another file")}</button></div>
          </div>
        )}
        {vault && stage === "pick" && (history.value?.imports.length ?? 0) > 0 && (
          <div className="card">
            <h2>{tr("Earlier imports")}</h2>
            <div className="tablewrap">
              <table>
                <thead><tr><th>{tr("File")}</th><th>{tr("Started")}</th><th>{tr("Status")}</th><th className="num">{tr("Rows")}</th><th className="num">{tr("With problems")}</th><th className="num">{tr("New values")}</th></tr></thead>
                <tbody>{history.value!.imports.map((j) => (
                  <tr key={j.id}><td className="small">{j.file_name}</td><td className="small">{when(j.created_at)}</td><td><Badge tone={j.status === "done" ? "good" : j.status === "cancelled" ? "warn" : "info"}>{{ done: "Finished", cancelled: "Stopped", running: "Unfinished", paused: "Unfinished" }[j.status as string]}</Badge></td><td className="num">{n(j.rows_done)}</td><td className="num">{n(j.rows_failed)}</td><td className="num">{n(j.values_new)}</td></tr>
                ))}</tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </Page>
  );
}
