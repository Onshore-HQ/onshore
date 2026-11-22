"use client";
import { tr } from "@/lib/i18n";
import { Server } from "lucide-react";
import { useState } from "react";
import { Badge, ErrorLine, Modal, ShownOnce } from "@/components/ui";
import { control, useLoad } from "@/lib/api";

// Installs in other countries (Enterprise), and Onshore Cloud regions. Each linked
// install keeps its customer data in its own country and reports only names,
// settings and counts here.

interface Install {
  id: string; country: string; name: string; status: "pending" | "active" | "unreachable"; version: string | null;
  last_seen_at: string | null; joined_at: string | null; join_expired: boolean;
  pending: { id: string; name: string }[]; failed: { id: string; error: string }[];
  vaults: { id: string; name: string; environment: string; packs: string[]; fields: number }[];
  detections_7d: Record<string, number>; reveals_7d: { plaintext: number; masked: number; denied: number } | null;
}
interface Country { code: string; name: string }

const errText = (e: unknown) => (e instanceof Error ? e.message : "failed");
const ago = (d: string | null) => {
  if (!d) return "never";
  const s = Math.round((Date.now() - new Date(d).getTime()) / 1000);
  return s < 90 ? "just now" : s < 5400 ? tr("{0} minutes ago", { 0: Math.round(s / 60) }) : tr("{0} hours ago", { 0: Math.round(s / 3600) });
};
const STATUS = { pending: ["Waiting to join", "warn"], active: ["Reporting", "good"], unreachable: ["Not reporting", "bad"] } as const;

function LinkModal({ countries, onClose, onDone, existing }: { countries: Country[]; onClose: () => void; onDone: () => void; existing?: Install }) {
  const [country, setCountry] = useState(existing?.country ?? "");
  const [out, setOut] = useState<{ command: string; join_code: string; expires_at: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (out) {
    return (
      <Modal title={tr("Run this on the new install")} onClose={onDone}>
        <p className="small muted">{tr("On a server in")} {countries.find((c) => c.code === country)?.name}{tr(", in the folder with Onshore’s compose files. The code works once and expires in 24 hours. Once it joins, it appears here within a minute, and any vaults waiting for it are created there.")}</p>
        <ShownOnce items={[{ label: "Command", value: out.command, block: true }]} />
        <div className="row" style={{ justifyContent: "flex-end" }}><button className="primary" onClick={onDone}>{tr("Done")}</button></div>
      </Modal>
    );
  }
  return (
    <Modal title={existing ? tr("New join code for {0}", { 0: existing.name }) : tr("Link an install in another country")} onClose={onClose}>
      <p className="small muted">{tr("The new install keeps its customer data in its own country. It sends this console only vault names, settings and counts, signed, every minute. This console never reaches into it.")}</p>
      {!existing && (
        <label className="field"><span>{tr("Country")}</span>
          <select value={country} onChange={(e) => setCountry(e.target.value)}><option value="" disabled>{tr("Choose a country")}</option>{countries.map((c) => <option key={c.code} value={c.code}>{c.name}</option>)}</select>
        </label>
      )}
      {existing && <p className="small">{tr("The old code stops working.")}</p>}
      <ErrorLine error={error} />
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button onClick={onClose}>{tr("Cancel")}</button>
        <button className="primary" disabled={!country} onClick={async () => {
          setError(null);
          try { setOut(await control(existing ? `/v1/installs/${existing.id}/join-code` : "/v1/installs", existing ? { method: "POST", body: {} } : { body: { country } })); } catch (e) { setError(errText(e)); }
        }}>{tr("Get join command")}</button>
      </div>
    </Modal>
  );
}

export function InstallsCard({ edition, countries, admin, waitlist, onChange }: { edition: "free" | "enterprise" | "cloud"; countries: Country[]; admin: boolean; waitlist: { country: string; since: string; open: boolean }[]; onChange: () => void }) {
  const { value, error, reload } = useLoad<{ installs: Install[]; cloud_regions: string[] }>(() => control("/v1/installs"));
  const [linking, setLinking] = useState<Install | "new" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const name = (code: string) => countries.find((c) => c.code === code)?.name ?? code;
  const installs = value?.installs ?? [];
  const canLink = edition !== "free";
  if (edition === "free" && installs.length === 0) {
    return (
      <div className="card">
        <h2>{tr("Installs in other countries")}</h2>
        <p className="small muted">{tr("This install keeps data in one country. To keep data in other countries from this console, link an install in each with Enterprise, or use Onshore Cloud.")}</p>
      </div>
    );
  }
  return (
    <div className="card">
      <div className="spread">
        <div><h2>{edition === "cloud" ? tr("Your regions") : tr("Installs in other countries")}</h2>
          <p className="small muted m-0">{edition === "cloud" ? tr("Each region is an install Onshore runs in that country. Customer data stays there; this console sees names, settings and counts.") : tr("Each install keeps its customer data in its own country, and reports names, settings and counts here every minute.")}</p></div>
        {admin && canLink && edition !== "cloud" && <button className="primary" onClick={() => setLinking("new")}>{tr("Link an install")}</button>}
      </div>
      <ErrorLine error={error ?? err} />
      {installs.length === 0 && <p className="small muted">{tr("None linked yet.")}</p>}
      <div className="grid gap-2">
        {installs.map((i) => {
          const [label, tone] = STATUS[i.status];
          const det = Object.values(i.detections_7d).reduce((a, b) => a + b, 0);
          return (
            <div key={i.id} className="grid gap-2 rounded-lg border px-4 py-3" style={{ borderColor: "var(--border)" }}>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <span className="flex items-center gap-2"><Server size={15} aria-hidden /><b>{i.name}</b><Badge tone={tone}>{label}</Badge></span>
                <span className="small muted">{i.status === "pending" ? (i.join_expired ? tr("Join code expired") : tr("Join code issued")) : tr("Last report {0}{1}", { 0: ago(i.last_seen_at), 1: i.version ? ` · ${i.version}` : "" })}</span>
              </div>
              {i.vaults.length > 0 && <span className="small">{tr("Vaults:")} {i.vaults.map((v) => `${v.name}${v.environment === "sandbox" ? " (sandbox)" : ""}`).join(", ")} · {det.toLocaleString()} {tr("values found in 7 days")}{i.reveals_7d ? tr(" · {0} reveals, {1} refused", { 0: i.reveals_7d.plaintext, 1: i.reveals_7d.denied }) : ""}</span>}
              {i.pending.length > 0 && <span className="small muted">{tr("Waiting to create:")} {i.pending.map((p) => p.name).join(", ")}</span>}
              {i.failed.map((f) => <span key={f.id} className="small" style={{ color: "var(--bad)" }}>{tr("Could not carry out an instruction:")} {f.error}</span>)}
              {admin && (
                <div className="row">
                  {i.status === "pending" && edition !== "cloud" && <button onClick={() => setLinking(i)}>{tr("New join code")}</button>}
                  <button onClick={async () => {
                    setErr(null);
                    try { await control(`/v1/installs/${i.id}`, { method: "DELETE" }); reload(); onChange(); } catch (e) { setErr(errText(e)); }
                  }}>{tr("Remove link")}</button>
                </div>
              )}
            </div>
          );
        })}
      </div>
      {edition === "cloud" && waitlist.length > 0 && (
        <div className="grid gap-2">
          <h3 className="m-0 text-sm font-semibold">{tr("Waiting for a region")}</h3>
          {waitlist.map((w) => (
            <div key={w.country} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-3" style={{ borderColor: "var(--border)" }}>
              <span><b>{name(w.country)}</b> <span className="small muted">{w.open ? tr("The region is open.") : tr("We'll tell you when it opens. Until then, its data has no vault.")}</span></span>
              {admin && w.open && <button className="primary" onClick={async () => {
                setErr(null);
                try { await control(`/v1/cloud/waitlist/${w.country}/start`, { body: {} }); reload(); onChange(); } catch (e) { setErr(errText(e)); }
              }}>{tr("Set it up")}</button>}
            </div>
          ))}
        </div>
      )}
      {linking && <LinkModal countries={countries} existing={linking === "new" ? undefined : linking} onClose={() => setLinking(null)} onDone={() => { setLinking(null); reload(); }} />}
    </div>
  );
}
