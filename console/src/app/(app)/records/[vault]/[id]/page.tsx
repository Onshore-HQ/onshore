"use client";
import { tr } from "@/lib/i18n";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { RevealButton } from "@/components/Reveal";
import { useMe } from "@/components/Shell";
import { Badge, DecisionBadge, ErrorLine, Loading, Modal, Page, TypedConfirm } from "@/components/ui";
import { control, data, day, useLoad, when } from "@/lib/api";

interface Detail { id: string; ref: string; created_at: string; restricted: boolean; fields: { field: string; data_type: string; token: string; masked?: string; decision: string; record_id: string }[] }

function downloadJson(name: string, value: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export default function SubjectPage() {
  const { vault, id } = useParams<{ vault: string; id: string }>();
  const router = useRouter();
  const me = useMe();
  const { value: s, error, loading, reload } = useLoad<Detail>(() => data(`/v1/vaults/${vault}/subjects/${id}`), [vault, id]);
  const records = s?.fields.map((f) => f.record_id).join(",");
  const timeline = useLoad<{ events: any[] }>(() => (records ? control(`/v1/audit-events?records=${records}&limit=50`) : Promise.resolve({ events: [] })), [records]);
  const [dialog, setDialog] = useState<"erase" | "export" | "restrict" | null>(null);
  const [purpose, setPurpose] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const [showViews, setShowViews] = useState(false);
  const fieldByRecord = new Map(s?.fields.map((f) => [f.record_id, f.field]));
  // Opening this page is audited per field; those rows would bury the real reveals.
  const events = (timeline.value?.events ?? []).filter((e) => showViews || e.purpose !== "subject page view");
  const close = () => { setDialog(null); setPurpose(""); setActionError(null); };

  if (!s) return <Page title={tr("Person")}><Loading error={error} loading={loading} /></Page>;
  const purposeInput = <label className="field"><span>{tr("Request or ticket reference")}</span><input value={purpose} onChange={(e) => setPurpose(e.target.value)} /></label>;

  return (
    <Page
      title={s.ref}
      sub={<>{tr("Created")} {day(s.created_at)}. <Link href="/records">{tr("Back to records")}</Link></>}
      actions={
        <>
          {s.restricted && <Badge tone="warn">restricted</Badge>}
          <button className="desktop-only" onClick={() => setDialog("export")}>{tr("Export")}</button>
          <button className="desktop-only" onClick={() => setDialog("restrict")}>{s.restricted ? "Lift restriction" : "Restrict"}</button>
          <button className="danger desktop-only" onClick={() => setDialog("erase")}>{tr("Erase")}</button>
        </>
      }
    >
      <div className="stack">
        <div className="mobile-note note small">{tr("Mobile is read-only: reveals, exports and erasure need a desktop.")}</div>
        <div className="tablewrap">
          <table>
            <thead><tr><th>{tr("Field")}</th><th>{tr("Token")}</th><th>{tr("Masked value")}</th><th>{tr("Your access")}</th><th></th></tr></thead>
            <tbody>
              {s.fields.map((f) => (
                <tr key={f.record_id}>
                  <td><code>{f.field}</code></td>
                  <td><code style={{ whiteSpace: "nowrap" }}>{f.token}</code></td>
                  <td><code>{f.masked ?? "hidden"}</code></td>
                  <td><DecisionBadge value={f.decision} /></td>
                  <td>{f.decision === "plaintext" && !s.restricted && <RevealButton vaultId={vault} token={f.token} viewer={me?.display_name ?? ""} label={f.field} />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card">
          <div className="spread">
            <h2>{tr("Access timeline")}</h2>
            <label className="row small muted"><input type="checkbox" checked={showViews} onChange={(e) => setShowViews(e.target.checked)} />{tr("Include page views")}</label>
          </div>
          <Loading error={timeline.error} loading={timeline.loading && !timeline.value} />
          {timeline.value && events.length === 0 && <p className="muted">{tr("No access is recorded yet.")}</p>}
          <div className="timeline">
            {events.map((e) => (
              <div key={e.seq}>
                <div className="row"><b>{e.action}</b><DecisionBadge value={e.decision} /><span className="small muted">{when(e.occurred_at)}</span></div>
                <div className="small muted">
                  {/^(usr|sa)_/.test(e.principal_id ?? "") ? <Link href={`/people/${e.principal_id}`}>{e.principal_id}</Link> : e.principal_id ?? "system"} · {e.network ?? tr("no approved network")} · {fieldByRecord.get(e.record_id) ?? e.field_id} {e.policy_id ? tr("· policy v{0}", { 0: e.policy_version }) : ""} {e.purpose ? `· “${e.purpose}”` : ""}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {dialog === "erase" && (
        <TypedConfirm
          title={tr("Erase {0}", { 0: s.ref })} word="erase" onClose={close} extra={purposeInput}
          onConfirm={async () => {
            if (purpose.trim().length < 3) throw new Error("Enter the request reference.");
            await data(`/v1/vaults/${vault}/subjects/${id}`, { method: "DELETE", purpose });
            router.push("/records");
          }}
        >
          {tr("This permanently deletes this person's values and tokens. A value shared with another person, such as one phone line, stays until its last owner is erased. The audit log keeps a record of the erasure.")}
        </TypedConfirm>
      )}
      {dialog === "export" && (
        <Modal title={tr("Export {0}", { 0: s.ref })} onClose={close}>
          <p className="muted">{tr("For a data subject access request. Each field follows the export policy, and the export is audited.")}</p>
          {purposeInput}
          <ErrorLine error={actionError} />
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button onClick={close}>{tr("Cancel")}</button>
            <button className="primary" disabled={purpose.trim().length < 3} onClick={async () => {
              try {
                downloadJson(`subject-${s.ref}.json`, await data(`/v1/vaults/${vault}/subjects/${id}/export`, { purpose }));
                close();
              } catch (e) { setActionError(e instanceof Error ? e.message : "failed"); }
            }}>{tr("Download")}</button>
          </div>
        </Modal>
      )}
      {dialog === "restrict" && (
        <Modal title={s.restricted ? tr("Lift restriction") : tr("Restrict processing")} onClose={close}>
          <p className="muted">{tr("While restricted, nobody can reveal this person's values, whatever the policies say.")}</p>
          {purposeInput}
          <ErrorLine error={actionError} />
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button onClick={close}>{tr("Cancel")}</button>
            <button className="primary" disabled={purpose.trim().length < 3} onClick={async () => {
              try {
                await data(`/v1/vaults/${vault}/subjects/${id}/restrict`, { body: { restricted: !s.restricted, purpose } });
                close();
                reload();
              } catch (e) { setActionError(e instanceof Error ? e.message : "failed"); }
            }}>{tr("Confirm")}</button>
          </div>
        </Modal>
      )}
    </Page>
  );
}
