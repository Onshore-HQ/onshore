"use client";
import { tr } from "@/lib/i18n";
import { useState } from "react";
import { Badge, ErrorLine, Loading, Page, TypedConfirm } from "@/components/ui";
import { control, useLoad, when } from "@/lib/api";

const ageDays = (d: string) => Math.floor((Date.now() - new Date(d).getTime()) / 86400000);

export default function Keys() {
  const keys = useLoad(() => control("/v1/keys"));
  const settings = useLoad(() => control("/v1/settings"));
  const [rotate, setRotate] = useState<{ kind: "kek" | "dek"; vault_id?: string } | null>(null);
  const [reencrypt, setReencrypt] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
  };
  const k = keys.value;
  return (
    <Page title={tr("Encryption keys")} sub={tr("The keys that protect your data. They stay in your vaults' country, inside the key service, and are only stored in encrypted form.")}>
      <div className="stack">
        <ErrorLine error={error} />
        <Loading error={keys.error} loading={keys.loading && !k} />
        {k && (
          <div className="card">
            <div className="spread">
              <div className="row"><h2>{tr("Key service")}</h2><Badge tone={k.health === "ok" ? "good" : "bad"}>{k.health === "ok" ? tr("healthy") : tr("unavailable")}</Badge><code className="small">{k.backend}</code></div>
              <button className="danger" onClick={() => setRotate({ kind: "kek" })}>{tr("Rotate master key")}</button>
            </div>
            <div className="tablewrap" style={{ maxHeight: 280 }}>
              <table>
                <thead><tr><th>{tr("Data key")}</th><th>{tr("Vault")}</th><th>{tr("Status")}</th><th>{tr("Algorithm")}</th><th>{tr("Protected by")}</th><th className="num">{tr("Age, days")}</th><th></th></tr></thead>
                <tbody>
                  {k.data_keys.map((d: any) => (
                    <tr key={d.id}>
                      <td><code className="small">{d.id.slice(0, 16)}…</code></td><td className="small mono">{d.vault_id}</td>
                      <td><Badge tone={d.status === "active" ? "good" : ""}>{d.status}</Badge></td><td className="small">{d.algorithm}</td><td className="small mono">{d.kek_ref}</td><td className="num">{ageDays(d.created_at)}</td>
                      <td>{d.status === "active" && <button onClick={() => setRotate({ kind: "dek", vault_id: d.vault_id })}>{tr("Rotate")}</button>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <h3>{tr("Rotation history")}</h3>
            {k.rotations.length === 0 ? <p className="muted small">{tr("No rotations yet.")}</p> : k.rotations.map((r: any, i: number) => <div key={i} className="small muted">{when(r.occurred_at)} by {r.principal_id}: {r.detail}</div>)}
          </div>
        )}
        <div className="card">
          <h2>{tr("Rotation schedule")}</h2>
          <p className="small muted">{tr("Onshore makes a new version of the master key on this schedule, and re-wraps the stored keys. This is quick, as no values are re-encrypted.")}</p>
          <label className="field" style={{ maxWidth: 280 }}><span>{tr("Rotate every")}</span>
            <select value={settings.value?.tenant?.kek_rotation_days ?? ""} onChange={(e) => act(async () => { await control("/v1/settings", { method: "PATCH", body: { kek_rotation_days: e.target.value ? Number(e.target.value) : null } }); settings.reload(); })}>
              <option value="">{tr("Manual only")}</option><option value="30">{tr("30 days")}</option><option value="60">{tr("60 days")}</option><option value="180">{tr("180 days")}</option><option value="360">{tr("360 days")}</option>
            </select>
          </label>
        </div>
      </div>
      {rotate && (
        <TypedConfirm
          title={rotate.kind === "kek" ? tr("Rotate the master key") : tr("Rotate this vault's data key")} word="rotate" onClose={() => setRotate(null)}
          extra={rotate.kind === "dek" ? <label className="row small"><input type="checkbox" checked={reencrypt} onChange={(e) => setReencrypt(e.target.checked)} />{tr("Also re-encrypt existing values now")}</label> : undefined}
          onConfirm={async () => { await control("/v1/keys/rotate", { body: { ...rotate, reencrypt } }); keys.reload(); }}
        >
          {rotate.kind === "kek" ? tr("Creates a new version of the master key and re-wraps every stored key. No values are re-encrypted, so this is fast.") : tr("New writes go to a new key. Re-encryption can take a while on large vaults.")}
        </TypedConfirm>
      )}
    </Page>
  );
}
