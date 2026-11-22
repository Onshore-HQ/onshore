"use client";
import { tr } from "@/lib/i18n";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { Badge, Empty, ErrorLine, Loading, Modal, Page } from "@/components/ui";
import { control, useLoad } from "@/lib/api";
import { entityLabel, TOKEN_FORMATS, TOKEN_KINDS } from "@/lib/labels";

const TYPES = ["bvn", "nin", "vnin", "ng_11_digit_id", "nuban", "phone_ng", "email", "person_name", "amount_ngn", "payment_ref", "address", "date", "free_text"];
const FP = new Set(["bvn", "nin", "ng_11_digit_id", "nuban", "phone_ng"]);
const SAMPLE: Record<string, string> = { amount: "$8,500.00", phone: "+44 20 7946 0958", iban: "GB82 WEST 1234 5698 7654 32", us_ssn: "123-45-6789", uk_nino: "AB 12 34 56 C", uk_nhs: "943 476 5919", ca_sin: "046 454 286", br_cpf: "123.456.789-09", in_pan: "ABCPE1234F", sg_nric: "S1234567D", emirates_id: "784-1990-1234567-6", za_id: "8001015009087", ghana_card: "GHA-123456789-1", bvn: "22123456789", nin: "31234567890", ng_11_digit_id: "41234567890", nuban: "0123456789", phone_ng: "08031234567", email: "ada@example.com", person_name: "Chioma Okafor", amount_ngn: "₦250,000", address: "12 Marina Road, Lagos", date: "14/03/1990", free_text: "Sample note", vnin: "AB123456789012CD", payment_ref: "000123456789" };

interface Field { id: string; name: string; data_type: string; token_kind: string; token_format: string; mask_rule: string; ttl_days: number | null; ttl_seconds: number | null; searchable: boolean; column_group_id: string | null; in_payment_scope: boolean }
interface Vault { id: string; name: string; environment: string; embed_origins: string[]; vault_fields: Field[]; column_groups: { id: string; name: string }[] }

const WHAT_TOKEN: Record<string, string> = { deterministic: "The same value always gets the same token", cell: "A new token every time", transient: "A token that expires" };

/** Try a made-up value. Sandbox vaults only, so that real values are never typed here. */
function TryField({ vault, field, onClose }: { vault: Vault; field: Field; onClose: () => void }) {
  const [sample, setSample] = useState(SAMPLE[field.data_type] ?? "");
  const [preview, setPreview] = useState<{ valid: boolean; token?: string; masked?: string; detected_as: string[]; score: number } | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      control(`/v1/vaults/${vault.id}/fields/preview`, { body: { data_type: field.data_type, token_format: field.token_format, mask_rule: field.mask_rule, value: sample } }).then(setPreview).catch(() => setPreview(null));
    }, 250);
    return () => clearTimeout(timer.current);
  }, [sample, vault.id, field.data_type, field.token_format, field.mask_rule]);
  return (
    <Modal title={tr("Try {0}", { 0: entityLabel(field.data_type) })} onClose={onClose}>
      <p className="muted">{tr("Type a made-up value, and see what your other systems would receive.")}</p>
      <div className="slot">
        <b>{tr("Live preview, sample values only")}</b>
        <input aria-label={tr("Sample value for {0}", { 0: field.name })} value={sample} onChange={(e) => setSample(e.target.value)} />
        {preview && (
          <div className="small" style={{ display: "grid", gap: 2 }}>
            {preview.valid ? (
              <>
                <div>{tr("Token")} <code style={{ overflowWrap: "anywhere" }}>{preview.token}</code></div>
                <div>{tr("Masked")} <code>{preview.masked}</code></div>
              </>
            ) : <Badge tone="bad">{tr("This is not a valid")} {entityLabel(field.data_type)}</Badge>}
            <div>{preview.detected_as.length ? <>{tr("In traffic, this would be recognised as")} <b>{preview.detected_as.map(entityLabel).join(", ")}</b> ({Math.round(preview.score * 100)}{tr("% confidence)")}</> : tr("In traffic, this would not be recognised")}</div>
          </div>
        )}
      </div>
    </Modal>
  );
}

function FieldRow({ vault, field, onChange }: { vault: Vault; field: Field; onChange: () => void }) {
  const [trying, setTrying] = useState(false);
  // A custom field's format depends on its data type, which this preview cannot check.
  const sandbox = vault.environment === "sandbox" && field.data_type !== "custom";
  const update = async (patch: object) => {
    await control(`/v1/vaults/${vault.id}/fields/${field.id}`, { method: "PATCH", body: patch });
    onChange();
  };
  const group = vault.column_groups.find((g) => g.id === field.column_group_id);
  return (
    <tr>
      <td><div className="font-medium">{entityLabel(field.data_type)}</div><code className="small muted">{field.name}</code>{group && <div><Badge tone="info">group: {group.name}</Badge></div>}</td>
      <td className="small">{WHAT_TOKEN[field.token_kind] ?? field.token_kind}{field.token_format === "format_preserving" ? tr(", looks like the real value") : ""}{field.ttl_seconds ? tr(", after {0}s", { 0: field.ttl_seconds }) : field.ttl_days ? tr(", after {0} days", { 0: field.ttl_days }) : ""}</td>
      <td><label className="row small"><input type="checkbox" aria-label={tr("Can search by {0}", { 0: field.name })} checked={field.searchable} onChange={(e) => update({ searchable: e.target.checked })} />{tr("Yes")}</label></td>
      <td><label className="row small"><input type="checkbox" aria-label={tr("{0} is payment data", { 0: field.name })} checked={field.in_payment_scope} onChange={(e) => update({ in_payment_scope: e.target.checked })} />{tr("Yes")}</label></td>
      <td><select aria-label={tr("How {0} is masked", { 0: field.name })} value={field.mask_rule} onChange={(e) => update({ mask_rule: e.target.value })}><option value="default">{tr("Show the usual part")}</option><option value="full">{tr("Hide all of it")}</option></select></td>
      {sandbox && <td><button onClick={() => setTrying(true)}>{tr("Try it")}</button>{trying && <TryField vault={vault} field={field} onClose={() => setTrying(false)} />}</td>}
    </tr>
  );
}

/** Which sites may frame this vault's collect and reveal components. */
function SecureComponents({ vault, onChange }: { vault: Vault; onChange: () => void }) {
  const [origins, setOrigins] = useState(vault.embed_origins.join("\n"));
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  // Saving reloads the vault, which must not clear the confirmation; moving to another vault does.
  const listed = vault.embed_origins.join("\n");
  useEffect(() => { setOrigins(listed); }, [vault.id, listed]);
  useEffect(() => { setSaved(false); setError(null); }, [vault.id]);
  const host = typeof window === "undefined" ? "" : window.location.origin;
  return (
    <details className="card">
      <summary><b>{tr("Secure components")}</b> <Badge tone={vault.embed_origins.length ? "good" : ""}>{vault.embed_origins.length ? tr("{0} site{1}", { 0: vault.embed_origins.length, 1: vault.embed_origins.length === 1 ? "" : "s" }) : tr("Off")}</Badge></summary>
      <div className="stack" style={{ marginTop: 10 }}>
        <p className="small muted">{tr("Collect or show a BVN, NIN or account number inside a frame on your own site. Your page and servers get a token, and never see the value. List the exact sites allowed to host the frame. No list means off.")}</p>
        <label className="field"><span>{tr("Allowed sites, one per line")}</span><textarea className="code" rows={3} placeholder={tr("https://app.example.com\nrvapp://com.example.wallet")} value={origins} onChange={(e) => { setOrigins(e.target.value); setSaved(false); }} /></label>
        <ErrorLine error={error} />
        <div className="row">
          <button className="primary" onClick={async () => {
            try {
              await control(`/v1/vaults/${vault.id}/embed`, { method: "PATCH", body: { origins: origins.split("\n").map((o) => o.trim()).filter(Boolean) } });
              setError(null); setSaved(true); onChange();
            } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
          }}>{tr("Save sites")}</button>
          {saved && <Badge tone="good">{tr("Saved")}</Badge>}
        </div>
        <pre className="pre small">{`<!-- On your page -->
<script src="${host}/embed/rv.js"></script>
<div id="bvn"></div>
<script>
  // clientToken comes from your server:
  // POST /v1/vaults/${vault.id}/client-tokens
  const form = Onshore.collect({ vault: "${vault.id}", clientToken, labels: { bvn: "BVN" } });
  form.mount("#bvn");
  const tokens = await form.submit(); // { bvn: "tok_bvn_..." }
</script>`}</pre>
      </div>
    </details>
  );
}

function AddField({ vault, onClose, onDone }: { vault: Vault; onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({ name: "", data_type: "bvn", token_kind: "deterministic", token_format: "opaque", ttl_days: "" });
  const [error, setError] = useState<string | null>(null);
  const customs = useLoad<{ entities: { id: string; slug: string; name: string; vault_id: string }[] }>(() => control("/v1/custom-entities/slugs"));
  const vaultCustoms = (customs.value?.entities ?? []).filter((e) => e.vault_id === vault.id);
  const customEntity = vaultCustoms.find((e) => e.slug === f.data_type);
  return (
    <Modal title={tr("Add a field")} onClose={onClose}>
      <label className="field"><span>{tr("Name")}</span><input autoFocus placeholder="account_number" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
      <label className="field"><span>{tr("Data type")}</span><select value={f.data_type} onChange={(e) => setF({ ...f, data_type: e.target.value, token_format: FP.has(e.target.value) || e.target.value.startsWith("c_") ? f.token_format : "opaque" })}><optgroup label={tr("Built-in")}>{TYPES.map((t) => <option key={t} value={t}>{entityLabel(t)}</option>)}</optgroup>{vaultCustoms.length > 0 && <optgroup label={tr("Custom")}>{vaultCustoms.map((e) => <option key={e.id} value={e.slug}>{e.name} ({e.slug})</option>)}</optgroup>}</select></label>
      <label className="field"><span>{tr("When the same value comes in again")}</span><select value={f.token_kind} onChange={(e) => setF({ ...f, token_kind: e.target.value })}><option value="deterministic">{tr("Give it the same token, so records can be matched up")}</option><option value="cell">{tr("Give it a new token each time; the value can be changed later")}</option><option value="transient">{tr("Give it a token that expires")}</option></select></label>
      <label className="field"><span>{tr("What the token looks like")}</span><select value={f.token_format} onChange={(e) => setF({ ...f, token_format: e.target.value })}><option value="opaque">{tr("Clearly a token (tok_…)")}</option>{(FP.has(f.data_type) || Boolean(customEntity)) && <option value="format_preserving">{tr("Looks like the real value")}</option>}</select></label>
      {f.token_kind === "transient" && <label className="field"><span>{tr("Expires after, in days")}</span><input type="number" min={1} value={f.ttl_days} onChange={(e) => setF({ ...f, ttl_days: e.target.value })} /></label>}
      {f.token_format === "format_preserving" && <div className="note warn small">{tr("No number range can be reserved for BVN or NIN: NIMC draws NINs at random. A token like this can look like a real number, so use it only where a downstream system demands the shape.")}</div>}
      <p className="small muted">{tr("Token settings cannot change later, because stored values depend on them.")}</p>
      <ErrorLine error={error} />
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button onClick={onClose}>{tr("Cancel")}</button>
        <button className="primary" disabled={!f.name} onClick={async () => {
          try {
            await control(`/v1/vaults/${vault.id}/fields`, { body: { name: f.name, data_type: customEntity ? "custom" : f.data_type, custom_entity_id: customEntity?.id, token_kind: f.token_kind, token_format: f.token_format, ttl_days: f.ttl_days ? Number(f.ttl_days) : null } });
            onDone();
          } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
        }}>{tr("Add field")}</button>
      </div>
    </Modal>
  );
}

function NewVault({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [environment, setEnv] = useState("sandbox");
  const [template, setTemplate] = useState("packs");
  const [error, setError] = useState<string | null>(null);
  return (
    <Modal title={tr("New vault")} onClose={onClose}>
      <label className="field"><span>{tr("Name")}</span><input autoFocus value={name} onChange={(e) => setName(e.target.value)} /></label>
      <label className="field"><span>{tr("Environment")}</span><select value={environment} onChange={(e) => setEnv(e.target.value)}><option value="sandbox">{tr("Test, with made-up customers")}</option><option value="production">{tr("Live data")}</option></select></label>
      <label className="field"><span>{tr("Template")}</span><select value={template} onChange={(e) => setTemplate(e.target.value)}><option value="packs">{tr("Fields for its country’s identifiers")}</option><option value="blank">{tr("Blank")}</option><optgroup label={tr("Nigerian payments (Nigeria pack)")}><option value="wallet_psp">{tr("Wallet / PSP")}</option><option value="lending">{tr("Lending")}</option><option value="microfinance">{tr("Microfinance bank")}</option></optgroup></select></label>
      <ErrorLine error={error} />
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button onClick={onClose}>{tr("Cancel")}</button>
        <button className="primary" disabled={!name} onClick={async () => {
          try {
            await control("/v1/vaults", { body: { name, environment, template, seed: environment === "sandbox" } });
            onDone();
          } catch (e) { setError(e instanceof Error ? e.message : "failed"); }
        }}>{tr("Create")}</button>
      </div>
    </Modal>
  );
}

export default function Vaults() {
  const { value, error, loading, reload } = useLoad<{ vaults: Vault[] }>(() => control("/v1/vaults"));
  const [sel, setSel] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [creating, setCreating] = useState(false);
  const vaults = value?.vaults ?? [];
  const vault = vaults.find((v) => v.id === sel) ?? vaults[0];
  return (
    <Page title={tr("Vaults")} sub={tr("A vault keeps real values on your servers, in the country it was created for. Each row sets how one kind of value is replaced and shown.")} actions={<button className="primary" onClick={() => setCreating(true)}>{tr("New vault")}</button>}>
      <Loading error={error} loading={loading && !value} />
      {value && vaults.length === 0 && <Empty title={tr("No vaults yet")} action={<Link className="btn primary" href="/onboarding">{tr("Open the setup guide")}</Link>}>{tr("The guide makes a test vault with made-up customers.")}</Empty>}
      {vault && (
        <div className="stack">
          <div className="spread">
            <div className="row">
              <select aria-label={tr("Vault")} value={vault.id} onChange={(e) => setSel(e.target.value)}>{vaults.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select>
              <Badge tone={vault.environment === "production" ? "warn" : "info"}>{vault.environment === "production" ? tr("Live data") : tr("Test data")}</Badge>
              <code className="small muted">{vault.id}</code>
            </div>
            <button onClick={() => setAdding(true)}>{tr("Add field")}</button>
          </div>
          <SecureComponents vault={vault} onChange={reload} />
          {vault.vault_fields.length === 0 ? <Empty title={tr("No fields yet")} action={<button className="primary" onClick={() => setAdding(true)}>{tr("Add field")}</button>}>{tr("A field is one kind of value to protect, such as a BVN.")}</Empty> : (
            <div className="grid gap-2">
              <div className="tablewrap">
                <table>
                  <thead><tr><th>{tr("What it holds")}</th><th>{tr("Token")}</th><th>{tr("Can search by it")}</th><th>{tr("Payment data")}</th><th>{tr("When masked")}</th>{vault.environment === "sandbox" && <th></th>}</tr></thead>
                  <tbody>{vault.vault_fields.map((f) => <FieldRow key={f.id} vault={vault} field={f} onChange={reload} />)}</tbody>
                </table>
              </div>
              {vault.environment !== "sandbox" && <p className="small muted">{tr("You can try values in test vaults only, so that real values are never typed here.")}</p>}
            </div>
          )}
        </div>
      )}
      {adding && vault && <AddField vault={vault} onClose={() => setAdding(false)} onDone={() => { setAdding(false); reload(); }} />}
      {creating && <NewVault onClose={() => setCreating(false)} onDone={() => { setCreating(false); reload(); }} />}
    </Page>
  );
}
