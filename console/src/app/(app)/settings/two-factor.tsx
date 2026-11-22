"use client";
import { tr } from "@/lib/i18n";
import QRCode from "qrcode";
import { useEffect, useState } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import { ErrorLine, Modal, ShownOnce, TypedConfirm } from "@/components/ui";
import { day, when } from "@/lib/api";
import { control, useLoad } from "@/lib/api";

/** Your own recovery codes and authenticator. Both ask for your password again. */
export function TwoFactorCard() {
  const s = useLoad<{ recovery_codes_left: number; source: string; passkeys: { id: string; name: string; created_at: string; last_used_at: string | null }[] }>(() => control("/v1/auth/security"));
  const [open, setOpen] = useState<"codes" | "app" | "passkey" | null>(null);
  const [keyName, setKeyName] = useState("");
  const [removing, setRemoving] = useState<string | null>(null);
  const [added, setAdded] = useState(false);
  const [pw, setPw] = useState("");
  const [totp, setTotp] = useState("");
  const [pending, setPending] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [qr, setQr] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { if (pending) QRCode.toDataURL(pending.otpauth_uri, { margin: 1, width: 180 }).then(setQr); }, [pending]);
  const close = () => { setOpen(null); setPw(""); setTotp(""); setPending(null); setQr(""); setCodes(null); setErr(null); setKeyName(""); setAdded(false); s.reload(); };
  const run = async (fn: () => Promise<void>) => { setErr(null); try { await fn(); } catch (e) { setErr(e instanceof Error ? e.message : "failed"); } };
  const left = s.value?.recovery_codes_left;
  return (
    <div className="card">
      <h2>{tr("Two-factor authentication")}</h2>
      <p className="small muted">{left === undefined ? "" : left === 0 ? tr("You have no recovery codes left. Make new ones, so that losing your phone can't lock you out.") : tr("You have {0} recovery code{1} left. Each gets you in once if you lose your phone.", { 0: left, 1: left === 1 ? "" : "s" })}</p>
      <div className="row"><button onClick={() => setOpen("codes")}>{tr("Make new recovery codes")}</button><button onClick={() => setOpen("app")}>{tr("Set up a new authenticator")}</button><button onClick={() => setOpen("passkey")}>{tr("Add a passkey or security key")}</button></div>
      <h3 className="m-0 text-sm font-semibold">{tr("Passkeys and security keys")}</h3>
      <p className="small muted m-0">{tr("Use one instead of the 6-digit code when you sign in. They can't be phished: your device signs only for this site.")}</p>
      {s.value?.passkeys?.length ? (
        <div className="tablewrap"><table><thead><tr><th>{tr("Name")}</th><th>{tr("Added")}</th><th>{tr("Last used")}</th><th /></tr></thead>
          <tbody>{s.value.passkeys.map((k) => <tr key={k.id}><td>{k.name}</td><td className="small">{day(k.created_at)}</td><td className="small">{k.last_used_at ? when(k.last_used_at) : tr("never")}</td><td><button className="danger" onClick={() => setRemoving(k.id)}>{tr("Remove")}</button></td></tr>)}</tbody></table></div>
      ) : <p className="small m-0">{tr("None yet.")}</p>}
      {removing && <TypedConfirm title={tr("Remove this passkey")} word="remove" onClose={() => setRemoving(null)} onConfirm={async () => { await control(`/v1/auth/passkeys/${removing}`, { method: "DELETE" }); setRemoving(null); s.reload(); }}>{tr("You'll use your authenticator code or another passkey instead.")}</TypedConfirm>}
      {open && (
        <Modal title={open === "codes" ? tr("Make new recovery codes") : open === "passkey" ? tr("Add a passkey or security key") : tr("Set up a new authenticator")} onClose={close}>
          {open === "passkey" ? (added ? (
            <>
              <div className="note good">{tr("Added. Next time you sign in, choose “Use a passkey” instead of typing a code.")}</div>
              <div className="row" style={{ justifyContent: "flex-end" }}><button className="primary" onClick={close}>{tr("Done")}</button></div>
            </>
          ) : (
            <>
              <label className="field"><span>{tr("A name you'll recognise, such as “Work laptop”")}</span><input autoFocus value={keyName} onChange={(e) => setKeyName(e.target.value)} /></label>
              <label className="field"><span>{tr("Your password")}</span><input type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} /></label>
              <ErrorLine error={err} />
              <div className="row" style={{ justifyContent: "flex-end" }}><button onClick={close}>{tr("Cancel")}</button><button className="primary" disabled={!pw || !keyName.trim()} onClick={() => run(async () => {
                const options = await control("/v1/auth/passkeys/options", { body: { password: pw } });
                let response;
                try { response = await startRegistration({ optionsJSON: options }); } catch { throw new Error(tr("Your device didn't create a passkey. Try again, or use another device.")); }
                await control("/v1/auth/passkeys", { body: { name: keyName.trim(), response } });
                setAdded(true);
              })}>{tr("Continue")}</button></div>
            </>
          )) : codes ? (
            <>
              <ShownOnce items={[{ label: tr("Recovery codes"), value: codes.join("\n"), block: true }]} />
              <div className="row" style={{ justifyContent: "flex-end" }}><button className="primary" onClick={close}>{tr("I've saved them")}</button></div>
            </>
          ) : pending ? (
            <>
              <p className="muted">{tr("Scan this with your new authenticator app, or enter the key by hand. Your old app keeps working until you confirm.")}</p>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              {qr && <img src={qr} width={180} height={180} alt={tr("Authenticator setup code")} />}
              <code style={{ overflowWrap: "anywhere" }} data-testid="new-totp-secret">{pending.secret}</code>
              <label className="field"><span>{tr("6-digit code from the new app")}</span><input inputMode="numeric" maxLength={6} autoFocus value={totp} onChange={(e) => setTotp(e.target.value)} /></label>
              <ErrorLine error={err} />
              <div className="row" style={{ justifyContent: "flex-end" }}><button className="primary" disabled={totp.length !== 6} onClick={() => run(async () => { const r = await control("/v1/auth/mfa/replace/confirm", { body: { totp } }); setCodes(r.recovery_codes); })}>{tr("Confirm")}</button></div>
            </>
          ) : (
            <>
              <p className="muted">{open === "codes" ? tr("Your old codes stop working as soon as you make new ones.") : tr("You'll scan a new code, then prove it works. You'll also get new recovery codes.")}</p>
              <label className="field"><span>{tr("Your password")}</span><input type="password" autoComplete="current-password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} /></label>
              <ErrorLine error={err} />
              <div className="row" style={{ justifyContent: "flex-end" }}><button onClick={close}>{tr("Cancel")}</button><button className="primary" disabled={!pw} onClick={() => run(async () => {
                if (open === "codes") setCodes((await control("/v1/auth/recovery-codes", { body: { password: pw } })).recovery_codes);
                else setPending(await control("/v1/auth/mfa/replace", { body: { password: pw } }));
              })}>{tr("Continue")}</button></div>
            </>
          )}
        </Modal>
      )}
    </div>
  );
}
