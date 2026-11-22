"use client";
import { tr } from "@/lib/i18n";
import { AlertCircle, Loader2 } from "lucide-react";
import Link from "next/link";
import QRCode from "qrcode";
import { startAuthentication } from "@simplewebauthn/browser";
import { useEffect, useState } from "react";
import { AuthLayout } from "@/components/AuthLayout";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Copy } from "@/components/ui";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [step, setStep] = useState<"password" | "totp" | "enrol" | "change" | "recovery" | "codes">("password");
  const [recovery, setRecovery] = useState("");
  const [codes, setCodes] = useState<string[]>([]);
  const [left, setLeft] = useState<number | null>(null);
  const [enrol, setEnrol] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [qr, setQr] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [needsSetup, setNeedsSetup] = useState(false);
  const [ssoFailed, setSsoFailed] = useState(false);
  const [passkey, setPasskey] = useState<any>(null);
  useEffect(() => { setSsoFailed(new URLSearchParams(window.location.search).get("sso") === "failed"); }, []);

  useEffect(() => {
    fetch("/api/proxy/control/v1/bootstrap/status").then((r) => r.json()).then((d) => setNeedsSetup(Boolean(d.needed))).catch(() => undefined);
  }, []);
  useEffect(() => {
    if (enrol) QRCode.toDataURL(enrol.otpauth_uri, { margin: 1, width: 180 }).then(setQr);
  }, [enrol]);

  const sso = async () => {
    setError(null);
    const res = await fetch("/api/proxy/control/v1/auth/sso/start", { method: "POST", headers: { "content-type": "application/json", "x-rv-console": "1" }, body: JSON.stringify({ email }) }).catch(() => null);
    const d = res ? await res.json().catch(() => ({})) : {};
    if (d.redirect) window.location.href = d.redirect;
    else setError("Your organisation has not set up single sign-on. Use your password.");
  };

  const submit = async (e: React.FormEvent | null, withPasskey?: unknown) => {
    e?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/session", { method: "POST", headers: { "content-type": "application/json", "x-rv-console": "1" }, body: JSON.stringify({ email, password, ...(withPasskey ? { passkey: withPasskey } : step === "recovery" ? { recovery_code: recovery.trim().toLowerCase() } : step !== "password" ? { totp } : {}), ...(step === "change" ? { new_password: newPassword } : {}) }) });
      const d = await res.json();
      if (!res.ok) {
        setError(d.error?.message ?? "login failed");
        setTotp("");
      } else if (d.step === "done") {
        // New recovery codes are shown once, before going on. So is a warning that few are left.
        if (d.recovery_codes?.length) { setCodes(d.recovery_codes); setStep("codes"); }
        else if (typeof d.recovery_codes_left === "number") { setLeft(d.recovery_codes_left); setStep("codes"); }
        else window.location.href = "/overview";
      } else if (d.step === "change_password") {
        // The code just used is spent, so the next submit needs a fresh one.
        setTotp("");
        setStep("change");
      } else if (d.step === "enrol_totp") {
        setEnrol(d);
        setStep("enrol");
      } else {
        setPasskey(d.passkey ?? null);
        setStep("totp");
      }
    } catch {
      setError("The service cannot be reached.");
    } finally {
      setBusy(false);
    }
  };

  if (step === "codes") {
    return (
      <AuthLayout>
        <div className="auth-form">
          {codes.length > 0 ? (
            <>
              <div className="grid gap-1">
                <h1 className="!text-2xl">{tr("Save your recovery codes")}</h1>
                <p className="text-muted-foreground">{tr("If you lose your phone, each code gets you in once. They're shown only now, so keep them somewhere safe, away from your phone.")}</p>
              </div>
              <pre className="pre" data-testid="recovery-codes">{codes.join("\n")}</pre>
              <div className="row">
                <Copy text={codes.join("\n")} label={tr("Copy all")} />
                <Button type="button" variant="outline" size="sm" onClick={() => { const u = URL.createObjectURL(new Blob([codes.join("\n")], { type: "text/plain" })); const a = document.createElement("a"); a.href = u; a.download = "onshore-recovery-codes.txt"; a.click(); URL.revokeObjectURL(u); }}>{tr("Download")}</Button>
              </div>
            </>
          ) : (
            <div className="grid gap-1">
              <h1 className="!text-2xl">{tr("You used a recovery code")}</h1>
              <p className="text-muted-foreground">{tr("You have")} {left} {tr("left. If you've lost your phone, set up a new authenticator now, in Settings under Sign-in.")}</p>
            </div>
          )}
          <Button size="lg" className="h-10 w-full" onClick={() => { window.location.href = codes.length ? "/overview" : "/settings?tab=signin"; }}>{codes.length ? tr("I've saved them") : tr("Go to Settings")}</Button>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <form className="auth-form" onSubmit={submit}>
        <div className="grid gap-1">
          <h1 className="!text-2xl">{step === "enrol" ? tr("Protect your account") : step === "change" ? tr("Choose your password") : step === "totp" ? tr("Enter your code") : step === "recovery" ? tr("Use a recovery code") : tr("Welcome back")}</h1>
          <p className="text-muted-foreground">{step === "enrol" ? tr("Set up two-factor authentication. It is required.") : step === "change" ? tr("Your password was set by an admin. Choose your own to finish signing in.") : tr("Sign in to the console.")}</p>
        </div>
        {ssoFailed && <Alert variant="destructive"><AlertCircle /><AlertDescription>{tr("Single sign-on could not be completed. Ask your admin to check that you have been added here.")}</AlertDescription></Alert>}
        {needsSetup && <div className="note">{tr("This installation has no admin yet.")} <Link href="/setup">{tr("Run first-time setup")}</Link>.</div>}
        {step === "password" && (
          <>
            <label className="field"><span>{tr("Email")}</span><Input className="h-10" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus /></label>
            <label className="field"><span>{tr("Password")}</span><Input className="h-10" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
          </>
        )}
        {step === "enrol" && enrol && (
          <>
            <p className="small muted">{tr("Scan this with your authenticator app, or enter the key by hand.")}</p>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            {qr && <img src={qr} width={180} height={180} alt={tr("Authenticator enrolment code")} style={{ justifySelf: "center", borderRadius: 6 }} />}
            <code style={{ overflowWrap: "anywhere" }} data-testid="totp-secret">{enrol.secret}</code>
          </>
        )}
        {step === "change" && <label className="field"><span>{tr("New password, at least 12 characters")}</span><Input className="h-10" type="password" autoComplete="new-password" minLength={12} required value={newPassword} onChange={(e) => setNewPassword(e.target.value)} /></label>}
        {step === "recovery" && <label className="field"><span>{tr("Recovery code")}</span><Input className="h-10 mono" required autoFocus autoComplete="off" placeholder="abcd-efgh-ijkl-mnop" value={recovery} onChange={(e) => setRecovery(e.target.value)} /></label>}
        {step !== "password" && step !== "recovery" && (
          <label className="field"><span>{step === "change" ? tr("Next 6-digit code from your app") : tr("6-digit code")}</span><Input className="h-10" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required value={totp} onChange={(e) => setTotp(e.target.value)} autoFocus /></label>
        )}
        {error && <Alert variant="destructive" role="alert"><AlertCircle /><AlertDescription>{error}</AlertDescription></Alert>}
        <Button size="lg" className="h-10 w-full" disabled={busy}>{busy && <Loader2 className="animate-spin" />}{step === "password" ? tr("Continue") : tr("Verify and sign in")}</Button>
        {step === "password" && <Button type="button" variant="outline" size="lg" className="h-10 w-full" disabled={!email} onClick={sso}>{tr("Continue with single sign-on")}</Button>}
        {step === "password" && <Link className="small text-center" href="/forgot">{tr("Forgot your password?")}</Link>}
        {step === "totp" && passkey && <Button type="button" variant="outline" size="lg" className="h-10 w-full" disabled={busy} onClick={async () => {
          setError(null);
          let response;
          // Each attempt needs a fresh challenge: ask again, then let the device sign it.
          try {
            const r = await fetch("/api/session", { method: "POST", headers: { "content-type": "application/json", "x-rv-console": "1" }, body: JSON.stringify({ email, password }) });
            const d = await r.json();
            response = await startAuthentication({ optionsJSON: d.passkey ?? passkey });
          } catch { setError(tr("Your device didn't sign in with a passkey. Try again, or type your code.")); return; }
          await submit(null, response);
        }}>{tr("Use a passkey")}</Button>}
        {step === "totp" && <Button type="button" variant="outline" size="lg" className="h-10 w-full" onClick={() => { setError(null); setStep("recovery"); }}>{tr("Use a recovery code instead")}</Button>}
        {step === "recovery" && <button type="button" className="link small" onClick={() => { setError(null); setStep("totp"); }}>{tr("Back to your 6-digit code")}</button>}
      </form>
    </AuthLayout>
  );
}
