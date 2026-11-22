"use client";
import { tr } from "@/lib/i18n";
import { Loader2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { AuthLayout } from "@/components/AuthLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

const post = (path: string, body: object) => fetch(`/api/proxy/control/v1/auth/account-link/${path}`, { method: "POST", headers: { "content-type": "application/json", "x-rv-console": "1" }, body: JSON.stringify(body) });

/** Where invitation and reset links land. The token is after the #, so it never reaches a server log. */
export default function Account() {
  const [token, setToken] = useState("");
  const [info, setInfo] = useState<{ kind: string; email: string; display_name: string } | null>(null);
  const [state, setState] = useState<"checking" | "ready" | "bad" | "done">("checking");
  const [pw, setPw] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const t = new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "";
    // Take it out of the address bar and history straight away.
    window.history.replaceState(null, "", window.location.pathname);
    setToken(t);
    if (!t) { setState("bad"); return; }
    post("check", { token: t }).then(async (r) => { if (r.ok) { setInfo(await r.json()); setState("ready"); } else setState("bad"); }).catch(() => setState("bad"));
  }, []);
  const invite = info?.kind === "invite";
  return (
    <AuthLayout>
      {state === "checking" && <div className="auth-form"><Loader2 className="animate-spin" aria-label={tr("Checking your link")} /></div>}
      {state === "bad" && (
        <div className="auth-form">
          <div className="grid gap-1"><h1 className="!text-2xl">{tr("This link no longer works")}</h1><p className="text-muted-foreground">{tr("It may have expired or been used already. Ask your admin for a new one, or request another password reset.")}</p></div>
          <Link className="small text-center" href="/forgot">{tr("Reset your password")}</Link>
        </div>
      )}
      {state === "done" && (
        <div className="auth-form">
          <div className="grid gap-1"><h1 className="!text-2xl">{tr("Password saved")}</h1><p className="text-muted-foreground">{info?.kind === "password_reset" ? tr("Sign in with it and your two-factor code.") : tr("Sign in with it, and you'll set up two-factor authentication.")}</p></div>
          <Button asChild size="lg" className="h-10 w-full"><Link href="/login">{tr("Go to sign in")}</Link></Button>
        </div>
      )}
      {state === "ready" && info && (
        <form className="auth-form" onSubmit={async (e) => {
          e.preventDefault();
          if (pw !== again) { setError("Those passwords don't match."); return; }
          setBusy(true); setError(null);
          try {
            const r = await post("redeem", { token, password: pw });
            if (r.ok) setState("done");
            else setError((await r.json()).error?.message ?? "That didn't work.");
          } catch { setError("The service cannot be reached."); } finally { setBusy(false); }
        }}>
          <div className="grid gap-1">
            <h1 className="!text-2xl">{invite ? tr("Welcome, {0}", { 0: info.display_name }) : tr("Choose a new password")}</h1>
            <p className="text-muted-foreground">{invite ? tr("Choose a password to finish setting up your account.") : tr("For")} {!invite && info.email}{info.kind === "admin_recovery" ? tr(". Your two-factor will be cleared, so you'll set it up again.") : ""}</p>
          </div>
          <input type="email" autoComplete="username" value={info.email} readOnly hidden />
          <label className="field"><span>{tr("New password, at least 12 characters")}</span><Input className="h-10" type="password" autoComplete="new-password" minLength={12} required autoFocus value={pw} onChange={(e) => setPw(e.target.value)} /></label>
          <label className="field"><span>{tr("Type it again")}</span><Input className="h-10" type="password" autoComplete="new-password" minLength={12} required value={again} onChange={(e) => setAgain(e.target.value)} /></label>
          {error && <div className="err" role="alert">{error}</div>}
          <Button size="lg" className="h-10 w-full" disabled={busy}>{busy && <Loader2 className="animate-spin" />}{tr("Save password")}</Button>
        </form>
      )}
    </AuthLayout>
  );
}
