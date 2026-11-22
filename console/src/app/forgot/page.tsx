"use client";
import { tr } from "@/lib/i18n";
import { Loader2 } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { AuthLayout } from "@/components/AuthLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export default function Forgot() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <AuthLayout>
      {sent ? (
        <div className="auth-form">
          <div className="grid gap-1">
            <h1 className="!text-2xl">{tr("Check your email")}</h1>
            <p className="text-muted-foreground">{tr("If that address has an account, and your organisation has set up email, a link is on its way. It works for an hour.")}</p>
            <p className="text-muted-foreground">{tr("Nothing after a few minutes? Ask your admin to reset your password from the People page.")}</p>
          </div>
          <Link className="small text-center" href="/login">{tr("Back to sign in")}</Link>
        </div>
      ) : (
        <form className="auth-form" onSubmit={async (e) => {
          e.preventDefault(); setBusy(true); setError(null);
          try {
            const r = await fetch("/api/proxy/control/v1/auth/forgot", { method: "POST", headers: { "content-type": "application/json", "x-rv-console": "1" }, body: JSON.stringify({ email }) });
            if (r.ok) setSent(true);
            else setError(r.status === 429 ? "Too many tries. Wait a while, or ask your admin." : "That didn't work. Check the address and try again.");
          } catch { setError("The service cannot be reached."); } finally { setBusy(false); }
        }}>
          <div className="grid gap-1">
            <h1 className="!text-2xl">{tr("Forgot your password?")}</h1>
            <p className="text-muted-foreground">{tr("We'll email you a link to choose a new one. You'll still need your two-factor code to sign in.")}</p>
          </div>
          <label className="field"><span>{tr("Email")}</span><Input className="h-10" type="email" autoComplete="username" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          {error && <div className="err" role="alert">{error}</div>}
          <Button size="lg" className="h-10 w-full" disabled={busy}>{busy && <Loader2 className="animate-spin" />}{tr("Send the link")}</Button>
          <Link className="small text-center" href="/login">{tr("Back to sign in")}</Link>
        </form>
      )}
    </AuthLayout>
  );
}
