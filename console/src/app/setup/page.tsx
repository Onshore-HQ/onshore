"use client";
import { tr } from "@/lib/i18n";
import { AuthLayout } from "@/components/AuthLayout";
import { useState } from "react";

export default function Setup() {
  const [f, setF] = useState({ bootstrap_token: "", organisation: "", display_name: "", email: "", password: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  return (
    <AuthLayout>
      <form
        className="auth-form"
        style={{ gap: 12, padding: 20 }}
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          const res = await fetch("/api/proxy/control/v1/bootstrap", { method: "POST", headers: { "content-type": "application/json", "x-rv-console": "1" }, body: JSON.stringify(f) });
          const d = await res.json().catch(() => ({}));
          if (res.ok) window.location.href = "/login";
          else {
            setError(d.error?.message ?? "setup failed");
            setBusy(false);
          }
        }}
      >
        <div>
          <h1>{tr("First-time setup")}</h1>
          <p className="muted">{tr("Create the first admin.")} <code>{tr("rv init")}</code> {tr("printed the bootstrap token.")}</p>
        </div>
        <label className="field"><span>{tr("Bootstrap token")}</span><input required value={f.bootstrap_token} onChange={set("bootstrap_token")} autoFocus /></label>
        <label className="field"><span>{tr("Organisation")}</span><input required value={f.organisation} onChange={set("organisation")} /></label>
        <label className="field"><span>{tr("Your name")}</span><input required value={f.display_name} onChange={set("display_name")} /></label>
        <label className="field"><span>{tr("Work email")}</span><input type="email" required value={f.email} onChange={set("email")} /></label>
        <label className="field"><span>{tr("Password, at least 12 characters")}</span><input type="password" required minLength={12} value={f.password} onChange={set("password")} /></label>
        {error && <div className="err" role="alert">{error}</div>}
        <button className="primary" disabled={busy} style={{ justifyContent: "center" }}>{tr("Create admin")}</button>
      </form>
    </AuthLayout>
  );
}
