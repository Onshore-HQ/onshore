"use client";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

async function post(path: string, body: unknown) {
  const r = await fetch(`/api/${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error ?? "Something went wrong");
  return j;
}
function values(f: HTMLFormElement) { return Object.fromEntries(new FormData(f).entries()) as Record<string, string>; }

export function SignupForm({ sample }: { sample: Record<string, string> }) {
  const router = useRouter(); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  return <form onSubmit={async (e) => { e.preventDefault(); setBusy(true); setErr(""); try { await post("signup", values(e.currentTarget)); router.push("/link"); } catch (x) { setErr((x as Error).message); setBusy(false); } }}>
    <label>Full name<input name="fullName" defaultValue={sample.fullName} required /></label>
    <label>Phone<input name="phone" defaultValue={sample.phone} required /></label>
    <label>Email<input name="email" type="email" defaultValue={sample.email} required /></label>
    <label>Date of birth<input name="dob" type="date" defaultValue={sample.dob} required /></label>
    <label>BVN<input name="bvn" defaultValue={sample.bvn} required pattern="\d{11}" /></label>
    <p className="muted">Filled with made-up details. Never type a real BVN here.</p>
    {err && <p className="err">{err}</p>}<button disabled={busy}>Create account</button>
  </form>;
}
export function LinkForm({ banks, sample }: { banks: string[]; sample: { bank: string; nuban: string } }) {
  const router = useRouter(); const [err, setErr] = useState("");
  return <form onSubmit={async (e) => { e.preventDefault(); try { await post("accounts", values(e.currentTarget)); router.push("/wallet"); router.refresh(); } catch (x) { setErr((x as Error).message); } }}>
    <label>Bank<select name="bank" defaultValue={sample.bank}>{banks.map((b) => <option key={b}>{b}</option>)}</select></label>
    <label>Account number<input name="account" defaultValue={sample.nuban} required pattern="\d{10}" /></label>
    {err && <p className="err">{err}</p>}<button>Link account</button>
  </form>;
}
export function SendForm({ banks }: { banks: string[] }) {
  const [msg, setMsg] = useState<{ ok: boolean; t: string } | null>(null); const router = useRouter();
  return <form onSubmit={async (e) => { e.preventDefault(); const f = e.currentTarget; const v = values(f); try { const t = await post("transfers", { bank: v.bank, account: v.account, name: v.name, amount: Number(v.amount), narration: v.narration, fail: v.fail === "on" ? true : undefined }); setMsg(t.status === "failed" ? { ok: false, t: "This transfer failed. Your money is safe." } : { ok: true, t: "Sent." }); router.refresh(); } catch (x) { setMsg({ ok: false, t: (x as Error).message }); } }}>
    <label>Recipient bank<select name="bank">{banks.map((b) => <option key={b}>{b}</option>)}</select></label>
    <label>Account number<input name="account" required pattern="\d{10}" defaultValue="0000000000" /></label>
    <label>Recipient name<input name="name" required defaultValue="Bisi Adeyemi" /></label>
    <label>Amount (₦)<input name="amount" type="number" min="100" required defaultValue="250000" /></label>
    <label>Narration<input name="narration" defaultValue="Rent" /></label>
    <label style={{ display: "flex", gap: 8, alignItems: "center" }}><input type="checkbox" name="fail" style={{ width: "auto" }} /> Make this one fail (for the demo)</label>
    {msg && <p className={msg.ok ? "okm" : "err"}>{msg.t}</p>}<button>Send money</button>
  </form>;
}
export function LoanForm() {
  const [msg, setMsg] = useState("");
  return <form onSubmit={async (e) => { e.preventDefault(); const r = await post("loans", values(e.currentTarget)); setMsg(`Application ${r.loanRef} is in review.`); }}>
    <label>Amount (₦)<input name="amount" type="number" defaultValue="300000" required /></label><label>Tenor (months)<input name="tenor" type="number" defaultValue="6" required /></label>
    <label>Monthly income (₦)<input name="income" type="number" defaultValue="250000" required /></label><label>Employer<input name="employer" defaultValue="Harbour Foods Ltd" required /></label>
    {msg && <p className="okm">{msg}</p>}<button>Apply</button>
  </form>;
}
export function Chat({ initial }: { initial: { role: string; content: string }[] }) {
  const [list, setList] = useState(initial); const [busy, setBusy] = useState(false); const end = useRef<HTMLDivElement>(null);
  useEffect(() => { end.current?.scrollIntoView(); }, [list]);
  return <div><div style={{ maxHeight: 420, overflow: "auto", display: "flex", flexDirection: "column" }}>{list.map((m, i) => <div key={i} className={`bubble ${m.role}`}>{m.content}</div>)}<div ref={end} /></div>
    <form style={{ display: "flex", gap: 8, marginTop: 8 }} onSubmit={async (e) => { e.preventDefault(); const f = e.currentTarget; const message = values(f).message; if (!message) return; f.reset(); setBusy(true); setList((l) => [...l, { role: "user", content: message }]); const r = await post("chat", { message }).catch((x) => ({ reply: x.message })); setList((l) => [...l, { role: "assistant", content: r.reply }]); setBusy(false); }}>
      <input name="message" aria-label="Your message" placeholder="Type your message" /><button disabled={busy}>Send</button></form></div>;
}
const STAFF: [string, string][] = [["support_agent", "Support agent, Lagos"], ["ops_lead", "Ops lead, Lagos"], ["contractor", "Contractor abroad"]];
export function StaffSwitch({ role }: { role: string }) {
  const router = useRouter();
  return <label style={{ margin: 0, display: "flex", gap: 6, alignItems: "center" }}>Signed in as<select style={{ width: "auto", padding: "4px 8px" }} value={role} onChange={async (e) => { await post("staff", { role: e.target.value }); router.refresh(); }}>{STAFF.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>;
}
export function Reveal({ token, label }: { token: string; label: string }) {
  const [open, setOpen] = useState(false); const [purpose, setPurpose] = useState(""); const [res, setRes] = useState<{ decision: string; value: string | null; policy?: string | null; who?: string } | null>(null);
  useEffect(() => { if (!res?.value) return; const t = setTimeout(() => setRes(null), 30000); return () => clearTimeout(t); }, [res]);
  if (res) return <span className="mono">{res.decision === "denied" ? <span className="tag bad">Denied by policy</span> : <><b>{res.value}</b> <span className={`tag ${res.decision === "plaintext" ? "ok" : ""}`}>{res.decision}</span></>} <span className="muted">{res.who}</span></span>;
  if (!open) return <button type="button" className="ghost" style={{ padding: "2px 9px", fontSize: 12 }} onClick={() => setOpen(true)}>Reveal</button>;
  return <form style={{ display: "flex", gap: 6, alignItems: "center" }} onSubmit={async (e) => { e.preventDefault(); setRes(await post("reveal", { token, purpose })); }}><input autoFocus style={{ padding: "3px 8px", fontSize: 13 }} aria-label={`Why do you need this ${label}?`} placeholder="Purpose, such as a ticket number" value={purpose} onChange={(e) => setPurpose(e.target.value)} required /><button style={{ padding: "3px 10px", fontSize: 13 }}>Show</button></form>;
}
