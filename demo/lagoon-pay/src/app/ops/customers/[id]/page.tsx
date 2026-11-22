import { notFound } from "next/navigation";
import { OpsNav } from "@/components/Nav";
import { Reveal, StaffSwitch } from "@/components/Forms";
import { db } from "@/lib/db";
import { staffRole } from "@/lib/staff";
export const dynamic = "force-dynamic";
const naira = (n: number) => `₦${n.toLocaleString("en-NG")}`;
function Field({ label, value }: { label: string; value: string }) {
  const tok = value.startsWith("tok_");
  return <tr><th style={{ width: 150 }}>{label}</th><td><span className="mono">{value || "None"}</span> {tok && <Reveal token={value} label={label} />}</td></tr>;
}
export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const c = await db.customer.findUnique({ where: { id: Number((await params).id) }, include: { accounts: true, transfers: { orderBy: { createdAt: "desc" }, take: 8 }, loans: { orderBy: { createdAt: "desc" }, take: 5 }, chats: { orderBy: { createdAt: "desc" }, take: 8 } } });
  if (!c) notFound();
  return <><OpsNav right={<StaffSwitch role={await staffRole()} />} /><main className="wide"><h1>{c.ref}</h1><p className="muted">{c.city}. {c.tokenized ? "Stored as tokens. Revealing needs a reason, and Onshore records it." : "Stored as real values."}</p>
    <div className="grid"><div className="card"><h2>Profile</h2><table><tbody><Field label="Name" value={c.fullName} /><Field label="BVN" value={c.bvn} /><Field label="NIN" value={c.nin} /><Field label="Phone" value={c.phone} /><Field label="Email" value={c.email} /><tr><th>Date of birth</th><td>{c.dob}</td></tr></tbody></table></div>
    <div className="card"><h2>Linked accounts</h2><table><tbody>{c.accounts.map((a) => <Field key={a.id} label={a.bank} value={a.nuban} />)}</tbody></table></div></div>
    <div className="card"><h2>Transfers</h2><table><thead><tr><th>Date</th><th>To</th><th>Account</th><th>Amount</th><th>Status</th></tr></thead><tbody>{c.transfers.map((t) => <tr key={t.id}><td>{t.createdAt.toISOString().slice(0, 10)}</td><td>{t.toName}</td><td className="mono">{t.toAccount}</td><td>{naira(t.amount)}</td><td><span className={`tag ${t.status === "success" ? "ok" : "bad"}`}>{t.status}</span></td></tr>)}</tbody></table></div>
    <div className="grid"><div className="card"><h2>Loans</h2>{c.loans.length === 0 ? <p className="muted">None.</p> : <table><tbody>{c.loans.map((l) => <tr key={l.id}><td className="mono">{l.loanRef}</td><td>{naira(l.amount)}</td><td>{l.status}</td></tr>)}</tbody></table>}</div>
    <div className="card"><h2>Chat history</h2>{c.chats.length === 0 ? <p className="muted">None.</p> : c.chats.map((m) => <p key={m.id} className="muted"><b>{m.role}:</b> {m.content}</p>)}</div></div></main></>;
}
