import Link from "next/link";
import { CustomerNav } from "@/components/Nav";
import { db } from "@/lib/db";
import { currentCustomer } from "@/lib/session";
export const dynamic = "force-dynamic";
const naira = (n: number) => `₦${n.toLocaleString("en-NG")}`;
export default async function Page() {
  const c = await currentCustomer();
  const tx = await db.transfer.findMany({ where: { customerId: c.id }, orderBy: { createdAt: "desc" }, take: 10 });
  return <><CustomerNav who={c.ref} /><main><div className="grid"><div className="card"><p className="muted">Wallet balance</p><div className="bal">{naira(c.accounts.reduce((t, a) => t + a.balance, 0))}</div><p style={{ marginTop: 10 }}><Link className="btn" href="/send">Send money</Link></p></div>
    <div className="card"><h2>Linked accounts</h2>{c.accounts.length === 0 ? <p className="muted">None yet. <Link href="/link">Link one</Link>.</p> : c.accounts.map((a) => <p key={a.id}>{a.bank} <span className="mono">•••• {a.last4}</span></p>)}</div></div>
    <div className="card"><h2>Recent transactions</h2>{tx.length === 0 ? <p className="muted">Nothing yet.</p> : <table><thead><tr><th>Date</th><th>To</th><th>Amount</th><th>Status</th></tr></thead><tbody>{tx.map((t) => <tr key={t.id}><td>{t.createdAt.toISOString().slice(0, 10)}</td><td>{t.toName}, {t.toBank}</td><td>{naira(t.amount)}</td><td><span className={`tag ${t.status === "success" ? "ok" : "bad"}`}>{t.status}</span></td></tr>)}</tbody></table>}</div></main></>;
}
