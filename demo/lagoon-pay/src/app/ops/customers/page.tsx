import Link from "next/link";
import { OpsNav } from "@/components/Nav";
import { StaffSwitch } from "@/components/Forms";
import { db } from "@/lib/db";
import { state } from "@/lib/config";
import { staffRole } from "@/lib/staff";
export const dynamic = "force-dynamic";
const short = (v: string) => (v.startsWith("tok_") ? `${v.slice(0, 16)}…` : v);
export default async function Page({ searchParams }: { searchParams: Promise<{ q?: string; city?: string }> }) {
  const { q, city } = await searchParams;
  const where = { ...(city ? { city } : {}), ...(q ? { OR: [{ ref: { contains: q, mode: "insensitive" as const } }, { fullName: { contains: q, mode: "insensitive" as const } }] } : {}) };
  const [rows, total, cities] = await Promise.all([db.customer.findMany({ where, include: { accounts: { take: 1 } }, orderBy: { id: "desc" }, take: 40 }), db.customer.count({ where }), db.customer.findMany({ distinct: ["city"], select: { city: true }, orderBy: { city: "asc" } })]);
  return <><OpsNav right={<StaffSwitch role={await staffRole()} />} /><main className="wide"><h1>Customers</h1><p className="muted">{total.toLocaleString("en-NG")} customers. {state().config.tokenize_at_source ? "Identifier columns hold tokens." : "Identifier columns hold real values."}</p>
    <form className="card" style={{ display: "flex", gap: 8, alignItems: "end" }}><label style={{ flex: 1, margin: 0 }}>Search<input name="q" defaultValue={q} placeholder="Name or reference" /></label><label style={{ margin: 0 }}>City<select name="city" defaultValue={city ?? ""}><option value="">Any</option>{cities.map((c) => <option key={c.city}>{c.city}</option>)}</select></label><button>Filter</button></form>
    <div className="card"><table><thead><tr><th>Reference</th><th>Name</th><th>BVN</th><th>Phone</th><th>Account</th><th>City</th></tr></thead><tbody>{rows.map((c) => <tr key={c.id}><td><Link href={`/ops/customers/${c.id}`}>{c.ref}</Link></td><td>{short(c.fullName)}</td><td className="mono">{short(c.bvn)}</td><td className="mono">{short(c.phone)}</td><td className="mono">{c.accounts[0] ? short(c.accounts[0].nuban) : ""}</td><td>{c.city}</td></tr>)}</tbody></table></div></main></>;
}
