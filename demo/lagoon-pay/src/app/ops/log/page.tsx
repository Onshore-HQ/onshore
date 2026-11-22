import { OpsNav } from "@/components/Nav";
import { db } from "@/lib/db";
export const dynamic = "force-dynamic";
export default async function Page() {
  const rows = await db.opsLine.findMany({ orderBy: { id: "desc" }, take: 80 });
  return <><OpsNav /><main className="wide"><h1>Ops log</h1><p className="muted">The app&rsquo;s own recent log lines, as written before they leave for the log tool.</p><div className="card"><table><tbody>{rows.map((l) => <tr key={l.id}><td className="muted" style={{ whiteSpace: "nowrap" }}>{l.createdAt.toISOString().slice(11, 19)}</td><td><span className={`tag ${l.level === "ERROR" ? "bad" : ""}`}>{l.level}</span></td><td className="mono">{l.line}</td></tr>)}</tbody></table></div></main></>;
}
