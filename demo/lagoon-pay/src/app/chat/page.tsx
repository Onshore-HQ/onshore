import { CustomerNav } from "@/components/Nav";
import { Chat } from "@/components/Forms";
import { db } from "@/lib/db";
import { currentCustomer } from "@/lib/session";
export const dynamic = "force-dynamic";
export default async function Page() {
  const c = await currentCustomer();
  const m = await db.chatMessage.findMany({ where: { customerId: c.id }, orderBy: { createdAt: "asc" }, take: 30 });
  return <><CustomerNav who={c.ref} /><main style={{ maxWidth: 640 }}><div className="card"><h1>Support</h1><p className="muted">Our assistant replies right away.</p><Chat initial={m.map((x) => ({ role: x.role, content: x.content }))} /></div></main></>;
}
