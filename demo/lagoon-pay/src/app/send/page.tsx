import { CustomerNav } from "@/components/Nav";
import { SendForm } from "@/components/Forms";
import { BANKS } from "@/lib/banks";
import { nuban } from "@/lib/sample";
import { currentCustomer } from "@/lib/session";
export const dynamic = "force-dynamic";
export default async function Page() {
  const c = await currentCustomer();
  return <><CustomerNav who={c.ref} /><main style={{ maxWidth: 520 }}><div className="card"><h1>Send money</h1><p className="muted">A made-up account to try: <span className="mono">{nuban("844")}</span> at Delta Crest Bank</p><SendForm banks={BANKS} /></div></main></>;
}
