import { CustomerNav } from "@/components/Nav";
import { LinkForm } from "@/components/Forms";
import { BANKS } from "@/lib/banks";
import { nuban } from "@/lib/sample";
import { currentCustomer } from "@/lib/session";
export const dynamic = "force-dynamic";
export default async function Page() {
  const c = await currentCustomer();
  return <><CustomerNav who={c.ref} /><main style={{ maxWidth: 520 }}><div className="card"><h1>Link your bank account</h1><p className="muted">These banks are fictional.</p><LinkForm banks={BANKS} sample={{ bank: BANKS[0]!, nuban: nuban("811") }} /></div></main></>;
}
