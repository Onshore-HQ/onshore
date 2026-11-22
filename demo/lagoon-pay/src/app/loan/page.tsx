import { CustomerNav } from "@/components/Nav";
import { LoanForm } from "@/components/Forms";
import { currentCustomer } from "@/lib/session";
export const dynamic = "force-dynamic";
export default async function Page() {
  const c = await currentCustomer();
  return <><CustomerNav who={c.ref} /><main style={{ maxWidth: 520 }}><div className="card"><h1>Apply for a loan</h1><LoanForm /></div></main></>;
}
