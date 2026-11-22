import { CustomerNav } from "@/components/Nav";
import { SignupForm } from "@/components/Forms";
import { sampleCustomer } from "@/lib/sample";
export const dynamic = "force-dynamic";
export default function Page() {
  return <><CustomerNav /><main style={{ maxWidth: 520 }}><div className="card"><h1>Open your Lagoon account</h1><p className="muted">It takes two minutes.</p><SignupForm sample={sampleCustomer()} /></div></main></>;
}
