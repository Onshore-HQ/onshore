import Link from "next/link";
export default function Home() {
  return <main><header className="logo" style={{ marginBottom: 18 }}><i />Lagoon Pay</header><div className="card"><h1>Your money, moving like water.</h1><p className="muted">A wallet and quick loans for Nigerians, wherever you are.</p><Link className="btn" href="/signup">Open an account</Link> <Link className="btn" style={{ background: "#e8efed", color: "#10211f" }} href="/ops/customers">Staff back office</Link></div></main>;
}
