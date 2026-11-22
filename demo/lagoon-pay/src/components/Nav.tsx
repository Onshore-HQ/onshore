import Link from "next/link";
export function CustomerNav({ who }: { who?: string }) {
  return <header className="top"><Link className="logo" href="/wallet"><i />Lagoon Pay</Link><nav><Link href="/wallet">Wallet</Link><Link href="/send">Send money</Link><Link href="/loan">Loans</Link><Link href="/chat">Support</Link><Link href="/link">Link a bank</Link></nav><span className="right">{who}</span></header>;
}
export function OpsNav({ right }: { right?: React.ReactNode }) {
  return <header className="top"><Link className="logo" href="/ops/customers"><i />Lagoon Back Office</Link><nav><Link href="/ops/customers">Customers</Link><Link href="/ops/log">Ops log</Link></nav><span className="right">{right}</span></header>;
}
