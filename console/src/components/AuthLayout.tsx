import { tr } from "@/lib/i18n";
import { Eye, FileCheck2, MapPin } from "lucide-react";
import { Logo } from "@/components/Logo";
import { ReactNode } from "react";

const POINTS = [
  { icon: MapPin, title: "Stays in the country", text: "Sensitive values live in your own vault, in the country they belong to, and only tokens leave." },
  { icon: Eye, title: "Nothing seen by accident", text: "Every look at a real value needs a policy, a reason and a record." },
  { icon: FileCheck2, title: "Evidence on demand", text: "A tamper-evident trail and reports, ready for your auditors." },
];

/** The sign-in and first-time setup pages. The panel says what the product is for. */
export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="auth">
      <aside className="auth-brand">
        <div className="flex items-center gap-3">
          <Logo light size={30} />
        </div>
        <div className="grid max-w-[30rem] gap-8">
          <p className="text-[34px] leading-[1.15] font-semibold tracking-tight">{tr("Your customers’ data, kept where it belongs.")}</p>
          <div className="grid gap-5">
            {POINTS.map((p) => (
              <div className="flex gap-3" key={p.title}>
                <span className="flex size-9 flex-none items-center justify-center rounded-lg bg-white/10"><p.icon className="size-[18px]" /></span>
                <div><div className="font-medium">{tr(p.title)}</div><div className="text-[13px] text-[#C4D2E8]">{tr(p.text)}</div></div>
              </div>
            ))}
          </div>
        </div>
        <div className="text-xs text-[#9DB2D3]">{tr("Self-hosted on your own infrastructure.")}</div>
      </aside>
      <main className="auth-main">{children}</main>
    </div>
  );
}
