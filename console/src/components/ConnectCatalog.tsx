"use client";
import { tr } from "@/lib/i18n";
import { ArrowLeft, ArrowRight } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { Modal } from "@/components/ui";
import { Source, SOURCES } from "@/lib/sources";

/** Pick what to connect, then see what it takes, without leaving the page you were on. */
export function ConnectCatalog({ onClose }: { onClose: () => void }) {
  const [open, setOpen] = useState<Source | null>(null);
  if (open) {
    return (
      <Modal title={open.title} onClose={onClose}>
        <button type="button" className="link w-fit text-[13px]" onClick={() => setOpen(null)}><ArrowLeft className="size-3.5" />{tr("All kinds")}</button>
        <SourceDetail s={open} />
      </Modal>
    );
  }
  return (
    <Modal title={tr("Add a connection")} onClose={onClose}>
      <p className="text-muted-foreground">{tr("Where does sensitive data leave your company? Pick one to see what it takes.")}</p>
      <div className="catalog-drawer">
        {SOURCES.map((x) => (
          <button key={x.key} type="button" className="catalog-card" onClick={() => setOpen(x)}>
            <span className="tile blue" aria-hidden><x.icon className="size-[18px]" /></span>
            <span className="min-w-0"><span className="block font-medium">{x.title}</span><span className="block text-[13px] font-normal text-muted-foreground">{x.line}</span></span>
          </button>
        ))}
      </div>
    </Modal>
  );
}

export function SourceDetail({ s }: { s: Source }) {
  return (
    <>
      <div className="row"><span className="tile blue" aria-hidden><s.icon className="size-[18px]" /></span><span className="text-muted-foreground">{s.line}</span></div>
      <div><h3>{tr("What this stops")}</h3><p className="text-muted-foreground">{s.stops}</p></div>
      <div><h3>{tr("What you need")}</h3><ul className="mt-1 list-disc pl-5 text-muted-foreground">{s.need.map((x) => <li key={x}>{x}</li>)}</ul></div>
      <div><h3>{tr("What happens")}</h3><ol className="mt-1 list-decimal pl-5 text-muted-foreground">{s.steps.map((x) => <li key={x}>{x}</li>)}</ol></div>
      {s.watch && <div className="note good small">{tr("It starts as watch only, so nothing changes until you turn protection on.")}</div>}
      <div className="row" style={{ justifyContent: "flex-end" }}>
        {s.href === "/developers"
          ? <a className="btn primary" href="https://onshorevault.com/developers" target="_blank" rel="noreferrer">{s.cta}<ArrowRight className="size-4" /></a>
          : <Link className="btn primary" href={s.href}>{s.cta}<ArrowRight className="size-4" /></Link>}
      </div>
    </>
  );
}
