"use client";
import { tr } from "@/lib/i18n";
import { ArrowRight } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { Modal, Page } from "@/components/ui";
import { Source, SOURCES } from "@/lib/sources";

export default function Connect() {
  const [open, setOpen] = useState<Source | null>(null);
  return (
    <Page title={tr("Connect something")} sub={tr("Where does sensitive data leave your company? Pick one to see what it takes. You can add more at any time.")}>
      <div className="catalog">
        {SOURCES.map((x) => (
          <button key={x.key} className="catalog-card" onClick={() => setOpen(x)}>
            <span className="tile blue" aria-hidden><x.icon className="size-[18px]" /></span>
            <span className="min-w-0"><span className="block font-medium">{x.title}</span><span className="block text-[13px] font-normal text-muted-foreground">{x.line}</span></span>
          </button>
        ))}
      </div>
      {open && (
        <Modal title={open.title} onClose={() => setOpen(null)}>
          <div><h3>{tr("What this stops")}</h3><p className="text-muted-foreground">{open.stops}</p></div>
          <div><h3>{tr("What you need")}</h3><ul className="mt-1 list-disc pl-5 text-muted-foreground">{open.need.map((x) => <li key={x}>{x}</li>)}</ul></div>
          <div><h3>{tr("What happens")}</h3><ol className="mt-1 list-decimal pl-5 text-muted-foreground">{open.steps.map((x) => <li key={x}>{x}</li>)}</ol></div>
          {open.watch && <div className="note good small">{tr("It starts as watch only, so nothing changes until you turn protection on.")}</div>}
          <div className="row" style={{ justifyContent: "flex-end" }}>
            {open.href === "/developers"
              ? <a className="btn primary" href="https://onshorevault.com/developers" target="_blank" rel="noreferrer">{open.cta}<ArrowRight className="size-4" /></a>
              : <Link className="btn primary" href={open.href}>{open.cta}<ArrowRight className="size-4" /></Link>}
          </div>
        </Modal>
      )}
    </Page>
  );
}
