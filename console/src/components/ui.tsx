"use client";
import { tr } from "@/lib/i18n";
import { AlertCircle, Check, CheckCircle2, CircleHelp, Copy as CopyIcon, Download, Inbox, Info, TriangleAlert, XCircle } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ReactNode, useState } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge as UiBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { GLOSSARY, HELP } from "@/lib/help";
import { decisionLabel } from "@/lib/labels";
import { findNav } from "@/lib/nav";
import { cn } from "@/lib/utils";

/** Answers "what am I looking at?" beside the work, in plain words. */
function HelpDrawer({ path }: { path: string }) {
  const [open, setOpen] = useState(false);
  const key = Object.keys(HELP).sort((a, b) => b.length - a.length).find((k) => path.startsWith(k));
  if (!key) return null;
  const h = HELP[key]!;
  const others = Object.keys(GLOSSARY).filter((t) => !h.terms?.includes(t));
  return (
    <>
      <Button variant="ghost" size="sm" className="text-muted-foreground" onClick={() => setOpen(true)}><CircleHelp />{tr("What is this?")}</Button>
      {open && (
        <Modal title={tr("What is this page?")} onClose={() => setOpen(false)}>
          <p>{tr(h.what)}</p>
          <div><h3>{tr("When you would use it")}</h3><ul className="mt-1 list-disc pl-5 text-muted-foreground">{h.when.map((w) => <li key={w}>{tr(w)}</li>)}</ul></div>
          {h.terms && <div className="grid gap-2"><h3>{tr("Words on this page")}</h3>{h.terms.map((t) => <div key={t}><b>{tr(t)}.</b> <span className="text-muted-foreground">{tr(GLOSSARY[t] ?? "")}</span></div>)}</div>}
          {h.next && <div><Link className="btn" href={h.next.href} onClick={() => setOpen(false)}>{tr(h.next.label)}</Link></div>}
          <details><summary className="cursor-pointer font-medium">{tr("All the words Onshore uses")}</summary><div className="mt-2 grid gap-2">{others.map((t) => <div key={t}><b>{tr(t)}.</b> <span className="text-muted-foreground">{tr(GLOSSARY[t] ?? "")}</span></div>)}</div></details>
        </Modal>
      )}
    </>
  );
}

export function Page({ title, sub, actions, children }: { title: string; sub?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  const path = usePathname();
  const nav = findNav(path);
  return (
    <div>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-[18rem] flex-1 basis-0 items-start gap-3">
          {nav && <span className="page-icon" aria-hidden><nav.icon className="size-5" /></span>}
          <div className="min-w-0">
            <h1>{title}</h1>
            {sub && <p className="mt-0.5 max-w-[72ch] text-muted-foreground">{sub}</p>}
          </div>
        </div>
        <div className="row"><HelpDrawer path={path} />{actions}</div>
      </div>
      {children}
    </div>
  );
}

/** A headline number that says what it means and what it is made of. */
export function Stat({ icon: Icon, tone = "blue", label, value, hint, children }: { icon: typeof Info; tone?: "blue" | "teal" | "amber" | "rose"; label: string; value: ReactNode; hint?: ReactNode; children?: ReactNode }) {
  return (
    <div className="card stat-card">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[13px] font-medium text-muted-foreground">{label}</span>
        <span className={`tile ${tone}`} aria-hidden><Icon className="size-[18px]" /></span>
      </div>
      <div className="stat">{value}</div>
      {hint && <div className="text-[13px] text-muted-foreground">{hint}</div>}
      {children && <div className="row mt-1">{children}</div>}
    </div>
  );
}

export function Loading({ error, loading }: { error: string | null; loading: boolean }) {
  if (error) return <Alert variant="destructive"><AlertCircle /><AlertDescription>{error}</AlertDescription></Alert>;
  if (loading) return <div className="grid gap-2" role="status" aria-label={tr("Loading")}><Skeleton className="h-9 w-full" /><Skeleton className="h-9 w-full" /><Skeleton className="h-9 w-2/3" /></div>;
  return null;
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="grid justify-items-center gap-2 rounded-xl border border-dashed bg-card p-10 text-center">
      <span className="flex size-10 items-center justify-center rounded-full bg-accent text-accent-foreground"><Inbox className="size-5" /></span>
      <h2>{title}</h2>
      {children && <div className="max-w-[56ch] text-muted-foreground">{children}</div>}
      {action && <div className="row mt-2 justify-center">{action}</div>}
    </div>
  );
}

type Tone = "good" | "warn" | "bad" | "info" | "";
const TONE: Record<string, { icon?: typeof Info; cls: string }> = {
  good: { icon: CheckCircle2, cls: "bg-good-soft text-good" },
  warn: { icon: TriangleAlert, cls: "bg-warn-soft text-warn" },
  bad: { icon: XCircle, cls: "bg-bad-soft text-bad" },
  info: { icon: Info, cls: "bg-info-soft text-info" },
  "": { cls: "bg-muted text-muted-foreground" },
};

/** Status never relies on color alone: every tone also has an icon and a word. */
export function Badge({ tone = "", children }: { tone?: Tone; children: ReactNode }) {
  const t = TONE[tone]!;
  return <UiBadge variant="secondary" className={cn("badge", tone, t.cls)}>{t.icon && <t.icon aria-hidden />}{children}</UiBadge>;
}

export function DecisionBadge({ value }: { value?: string | null }) {
  const tone: Tone = value === "plaintext" ? "warn" : value === "masked" ? "info" : value === "denied" ? "bad" : value ? "good" : "";
  return <Badge tone={tone}>{value ? decisionLabel(value) : "n/a"}</Badge>;
}

/** Tasks open in a drawer, so the page you came from stays in view. */
export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="modal w-full gap-0 overflow-y-auto sm:max-w-xl" aria-describedby={undefined}>
        <SheetHeader className="border-b"><SheetTitle className="pr-8 text-base">{title}</SheetTitle></SheetHeader>
        <div className="grid min-w-0 gap-3 p-4">{children}</div>
      </SheetContent>
    </Sheet>
  );
}

/** A decision that needs full attention stays in the centre of the screen. */
function CentredDialog({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="modal max-h-[90vh] overflow-auto sm:max-w-lg" aria-describedby={undefined}>
        <DialogHeader><DialogTitle>{title}</DialogTitle></DialogHeader>
        <div className="grid min-w-0 gap-3">{children}</div>
      </DialogContent>
    </Dialog>
  );
}

/** The hand-off after creating something secret: copy it, download it, and know it won't come back. */
export function ShownOnce({ items, children }: { items: { label: string; value: string; block?: boolean }[]; children?: ReactNode }) {
  const [json, setJson] = useState(false);
  const single = items.length === 1;
  const asText = items.map((i) => (i.block ? `${i.label}:\n${i.value}` : `${i.label}: ${i.value}`)).join("\n");
  const asJson = JSON.stringify(Object.fromEntries(items.map((i) => [i.label, i.value])), null, 2);
  const download = () => {
    const url = URL.createObjectURL(new Blob([json ? asJson : asText], { type: json ? "application/json" : "text/plain" }));
    const a = document.createElement("a");
    a.href = url; a.download = json ? "onshore-credentials.json" : "onshore-credentials.txt"; a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="grid gap-3">
      <div className="note warn"><b>{tr("This is shown once.")}</b> {tr("Copy or download it now, as you won't be able to see it again. Keep it in your secret store.")}</div>
      {!single && <div className="tabs w-fit">{[false, true].map((j) => <button key={String(j)} type="button" className={json === j ? "on" : ""} onClick={() => setJson(j)}>{j ? tr("JSON") : tr("Text")}</button>)}</div>}
      {json ? <pre className="pre">{asJson}</pre> : items.map((i) => (
        <div key={i.label} className="grid gap-1">
          <div className="spread"><span className="text-[13px] font-medium">{i.label}</span>{!single && <Copy text={i.value} />}</div>
          {i.block ? <pre className="pre">{i.value}</pre> : <code className="rounded-md border bg-muted px-2 py-1.5" style={{ overflowWrap: "anywhere" }}>{i.value}</code>}
        </div>
      ))}
      <div className="row"><Copy text={json ? asJson : asText} label={tr("Copy all")} /><Button type="button" variant="outline" size="sm" onClick={download}><Download />{tr("Download")}</Button></div>
      {children}
    </div>
  );
}

/** Destructive actions need the exact word typed: erase, revoke, rotate. */
export function TypedConfirm({ title, word, children, extra, onConfirm, onClose }: { title: string; word: string; children: ReactNode; extra?: ReactNode; onConfirm: () => Promise<void>; onClose: () => void }) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <CentredDialog title={title} onClose={onClose}>
      <div className="muted">{children}</div>
      {extra}
      <label className="field">
        <span>{tr("Type")} <b>{word}</b> {tr("to confirm")}</span>
        <Input autoFocus value={typed} onChange={(e) => setTyped(e.target.value)} />
      </label>
      {error && <div className="err">{error}</div>}
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <Button variant="outline" onClick={onClose}>{tr("Cancel")}</Button>
        <Button
          variant="destructive"
          className="danger"
          disabled={typed !== word || busy}
          onClick={async () => {
            setBusy(true);
            setError(null);
            try {
              await onConfirm();
              onClose();
            } catch (e) {
              setError(e instanceof Error ? e.message : "failed");
              setBusy(false);
            }
          }}
        >
          {word}
        </Button>
      </div>
    </CentredDialog>
  );
}

export function Copy({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setDone(true);
        setTimeout(() => setDone(false), 1500);
      }}
    >
      {done ? <Check /> : <CopyIcon />}{done ? tr("Copied") : label}
    </Button>
  );
}

export function ErrorLine({ error }: { error: string | null }) {
  return error ? <div className="err" role="alert">{error}</div> : null;
}

export function Checks({ options, value, onChange }: { options: string[]; value: string[]; onChange: (v: string[]) => void }) {
  return (
    <div className="checks">
      {options.map((o) => (
        <label key={o}>
          <Checkbox checked={value.includes(o)} onCheckedChange={(c) => onChange(c === true ? [...value, o] : value.filter((x) => x !== o))} />
          {o}
        </label>
      ))}
    </div>
  );
}

/** Arrow keys move through rows; Enter opens. */
export function rowKeys(e: React.KeyboardEvent<HTMLTableRowElement>, open: () => void) {
  if (e.key === "Enter") open();
  if (e.key === "ArrowDown") (e.currentTarget.nextElementSibling as HTMLElement | null)?.focus();
  if (e.key === "ArrowUp") (e.currentTarget.previousElementSibling as HTMLElement | null)?.focus();
}
