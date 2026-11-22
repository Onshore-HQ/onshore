"use client";
import { tr } from "@/lib/i18n";
import { ArrowDown, ArrowUp, Check, ChevronsUpDown, X } from "lucide-react";
import { ReactNode, useState } from "react";
import { Button } from "@/components/ui/button";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { TableHead } from "@/components/ui/table";
import { n } from "@/lib/api";
import { cn } from "@/lib/utils";

export type Dir = "asc" | "desc";
export interface SortState<K extends string> { key: K; dir: Dir }

/** A column heading that sorts. The first click on a new column uses `first`. */
export function SortHead<K extends string>({ label, col, sort, onSort, first = "desc", num }: { label: string; col: K; sort: SortState<K>; onSort: (s: SortState<K>) => void; first?: Dir; num?: boolean }) {
  const on = sort.key === col;
  const Icon = !on ? ChevronsUpDown : sort.dir === "asc" ? ArrowUp : ArrowDown;
  return (
    <TableHead className={num ? "num text-right" : undefined} aria-sort={on ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" data-slot="sort-button" className={cn("sort-head", on && "on")} onClick={() => onSort({ key: col, dir: on ? (sort.dir === "asc" ? "desc" : "asc") : first })}>
        {label}<Icon aria-hidden className="size-3.5" />
      </button>
    </TableHead>
  );
}

const ALL = "__all";

/** A dropdown filter. An empty value means no filter; Radix does not allow an empty item value. */
export function FilterSelect({ label, all, value, onChange, options, className }: { label: string; all: string; value: string; onChange: (v: string) => void; options: [string, string][]; className?: string }) {
  return (
    <Select value={value || ALL} onValueChange={(v) => onChange(v === ALL ? "" : v)}>
      <SelectTrigger aria-label={label} className={cn("filter-trigger", value && "active", className)}><SelectValue /></SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>{all}</SelectItem>
        {options.map(([v, l]) => <SelectItem key={v} value={v}>{l}</SelectItem>)}
      </SelectContent>
    </Select>
  );
}

/** A searchable dropdown, for lists too long to scan. */
export function FilterCombo({ label, all, value, onChange, options, placeholder }: { label: string; all: string; value: string; onChange: (v: string) => void; options: [string, string][]; placeholder: string }) {
  const [open, setOpen] = useState(false);
  const pick = (v: string) => { onChange(v); setOpen(false); };
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button type="button" variant="outline" role="combobox" aria-label={label} aria-expanded={open} className={cn("filter-trigger font-normal", value && "active")}>
          {options.find(([v]) => v === value)?.[1] ?? all}<ChevronsUpDown aria-hidden className="size-4 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-64 p-0">
        <Command>
          <CommandInput placeholder={placeholder} />
          <CommandList>
            <CommandEmpty>{tr("Nothing matches.")}</CommandEmpty>
            <CommandGroup>
              <CommandItem value={all} onSelect={() => pick("")}>{all}{!value && <Check aria-hidden className="ml-auto" />}</CommandItem>
              {options.map(([v, l]) => <CommandItem key={v} value={`${l} ${v}`} onSelect={() => pick(v)}>{l}{value === v && <Check aria-hidden className="ml-auto" />}</CommandItem>)}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

/** What is filtered right now, each removable on its own. */
export function FilterChips({ chips, onClear }: { chips: { key: string; label: ReactNode; clear: () => void }[]; onClear: () => void }) {
  if (chips.length === 0) return null;
  return (
    <div className="filter-chips">
      {chips.map((c) => (
        <span key={c.key} className="filter-chip">{c.label}<button type="button" data-slot="chip-remove" aria-label={tr("Remove this filter")} onClick={c.clear}><X aria-hidden className="size-3" /></button></span>
      ))}
      <Button type="button" variant="link" size="sm" className="h-auto p-0" onClick={onClear}>{tr("Clear all")}</Button>
    </div>
  );
}

/** "Showing 1 to 50 of 120", with paging and page size. */
export function PageBar({ offset, size, total, noun, onOffset, onSize }: { offset: number; size: number; total: number; noun: string; onOffset: (o: number) => void; onSize: (s: number) => void }) {
  return (
    <div className="spread mt-2 flex-wrap gap-2 text-[13px] text-muted-foreground">
      <span>{tr("Showing")} {n(Math.min(offset + 1, total))} to {n(Math.min(offset + size, total))} of {n(total)} {noun}</span>
      <span className="row">
        <Select value={String(size)} onValueChange={(v) => onSize(Number(v))}>
          <SelectTrigger aria-label={tr("Rows per page")} className="filter-trigger"><SelectValue /></SelectTrigger>
          <SelectContent>{[25, 50, 100].map((s) => <SelectItem key={s} value={String(s)}>{s} {tr("per page")}</SelectItem>)}</SelectContent>
        </Select>
        <Button type="button" variant="outline" size="sm" disabled={offset === 0} onClick={() => onOffset(Math.max(0, offset - size))}>{tr("Previous")}</Button>
        <Button type="button" variant="outline" size="sm" disabled={offset + size >= total} onClick={() => onOffset(offset + size)}>{tr("Next")}</Button>
      </span>
    </div>
  );
}
