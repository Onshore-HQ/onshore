"use client";
import { tr } from "@/lib/i18n";
import { createContext, ReactNode, useContext, useMemo } from "react";
import { control, useLoad } from "./api";

interface Principal { id: string; display_name: string }
const Ctx = createContext<Map<string, string>>(new Map());

const CAN_LIST = ["admin", "compliance", "dpo", "engineer"];

/** Some roles cannot list people. They see "A teammate" rather than a raw ID, with the ID on hover. */
export function PeopleProvider({ roles, children }: { roles?: string[]; children: ReactNode }) {
  const allowed = (roles ?? []).some((r) => CAN_LIST.includes(r));
  const { value } = useLoad<{ principals: Principal[] } | null>(() => (allowed ? control("/v1/principals") : Promise.resolve(null)), [allowed]);
  const names = useMemo(() => new Map((value?.principals ?? []).map((p) => [p.id, p.display_name] as const)), [value]);
  return <Ctx.Provider value={names}>{children}</Ctx.Provider>;
}

export const usePeople = () => useContext(Ctx);

export function personName(names: Map<string, string>, id?: string | null): string {
  if (!id || id.startsWith("system:")) return "System";
  return names.get(id) ?? (/^(usr|sa)_/.test(id) ? "A teammate" : id);
}

/** A name for a principal ID. Older rows may already hold a name, which passes through. */
export function Person({ id, fallback }: { id?: string | null; fallback?: string }) {
  const names = usePeople();
  if (!id) return <>{fallback ?? tr("System")}</>;
  return <span title={id}>{personName(names, id)}</span>;
}
