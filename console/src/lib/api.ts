"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { localiseReply } from "./i18n";

export class ApiErr extends Error {
  constructor(public status: number, public code: string, message: string, public policy?: string) {
    super(message);
  }
}

export interface CallOpts {
  method?: string;
  body?: unknown;
  purpose?: string;
}

export async function api<T = any>(plane: "control" | "data", path: string, opts: CallOpts = {}): Promise<T> {
  const res = await fetch(`/api/proxy/${plane}${path}`, {
    method: opts.method ?? (opts.body !== undefined ? "POST" : "GET"),
    headers: { ...(opts.body !== undefined ? { "content-type": "application/json" } : {}), "x-rv-console": "1", ...(opts.purpose ? { "x-rv-purpose": opts.purpose } : {}) },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) window.location.href = "/login";
    throw new ApiErr(res.status, data.error?.code ?? "error", data.error?.message ?? "request failed", data.error?.policy);
  }
  return localiseReply(data) as T;
}

export const control = <T = any>(path: string, opts?: CallOpts) => api<T>("control", path, opts);
export const data = <T = any>(path: string, opts?: CallOpts) => api<T>("data", path, opts);

export function useLoad<T = any>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [value, setValue] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const latest = useRef(0);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const load = useCallback(async () => {
    setLoading(true);
    // Only the newest request may fill the page: a slow older one must not overwrite it.
    const mine = ++latest.current;
    try {
      const v = await fn();
      if (mine !== latest.current) return;
      setValue(v);
      setError(null);
    } catch (e) {
      if (mine !== latest.current) return;
      setError(e instanceof Error ? e.message : "could not load");
    } finally {
      if (mine === latest.current) setLoading(false);
    }
  }, deps);
  useEffect(() => {
    load();
  }, [load]);
  return { value, error, loading, reload: load };
}

export function when(d?: string | Date | null): string {
  if (!d) return "never";
  return new Date(d).toLocaleString(undefined, { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", hour12: false, timeZoneName: "short" });
}

export function day(d?: string | Date | null): string {
  if (!d) return "never";
  return new Date(d).toLocaleDateString(undefined, { day: "2-digit", month: "short", year: "numeric" });
}

export const n = (v: unknown) => Number(v ?? 0).toLocaleString("en-NG");
