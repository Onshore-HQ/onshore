"use client";
import { Fragment, ReactNode, useEffect, useState } from "react";
import fr from "./i18n/fr.json";

// The console's language. Text is written in English in the code and wrapped in
// t(); a dictionary per language maps the English to the translation. Anything not
// translated yet shows in English, so a missing entry never breaks a page.
//
// The language comes from the organisation's setting once signed in, and from the
// browser before that (sign-in, first-time setup). Changing it re-renders the console.

export type Lang = "en" | "fr";
const dictionaries: Record<Exclude<Lang, "en">, Record<string, string>> = { fr };
let current: Lang = "en";
const EVENT = "rv-lang";
const STORE = "rv-lang";

/** Translates English text. {name} placeholders are filled from vars. */
export function t(text: string, vars?: Record<string | number, unknown>): string {
  let out = current === "en" ? text : dictionaries[current][text] ?? text;
  if (vars) for (const [k, v] of Object.entries(vars)) out = out.split(`{${k}}`).join(String(v));
  return out;
}

/** The same as t, under a name no component uses for anything else. */
export const tr = t;

export const currentLanguage = () => current;

/** A country's name in the console's language, from the browser's own list. */
export function countryName(code: string, english: string): string {
  if (current === "en" || !/^[A-Z]{2}$/.test(code)) return english;
  try { return new Intl.DisplayNames([current], { type: "region" }).of(code) ?? english; } catch { return english; }
}

/** A date and a number as a country writes them, from the browser's own data. */
export function formatPreview(code: string, known?: string): string {
  if (known) return known;
  try {
    // The region's likely language decides the style; Latin digits keep it readable.
    const loc = `${new Intl.Locale(`und-${code}`).maximize().toString()}-u-nu-latn`;
    const out = `${new Intl.DateTimeFormat(loc, { day: "2-digit", month: "2-digit", year: "numeric" }).format(new Date(2026, 10, 21))} · ${new Intl.NumberFormat(loc, { minimumFractionDigits: 2 }).format(1250.5)}`;
    return out.replace(/[\u200e\u200f\u061c]/g, "");
  } catch { return ""; }
}

/** Renames the countries in an API reply ({ countries: [{ code, name }] }) into the console's language. */
export function localiseReply<T>(data: T): T {
  if (current === "en" || !data || typeof data !== "object") return data;
  const list = (data as { countries?: unknown }).countries;
  if (Array.isArray(list)) for (const c of list) if (c && typeof c.code === "string" && typeof c.name === "string") c.name = countryName(c.code, c.name);
  return data;
}

/** Switches the console's language, for example when the organisation's setting loads. */
export function setLanguage(lang: Lang) {
  if (typeof window === "undefined" || lang === current) return;
  window.dispatchEvent(new CustomEvent(EVENT, { detail: lang }));
}

function initial(): Lang {
  try {
    const stored = localStorage.getItem(STORE);
    if (stored === "en" || stored === "fr") return stored;
  } catch { /* storage may be blocked */ }
  return navigator.language?.toLowerCase().startsWith("fr") ? "fr" : "en";
}

/** Wraps the whole console. The server renders English; the browser switches after loading. */
export function LanguageRoot({ children }: { children: ReactNode }) {
  const [lang, setLang] = useState<Lang>("en");
  useEffect(() => {
    const apply = (l: Lang) => {
      current = l;
      document.documentElement.lang = l;
      try { localStorage.setItem(STORE, l); } catch { /* storage may be blocked */ }
      setLang(l);
    };
    apply(initial());
    const on = (e: Event) => apply((e as CustomEvent<Lang>).detail);
    window.addEventListener(EVENT, on);
    return () => window.removeEventListener(EVENT, on);
  }, []);
  return <Fragment key={lang}>{children}</Fragment>;
}
