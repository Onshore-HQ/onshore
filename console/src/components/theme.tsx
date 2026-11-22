"use client";
import { ThemeProvider as Provider } from "next-themes";
import { ReactNode } from "react";

/** The nonce lets its small inline script, which avoids a flash of the wrong theme, pass the CSP. */
export function ThemeProvider({ nonce, children }: { nonce?: string; children: ReactNode }) {
  return <Provider attribute="class" storageKey="rv-theme" defaultTheme="system" enableSystem disableTransitionOnChange nonce={nonce}>{children}</Provider>;
}
