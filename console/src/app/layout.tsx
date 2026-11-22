import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import { ThemeProvider } from "@/components/theme";
import { LanguageRoot } from "@/lib/i18n";
import "./globals.css";

export const metadata: Metadata = { title: "Onshore", description: "Data residency vault console", robots: { index: false, follow: false } };
// Nonces are per request, so nothing here may be prerendered.
export const dynamic = "force-dynamic";
export const viewport: Viewport = { width: "device-width", initialScale: 1 };

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`} suppressHydrationWarning>
      <body>
        <ThemeProvider nonce={nonce}><LanguageRoot>{children}</LanguageRoot></ThemeProvider>
      </body>
    </html>
  );
}
