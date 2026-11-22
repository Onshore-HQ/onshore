export const COOKIE = "rv_session";

export const CONTROL_URL = process.env.CONTROL_API_URL ?? "http://127.0.0.1:8081";
export const VAULT_URL = process.env.VAULT_API_URL ?? "http://127.0.0.1:8080";
export const FILES_URL = process.env.FILES_URL ?? "http://127.0.0.1:8094";

export function cookieOptions(maxAge: number) {
  return { httpOnly: true, sameSite: "strict" as const, secure: process.env.NODE_ENV === "production" && process.env.RV_INSECURE_COOKIE !== "true", path: "/", maxAge };
}

export function tokenExpiry(token: string): number {
  try {
    return JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString()).exp ?? 0;
  } catch {
    return 0;
  }
}

// mTLS to the control plane and the vault when certificates are configured.
import fs from "node:fs";
import { Agent, fetch as undiciFetch } from "undici";

const agent = process.env.RV_TLS_CA
  ? new Agent({ connect: { ca: fs.readFileSync(process.env.RV_TLS_CA), cert: fs.readFileSync(process.env.RV_TLS_CERT!), key: fs.readFileSync(process.env.RV_TLS_KEY!), minVersion: "TLSv1.3" } })
  : undefined;

export function internalFetch(url: string, init: Parameters<typeof undiciFetch>[1] = {}) {
  return undiciFetch(url, { ...init, ...(agent ? { dispatcher: agent } : {}) });
}
