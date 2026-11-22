// A copy of sdks/node/dist, made by `./demo up`, so that this app needs no package registry.
import { VaultClient } from "@/vendor/onshore-sdk.js";
import { state } from "./config";

const clients = new Map<string, VaultClient>();
function client(who: { id: string; key: string; seed: string }, base: string) {
  const k = who.key;
  if (!clients.has(k)) clients.set(k, new VaultClient({ baseUrl: base, serviceAccountId: who.id, keyId: who.key, privateKey: who.seed }));
  return clients.get(k)!;
}
export function backend() { const { onshore } = state(); if (!onshore) throw new Error("Onshore is not set up: run demo reset"); return { c: client(onshore.backend, onshore.base), onshore }; }
export function staff(role: string) { const { onshore } = state(); const s = onshore?.staff[role]; if (!onshore || !s) throw new Error("unknown staff role"); return { c: client(s, onshore.base), onshore, label: s.label }; }

export const FIELDS = { bvn: "bvn", nin: "nin", nuban: "account_number", phone: "phone", email: "email", fullName: "full_name" } as const;

export async function tokenizeOne(field: string, value: string, subject: string) {
  const { c, onshore } = backend();
  const [r] = await c.tokenize(onshore.vault, [{ field, value, subject_ref: subject }]);
  if (!r?.token) throw new Error(`Onshore refused ${field}`);
  return r.token;
}
export const isToken = (v: string) => v.startsWith("tok_");

/** Identifiers in free text become tokens, for the Sentry hook. Returns the cleaned text. */
export async function cleanText(text: string) {
  const { c, onshore } = backend();
  const r = (await c.detect(text, { tokenize: true, vault: onshore.vault })) as { text: string };
  return r.text;
}
export async function checkFlow(flow: string, text: string) {
  const { c, onshore } = backend();
  return c.checkFlow(onshore.vault, flow, text);
}
