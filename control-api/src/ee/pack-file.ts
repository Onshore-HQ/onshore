// Signing and checking country pack files. Pure, so tests need no database.

import crypto from "node:crypto";

/** JSON with keys in a fixed order, so a signature covers the same bytes everywhere. */
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v as object).sort().filter((k) => (v as Record<string, unknown>)[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v);
}
export const fingerprint = (publicKeyB64: string) => (crypto.createHash("sha256").update(Buffer.from(publicKeyB64, "base64")).digest("hex").slice(0, 32).toUpperCase().match(/.{4}/g) ?? []).join(" ");

/** Checks a pack file's signature. It proves the file is unchanged since that key signed it. */
export function verifyFile(file: Record<string, unknown>): { ok: boolean; fingerprint: string } {
  const { signature, ...body } = file;
  const by = body.signed_by as { public_key?: string } | undefined;
  if (typeof signature !== "string" || !by?.public_key) return { ok: false, fingerprint: "" };
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(by.public_key, "base64"), format: "der", type: "spki" });
    return { ok: crypto.verify(null, Buffer.from(canonical(body)), key, Buffer.from(signature, "base64url")), fingerprint: fingerprint(by.public_key) };
  } catch {
    return { ok: false, fingerprint: "" };
  }
}

