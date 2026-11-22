// The wire format between linked installs, with no database: what a member may send
// and how it is signed. Kept apart so it can be tested and audited on its own.
import crypto from "node:crypto";
import { z } from "zod";

export const hash = (s: string) => crypto.createHash("sha256").update(s).digest("hex");
export const sign = (secret: string, ts: string, body: string) => crypto.createHmac("sha256", secret).update(`${ts}.${body}`).digest("hex");

/** What a member may send. Only names, settings and counts: anything else is refused. */
export const reportSchema = z
  .object({
    version: z.string().max(40),
    country: z.string().regex(/^[A-Z]{2}$/),
    vaults: z.array(z.object({ id: z.string().max(40), name: z.string().max(80), country: z.string().regex(/^[A-Z]{2}$/), environment: z.enum(["sandbox", "production"]), packs: z.array(z.string().max(20)).max(30), fields: z.number().int().min(0) }).strict()).max(200),
    detections_7d: z.record(z.string().max(60), z.number().int().min(0)),
    reveals_7d: z.object({ plaintext: z.number().int().min(0), masked: z.number().int().min(0), denied: z.number().int().min(0) }).strict(),
    done: z.array(z.string().max(40)).max(100).default([]),
    failed: z.array(z.object({ id: z.string().max(40), error: z.string().max(300) }).strict()).max(100).default([]),
  })
  .strict();
export type Report = z.infer<typeof reportSchema>;

export interface Instruction { id: string; type: "create_vault"; name: string; country: string; packs: string[]; environment: "sandbox" | "production" }

