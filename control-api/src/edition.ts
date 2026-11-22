// Which Onshore edition this install runs, and the gate paid features use.
// Paid features live in src/ee under the Onshore Commercial Licence (ee/LICENSE
// at the repository root).

import type { FastifyInstance, FastifyRequest } from "fastify";
import { ApiError, vault } from "./lib.js";

/**
 * free: Community. business / enterprise: from a signed licence. cloud: Onshore Cloud.
 * development: a build without the licence key, with every feature on for
 * development and testing only.
 */
export type Edition = "free" | "business" | "enterprise" | "cloud" | "development";
export type Level = "business" | "enterprise";

const RANK: Record<Edition, number> = { free: 0, business: 1, enterprise: 2, cloud: 3, development: 3 };
const NAMES: Record<Level, string> = { business: "Onshore Business", enterprise: "Onshore Enterprise" };

let cached: { ed: Edition; at: number } | null = null;

/**
 * How this install runs. Onshore Cloud says so in its environment; otherwise the
 * vault answers from its licence, checked offline.
 */
export async function edition(): Promise<Edition> {
  if (process.env.RV_CLOUD === "1") return "cloud";
  if (cached && Date.now() - cached.at < 30_000) return cached.ed;
  let ed: Edition = "free";
  try {
    const lic = await vault<{ edition?: string; installed: boolean; valid?: boolean; modules?: string[] }>("/internal/licence", {});
    if (lic.edition && lic.edition in RANK && lic.edition !== "cloud") ed = lic.edition as Edition;
    else if (lic.installed && lic.valid && lic.modules?.includes("enterprise")) ed = "enterprise";
  } catch {
    // The vault being unreachable must not upgrade anyone.
    return "free";
  }
  cached = { ed, at: Date.now() };
  return ed;
}

export const has = (ed: Edition, level: Level) => RANK[ed] >= RANK[level];

export function needs(level: Level, what: string) {
  return new ApiError(403, `needs_${level}`, `${what} needs ${NAMES[level]}`);
}

/** Throws unless this install's edition includes the level. */
export async function requireEdition(level: Level, what: string) {
  const ed = await edition();
  if (!has(ed, level)) throw needs(level, what);
  return ed;
}

/**
 * Gates every route a plugin registers. Reading and deleting stay open by default,
 * so an organisation that stops paying can still see and remove what it set up;
 * `all` gates reads too, for features whose output is the product (reports).
 */
export function gated(level: Level, what: string, plugin: (app: FastifyInstance) => Promise<void>, opts: { all?: boolean } = {}) {
  return async (app: FastifyInstance) => {
    app.addHook("preHandler", async (req: FastifyRequest) => {
      if (!opts.all && (req.method === "GET" || req.method === "HEAD" || req.method === "DELETE")) return;
      await requireEdition(level, what);
    });
    await plugin(app);
  };
}
