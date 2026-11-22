import fs from "node:fs";
import path from "node:path";

export interface Config {
  /** ONSHORE_MODE from the spec, by leak. "off" is every path going straight to its foreign tool. */
  mode: "off" | "on";
  sentry_hook: boolean;
  ai_gateway: boolean;
  tokenize_at_source: boolean;
  stage: string;
}
export interface OnshoreState {
  base: string;
  vault: string;
  ai_route: string;
  ai_route_key: string;
  ai_upstream: string;
  flows: { sentry?: string; analytics?: string };
  backend: { id: string; key: string; seed: string };
  staff: Record<string, { id: string; key: string; seed: string; label: string }>;
}
const FILE = process.env.DEMO_STATE_FILE ?? path.resolve(process.cwd(), "../.state/lagoon.json");
const OFF: Config = { mode: "off", sentry_hook: false, ai_gateway: false, tokenize_at_source: false, stage: "before" };

/** Read on every request, so a switch takes effect at once, with no restart. */
export function state(): { config: Config; onshore: OnshoreState | null } {
  try {
    const s = JSON.parse(fs.readFileSync(FILE, "utf8"));
    return { config: { ...OFF, ...s.config }, onshore: s.onshore ?? null };
  } catch {
    return { config: OFF, onshore: null };
  }
}
