// Which parts of an access rule are "advanced" (Onshore Business): purposes,
// office hours, reveal limits, and network or MFA conditions. Basic rules (who,
// which action, which fields, plaintext or masked) stay in every edition.
// Under the Onshore Commercial Licence; see ee/LICENSE at the repository root.

interface RuleSource {
  limit_per_hour?: number;
  rules?: { who?: { networks?: string[]; require_mfa?: boolean }; when?: { purpose_required?: boolean; hour_from?: number | null; hour_to?: number | null } }[];
}

/** The advanced features a policy uses, in plain words; empty when it uses none. */
export function advancedFeatures(source: unknown): string[] {
  const s = (source ?? {}) as RuleSource;
  const out = new Set<string>();
  if (s.limit_per_hour) out.add("reveal limits");
  for (const r of s.rules ?? []) {
    if (r.when?.purpose_required) out.add("required purposes");
    if (r.when?.hour_from != null || r.when?.hour_to != null) out.add("office hours");
    if (r.who?.networks?.length) out.add("network conditions");
    if (r.who?.require_mfa) out.add("MFA conditions");
  }
  return [...out];
}
