import crypto from "node:crypto";
import { Agent, fetch as plainFetch } from "undici";
import { db, decryptSecret } from "./lib.js";
import { guardedLookup } from "./netguard.js";

// Checks at connect time, after DNS, so that rebinding cannot reach internal services.
const guarded = new Agent({ connect: { lookup: guardedLookup("destination is not public") } });

const BATCH = 500;

/** Pushes new audit events to each tenant's SIEM, so a copy exists outside this
 *  database. That closes the gap where an attacker with database owner rights could
 *  rewrite the chain since the last signed checkpoint. Delivery is at least once. */
export async function pushSiem(): Promise<void> {
  const tenants = await db.tenants.findMany({ where: { siem_url: { not: null } } });
  for (const t of tenants) {
    for (;;) {
      const events = await db.audit_events.findMany({ where: { tenant_id: t.id, seq: { gt: BigInt(t.siem_cursor) } }, orderBy: { seq: "asc" }, take: BATCH });
      if (events.length === 0) break;
      const body = events.map((e) => JSON.stringify(e, (_k, v) => (typeof v === "bigint" ? Number(v) : v))).join("\n");
      const sig = crypto.createHmac("sha256", decryptSecret(t.siem_secret_enc!)).update(body).digest("hex");
      const res = await plainFetch(t.siem_url!, { method: "POST", dispatcher: guarded, redirect: "manual", headers: { "content-type": "application/x-ndjson", "x-rv-signature": `sha256=${sig}` }, body, signal: AbortSignal.timeout(20_000) });
      if (!res.ok) throw new Error(`SIEM answered ${res.status}`);
      const last = events[events.length - 1]!.seq;
      await db.tenants.update({ where: { id: t.id }, data: { siem_cursor: last } });
      t.siem_cursor = last;
      if (events.length < BATCH) break;
    }
  }
}
