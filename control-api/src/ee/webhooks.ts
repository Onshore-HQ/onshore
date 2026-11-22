import crypto from "node:crypto";
import { Agent, fetch as plainFetch } from "undici";
import { db, decryptSecret } from "../lib.js";
import { guardedLookup } from "../netguard.js";

// Checks at connect time, after DNS, so that rebinding cannot reach internal services.
const guarded = new Agent({ connect: { lookup: guardedLookup("destination is not public") } });

/** Everything a customer can subscribe to. High-volume actions such as tokenize are left
 *  out on purpose: this tells people that something needs attention, it is not a data feed. */
export const EVENT_TYPES = {
  "reveal.performed": "A value was shown in plaintext",
  "reveal.denied": "A policy refused a reveal",
  "access.denied": "A policy refused something else, such as an export or a comparison",
  "access.break_glass": "Break-glass access was requested or used",
  "key.changed": "A key was rotated, created or revoked",
  "policy.published": "A policy went live",
  "custom_entity.published": "A custom detection entity went live or changed status",
  "data.exported": "An export was made",
  "data.deleted": "A record was erased",
  "components.sites_changed": "The sites allowed to use secure components changed",
  "identity.changed": "A person, service account or single sign-on setting changed",
  "page.script_new": "A script not seen before ran on a protected page",
  "page.script_changed": "An approved script's contents changed",
  "page.script_rejected_seen": "A rejected script ran on a protected page again",
  "alert.raised": "An alert was raised, such as a lookup spike",
  "monitor.component_down": "A service stopped answering",
  "monitor.component_recovered": "A service answered again",
  "webhook.endpoint_disabled": "Another endpoint was turned off after repeated failures",
  "test.ping": "A test you asked for",
} as const;
export type EventType = keyof typeof EVENT_TYPES;

const IDENTITY = ["principal_create", "principal_update", "sso_configure", "sso_remove", "key_create", "key_revoke", "password_reset_by_admin", "mfa_reset_by_admin", "mfa_replace", "recovery_codes_replace", "invite_send", "invite_accept"];
const AUDIT_ACTIONS = ["detokenize", "break_glass_request", "key_rotate", "policy_publish", "custom_entity_publish", "custom_entity_status_change", "export", "delete", "embed_origins_change", ...IDENTITY];

interface AuditRow { seq: bigint; event_id: string; occurred_at: Date; vault_id: string | null; principal_id: string | null; principal_kind: string | null; module: string; action: string; field_id: string | null; decision: string | null; policy_id: string | null; policy_version: number | null; break_glass: boolean; request_id: string | null }

/** Which subscription an audit event belongs to. Pure, so that it can be tested alone. */
export function eventTypesFor(e: Pick<AuditRow, "action" | "decision" | "break_glass">): EventType[] {
  const out: EventType[] = [];
  if (e.break_glass || e.action === "break_glass_request") out.push("access.break_glass");
  // A refused action did not happen, so it must never be announced as if it had.
  if (e.decision === "denied") {
    out.push(e.action === "reveal_denied" || e.action === "detokenize" ? "reveal.denied" : "access.denied");
    return out;
  }
  switch (e.action) {
    case "detokenize":
      if (e.decision === "plaintext") out.push("reveal.performed");
      break;
    case "key_rotate": out.push("key.changed"); break;
    case "policy_publish": out.push("policy.published"); break;
    case "custom_entity_publish": case "custom_entity_status_change": out.push("custom_entity.published"); break;
    case "export": out.push("data.exported"); break;
    case "delete": out.push("data.deleted"); break;
    case "embed_origins_change": out.push("components.sites_changed"); break;
    default: if (IDENTITY.includes(e.action)) out.push(e.action.startsWith("key_") ? "key.changed" : "identity.changed");
  }
  return out;
}

/** The whole of what leaves about an audit event. An allowlist, not a filter: purpose,
 *  detail, source address and token hash stay behind, however they change later. */
export function auditPayload(e: AuditRow): Record<string, unknown> {
  return {
    audit_seq: Number(e.seq), occurred_at: e.occurred_at.toISOString(), vault_id: e.vault_id, principal_id: e.principal_id, principal_kind: e.principal_kind,
    module: e.module, action: e.action, field_id: e.field_id, decision: e.decision, policy_id: e.policy_id, policy_version: e.policy_version, break_glass: e.break_glass, request_id: e.request_id,
  };
}

/** `t=<unix>,v1=<hmac>`. The time is inside the signature, so an old request cannot be replayed. */
export function signature(secrets: string[], body: string, at = Math.floor(Date.now() / 1000)): string {
  return [`t=${at}`, ...secrets.map((s) => `v1=${crypto.createHmac("sha256", s).update(`${at}.${body}`).digest("hex")}`)].join(",");
}

const BACKOFF_SECONDS = [30, 120, 600, 1800, 7200, 21600, 43200, 86400];
const DISABLE_AFTER = 100;
const BACKLOG_LIMIT = 10_000;

/** When to try again after this many attempts, or null when it is time to give up. */
export function nextDelay(attempts: number): number | null {
  return attempts > BACKOFF_SECONDS.length ? null : BACKOFF_SECONDS[attempts - 1]!;
}

export async function enqueue(endpoint: { id: string; tenant_id: string }, eventId: string, type: EventType, data: Record<string, unknown>, occurredAt = new Date()): Promise<void> {
  const payload = { id: eventId, type, created_at: occurredAt.toISOString(), tenant_id: endpoint.tenant_id, data };
  await db.$executeRaw`INSERT INTO control.webhook_deliveries(id,endpoint_id,tenant_id,event_id,event_type,payload)
    VALUES (${crypto.randomUUID()}::uuid,${endpoint.id},${endpoint.tenant_id},${eventId},${type},${JSON.stringify(payload)}::jsonb)
    ON CONFLICT (endpoint_id,event_id) DO NOTHING`;
}

/** Sends an event that does not come from the audit log to everyone subscribed to it. */
export async function broadcast(tenantId: string | null, eventId: string, type: EventType, data: Record<string, unknown>): Promise<void> {
  const endpoints = await db.webhook_endpoints.findMany({ where: { enabled: true, event_types: { has: type }, ...(tenantId ? { tenant_id: tenantId } : {}) } });
  for (const ep of endpoints) await enqueue(ep, eventId, type, data);
}

/** Turns new audit events and alerts into deliveries. Repeating this is harmless. */
export async function enqueueWebhooks(): Promise<void> {
  const endpoints = await db.webhook_endpoints.findMany({ where: { enabled: true } });
  for (const ep of endpoints) {
    // A receiver that has been down for days should not grow this table without limit.
    const backlog = await db.webhook_deliveries.count({ where: { endpoint_id: ep.id, status: "pending" } });
    if (backlog >= BACKLOG_LIMIT) continue;
    const tip = await db.audit_events.aggregate({ where: { tenant_id: ep.tenant_id }, _max: { seq: true } });
    const top = tip._max.seq ?? 0n;
    const events = (await db.audit_events.findMany({
      where: { tenant_id: ep.tenant_id, seq: { gt: ep.audit_cursor, lte: top }, OR: [{ action: { in: AUDIT_ACTIONS } }, { decision: "denied" }, { break_glass: true }] },
      orderBy: { seq: "asc" }, take: 500,
    })) as unknown as AuditRow[];
    for (const e of events) {
      for (const type of eventTypesFor(e)) {
        if (ep.event_types.includes(type)) await enqueue(ep, `aud_${e.event_id}_${type}`, type, auditPayload(e), e.occurred_at);
      }
    }
    const cursor = events.length === 500 ? events[events.length - 1]!.seq : top;

    let alertCursor = ep.alert_cursor;
    if (ep.event_types.includes("alert.raised")) {
      // Looks back a little, since raised_at is the transaction's start and not its commit.
      const since = new Date(Math.max(ep.alert_cursor.getTime() - 5 * 60_000, ep.created_at.getTime()));
      const alerts = await db.alerts.findMany({ where: { tenant_id: ep.tenant_id, raised_at: { gt: since } }, orderBy: { raised_at: "asc" }, take: 200 });
      for (const a of alerts) {
        await enqueue(ep, `alert_${a.id}`, "alert.raised", { alert_id: a.id, kind: a.kind, principal_id: a.principal_id, event_at: a.event_at.toISOString() }, a.raised_at);
        if (a.raised_at > alertCursor) alertCursor = a.raised_at;
      }
    }
    if (cursor !== ep.audit_cursor || alertCursor !== ep.alert_cursor) {
      await db.webhook_endpoints.update({ where: { id: ep.id }, data: { audit_cursor: cursor, alert_cursor: alertCursor } });
    }
  }
}

interface Claimed { id: string; endpoint_id: string; tenant_id: string; event_id: string; event_type: string; payload: unknown; attempts: number }

/** Attempts what is due. Claiming pushes the next attempt forward, so another replica skips
 *  these rows, and a crash mid-send only means that the event is sent again later. */
export async function deliverWebhooks(): Promise<number> {
  const claimed = await db.$queryRaw<Claimed[]>`
    UPDATE control.webhook_deliveries SET next_attempt_at = now() + interval '2 minutes'
    WHERE id IN (
      SELECT id FROM (
        SELECT d.id, row_number() OVER (PARTITION BY d.endpoint_id ORDER BY d.next_attempt_at) AS n
        FROM control.webhook_deliveries d JOIN control.webhook_endpoints e ON e.id = d.endpoint_id
        WHERE d.status = 'pending' AND d.next_attempt_at <= now() AND e.enabled
      ) due WHERE n <= 25 LIMIT 200
    ) AND status = 'pending' AND next_attempt_at <= now()
    RETURNING id, endpoint_id, tenant_id, event_id, event_type, payload, attempts`;
  const queue = [...claimed];
  await Promise.all(Array.from({ length: 16 }, async () => {
    for (let d = queue.shift(); d; d = queue.shift()) await attempt(d).catch(() => undefined);
  }));
  return claimed.length;
}

/** What is recorded about a failure. Never the receiver's response, which could hold anything. */
export function classifyFailure(err: unknown): string {
  const e = err as { name?: string; cause?: { code?: string; message?: string }; message?: string };
  if (e?.name === "TimeoutError" || e?.cause?.code === "UND_ERR_CONNECT_TIMEOUT") return "timed out";
  if ((e?.cause?.message ?? "").includes("not public")) return "refused: the destination is not public";
  if (e?.cause?.code === "ENOTFOUND") return "the host name did not resolve";
  if (e?.cause?.code === "ECONNREFUSED") return "connection refused";
  if ((e?.cause?.code ?? "").includes("CERT") || (e?.cause?.code ?? "").includes("TLS")) return "certificate problem";
  return "connection failed";
}

async function attempt(d: Claimed): Promise<void> {
  const ep = await db.webhook_endpoints.findUnique({ where: { id: d.endpoint_id } });
  if (!ep?.enabled) return;
  const secrets = [decryptSecret(ep.secret_enc)];
  if (ep.secret_prev_enc && ep.secret_prev_until && ep.secret_prev_until > new Date()) secrets.push(decryptSecret(ep.secret_prev_enc));
  const body = JSON.stringify(d.payload);
  let status: number | null = null;
  let failure: string | null = null;
  try {
    const res = await plainFetch(ep.url, {
      method: "POST", dispatcher: guarded, redirect: "manual", signal: AbortSignal.timeout(10_000),
      headers: { "content-type": "application/json", "user-agent": "Onshore-Webhooks/1", "x-rv-signature": signature(secrets, body), "x-rv-event-id": d.event_id, "x-rv-event-type": d.event_type, "x-rv-delivery-attempt": String(d.attempts + 1) },
      body,
    });
    status = res.status;
    await res.body?.cancel().catch(() => undefined);
    // A redirect is a failure: following it could carry the event somewhere unchecked.
    if (status < 200 || status >= 300) failure = status >= 300 && status < 400 ? `answered ${status}: redirects are not followed` : `answered ${status}`;
  } catch (e) {
    failure = classifyFailure(e);
  }
  const attempts = d.attempts + 1;
  if (!failure) {
    await db.webhook_deliveries.update({ where: { id: d.id }, data: { status: "delivered", attempts, last_status: status, last_error: null, delivered_at: new Date() } });
    await db.webhook_endpoints.update({ where: { id: ep.id }, data: { consecutive_failures: 0, last_success_at: new Date() } });
    return;
  }
  const delay = nextDelay(attempts);
  await db.webhook_deliveries.update({ where: { id: d.id }, data: delay === null
    ? { status: "dead", attempts, last_status: status, last_error: failure }
    : { attempts, last_status: status, last_error: failure, next_attempt_at: new Date(Date.now() + delay * 1000) } });
  const updated = await db.webhook_endpoints.update({ where: { id: ep.id }, data: { consecutive_failures: { increment: 1 }, last_failure_at: new Date() } });
  if (updated.consecutive_failures >= DISABLE_AFTER) await disable(updated.id, updated.tenant_id);
}

async function disable(id: string, tenantId: string): Promise<void> {
  const r = await db.webhook_endpoints.updateMany({ where: { id, enabled: true }, data: { enabled: false, disabled_reason: `turned off after ${DISABLE_AFTER} failures in a row` } });
  if (r.count === 0) return;
  await db.$executeRaw`INSERT INTO events.alerts(id,tenant_id,kind,detail,event_at) VALUES (${crypto.randomUUID()}::uuid,${tenantId},'webhook_disabled',${JSON.stringify({ endpoint_id: id })}::jsonb,now())`;
  await broadcast(tenantId, `disabled_${id}_${Date.now()}`, "webhook.endpoint_disabled", { endpoint_id: id });
}

/** Keeps a month of delivery history. */
export async function purgeDeliveries(): Promise<void> {
  await db.$executeRaw`DELETE FROM control.webhook_deliveries WHERE created_at < now() - interval '30 days' AND status <> 'pending'`;
  await db.webhook_endpoints.updateMany({ where: { secret_prev_until: { lt: new Date() } }, data: { secret_prev_enc: null, secret_prev_until: null } });
}
