// The member side of linked installs: join the primary once, then report every
// minute and carry out the instructions it sends back. See federation.ts.

import fs from "node:fs";
import { Agent, fetch as tlsFetch } from "undici";
import { db, decryptSecret, encryptSecret, type Actor } from "../lib.js";
import { ROLES } from "../templates.js";
import { isCountry } from "../catalog.js";
import { sign, type Instruction, type Report } from "./federation-protocol.js";
import { createVault } from "../routes/vaults.js";

const VERSION = process.env.RV_VERSION ?? "dev";
// A primary with a private CA (common in a bank) can be trusted explicitly.
const agent = process.env.RV_PRIMARY_CA ? new Agent({ connect: { ca: fs.readFileSync(process.env.RV_PRIMARY_CA), minVersion: "TLSv1.2" } }) : undefined;

async function post(url: string, body: string, headers: Record<string, string> = {}) {
  const r = await tlsFetch(url, { method: "POST", body, headers: { "content-type": "application/json", ...headers }, ...(agent ? { dispatcher: agent } : {}) });
  const text = await r.text();
  if (!r.ok) throw new Error(`${r.status} ${text.slice(0, 200)}`);
  return JSON.parse(text) as Record<string, unknown>;
}

const base = (u: string) => u.replace(/\/+$/, "") + "/control";

/** Joins with the code `rv init --join` wrote, once. A used or expired code is reported, not retried forever. */
async function join(): Promise<boolean> {
  const primary = process.env.RV_PRIMARY_URL, code = process.env.RV_JOIN_CODE, country = (process.env.RV_COUNTRY ?? "").toUpperCase();
  if (!primary || !code) return false;
  if (!isCountry(country)) throw new Error("RV_COUNTRY must be set on a member install");
  const res = await post(`${base(primary)}/v1/federation/join`, JSON.stringify({ code, country, base_url: `https://${process.env.RV_HOST ?? "localhost"}`, version: VERSION }));
  await db.federation.create({ data: { primary_url: primary, install_id: String(res.install_id), secret_enc: encryptSecret(String(res.secret)) } });
  // A member has no first-time setup of its own: the primary's organisation is its organisation.
  if ((await db.tenants.count()) === 0) {
    const id = `t_${Date.now().toString(36)}`;
    await db.$transaction(async (tx) => {
      await tx.tenants.create({ data: { id, name: String(res.organisation || "Linked install"), hosting_country: country, home_country: country, console_format: country, time_zone: String(res.time_zone || "UTC"), setup_completed_at: new Date() } });
      for (const r of ROLES) await tx.roles.create({ data: { id: `${id}:${r}`, tenant_id: id, name: r } });
    });
  }
  return true;
}

let done: string[] = [];
let failed: { id: string; error: string }[] = [];

async function summary(): Promise<Report> {
  const vaults = await db.vaults.findMany({ select: { id: true, name: true, country: true, environment: true, packs: true, _count: { select: { vault_fields: true } } } });
  const det = await db.$queryRaw<{ entity_type: string; n: bigint }[]>`SELECT entity_type, sum(count)::bigint AS n FROM events.detection_events WHERE occurred_at>now()-interval '7 days' GROUP BY 1`;
  const rev = await db.$queryRaw<{ decision: string | null; n: bigint }[]>`SELECT decision, count(*)::bigint AS n FROM events.audit_events WHERE action='detokenize' AND occurred_at>now()-interval '7 days' GROUP BY 1`;
  const count = (d: string) => Number(rev.find((r) => r.decision === d)?.n ?? 0);
  return {
    version: VERSION,
    country: (process.env.RV_COUNTRY ?? "").toUpperCase(),
    vaults: vaults.map((v) => ({ id: v.id, name: v.name, country: v.country, environment: v.environment as "sandbox" | "production", packs: v.packs, fields: v._count.vault_fields })),
    detections_7d: Object.fromEntries(det.map((d) => [d.entity_type, Number(d.n)])),
    reveals_7d: { plaintext: count("plaintext"), masked: count("masked"), denied: count("denied") },
    done, failed,
  };
}

async function apply(instructions: Instruction[]) {
  const t = await db.tenants.findFirst();
  if (!t) return;
  const actor: Actor = { id: "system:linked-install", tenantId: t.id, roles: ["admin"], displayName: "Linked install", ip: "", authTime: 0 };
  for (const ins of instructions) {
    if (done.includes(ins.id) || failed.some((f) => f.id === ins.id)) continue;
    try {
      if (ins.type !== "create_vault") throw new Error(`unknown instruction ${ins.type}`);
      // Safe to repeat: a vault of that name is the vault asked for.
      if (!(await db.vaults.findFirst({ where: { tenant_id: t.id, name: ins.name } }))) {
        await createVault(actor, { name: ins.name, environment: ins.environment, template: "packs", country: ins.country, packs: ins.packs });
      }
      done.push(ins.id);
    } catch (e) {
      failed.push({ id: ins.id, error: (e instanceof Error ? e.message : "failed").slice(0, 300) });
    }
  }
}

/** One round: join if needed, report, act on the reply. */
export async function memberTick() {
  let f = await db.federation.findFirst();
  if (!f) {
    if (!(await join())) return;
    f = await db.federation.findFirst();
    if (!f) return;
  }
  try {
    const body = JSON.stringify(await summary());
    const ts = String(Date.now());
    const res = await post(`${base(f.primary_url)}/v1/federation/report`, body, { "x-rv-install": f.install_id, "x-rv-timestamp": ts, "x-rv-signature": sign(decryptSecret(f.secret_enc), ts, body) });
    done = []; failed = [];
    await apply((res.instructions ?? []) as Instruction[]);
    await db.federation.update({ where: { id: true }, data: { last_report_at: new Date(), last_error: null } });
  } catch (e) {
    await db.federation.update({ where: { id: true }, data: { last_error: (e instanceof Error ? e.message : "failed").slice(0, 300) } });
    throw e;
  }
}

export const isMember = () => !!process.env.RV_PRIMARY_URL;
