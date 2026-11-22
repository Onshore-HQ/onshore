import dns from "node:dns/promises";
import net from "node:net";
import os from "node:os";
import nodemailer from "nodemailer";
import { db, decryptSecret } from "./lib.js";

export interface MailConfig { host: string; port: number; tls_mode: string; username: string | null; password_enc: string | null; from_address: string; from_name: string; console_url: string }

/** What went wrong, in words an admin can act on. The server's own reply is never echoed, so this can't be used to read internal services. */
export class MailError extends Error {}

function internalNetworks(): net.BlockList {
  const b = new net.BlockList();
  b.addSubnet("127.0.0.0", 8, "ipv4");
  b.addSubnet("169.254.0.0", 16, "ipv4");
  b.addSubnet("0.0.0.0", 8, "ipv4");
  b.addAddress("::1", "ipv6");
  b.addSubnet("fe80::", 10, "ipv6");
  // Onshore's own networks, so the mail setting can't be used to probe the database or key service.
  for (const list of Object.values(os.networkInterfaces())) {
    for (const i of list ?? []) {
      if (!i.cidr) continue;
      const [addr, bits] = i.cidr.split("/");
      if (i.family === "IPv4") b.addSubnet(addr!, Number(bits), "ipv4");
      else if (!i.internal) b.addSubnet(addr!, Number(bits), "ipv6");
    }
  }
  return b;
}

/** A customer's mail server is often private, so private addresses are allowed. Onshore's own are not. */
export async function resolveMailHost(host: string): Promise<string> {
  let addrs: string[];
  if (net.isIP(host)) addrs = [host];
  else {
    try { addrs = (await dns.lookup(host, { all: true })).map((a) => a.address); }
    catch { throw new MailError("That mail server's name could not be found."); }
  }
  const blocked = internalNetworks();
  for (const a of addrs) {
    const family = net.isIP(a) === 6 ? "ipv6" : "ipv4";
    if (blocked.check(a, family)) throw new MailError("That address belongs to this installation. Use your organisation's mail server.");
  }
  return addrs[0]!;
}

function explain(e: unknown): MailError {
  if (e instanceof MailError) return e;
  const x = e as { code?: string; responseCode?: number };
  if (x.code === "EAUTH" || x.responseCode === 535 || x.responseCode === 534) return new MailError("The mail server refused the username or password.");
  if (x.code === "ETLS" || x.code === "ESOCKET" && /certificate|TLS|SSL/i.test(String((e as Error).message))) return new MailError("A secure connection to the mail server failed. Check the security setting and its certificate.");
  if (x.code === "ETIMEDOUT" || x.code === "ECONNECTION" || x.code === "ESOCKET" || x.code === "EDNS") return new MailError("The mail server could not be reached. Check the address and port.");
  if (x.responseCode && x.responseCode >= 500) return new MailError("The mail server refused this message. Check the sender address is allowed.");
  return new MailError("The email could not be sent.");
}

export async function sendWith(cfg: MailConfig, to: string, subject: string, text: string): Promise<void> {
  // Connect to the address that was checked, so that DNS can't change the answer afterwards.
  const address = await resolveMailHost(cfg.host);
  if (cfg.tls_mode === "none" && cfg.password_enc) throw new MailError("A password can't be sent without a secure connection. Choose a secure setting, or remove the password.");
  const t = nodemailer.createTransport({
    host: address, port: cfg.port, secure: cfg.tls_mode === "tls", requireTLS: cfg.tls_mode === "starttls", ignoreTLS: cfg.tls_mode === "none",
    auth: cfg.username ? { user: cfg.username, pass: cfg.password_enc ? decryptSecret(cfg.password_enc) : "" } : undefined,
    tls: { servername: net.isIP(cfg.host) ? undefined : cfg.host, minVersion: "TLSv1.2", rejectUnauthorized: true },
    connectionTimeout: 10_000, greetingTimeout: 10_000, socketTimeout: 20_000,
  });
  try {
    await t.sendMail({ from: { name: cfg.from_name, address: cfg.from_address }, to, subject, text });
  } catch (e) {
    throw explain(e);
  } finally {
    t.close();
  }
}

export const mailFor = (tenantId: string) => db.mail_settings.findUnique({ where: { tenant_id: tenantId } }) as Promise<MailConfig | null>;

/** Sends if email is set up. Returns whether it went. Notices must not block the action they describe. */
export async function notify(tenantId: string, to: string | null | undefined, subject: string, text: string): Promise<boolean> {
  if (!to) return false;
  const cfg = await mailFor(tenantId);
  if (!cfg) return false;
  try { await sendWith(cfg, to, subject, text); return true; } catch { return false; }
}

const ALERT_WORDS: [RegExp, string][] = [[/^map_/, "A residency map change to review"], [/spike|anomal/, "Unusual access to real values"]];
const alertWord = (kind: string) => ALERT_WORDS.find(([r]) => r.test(kind))?.[1] ?? "An alert to review";

/** A digest of new alerts to admins and DPOs. It names kinds and counts, and never people's data. */
export async function emailAlerts(): Promise<void> {
  const settings = await db.mail_settings.findMany({ where: { alerts_enabled: true } });
  for (const cfg of settings) {
    const fresh = await db.alerts.findMany({ where: { tenant_id: cfg.tenant_id, emailed_at: null, acknowledged_at: null, raised_at: { gt: new Date(Date.now() - 86_400_000) } }, select: { id: true, kind: true }, take: 500 });
    if (!fresh.length) continue;
    const people = await db.principals.findMany({ where: { tenant_id: cfg.tenant_id, kind: "user", status: "active", email: { not: null }, role_assignments: { some: { roles: { name: { in: ["admin", "dpo"] } } } } }, select: { email: true } });
    if (!people.length) continue;
    const counts = new Map<string, number>();
    for (const a of fresh) counts.set(alertWord(a.kind), (counts.get(alertWord(a.kind)) ?? 0) + 1);
    const lines = [...counts].map(([w, c]) => `- ${w}: ${c}`).join("\n");
    await sendWith(cfg, people.map((p) => p.email!).join(", "), `Onshore: ${fresh.length} new alert${fresh.length === 1 ? "" : "s"}`, `New alerts in Onshore:\n\n${lines}\n\nSign in to review them: ${cfg.console_url}/monitoring\n\nThis email holds no customer data.`);
    await db.alerts.updateMany({ where: { id: { in: fresh.map((a) => a.id) } }, data: { emailed_at: new Date() } });
  }
}
