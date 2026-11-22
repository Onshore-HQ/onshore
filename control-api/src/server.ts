import fs from "node:fs";
import Fastify from "fastify";
import { db, env, sendError, verifyToken } from "./lib.js";
import { pushSiem } from "./siem.js";
import { checkComponents } from "./monitoring.js";
import { deliverWebhooks, enqueueWebhooks, purgeDeliveries } from "./webhooks.js";
import { webhookRoutes } from "./routes/webhooks.js";
import { pageProtectionRoutes, pageReportRoute } from "./routes/page-protection.js";
import { scanAllPages } from "./pageprotect.js";
import { adapterRoutes } from "./routes/adapters.js";
import { authRoutes } from "./routes/auth.js";
import { apiKeyFrom, setupRoutes } from "./routes/setup.js";
import { importRoutes } from "./routes/imports.js";
import { accountRoutes } from "./routes/accounts.js";
import { emailAlerts } from "./mail.js";
import { ssoRoutes } from "./routes/sso.js";
import { identityRoutes } from "./routes/identity.js";
import { scimRoutes } from "./routes/scim.js";
import { packRoutes } from "./routes/packs.js";
import { evidenceRoutes } from "./routes/evidence.js";
import { customEntityRoutes } from "./routes/custom-entities.js";
import { gatewayRoutes } from "./routes/gateways.js";
import { peopleRoutes } from "./routes/people.js";
import { pipelineRoutes } from "./routes/pipelines.js";
import { policyRoutes } from "./routes/policies.js";
import { vaultRoutes } from "./routes/vaults.js";
import { edition, locationRoutes } from "./routes/locations.js";
import { federationRoutes, REPORT_EVERY_MS } from "./federation.js";
import { isMember, memberTick } from "./member.js";
import { mapRoutes } from "./routes/map.js";
import { usageRoutes } from "./routes/usage.js";
import { mapTick } from "./map/run.js";

const trusted = (process.env.RV_TRUSTED_PROXIES ?? "").split(",").map((s) => s.trim()).filter(Boolean);

const tlsCert = process.env.RV_TLS_CERT;
const app = Fastify({
  // mTLS: only holders of a certificate from the internal CA reach this service.
  ...(tlsCert ? { https: { cert: fs.readFileSync(tlsCert), key: fs.readFileSync(process.env.RV_TLS_KEY!), ca: fs.readFileSync(process.env.RV_TLS_CA!), requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3" as const } } : {}),
  trustProxy: trusted.length ? trusted : false,
  bodyLimit: 8 << 20,
  // Default request serialisers log URLs, whose query strings can carry search
  // terms, so routes are logged by pattern only.
  disableRequestLogging: true,
  logger: { level: process.env.LOG_LEVEL ?? "info", redact: ["req.headers.authorization"] },
});

app.setErrorHandler((err, _req, reply) => sendError(reply, err));

app.addHook("onResponse", async (req, reply) => {
  req.log.info({ route: req.routeOptions.url, method: req.method, status: reply.statusCode, ms: Math.round(reply.elapsedTime) });
});

app.addHook("onRequest", async (req) => {
  const h = req.headers.authorization;
  if (!h?.startsWith("Bearer ")) return;
  // A setup key opens the setup endpoints only: it never becomes an actor.
  if (h.startsWith("Bearer onsk_")) { req.apiKey = await apiKeyFrom(h.slice(7)); return; }
  const claims = verifyToken(h.slice(7));
  if (!claims) return;
  const p = await db.principals.findUnique({ where: { id: claims.sub }, include: { role_assignments: { include: { roles: true } } } });
  if (!p || p.status !== "active" || p.tenant_id !== claims.tid || !p.mfa_enabled || p.must_change_password) return;
  // A password change ends every session issued before it.
  if (p.sessions_valid_after && claims.iat <= Math.floor(p.sessions_valid_after.getTime() / 1000)) return;
  req.actor = { id: p.id, tenantId: p.tenant_id, roles: p.role_assignments.map((r) => r.roles.name), displayName: p.display_name, ip: req.ip, authTime: claims.auth_time };
});

app.get("/healthz", async () => {
  await db.$queryRaw`SELECT 1`;
  return { status: "ok" };
});

await app.register(authRoutes);
await app.register(accountRoutes);
await app.register(setupRoutes);
await app.register(importRoutes);
await app.register(vaultRoutes);
await app.register(locationRoutes);
await app.register(policyRoutes);
await app.register(peopleRoutes);
await app.register(pipelineRoutes);
await app.register(gatewayRoutes);
await app.register(ssoRoutes);
await app.register(identityRoutes);
await app.register(scimRoutes);
await app.register(packRoutes);
await app.register(adapterRoutes);
await app.register(evidenceRoutes);
await app.register(usageRoutes);
await app.register(customEntityRoutes);
await app.register(webhookRoutes);
await app.register(pageProtectionRoutes);
await app.register(pageReportRoute);
await app.register(mapRoutes);
await app.register(async (a) => federationRoutes(a, edition));

env("RV_BOOTSTRAP_TOKEN");
setInterval(() => pushSiem().catch(() => app.log.warn("SIEM push failed; retrying")), 30_000).unref();
// A tick that overruns must not start a second one on top of it.
const every = (ms: number, name: string, fn: () => Promise<unknown>) => {
  let running = false;
  setInterval(async () => {
    if (running) return;
    running = true;
    try { await fn(); } catch { app.log.warn(`${name} failed; retrying`); } finally { running = false; }
  }, ms).unref();
};
every(5_000, "webhook delivery", async () => { await enqueueWebhooks(); await deliverWebhooks(); });
every(Number(process.env.RV_MONITOR_INTERVAL_MS ?? 30_000), "health check", checkComponents);
every(3_600_000, "webhook history purge", purgeDeliveries);
every(Number(process.env.RV_MAIL_ALERT_INTERVAL_MS ?? 60_000), "alert email", emailAlerts);
// The spec asks for hourly at least. Each run only writes what changed, so a minute is cheap and
// a new flow shows within the five minutes it allows.
every(Number(process.env.RV_MAP_INTERVAL_MS ?? 60_000), "residency map", mapTick);
every(Number(process.env.RV_PAGE_SCAN_INTERVAL_MS ?? 900_000), "page scan", scanAllPages);
// A member install reports to its primary; the first round joins it.
if (isMember()) {
  memberTick().catch(() => app.log.warn("first report to the primary install failed; retrying"));
  every(REPORT_EVERY_MS, "report to primary install", memberTick);
}
await app.listen({ host: process.env.HOST ?? "0.0.0.0", port: Number(process.env.PORT ?? 8081) });
