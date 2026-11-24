import fs from "node:fs";
import Fastify from "fastify";
import { db, env, sendError, verifyToken } from "./lib.js";
import { pushSiem } from "./ee/siem.js";
import { checkComponents } from "./monitoring.js";
import { deliverWebhooks, enqueueWebhooks, purgeDeliveries } from "./ee/webhooks.js";
import { webhookRoutes } from "./ee/routes/webhooks.js";
import { pageProtectionRoutes, pageReportRoute } from "./ee/routes/page-protection.js";
import { scanAllPages } from "./ee/pageprotect.js";
import { adapterRoutes } from "./ee/routes/adapters.js";
import { authRoutes } from "./routes/auth.js";
import { apiKeyFrom, setupRoutes } from "./routes/setup.js";
import { importRoutes } from "./routes/imports.js";
import { accountRoutes } from "./routes/accounts.js";
import { emailAlerts } from "./mail.js";
import { ssoRoutes } from "./ee/routes/sso.js";
import { identityRoutes } from "./routes/identity.js";
import { scimRoutes } from "./ee/routes/scim.js";
import { packRoutes } from "./ee/routes/packs.js";
import { evidenceRoutes } from "./routes/evidence.js";
import { customEntityRoutes } from "./ee/routes/custom-entities.js";
import { detectionModelRoutes } from "./ee/routes/detection-models.js";
import { gatewayRoutes } from "./ee/routes/gateways.js";
import { aiRoutes } from "./routes/ai-routes.js";
import { peopleRoutes } from "./routes/people.js";
import { pipelineRoutes } from "./ee/routes/pipelines.js";
import { policyRoutes } from "./routes/policies.js";
import { vaultRoutes } from "./routes/vaults.js";
import { locationRoutes } from "./routes/locations.js";
import { edition, gated, has } from "./edition.js";
import { reportRoutes } from "./ee/routes/reports.js";
import { federationRoutes, REPORT_EVERY_MS } from "./ee/federation.js";
import { isMember, memberTick } from "./ee/member.js";
import { mapRoutes } from "./ee/routes/map.js";
import { usageRoutes } from "./routes/usage.js";
import { mapTick } from "./ee/map/run.js";

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
await app.register(gated("business", "log pipelines", pipelineRoutes));
await app.register(aiRoutes); // community edition; its paid extras check the edition themselves
await app.register(gated("business", "the HTTP proxy and shared cloak settings", gatewayRoutes));
await app.register(ssoRoutes);
await app.register(identityRoutes);
await app.register(gated("business", "SCIM", scimRoutes));
await app.register(gated("business", "your own country packs", packRoutes));
await app.register(gated("business", "ticket adapters", adapterRoutes));
await app.register(evidenceRoutes);
await app.register(gated("business", "evidence reports", reportRoutes, { all: true }));
await app.register(usageRoutes);
await app.register(gated("business", "your own data types", customEntityRoutes));
// Language-model detection checks its edition itself, so sandbox vaults can try it.
await app.register(detectionModelRoutes);
await app.register(gated("business", "webhooks", webhookRoutes));
await app.register(gated("business", "page protection", pageProtectionRoutes));
await app.register(gated("business", "page protection", pageReportRoute));
await app.register(gated("business", "the residency map", mapRoutes));
await app.register(async (a) => federationRoutes(a, edition));
// Paid features (src/ee) are under the Onshore Commercial Licence; see ee/LICENSE.

env("RV_BOOTSTRAP_TOKEN");
setInterval(async () => { if (has(await edition(), "enterprise")) await pushSiem().catch(() => app.log.warn("SIEM push failed; retrying")); }, 30_000).unref();
// A tick that overruns must not start a second one on top of it.
const every = (ms: number, name: string, fn: () => Promise<unknown>) => {
  let running = false;
  setInterval(async () => {
    if (running) return;
    running = true;
    try { await fn(); } catch { app.log.warn(`${name} failed; retrying`); } finally { running = false; }
  }, ms).unref();
};
every(5_000, "webhook delivery", async () => { if (!has(await edition(), "business")) return; await enqueueWebhooks(); await deliverWebhooks(); });
every(Number(process.env.RV_MONITOR_INTERVAL_MS ?? 30_000), "health check", checkComponents);
every(3_600_000, "webhook history purge", purgeDeliveries);
every(Number(process.env.RV_MAIL_ALERT_INTERVAL_MS ?? 60_000), "alert email", emailAlerts);
// The spec asks for hourly at least. Each run only writes what changed, so a minute is cheap and
// a new flow shows within the five minutes it allows.
every(Number(process.env.RV_MAP_INTERVAL_MS ?? 60_000), "residency map", async () => { if (has(await edition(), "business")) await mapTick(); });
every(Number(process.env.RV_PAGE_SCAN_INTERVAL_MS ?? 900_000), "page scan", async () => { if (has(await edition(), "business")) await scanAllPages(); });
// A member install reports to its primary; the first round joins it.
if (isMember()) {
  memberTick().catch(() => app.log.warn("first report to the primary install failed; retrying"));
  every(REPORT_EVERY_MS, "report to primary install", memberTick);
}
await app.listen({ host: process.env.HOST ?? "0.0.0.0", port: Number(process.env.PORT ?? 8081) });
