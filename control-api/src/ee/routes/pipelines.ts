import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { DEFAULT_ENTITY_TYPES, ENTITY_TYPES } from "../../catalog.js";
import { audit, checkUpstreamUrl, db, newId, notFound, READ_CONFIG, requireRole, vault, WRITE } from "../../lib.js";
import { ownedVault } from "../../routes/vaults.js";
import { mapChanged } from "../map/run.js";
import { TRANSFER_BASIS } from "../../routes/ai-routes.js";
export { TRANSFER_BASIS };

const ENTITIES = ENTITY_TYPES as [string, ...string[]];
// payment_ref is opt-in: whether references are "payment transaction data" is undecided.
const DEFAULT_ENTITIES = DEFAULT_ENTITY_TYPES;
const ACTION = z.enum(["tokenize", "mask", "drop", "pass"]);

const sensitive = z.array(z.string().regex(/^\$\.[\w.]+:[a-z_0-9]+$/, "use $.path.to.value:entity_type")).default([]);

const hashKey = (k: string) => crypto.createHash("sha256").update(k).digest("hex");

function setup(p: { id: string; source_type: string; upstream_url: string }, key: string | null) {
  const host = process.env.RV_HOST ?? "vault.example.com";
  const k = key ?? "<your-pipeline-key>";
  if (p.source_type === "otlp") {
    return `# OpenTelemetry Collector: swap one exporter endpoint.
exporters:
  otlphttp/onshore:
    endpoint: https://${host}/logs/otlp/${p.id}
    headers:
      X-RV-Pipeline-Key: ${k}
    # When the vault is unreachable the processor answers 503. These settings keep
    # the batch here and retry; raw logs are never forwarded around it.
    retry_on_failure: { enabled: true, max_elapsed_time: 0 }
    sending_queue: { enabled: true, storage: file_storage }
service:
  pipelines:
    logs:
      exporters: [otlphttp/onshore]`;
  }
  if (p.source_type === "fluentbit") {
    return `# Fluent Bit: send to the processor, which forwards to ${p.upstream_url}
[OUTPUT]
    Name          http
    Match         *
    Host          ${host}
    Port          443
    URI           /logs/http/${p.id}
    Format        json_lines
    tls           On
    tls.verify    On
    Header        X-RV-Pipeline-Key ${k}
    Retry_Limit   False
    storage.total_limit_size 2G`;
  }
  return `# Vector: an HTTP sink to the processor, which forwards to ${p.upstream_url}
[sinks.onshore]
type = "http"
inputs = ["your_logs"]
uri = "https://${host}/logs/http/${p.id}"
encoding.codec = "json"
request.headers.X-RV-Pipeline-Key = "${k}"
request.retry_attempts = 9007199254740991
buffer.type = "disk"
buffer.max_size = 2147483648`;
}

function view<T extends { ingest_key_hash: string; id: string; source_type: string; upstream_url: string }>(p: T) {
  const { ingest_key_hash: _h, ...rest } = p;
  return { ...rest, setup: setup(p, null) };
}

export async function pipelineRoutes(app: FastifyInstance) {
  app.get("/v1/log-pipelines", async (req) => {
    const a = requireRole(req, ...READ_CONFIG);
    const rows = await db.log_pipelines.findMany({ where: { vaults: { tenant_id: a.tenantId } }, orderBy: { created_at: "asc" } });
    const spark = await db.$queryRaw<{ source_id: string; day: Date; n: bigint }[]>`
      SELECT d.source_id, date_trunc('day', d.occurred_at) AS day, sum(d.count)::bigint AS n
      FROM events.detection_events d JOIN control.vaults v ON v.id=d.vault_id
      WHERE v.tenant_id=${a.tenantId} AND d.module='logs' AND d.occurred_at>now()-interval '14 days' GROUP BY 1,2 ORDER BY 2`;
    return { pipelines: rows.map((p) => ({ ...view(p), sparkline: spark.filter((s) => s.source_id === p.id).map((s) => ({ day: s.day, count: s.n })) })) };
  });

  app.post("/v1/log-pipelines", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z
      .object({
        vault_id: z.string(),
        name: z.string().min(1).max(80),
        source_type: z.enum(["otlp", "fluentbit", "vector"]),
        destination: z.string().min(1).max(60),
        upstream_url: z.url(),
        entity_types: z.array(z.enum(ENTITIES)).min(1).default(DEFAULT_ENTITIES),
        action_per_type: z.record(z.string(), ACTION).default({}),
        sensitive_paths: sensitive,
        sample_rate: z.number().min(0.01).max(1).default(1),
        failure_mode: z.enum(["buffer", "drop"]).default("buffer"),
        transfer_basis: TRANSFER_BASIS.default("not_assessed"),
      })
      .parse(req.body);
    await ownedVault(a.tenantId, b.vault_id);
    checkUpstreamUrl(b.upstream_url);
    const id = newId("pl");
    const key = `rvk_${crypto.randomBytes(24).toString("base64url")}`;
    // Every pipeline starts in shadow mode: detect and count, change nothing.
    const p = await db.log_pipelines.create({ data: { id, ...b, mode: "shadow", ingest_key_hash: hashKey(key) } });
    await audit(a, "pipeline_create", { vaultId: b.vault_id, detail: { pipeline: id, destination: b.destination } });
    return { id, ingest_key: key, setup: setup(p, key) };
  });

  app.patch<{ Params: { id: string } }>("/v1/log-pipelines/:id", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z
      .object({
        mode: z.enum(["shadow", "enforcing"]).optional(),
        failure_mode: z.enum(["buffer", "drop"]).optional(),
        action_per_type: z.record(z.string(), ACTION).optional(),
        entity_types: z.array(z.enum(ENTITIES)).min(1).optional(),
        sensitive_paths: sensitive.optional(),
        sample_rate: z.number().min(0.01).max(1).optional(),
        upstream_url: z.url().optional(),
        destination: z.string().min(1).max(60).optional(),
        transfer_basis: TRANSFER_BASIS.optional(),
      })
      .parse(req.body);
    if (b.upstream_url) checkUpstreamUrl(b.upstream_url);
    const p = await db.log_pipelines.findFirst({ where: { id: req.params.id, vaults: { tenant_id: a.tenantId } } });
    if (!p) throw notFound();
    await db.log_pipelines.update({ where: { id: p.id }, data: b });
    await audit(a, "pipeline_update", { vaultId: p.vault_id, detail: { pipeline: p.id, ...b } });
    if (b.mode || b.upstream_url || b.action_per_type) await mapChanged(p.vault_id, { cause: b.mode === "enforcing" ? "route_enforcing" : undefined });
    return { ok: true };
  });

  app.post<{ Params: { id: string } }>("/v1/log-pipelines/:id/rotate-key", async (req) => {
    const a = requireRole(req, ...WRITE);
    const p = await db.log_pipelines.findFirst({ where: { id: req.params.id, vaults: { tenant_id: a.tenantId } } });
    if (!p) throw notFound();
    const key = `rvk_${crypto.randomBytes(24).toString("base64url")}`;
    await db.log_pipelines.update({ where: { id: p.id }, data: { ingest_key_hash: hashKey(key) } });
    await audit(a, "pipeline_key_rotate", { vaultId: p.vault_id, detail: { pipeline: p.id } });
    return { ingest_key: key };
  });

  // Before and after: exactly what would be forwarded. Nothing is stored.
  app.post("/v1/log-pipelines/preview", async (req) => {
    const a = requireRole(req, ...WRITE, "engineer");
    const b = z
      .object({
        sample: z.string().max(65536),
        action_per_type: z.record(z.string(), ACTION).default({}),
        entity_types: z.array(z.enum(ENTITIES)).default(DEFAULT_ENTITIES),
        sensitive_paths: sensitive,
        vault_id: z.string().optional(),
      })
      .parse(req.body);
    if (b.vault_id) await ownedVault(a.tenantId, b.vault_id);
    return vault("/internal/logs/preview", b);
  });
}

