import crypto from "node:crypto";
import fs from "node:fs";
import { PrismaPg } from "@prisma/adapter-pg";
import { Agent, fetch as tlsFetch } from "undici";
import type { FastifyReply, FastifyRequest } from "fastify";
import { PrismaClient } from "./generated/prisma/client.js";
import { upstreamUrlProblem } from "./netguard.js";

// JSON has no bigint; counts here are far below 2^53.
(BigInt.prototype as unknown as { toJSON(): number }).toJSON = function (this: bigint) {
  return Number(this);
};

export function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

const dbCa = process.env.DATABASE_CA;
export const db = new PrismaClient({ adapter: new PrismaPg({ connectionString: env("DATABASE_URL"), ...(dbCa ? { ssl: { ca: fs.readFileSync(dbCa, "utf8"), rejectUnauthorized: true, minVersion: "TLSv1.3" as const } } : {}) }) });

// mTLS to the vault's internal API when certificates are configured.
export const internalAgent = process.env.RV_TLS_CA
  ? new Agent({ connect: { ca: fs.readFileSync(process.env.RV_TLS_CA), cert: fs.readFileSync(env("RV_TLS_CERT")), key: fs.readFileSync(env("RV_TLS_KEY")), minVersion: "TLSv1.3" } })
  : undefined;

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: Record<string, unknown>,
  ) {
    super(message);
  }
}

export const badRequest = (m: string) => new ApiError(400, "invalid_request", m);
export const forbidden = (m = "your role does not allow this") => new ApiError(403, "forbidden", m);
export const notFound = (m = "not found") => new ApiError(404, "not_found", m);

export function newId(prefix: string, bytes = 10): string {
  return `${prefix}_${crypto.randomBytes(bytes).toString("hex")}`;
}

// ---- tokens (EdDSA, verified by vault-api with the public key) ----------------

const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
const userKey = crypto.createPrivateKey({
  key: Buffer.concat([PKCS8_ED25519, Buffer.from(env("RV_USER_TOKEN_SEED"), "base64")]),
  format: "der",
  type: "pkcs8",
});
const userPublic = crypto.createPublicKey(userKey);
const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");

// Console sessions end after this long without activity. 15 minutes by default; an install can set
// RV_SESSION_IDLE_MINUTES between 5 and 720 (a local demo uses 720). A session never outlives SESSION_MAX_SECONDS.
const idleMinutes = Number(process.env.RV_SESSION_IDLE_MINUTES ?? 15);
export const TOKEN_TTL_SECONDS = Math.round(Math.min(Math.max(Number.isFinite(idleMinutes) ? idleMinutes : 15, 5), 720) * 60);
export const SESSION_MAX_SECONDS = 12 * 60 * 60;

export interface Claims {
  iss: string;
  sub: string;
  aud: string;
  tid: string;
  knd: string;
  mfa: boolean;
  iat: number;
  exp: number;
  auth_time: number;
}

export function issueToken(principalId: string, tenantId: string, authTime = Math.floor(Date.now() / 1000)): string {
  const now = Math.floor(Date.now() / 1000);
  const claims: Claims = { iss: "rv-control", sub: principalId, aud: "onshore", tid: tenantId, knd: "user", mfa: true, iat: now, exp: now + TOKEN_TTL_SECONDS, auth_time: authTime };
  const signing = `${b64u(JSON.stringify({ alg: "EdDSA", typ: "JWT" }))}.${b64u(JSON.stringify(claims))}`;
  return `${signing}.${b64u(crypto.sign(null, Buffer.from(signing), userKey))}`;
}

export function verifyToken(token: string): Claims | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  try {
    const header = JSON.parse(Buffer.from(h, "base64url").toString());
    if (header.alg !== "EdDSA") return null;
    if (!crypto.verify(null, Buffer.from(`${h}.${p}`), userPublic, Buffer.from(s, "base64url"))) return null;
    const c = JSON.parse(Buffer.from(p, "base64url").toString()) as Claims;
    if (c.iss !== "rv-control" || c.aud !== "onshore" || !c.mfa || c.exp <= Date.now() / 1000) return null;
    return c;
  } catch {
    return null;
  }
}

// ---- passwords and MFA --------------------------------------------------------

const SCRYPT = { N: 2 ** 16, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

export function hashPassword(pw: string): string {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(pw, salt, 32, SCRYPT);
  return `scrypt$${SCRYPT.N}$${salt.toString("base64")}$${dk.toString("base64")}`;
}

// Compared against when the email is unknown, so timing does not reveal accounts.
const DUMMY_HASH = hashPassword(crypto.randomBytes(16).toString("hex"));

export function verifyPassword(pw: string, stored: string | null): boolean {
  const parts = (stored ?? DUMMY_HASH).split("$");
  const dk = crypto.scryptSync(pw, Buffer.from(parts[2]!, "base64"), 32, { ...SCRYPT, N: Number(parts[1]) });
  const ok = crypto.timingSafeEqual(dk, Buffer.from(parts[3]!, "base64"));
  return ok && stored !== null;
}

const secretKey = crypto.hkdfSync("sha256", Buffer.from(env("RV_CONTROL_SECRET")), Buffer.alloc(0), "rv-totp", 32);

export function encryptSecret(plain: string): string {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", Buffer.from(secretKey), iv);
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64");
}

export function decryptSecret(enc: string): string {
  const b = Buffer.from(enc, "base64");
  const d = crypto.createDecipheriv("aes-256-gcm", Buffer.from(secretKey), b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8");
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function fromBase32(s: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
    value &= (1 << bits) - 1;
  }
  return Buffer.from(out);
}

export function totpAt(secret: string, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = crypto.createHmac("sha1", fromBase32(secret)).update(counter).digest();
  const offset = mac[mac.length - 1]! & 15;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

/** Returns the matched time step, so that a code cannot be used twice. */
export function matchTotp(secret: string, code: string, lastStep: bigint | null): number | null {
  const now = Math.floor(Date.now() / 1000 / 30);
  for (const step of [now, now - 1, now + 1]) {
    if (lastStep !== null && BigInt(step) <= lastStep) continue;
    const want = totpAt(secret, step);
    if (code.length === 6 && crypto.timingSafeEqual(Buffer.from(want), Buffer.from(code))) return step;
  }
  return null;
}

// ---- request context ----------------------------------------------------------

export interface Actor {
  id: string;
  tenantId: string;
  roles: string[];
  displayName: string;
  ip: string;
  authTime: number;
}

declare module "fastify" {
  interface FastifyRequest {
    actor?: Actor;
    apiKey?: { id: string; tenantId: string; scopes: string[]; createdBy: string } | null;
  }
}

export function actor(req: FastifyRequest): Actor {
  if (!req.actor) throw new ApiError(401, "unauthenticated", "missing or expired token");
  return req.actor;
}

export function requireRole(req: FastifyRequest, ...roles: string[]): Actor {
  const a = actor(req);
  if (!a.roles.some((r) => roles.includes(r))) throw forbidden();
  return a;
}

export const WRITE = ["admin"];
export const READ_AUDIT = ["admin", "compliance", "dpo"];
// Staff lists, pipeline config and policies: not needed by a support agent.
export const READ_CONFIG = ["admin", "compliance", "dpo", "engineer"];

/** Refuses destinations that could reach internal services (SSRF). The processor
 *  checks again at connect time, which also covers DNS rebinding. */
export function checkUpstreamUrl(url: string) {
  const problem = upstreamUrlProblem(url);
  if (problem) throw badRequest(problem);
}

/** Removes identifiers from free text before it is stored. */
export async function redactText(text: string): Promise<string> {
  return (await vault<{ text: string }>("/internal/redact", { text })).text;
}

export function clientIp(req: FastifyRequest): string {
  return req.ip;
}

// ---- vault-api internal client ------------------------------------------------

const VAULT = env("VAULT_INTERNAL_URL");
const INTERNAL = env("RV_INTERNAL_TOKEN");

export async function vault<T = Record<string, unknown>>(path: string, body: unknown, timeoutMs = 60_000): Promise<T> {
  let resp;
  try {
    resp = await tlsFetch(`${VAULT}${path}`, {
      method: "POST",
      ...(internalAgent ? { dispatcher: internalAgent } : {}),
      headers: { "content-type": "application/json", authorization: `Bearer ${INTERNAL}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    throw new ApiError(503, "vault_unavailable", "the vault service cannot be reached");
  }
  const data = (await resp.json().catch(() => ({}))) as { error?: { code?: string; message?: string } };
  if (!resp.ok) {
    throw new ApiError(resp.status, data.error?.code ?? "vault_error", data.error?.message ?? "vault request failed");
  }
  return data as T;
}

/** Records a control-plane action on the tamper-evident chain. Failure fails the action. */
export async function audit(
  a: Pick<Actor, "tenantId" | "id" | "ip">,
  action: string,
  extra: { vaultId?: string; detail?: unknown; policyId?: string; policyVersion?: number; decision?: string; breakGlass?: boolean } = {},
): Promise<void> {
  await vault("/internal/audit/append", {
    tenant_id: a.tenantId,
    principal_id: a.id,
    principal_kind: "user",
    source_ip: a.ip,
    action,
    vault_id: extra.vaultId ?? "",
    policy_id: extra.policyId ?? "",
    policy_version: extra.policyVersion ?? 0,
    decision: extra.decision ?? "",
    break_glass: extra.breakGlass ?? false,
    detail: extra.detail === undefined ? "" : JSON.stringify(extra.detail),
  });
}

export function sendError(reply: FastifyReply, err: unknown) {
  if (err instanceof ApiError) {
    return reply.status(err.status).send({ error: { code: err.code, message: err.message, ...(err.details ?? {}) } });
  }
  const e = err as { name?: string; issues?: { path: (string | number)[]; message: string }[]; statusCode?: number };
  if (e?.name === "ZodError" && e.issues) {
    const first = e.issues[0];
    return reply.status(400).send({ error: { code: "invalid_request", message: `${first?.path.join(".")}: ${first?.message}` } });
  }
  if (e?.statusCode && e.statusCode < 500) {
    return reply.status(e.statusCode).send({ error: { code: "invalid_request", message: "malformed request" } });
  }
  // The error may quote query parameters, so it stays out of logs and responses.
  reply.log.error({ kind: e?.name }, "unhandled error");
  return reply.status(500).send({ error: { code: "internal", message: "internal error" } });
}
