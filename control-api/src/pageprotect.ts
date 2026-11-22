import crypto from "node:crypto";
import { Agent, fetch as plainFetch } from "undici";
import { db, newId } from "./lib.js";
import { guardedLookup } from "./netguard.js";
import { broadcast } from "./webhooks.js";

const guarded = new Agent({ connect: { lookup: guardedLookup("destination is not public") } });
const MAX_SCRIPTS = 500, MAX_NEW_PER_HOUR = 50, MAX_DOWNLOAD = 5 << 20;

/**
 * An address safe to keep. A query string or fragment can carry anything a page puts
 * there, so both go. In the path, a long number or an address-shaped segment goes too.
 * Shorter values in a path cannot be told from a file name, which the docs say.
 */
export function scrubUrl(raw: unknown, base?: string): string | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 4000) return null;
  if (raw === "inline" || raw === "eval" || raw === "wasm-eval") return raw;
  let u: URL;
  try {
    u = new URL(raw, base);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  const path = u.pathname.split("/").map((seg) => {
    const plain = (() => { try { return decodeURIComponent(seg); } catch { return seg; } })();
    if (plain.includes("@")) return "[removed]";
    return /\d(?:[ .\-_]?\d){9,}/.test(plain) ? "[removed]" : seg;
  }).join("/");
  const out = u.origin + path;
  return out.length > 1000 ? null : out;
}

export interface ParsedReport { document: string | null; scripts: string[]; source: "csp" | "watcher" }

/** Reads what a browser sends: a legacy CSP report, the Reporting API, or the watcher. */
export function parseReport(text: string): ParsedReport[] {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return [];
  }
  const out: ParsedReport[] = [];
  const isScript = (d: unknown) => typeof d === "string" && d.startsWith("script-src");
  const legacy = (body as { "csp-report"?: Record<string, unknown> })?.["csp-report"];
  if (legacy) {
    if (isScript(legacy["effective-directive"] ?? legacy["violated-directive"])) out.push({ document: String(legacy["document-uri"] ?? ""), scripts: [String(legacy["blocked-uri"] ?? "")], source: "csp" });
    return out;
  }
  if (Array.isArray(body)) {
    for (const r of body.slice(0, 100) as { type?: string; body?: Record<string, unknown> }[]) {
      if (r?.type === "csp-violation" && r.body && isScript(r.body.effectiveDirective)) out.push({ document: String(r.body.documentURL ?? ""), scripts: [String(r.body.blockedURL ?? "")], source: "csp" });
    }
    return out;
  }
  const w = body as { page?: unknown; scripts?: unknown };
  if (typeof w?.page === "string" && Array.isArray(w.scripts)) out.push({ document: w.page, scripts: w.scripts.slice(0, 100).filter((s): s is string => typeof s === "string"), source: "watcher" });
  return out;
}

/** The origin a report claims to come from must be the page's, unless it is plainly not a page at all. */
export function sameOrigin(url: string | null | undefined, origin: string): boolean {
  if (!url) return false;
  try {
    return new URL(url).origin === origin;
  } catch {
    return false;
  }
}

type Page = { id: string; tenant_id: string; origin: string; name: string; flood_alerted_at: Date | null };

async function alert(tenantId: string, kind: string, detail: Record<string, unknown>) {
  await db.$executeRaw`INSERT INTO events.alerts(id,tenant_id,kind,detail,event_at) VALUES (${crypto.randomUUID()}::uuid,${tenantId},${kind},${JSON.stringify(detail)}::jsonb,now())`;
}

// A page in production reports the same few scripts on every load.
const recent = new Map<string, number>();
const DEDUPE_MS = 60_000;

/** Records scripts seen on a page. A report can add to the list and nothing more: it cannot approve. */
export async function ingest(page: Page, urls: string[], source: "csp" | "watcher" | "scan"): Promise<void> {
  const now = Date.now();
  if (recent.size > 20_000) recent.clear();
  for (const raw of new Set(urls)) {
    const url = scrubUrl(raw, page.origin);
    if (!url) continue;
    const k = `${page.id} ${url}`;
    if (now - (recent.get(k) ?? 0) < DEDUPE_MS) continue;
    recent.set(k, now);

    const known = await db.page_scripts.findUnique({ where: { page_id_script_url: { page_id: page.id, script_url: url } } });
    if (known) {
      await db.page_scripts.update({ where: { id: known.id }, data: { last_seen: new Date(), seen_count: { increment: 1 } } });
      if (known.status === "rejected" && (!known.notified_at || now - known.notified_at.getTime() > 3600_000)) {
        await db.page_scripts.update({ where: { id: known.id }, data: { notified_at: new Date() } });
        await alert(page.tenant_id, "page_script_rejected_seen", { page_id: page.id, script_url: url });
        await broadcast(page.tenant_id, `page_rejected_${known.id}_${Math.floor(now / 3600_000)}`, "page.script_rejected_seen", { page_id: page.id, page: page.name, script_url: url });
      }
      continue;
    }
    // Reports are unauthenticated, so someone holding the page's key could send made-up
    // scripts. These limits keep that from filling the list or the alert queue.
    const [total, lastHour] = await Promise.all([
      db.page_scripts.count({ where: { page_id: page.id } }),
      db.page_scripts.count({ where: { page_id: page.id, first_seen: { gt: new Date(now - 3600_000) } } }),
    ]);
    if (total >= MAX_SCRIPTS || lastHour >= MAX_NEW_PER_HOUR) {
      if (!page.flood_alerted_at || now - page.flood_alerted_at.getTime() > 3600_000) {
        page.flood_alerted_at = new Date();
        await db.protected_pages.update({ where: { id: page.id }, data: { flood_alerted_at: page.flood_alerted_at } });
        await alert(page.tenant_id, "page_report_flood", { page_id: page.id });
      }
      return;
    }
    const created = await db.page_scripts.createMany({ data: [{ id: newId("ps"), page_id: page.id, tenant_id: page.tenant_id, script_url: url, source }], skipDuplicates: true });
    if (created.count === 0) continue;
    const row = await db.page_scripts.findUnique({ where: { page_id_script_url: { page_id: page.id, script_url: url } } });
    await alert(page.tenant_id, "page_script_new", { page_id: page.id, script_url: url, source });
    await broadcast(page.tenant_id, `page_new_${row!.id}`, "page.script_new", { page_id: page.id, page: page.name, script_url: url, source });
  }
}

/** Reads at most `limit` bytes, and gives up on anything larger. Nothing fetched is stored. */
async function download(url: string, limit: number): Promise<Buffer> {
  const res = await plainFetch(url, { dispatcher: guarded, redirect: "manual", signal: AbortSignal.timeout(15_000), headers: { "user-agent": "Onshore-PageScan/1", accept: "*/*" } });
  if (res.status < 200 || res.status >= 300) {
    await res.body?.cancel().catch(() => undefined);
    throw new Error(`answered ${res.status}`);
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of res.body as unknown as AsyncIterable<Uint8Array>) {
    size += c.length;
    if (size > limit) throw new Error("too large to check");
    chunks.push(Buffer.from(c));
  }
  return Buffer.concat(chunks);
}

const describeFailure = (e: unknown) => {
  const m = e instanceof Error ? e.message : "";
  if (/^answered \d+$|^too large to check$/.test(m)) return m;
  if ((e as { name?: string })?.name === "TimeoutError") return "timed out";
  if (((e as { cause?: { message?: string } })?.cause?.message ?? "").includes("not public")) return "refused: the destination is not public";
  return "could not connect";
};

/** Script addresses in a page's HTML. A plain read: dynamically added scripts are the watcher's job. */
export function scriptsInHtml(html: string, base: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi)) {
    try {
      out.push(new URL(m[1] ?? m[2] ?? m[3]!, base).toString());
    } catch { /* not an address */ }
  }
  return out;
}

export async function hashScript(url: string): Promise<string> {
  return crypto.createHash("sha256").update(await download(url, MAX_DOWNLOAD)).digest("hex");
}

/** Checks one page from outside: what its HTML loads, and whether approved scripts changed. */
export async function scanPage(pageId: string): Promise<void> {
  const page = await db.protected_pages.findUnique({ where: { id: pageId } });
  if (!page) return;
  let scanError: string | null = null;
  try {
    const html = (await download(page.page_url, MAX_DOWNLOAD)).toString("utf8");
    await ingest(page, scriptsInHtml(html, page.page_url), "scan");
  } catch (e) {
    scanError = describeFailure(e);
  }
  await db.protected_pages.update({ where: { id: page.id }, data: { last_scan_at: new Date(), last_scan_error: scanError } });

  const approved = await db.page_scripts.findMany({ where: { page_id: page.id, status: "approved", script_url: { startsWith: "http" } } });
  for (const s of approved) {
    try {
      const hash = await hashScript(s.script_url);
      if (s.content_hash && s.content_hash !== hash) {
        // Approval was for what it held then, so a change needs someone to look again.
        await db.page_scripts.update({ where: { id: s.id }, data: { status: "changed", content_hash: hash, hash_checked_at: new Date(), hash_changed_at: new Date(), hash_error: null } });
        await alert(page.tenant_id, "page_script_changed", { page_id: page.id, script_url: s.script_url });
        await broadcast(page.tenant_id, `page_changed_${s.id}_${hash.slice(0, 16)}`, "page.script_changed", { page_id: page.id, page: page.name, script_url: s.script_url });
      } else {
        await db.page_scripts.update({ where: { id: s.id }, data: { content_hash: hash, hash_checked_at: new Date(), hash_error: null } });
      }
    } catch (e) {
      await db.page_scripts.update({ where: { id: s.id }, data: { hash_checked_at: new Date(), hash_error: describeFailure(e) } });
    }
  }
}

export async function scanAllPages(): Promise<void> {
  for (const p of await db.protected_pages.findMany({ select: { id: true } })) await scanPage(p.id).catch(() => undefined);
}
