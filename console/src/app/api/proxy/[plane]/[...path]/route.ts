import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { CONTROL_URL, COOKIE, cookieOptions, FILES_URL, internalFetch, tokenExpiry, VAULT_URL } from "@/lib/session";

// The browser never holds the bearer token: it stays in an HttpOnly cookie and is
// attached here. The data plane is reachable only through its public /v1/vaults
// routes, and /internal is never forwarded.
const SAFE_SEGMENT = /^[A-Za-z0-9_.:-]+$/;

async function forward(req: NextRequest, ctx: { params: Promise<{ plane: string; path: string[] }> }) {
  const { plane, path } = await ctx.params;
  if (req.method !== "GET" && req.headers.get("x-rv-console") !== "1") {
    return NextResponse.json({ error: { code: "forbidden", message: "missing console header" } }, { status: 403 });
  }
  if (!path.every((s) => SAFE_SEGMENT.test(s) && s !== "..")) {
    return NextResponse.json({ error: { code: "invalid_request", message: "bad path" } }, { status: 400 });
  }
  const isData = plane === "data";
  const isFiles = plane === "files";
  if (plane !== "control" && !isData && !isFiles) return NextResponse.json({ error: { code: "not_found", message: "not found" } }, { status: 404 });
  if (isData && !(path[0] === "v1" && path[1] === "vaults")) return NextResponse.json({ error: { code: "not_found", message: "not found" } }, { status: 404 });

  const store = await cookies();
  let token = store.get(COOKIE)?.value;
  const base = isData ? VAULT_URL : isFiles ? FILES_URL : CONTROL_URL;
  const headers: Record<string, string> = { "x-rv-module": "console" };
  const contentType = req.headers.get("content-type");
  if (contentType) headers["content-type"] = contentType;
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) headers["x-forwarded-for"] = fwd;
  const purpose = req.headers.get("x-rv-purpose");
  if (purpose) headers["x-rv-purpose"] = purpose;

  // Sliding renewal: the control plane caps total session length.
  let renewed: string | null = null;
  if (token && tokenExpiry(token) - Date.now() / 1000 < 300) {
    const r = await internalFetch(`${CONTROL_URL}/v1/auth/refresh`, { method: "POST", headers: { authorization: `Bearer ${token}`, ...(fwd ? { "x-forwarded-for": fwd } : {}) } }).catch(() => null);
    if (r?.ok) {
      renewed = ((await r.json()) as { access_token: string }).access_token;
      token = renewed;
    }
  }
  if (token) headers.authorization = `Bearer ${token}`;

  const body = req.method === "GET" || req.method === "HEAD" ? undefined : await req.arrayBuffer();
  let upstream;
  try {
    upstream = await internalFetch(`${base}/${path.join("/")}${req.nextUrl.search}`, { method: req.method, headers, body: body && body.byteLength ? body : undefined, signal: AbortSignal.timeout(120_000) });
  } catch {
    return NextResponse.json({ error: { code: "unavailable", message: "the service cannot be reached" } }, { status: 503 });
  }
  const res = new NextResponse(upstream.body as ReadableStream | null, { status: upstream.status });
  for (const h of ["content-type", "content-disposition", "x-request-id", "x-rv-findings", "x-rv-low-confidence"]) {
    const v = upstream.headers.get(h);
    if (v) res.headers.set(h, v);
  }
  res.headers.set("cache-control", "no-store");
  if (renewed) res.cookies.set(COOKIE, renewed, cookieOptions(15 * 60));
  return res;
}

export const GET = forward;
export const POST = forward;
export const PUT = forward;
export const PATCH = forward;
export const DELETE = forward;
