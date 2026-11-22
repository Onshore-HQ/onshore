import { NextRequest, NextResponse } from "next/server";
import { CONTROL_URL, COOKIE, cookieOptions, internalFetch } from "@/lib/session";

function publicUrl(req: NextRequest, path: string) {
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host") ?? "localhost";
  return new URL(path, `https://${host}`);
}

async function complete(req: NextRequest, path: string, body: unknown) {
  const fwd = req.headers.get("x-forwarded-for");
  let data: { access_token?: string; expires_in?: number } = {};
  try {
    const r = await internalFetch(`${CONTROL_URL}${path}`, { method: "POST", headers: { "content-type": "application/json", ...(fwd ? { "x-forwarded-for": fwd } : {}) }, body: JSON.stringify(body) });
    data = (await r.json()) as typeof data;
  } catch {
    data = {};
  }
  if (!data.access_token) return NextResponse.redirect(publicUrl(req, "/login?sso=failed"), 303);
  const res = NextResponse.redirect(publicUrl(req, "/overview"), 303);
  res.cookies.set(COOKIE, data.access_token, cookieOptions(data.expires_in ?? 900));
  return res;
}

// OIDC returns here by GET, with the single-use state the control plane checks.
export async function GET(req: NextRequest) {
  const state = req.nextUrl.searchParams.get("state") ?? "";
  const code = req.nextUrl.searchParams.get("code") ?? "";
  return complete(req, "/v1/auth/sso/oidc", { state, code });
}

// SAML posts its response here.
export async function POST(req: NextRequest) {
  const form = await req.formData();
  return complete(req, "/v1/auth/sso/saml", { SAMLResponse: String(form.get("SAMLResponse") ?? ""), RelayState: String(form.get("RelayState") ?? "") });
}
