import { NextRequest, NextResponse } from "next/server";
import { CONTROL_URL, COOKIE, cookieOptions, internalFetch } from "@/lib/session";

// Log in through the control plane; a finished login becomes an HttpOnly cookie.
export async function POST(req: NextRequest) {
  if (req.headers.get("x-rv-console") !== "1") return NextResponse.json({ error: { code: "forbidden", message: "missing console header" } }, { status: 403 });
  const fwd = req.headers.get("x-forwarded-for");
  let upstream;
  try {
    upstream = await internalFetch(`${CONTROL_URL}/v1/auth/login`, { method: "POST", headers: { "content-type": "application/json", ...(fwd ? { "x-forwarded-for": fwd } : {}) }, body: await req.text() });
  } catch {
    return NextResponse.json({ error: { code: "unavailable", message: "the service cannot be reached" } }, { status: 503 });
  }
  const data = (await upstream.json()) as { step?: string; access_token?: string; expires_in?: number; recovery_codes?: string[]; recovery_codes_left?: number };
  if (data.access_token) {
    const res = NextResponse.json({ step: "done", recovery_codes: data.recovery_codes, recovery_codes_left: data.recovery_codes_left });
    res.cookies.set(COOKIE, data.access_token, cookieOptions(data.expires_in ?? 900));
    return res;
  }
  return NextResponse.json(data, { status: upstream.status });
}

export async function DELETE() {
  const res = NextResponse.json({ ok: true });
  res.cookies.set(COOKIE, "", cookieOptions(0));
  return res;
}
