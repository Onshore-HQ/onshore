import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { analyticsCopy, applyLoan, chat, linkAccount, reveal, signup, tokenizeExisting, transfer } from "@/lib/core";

const ok = (x: unknown) => NextResponse.json(x);
const who = async (b: { customer_id?: number }) => b.customer_id ?? Number((await cookies()).get("cid")?.value ?? 0);

export async function POST(req: NextRequest, ctx: { params: Promise<{ route: string[] }> }) {
  const path = (await ctx.params).route.join("/");
  const b = await req.json().catch(() => ({}));
  try {
    switch (path) {
      case "signup": { const c = await signup(b); const r = NextResponse.json({ id: c.id, ref: c.ref }); r.cookies.set("cid", String(c.id), { path: "/", httpOnly: true, sameSite: "lax" }); return r; }
      case "accounts": return ok(await linkAccount(await who(b), b.bank, b.account));
      case "transfers": return ok(await transfer(await who(b), b));
      case "loans": return ok(await applyLoan(await who(b), { amount: Number(b.amount), tenor: Number(b.tenor), income: Number(b.income), employer: b.employer }));
      case "chat": return ok({ reply: await chat(await who(b), b.message) });
      case "reveal": { const role = b.role ?? (await cookies()).get("staff")?.value ?? "support_agent"; if (!String(b.purpose ?? "").trim()) return NextResponse.json({ error: "A purpose is required" }, { status: 400 }); return ok(await reveal(role, b.token, b.purpose)); }
      case "staff": { const r = NextResponse.json({ ok: true }); r.cookies.set("staff", b.role, { path: "/", httpOnly: true, sameSite: "lax" }); return r; }
      case "jobs/analytics-copy": return ok(await analyticsCopy());
      case "jobs/tokenize-existing": return ok(await tokenizeExisting());
      default: return NextResponse.json({ error: "not found" }, { status: 404 });
    }
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "failed" }, { status: 500 });
  }
}
