import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { db } from "./db";
export async function currentCustomer() {
  const id = Number((await cookies()).get("cid")?.value ?? 0);
  const c = id ? await db.customer.findUnique({ where: { id }, include: { accounts: true } }) : null;
  if (!c) redirect("/signup");
  return c;
}
export const display = (v: string) => (v.startsWith("tok_") ? "On file" : v);
