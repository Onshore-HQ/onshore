import { cookies } from "next/headers";
export async function staffRole() { return (await cookies()).get("staff")?.value ?? "support_agent"; }
