import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@/generated/prisma/client";

const g = globalThis as unknown as { __db?: PrismaClient };
export const db = g.__db ?? new PrismaClient({ adapter: new PrismaPg({ connectionString: process.env.LAGOON_DATABASE_URL ?? "postgres://lagoon:lagoon-demo-only@127.0.0.1:55433/lagoon", max: 6 }) });
g.__db = db;
