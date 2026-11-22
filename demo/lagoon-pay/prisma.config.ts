import { defineConfig } from "prisma/config";
export default defineConfig({ schema: "prisma/schema.prisma", datasource: { url: process.env.LAGOON_DATABASE_URL ?? "postgres://lagoon:lagoon-demo-only@127.0.0.1:55433/lagoon" } });
