import { defineConfig } from "prisma/config";

// The SQL migrations in data-plane/migrations own the schema. This client is
// generated from a migrated database (`npm run prisma:pull`) and never migrates.
export default defineConfig({
  schema: "prisma/schema.prisma",
  datasource: { url: process.env.PRISMA_DATABASE_URL ?? "postgres://localhost/unused" },
});
