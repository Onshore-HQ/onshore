import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { ApiError, actor, audit, badRequest, db, requireRole, vault, WRITE } from "../lib.js";
import { ALL_COUNTRIES, builtInPack, cloudRegions, COUNTRIES, COUNTRY, countryName, isCountry, LAWS, LAWS_CHECKED, MARKETS, PACKS, SECTORS, suggestLaws, suggestPacks } from "../catalog.js";
import { createVault, ownedVault } from "./vaults.js";
import { planInstall } from "../ee/federation.js";

export { edition, type Edition } from "../edition.js";
import { edition } from "../edition.js";

/**
 * The country this install keeps data in: set by `rv init --country`, else the one
 * recorded at setup. Null until someone says; no country is assumed.
 */
export async function installCountry(tenantId?: string): Promise<string | null> {
  const env = (process.env.RV_COUNTRY ?? "").toUpperCase();
  if (isCountry(env)) return env;
  const t = tenantId ? await db.tenants.findUnique({ where: { id: tenantId } }) : await db.tenants.findFirst();
  return t?.hosting_country && isCountry(t.hosting_country) ? t.hosting_country : null;
}

function catalog() {
  return {
    checked: LAWS_CHECKED,
    countries: COUNTRIES,
    // Every country can be chosen; those without a built-in pack get the organisation's own.
    all_countries: ALL_COUNTRIES,
    laws: LAWS,
    markets: MARKETS,
    packs: PACKS,
    sectors: SECTORS.map(([id, label]) => ({ id, label })),
    cloud_regions: cloudRegions(),
  };
}

const code = z.string().regex(/^[A-Z]{2}$/).refine(isCountry, "unknown country");
const lawId = z.string().refine((l) => !!LAWS[l], "unknown law");
const marketId = z.string().refine((m) => MARKETS.some((x) => x.id === m), "unknown market");
const packId = z.string().refine((p) => !!PACKS[p], "unknown country pack");
const sector = z.enum(SECTORS.map((s) => s[0]) as [string, ...string[]]);
// IANA names such as Europe/London; the database refuses one it does not know.
const timeZone = z.string().regex(/^[A-Za-z]+(?:\/[A-Za-z0-9_+-]+){0,2}$|^UTC$/, "use a time zone such as Europe/London");

async function checkZone(zone: string | undefined) {
  if (!zone) return;
  const found = await db.$queryRaw<{ n: number }[]>`SELECT 1 AS n FROM pg_timezone_names WHERE name=${zone} LIMIT 1`;
  if (found.length === 0) throw badRequest(`unknown time zone ${zone}`);
}

export async function locationRoutes(app: FastifyInstance) {
  app.get("/v1/catalog", async (req) => {
    actor(req);
    return catalog();
  });

  // Everything the setup screen needs in one call.
  app.get("/v1/setup", async (req) => {
    const a = actor(req);
    const t = await db.tenants.findUnique({ where: { id: a.tenantId } });
    return {
      needed: !t?.setup_completed_at,
      edition: await edition(),
      install_country: await installCountry(a.tenantId),
      organisation: t?.name ?? "",
      catalog: catalog(),
    };
  });

  app.post("/v1/setup/complete", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z
      .object({
        organisation: z.string().trim().min(2).max(120),
        home_country: code,
        sector,
        console_language: z.enum(["en", "fr"]),
        console_format: code,
        countries: z.array(code).min(1).max(20),
        markets: z.array(marketId).max(20).default([]),
        laws: z.array(lawId).max(40),
        packs: z.array(packId).max(30),
        // Needed when the install's country was not set by `rv init --country`.
        install_country: code.optional(),
        // The organisation's time zone, from the browser; it decides where a "day" ends.
        time_zone: timeZone.default("UTC"),
        // The screen asks people to confirm that a vault's country is final.
        confirm_countries_final: z.literal(true),
      })
      .parse(req.body);
    const t = await db.tenants.findUnique({ where: { id: a.tenantId } });
    if (t?.setup_completed_at) throw new ApiError(409, "already_set_up", "setup is already finished; change these in Settings");
    await checkZone(b.time_zone);
    const ed = await edition();
    let install = await installCountry(a.tenantId);
    if (ed !== "cloud" && !install) {
      if (!b.install_country) throw badRequest("say which country this install keeps data in");
      install = b.install_country;
      await db.tenants.update({ where: { id: a.tenantId }, data: { hosting_country: install } });
    }
    const countries = [...new Set(b.countries)];

    // Which countries get a vault now, and which are kept for later.
    const now: string[] = [];
    const planned: { country: string; reason: "enterprise_install" | "cloud_region" | "cloud_waitlist" }[] = [];
    if (ed === "cloud") {
      // The cloud console's own country is local; another open region is an Onshore-run
      // install there, linked like an Enterprise one; anywhere else waits for a region.
      const regions = cloudRegions();
      for (const c of countries) {
        if (c === install) now.push(c);
        else planned.push({ country: c, reason: regions.includes(c) ? "cloud_region" : "cloud_waitlist" });
      }
    } else {
      if (!install || !countries.includes(install)) throw badRequest(`this install keeps data in ${install ? countryName(install) : "another country"}, so its vault must be there`);
      if (ed === "free" && countries.length > 1) throw badRequest("the free edition keeps one country per install; more countries need Enterprise or Onshore Cloud");
      now.push(install!);
      for (const c of countries) if (c !== install) planned.push({ country: c, reason: "enterprise_install" });
    }

    const packs = [...new Set(["everywhere", ...b.packs])];
    await db.tenants.update({
      where: { id: a.tenantId },
      data: {
        name: b.organisation, home_country: b.home_country, sector: b.sector, console_language: b.console_language, console_format: b.console_format, time_zone: b.time_zone,
        laws: [...new Set(b.laws)], markets: [...new Set(b.markets)], planned_countries: planned.map((p) => p.country),
      },
    });
    const vaults: { id: string; country: string }[] = [];
    for (const c of now) {
      // Every vault gets the fields its country packs bring, whichever the country.
      const vaultPacks = [...new Set([...packs, builtInPack(c)].filter((x): x is string => !!x))];
      const { id } = await createVault(a, { name: `${b.organisation} · ${countryName(c)}`.slice(0, 80), environment: "production", template: "packs", country: c, packs: vaultPacks });
      vaults.push({ id, country: c });
    }
    // Countries on another install: queue their vault, ready for when that install joins.
    const links: { country: string; command?: string; expires_at?: Date | null }[] = [];
    for (const p of planned) {
      if (p.reason === "cloud_waitlist") {
        await db.region_waitlist.upsert({ where: { tenant_id_country: { tenant_id: a.tenantId, country: p.country } }, create: { tenant_id: a.tenantId, country: p.country, requested_by: a.id }, update: {} });
        continue;
      }
      const vaultPacks = [...new Set([...packs, builtInPack(p.country)].filter((x): x is string => !!x))];
      const link = await planInstall(a, p.country, { vaults: [{ name: `${b.organisation} · ${countryName(p.country)}`.slice(0, 80), country: p.country, packs: vaultPacks, environment: "production" }] });
      // Onshore runs cloud regions, so the join command is for Onshore's operators, not this admin.
      links.push(p.reason === "enterprise_install" ? { country: p.country, command: link.command, expires_at: link.expires_at } : { country: p.country });
    }
    await db.tenants.update({ where: { id: a.tenantId }, data: { setup_completed_at: new Date() } });
    await audit(a, "setup_complete", { detail: { edition: ed, install_country: install, countries, laws: b.laws, markets: b.markets, packs, planned } });
    return { vaults, planned, links };
  });

  // Settings → Locations and laws. A vault's country is not here: it never changes.
  app.get("/v1/settings/locations", async (req) => {
    const a = actor(req);
    const t = await db.tenants.findUnique({ where: { id: a.tenantId } });
    const vs = await db.vaults.findMany({ where: { tenant_id: a.tenantId }, orderBy: { created_at: "asc" }, select: { id: true, name: true, country: true, packs: true, environment: true, time_zone: true } });
    const countries = [...new Set(vs.map((v) => v.country))];
    const suggested = suggestLaws({ countries, sector: t?.sector ?? "other", markets: t?.markets ?? [] });
    return {
      edition: await edition(),
      install_country: await installCountry(a.tenantId),
      home_country: t?.home_country, sector: t?.sector, console_language: t?.console_language, console_format: t?.console_format, time_zone: t?.time_zone ?? "UTC",
      laws: t?.laws ?? [], markets: t?.markets ?? [], planned_countries: t?.planned_countries ?? [],
      suggested_laws: Object.fromEntries(suggested), suggested_packs: suggestPacks({ countries, markets: t?.markets ?? [] }),
      vaults: vs,
      // Laws from the organisation's own country packs, shown beside the built-in ones.
      pack_laws: (await db.custom_packs.findMany({ where: { tenant_id: a.tenantId, archived_at: null }, select: { id: true, name: true, country: true, laws: true } })).filter((p) => (p.laws as unknown[]).length).map((p) => ({ pack: p.id, pack_name: p.name, country: p.country, country_name: countryName(p.country), laws: p.laws })),
      waitlist: (await db.region_waitlist.findMany({ where: { tenant_id: a.tenantId } })).map((w) => ({ country: w.country, since: w.created_at, open: cloudRegions().includes(w.country) })),
      catalog: catalog(),
    };
  });

  app.patch("/v1/settings/locations", async (req) => {
    const a = requireRole(req, ...WRITE);
    const b = z
      .object({
        home_country: code.optional(), sector: sector.optional(), console_language: z.enum(["en", "fr"]).optional(), console_format: code.optional(), time_zone: timeZone.optional(),
        laws: z.array(lawId).max(40).optional(), markets: z.array(marketId).max(20).optional(),
        // Planned countries can only be dropped here; adding one is a new vault or install.
        planned_countries: z.array(z.string().regex(/^[A-Z]{2}$/)).max(20).optional(),
      })
      .parse(req.body);
    await checkZone(b.time_zone);
    const before = await db.tenants.findUnique({ where: { id: a.tenantId } });
    if (b.planned_countries && b.planned_countries.some((c) => !(before?.planned_countries ?? []).includes(c))) throw badRequest("a country can only be removed from the planned list here");
    await db.tenants.update({ where: { id: a.tenantId }, data: { ...b, ...(b.laws ? { laws: [...new Set(b.laws)] } : {}), ...(b.markets ? { markets: [...new Set(b.markets)] } : {}) } });
    await audit(a, "locations_update", { detail: { before: { sector: before?.sector, laws: before?.laws, markets: before?.markets, planned_countries: before?.planned_countries, time_zone: before?.time_zone }, after: b } });
    return { ok: true };
  });

  // A waited-for cloud region has opened: plan its install and queue the vault.
  app.post<{ Params: { country: string } }>("/v1/cloud/waitlist/:country/start", async (req) => {
    const a = requireRole(req, ...WRITE);
    const country = req.params.country.toUpperCase();
    if ((await edition()) !== "cloud") throw badRequest("only Onshore Cloud has regions");
    if (!cloudRegions().includes(country)) throw badRequest("that region is not open yet");
    const w = await db.region_waitlist.findUnique({ where: { tenant_id_country: { tenant_id: a.tenantId, country } } });
    if (!w) throw badRequest("that country is not on your waitlist");
    const t = await db.tenants.findUnique({ where: { id: a.tenantId } });
    const packs = [...new Set(["everywhere", builtInPack(country) ?? "everywhere", ...(t?.markets ?? []).map((m) => MARKETS.find((x) => x.id === m)?.pack).filter((p): p is string => !!p)])];
    const link = await planInstall(a, country, { vaults: [{ name: `${t?.name ?? "Vault"} · ${countryName(country)}`.slice(0, 80), country, packs, environment: "production" }] });
    await db.region_waitlist.delete({ where: { tenant_id_country: { tenant_id: a.tenantId, country } } });
    return { install: link.id };
  });

  app.patch<{ Params: { id: string } }>("/v1/vaults/:id/packs", async (req) => {
    const a = requireRole(req, ...WRITE);
    const v = await ownedVault(a.tenantId, req.params.id);
    const b = z.object({ packs: z.array(packId).max(30) }).parse(req.body);
    const packs = [...new Set(["everywhere", ...b.packs])];
    await db.$transaction(async (tx) => {
      await tx.vaults.update({ where: { id: v.id }, data: { packs } });
      // Services recompile this vault's detectors on the next notification.
      await tx.$executeRaw`INSERT INTO control.ruleset_versions(vault_id,version) VALUES (${v.id},1) ON CONFLICT (vault_id) DO UPDATE SET version=control.ruleset_versions.version+1`;
      await tx.$executeRaw`SELECT pg_notify('rv_rulesets', ${v.id})`;
    });
    await audit(a, "vault_packs_update", { vaultId: v.id, detail: { from: v.packs, to: packs } });
    return { packs };
  });
}
