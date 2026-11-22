// What setup and Settings offer: countries, the laws they suggest, the places
// customers may live, and the country packs that detect each country's data.
// Law summaries are not legal advice; each carries its source and the date it was
// last checked, and the console shows both.

export const LAWS_CHECKED = "2026-11-21";

export interface Country { code: string; name: string; region: "Africa" | "Middle East" | "Europe" | "Americas" | "Asia-Pacific"; city: string; laws: string[]; pack: string; market?: string; eu?: boolean; format: string; zone?: string }
export interface Law { name: string; effect: string; note?: string; sources: string[] }
export interface Market { id: string; label: string; laws: string[]; pack: string }
export interface Pack { name: string; ready: boolean; examples: [string, string][] }

export const COUNTRIES: Country[] = [
  { code: "NG", name: "Nigeria", region: "Africa", city: "Lagos", laws: ["ndpa"], pack: "ng", market: "ng", format: "21/11/2026 · ₦1,250.50 · +234", zone: "Africa/Lagos" },
  { code: "GH", name: "Ghana", region: "Africa", city: "Accra", laws: ["gh_dpa"], pack: "gh", market: "gh", format: "21/11/2026 · GH₵1,250.50 · +233", zone: "Africa/Accra" },
  { code: "KE", name: "Kenya", region: "Africa", city: "Nairobi", laws: ["ke_dpa"], pack: "ke", market: "ke", format: "21/11/2026 · KSh 1,250.50 · +254", zone: "Africa/Nairobi" },
  { code: "ZA", name: "South Africa", region: "Africa", city: "Johannesburg", laws: ["popia"], pack: "za", format: "2026/11/21 · R 1 250,50 · +27", zone: "Africa/Johannesburg" },
  { code: "EG", name: "Egypt", region: "Africa", city: "Cairo", laws: ["eg_pdpl"], pack: "eg", format: "21/11/2026 · EGP 1,250.50 · +20", zone: "Africa/Cairo" },
  { code: "AE", name: "United Arab Emirates", region: "Middle East", city: "Dubai", laws: ["ae_pdpl"], pack: "ae", market: "gulf", format: "21/11/2026 · AED 1,250.50 · +971", zone: "Asia/Dubai" },
  { code: "SA", name: "Saudi Arabia", region: "Middle East", city: "Riyadh", laws: ["sa_pdpl"], pack: "sa", format: "21/11/2026 · SAR 1,250.50 · +966", zone: "Asia/Riyadh" },
  { code: "QA", name: "Qatar", region: "Middle East", city: "Doha", laws: ["qa_pdppl"], pack: "qa", format: "21/11/2026 · QAR 1,250.50 · +974", zone: "Asia/Qatar" },
  { code: "GB", name: "United Kingdom", region: "Europe", city: "London", laws: ["uk_gdpr"], pack: "gb", market: "gb", format: "21/11/2026 · £1,250.50 · +44", zone: "Europe/London" },
  { code: "DE", name: "Germany", region: "Europe", city: "Frankfurt", laws: ["gdpr"], pack: "eu", market: "eu", eu: true, format: "21.11.2026 · 1.250,50 € · +49", zone: "Europe/Berlin" },
  { code: "FR", name: "France", region: "Europe", city: "Paris", laws: ["gdpr"], pack: "eu", market: "eu", eu: true, format: "21/11/2026 · 1 250,50 € · +33", zone: "Europe/Paris" },
  { code: "IE", name: "Ireland", region: "Europe", city: "Dublin", laws: ["gdpr"], pack: "eu", market: "eu", eu: true, format: "21/11/2026 · €1,250.50 · +353", zone: "Europe/Dublin" },
  { code: "NL", name: "Netherlands", region: "Europe", city: "Amsterdam", laws: ["gdpr"], pack: "eu", market: "eu", eu: true, format: "21-11-2026 · € 1.250,50 · +31", zone: "Europe/Amsterdam" },
  { code: "US", name: "United States", region: "Americas", city: "Virginia", laws: [], pack: "us", format: "11/21/2026 · $1,250.50 · +1" },
  { code: "CA", name: "Canada", region: "Americas", city: "Toronto", laws: ["pipeda", "qc25"], pack: "ca", format: "2026-11-21 · $1,250.50 · +1" },
  { code: "BR", name: "Brazil", region: "Americas", city: "São Paulo", laws: ["lgpd"], pack: "br", format: "21/11/2026 · R$ 1.250,50 · +55", zone: "America/Sao_Paulo" },
  { code: "IN", name: "India", region: "Asia-Pacific", city: "Mumbai", laws: ["dpdp"], pack: "in", format: "21/11/2026 · ₹1,250.50 · +91", zone: "Asia/Kolkata" },
  { code: "SG", name: "Singapore", region: "Asia-Pacific", city: "Singapore", laws: ["sg_pdpa"], pack: "sg", format: "21/11/2026 · S$1,250.50 · +65", zone: "Asia/Singapore" },
];
// Alphabetical: no country comes first.
COUNTRIES.sort((a, b) => a.name.localeCompare(b.name));
export const COUNTRY = Object.fromEntries(COUNTRIES.map((c) => [c.code, c])) as Record<string, Country>;

// Every country (ISO 3166-1). The 18 above come with a built-in pack and laws; any other
// can be chosen too, with an organisation's own country pack (routes/packs.ts).
const ISO = new Set("AD AE AF AG AI AL AM AO AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GT GU GW GY HK HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split(" "));
const regionNames = new Intl.DisplayNames(["en"], { type: "region" });
export const isCountry = (c: string) => ISO.has(c);
export const countryName = (c: string) => COUNTRY[c]?.name ?? (ISO.has(c) ? regionNames.of(c) ?? c : c);
/** The built-in pack for a country, or null when it has none (an organisation can make its own). */
export const builtInPack = (c: string): string | null => COUNTRY[c]?.pack ?? null;
export const ALL_COUNTRIES = [...ISO].map((code) => ({ code, name: countryName(code), built_in: !!COUNTRY[code] })).sort((a, b) => a.name.localeCompare(b.name));

export const LAWS: Record<string, Law> = {
  ndpa: { name: "Nigeria Data Protection Act 2023", effect: "Data leaving Nigeria needs a recorded ground under Part VIII (sections 41 to 43). Adds the yearly compliance audit return: due 31 March, filed through a licensed audit firm, by the highest-tier controllers under the NDPC's 2025 directive (GAID).", sources: ["https://ndpc.gov.ng/wp-content/uploads/2025/07/NDP-ACT-GAID-2025-MARCH-20TH.pdf", "https://www.mondaq.com/nigeria/data-protection/1736914/data-protection-compliance-in-nigeria-audit-return-obligations-for-2026"] },
  cbn: { name: "CBN rule on data localisation in payments", effect: "Payment data must be stored and managed in Nigeria from 1 January 2027 (circular of 15 June 2026). Flags any flow that stores it abroad on the residency map.", sources: ["https://www.cbn.gov.ng/Out/2026/CCD/CIRCULAR%20ON%20INTRODUCTION%20OF%20MARKET%20STRUCTURE%20REQUIREMENTS%2C%20DATA%20LOCALISATION%2C%20ULTIMATE%20BENEFICIAL%20OWNERSHIP%20DISCLOSURE%2C%20AND%20SYSTEMIC%20OVERSIGHT%20MEASURES%20IN%20THE%20NIGERIA%20PAYMENTS%20SYSTEM.pdf"] },
  gh_dpa: { name: "Ghana Data Protection Act 2012 (Act 843)", effect: "Adds registration with the Data Protection Commission and its renewal to Reports.", sources: ["https://www.dataprotection.org.gh/"] },
  ke_dpa: { name: "Kenya Data Protection Act 2019", effect: "Adds registration with the ODPC (section 18). Data leaving Kenya needs proof of safeguards, or consent, under sections 48 to 50.", sources: ["https://www.odpc.go.ke/wp-content/uploads/2024/02/TheDataProtectionAct__No24of2019.pdf", "https://www.odpc.go.ke/wp-content/uploads/2026/04/Guidance-Note-on-Cross-border-Data-Transfers.pdf"] },
  popia: { name: "South Africa: Protection of Personal Information Act (POPIA)", effect: "Adds information officer registration. Data leaving South Africa needs one of the grounds in section 72.", sources: ["https://inforegulator.org.za/"] },
  eg_pdpl: { name: "Egypt Personal Data Protection Law (Law 151 of 2020)", effect: "Most controllers and processors need a licence from the Personal Data Protection Centre, and sending data abroad needs its own licence or permit.", note: "Executive regulations issued November 2025 (Decree 816 of 2025). The one-year grace period ended November 2026.", sources: ["https://cms.law/en/are/legal-updates/egypt-s-pdpl-executive-regulations-issued-one-year-compliance-countdown-begins", "https://www.tamimi.com/news/from-policy-to-practice-egypt-issues-executive-regulations-of-the-personal-data-protection-law"] },
  ae_pdpl: { name: "UAE Personal Data Protection Law (Federal Decree-Law 45 of 2021)", effect: "Tracks the conditions for sending data abroad (Articles 22 and 23). The DIFC and ADGM free zones have their own data protection laws.", note: "In force, but its executive regulations had still not been issued as of mid-2026.", sources: ["https://www.morganlewis.com/pubs/2026/06/uae-establishes-federal-authority-for-artificial-intelligence-and-data"] },
  sa_pdpl: { name: "Saudi Personal Data Protection Law", effect: "Data leaving the Kingdom needs SDAIA's standard contractual clauses, binding common rules or another ground, plus a risk assessment in some cases (Transfer Regulation, amended September 2024). Some controllers must register with SDAIA.", note: "SDAIA published draft amendments for consultation in October 2026.", sources: ["https://insightplus.bakermckenzie.com/bm/data-technology/saudi-arabia-updates-data-transfer-regulations-and-introduces-the-first-set-of-standard-contractual-clauses", "https://www.clydeco.com/es/insights/2026/10/sdaia-publishes-draft-amendments-to-the-pdpl"] },
  qa_pdppl: { name: "Qatar Personal Data Privacy Protection Law (Law 13 of 2016)", effect: "Adds the law's processing and cross-border duties to Reports.", sources: ["https://compliance.qcert.org/"] },
  uk_gdpr: { name: "UK GDPR and Data Protection Act 2018, as amended in 2025", effect: "Data leaving the UK needs UK adequacy or a safeguard such as the IDTA, checked against the data protection test: protection not materially lower than the UK's.", note: "The test applies to new transfers from 5 February 2026 (Data (Use and Access) Act 2025).", sources: ["https://privacymatters.dlapiper.com/2026/02/uk-commencement-of-the-data-protection-provisions-in-the-data-use-and-access-act/", "https://www.mills-reeve.com/publications/what-are-the-new-rules-on-international-data-transfers/"] },
  gdpr: { name: "EU General Data Protection Regulation (GDPR)", effect: "Adds records of processing (Article 30). Data leaving the EU needs adequacy, standard contractual clauses or binding corporate rules (Chapter V).", sources: ["https://eur-lex.europa.eu/eli/reg/2016/679/oj"] },
  dora: { name: "EU Digital Operational Resilience Act (DORA)", effect: "Adds the register of information on ICT third-party providers (Article 28), in force since 17 January 2025.", sources: ["https://eur-lex.europa.eu/eli/reg/2022/2554/oj"] },
  ccpa: { name: "California Consumer Privacy Act, as amended by the CPRA", effect: "Adds requests to see, delete and correct data, and the right to limit use of sensitive personal information.", sources: ["https://cppa.ca.gov/"] },
  glba: { name: "US Gramm-Leach-Bliley Act (financial privacy)", effect: "Adds evidence for the Safeguards Rule (non-bank lenders and fintechs) or banking regulators' guidelines.", sources: ["https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act"] },
  hipaa: { name: "US HIPAA (health information)", effect: "Adds business associate agreement tracking for every tool that touches protected health information.", sources: ["https://www.hhs.gov/hipaa/"] },
  pipeda: { name: "Canada PIPEDA", effect: "You stay accountable for data sent to service providers abroad, and must say so in your privacy notice.", sources: ["https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/"] },
  qc25: { name: "Quebec Law 25", effect: "Data about people in Quebec needs a privacy impact assessment before it leaves the province.", sources: ["https://www.cai.gouv.qc.ca/"] },
  lgpd: { name: "Brazil LGPD", effect: "Adds records of processing (Article 37). Data leaving Brazil on contract terms must use the ANPD's standard clauses (Resolution 19/2024), required since August 2025.", sources: ["https://www.mattosfilho.com.br/en/unico/dpas-contractual-clauses/", "https://www.hunton.com/privacy-and-cybersecurity-law-blog/brazilian-data-protection-authority-regulates-international-data-transfers"] },
  dpdp: { name: "India Digital Personal Data Protection Act 2023", effect: "Adds consent and notice records. Data may go abroad except to countries the government restricts (section 16).", note: "Rules notified 13 November 2025; most duties apply from May 2027.", sources: ["https://www.barandbench.com/view-point/meity-notifies-final-digital-personal-data-protection-rules-2025"] },
  sg_pdpa: { name: "Singapore PDPA", effect: "Adds the Transfer Limitation Obligation: data sent abroad must keep comparable protection.", sources: ["https://www.pdpc.gov.sg/"] },
};

export const MARKETS: Market[] = [
  { id: "ng", label: "People in Nigeria", laws: ["ndpa"], pack: "ng" },
  { id: "gh", label: "People in Ghana", laws: ["gh_dpa"], pack: "gh" },
  { id: "ke", label: "People in Kenya", laws: ["ke_dpa"], pack: "ke" },
  { id: "eu", label: "People in the EU", laws: ["gdpr"], pack: "eu" },
  { id: "gb", label: "People in the UK", laws: ["uk_gdpr"], pack: "gb" },
  { id: "ca_us", label: "People in California", laws: ["ccpa"], pack: "us" },
  { id: "gulf", label: "People in the UAE", laws: ["ae_pdpl"], pack: "ae" },
];

// `ready` packs have detectors in the data plane (data-plane/internal/detect/packs.go).
// A pack added to this list before its detectors exist must say ready: false; its
// vaults then detect only the "everywhere" types.
export const PACKS: Record<string, Pack> = {
  everywhere: { name: "Everywhere", ready: true, examples: [["Names, from every region", "Sarah Johnson, Kofi Mensah"], ["Email addresses", "sarah@example.com"], ["Payment card numbers", "4111 1111 1111 1111"], ["Amounts in any currency", "$8,500 · €1.250,50"], ["Phone numbers with a country code", "+44 20 7946 0958"], ["Your own custom types", "STAFF-00421"]] },
  ng: { name: "Nigeria", ready: true, examples: [["BVN (11 digits)", "22123456789"], ["NIN (11 digits)", "12345678901"], ["Bank account (NUBAN)", "0123456789"], ["Phone", "+234 803 123 4567"], ["Amounts in naira", "₦850,000"], ["Places", "Lekki → Lagos"]] },
  gh: { name: "Ghana", ready: true, examples: [["Ghana Card (also the tax ID)", "GHA-123456789-1"], ["Mobile and mobile money numbers", "024 123 4567"]] },
  ke: { name: "Kenya", ready: true, examples: [["KRA PIN", "A123456789Z"], ["National ID, with “ID” nearby", "12345678"], ["Mobile and M-Pesa numbers", "0712 345 678"]] },
  za: { name: "South Africa", ready: true, examples: [["ID number, date and check digit checked", "8001015009087"], ["Mobile", "082 123 4567"]] },
  eg: { name: "Egypt", ready: true, examples: [["National ID, date and governorate checked", "29001011234567"], ["Mobile", "+20 100 123 4567"]] },
  ae: { name: "United Arab Emirates", ready: true, examples: [["Emirates ID, check digit checked", "784-1990-1234567-6"], ["IBAN", "AE07 0331 2345 6789 0123 456"], ["Mobile", "050 123 4567"]] },
  sa: { name: "Saudi Arabia", ready: true, examples: [["National ID (starts 1), with “ID” nearby", "1012345672"], ["Iqama (starts 2), with “Iqama” nearby", "2012345670"], ["IBAN", "SA03 8000 0000 6080 1016 7519"], ["Mobile", "050 123 4567"]] },
  qa: { name: "Qatar", ready: true, examples: [["Qatar ID, with “QID” or “ID” nearby", "28763412345"], ["IBAN", "QA58 DOHB 0000 1234 5678 90AB CDEF G"], ["Mobile", "+974 5512 3456"]] },
  gb: { name: "United Kingdom", ready: true, examples: [["National Insurance number", "AB 12 34 56 C"], ["NHS number, with “NHS” nearby", "943 476 5919"], ["Sort code and account", "12-34-56 12345678"], ["IBAN", "GB82 WEST 1234 5698 7654 32"], ["Mobile", "07700 900123"]] },
  eu: { name: "European Union", ready: true, examples: [["IBAN", "DE89 3704 0044 0532 0130 00"], ["VAT number", "DE123456789"], ["German tax ID, with “tax ID” nearby", "36 574 261 809"], ["French social security number", "2 95 10 99 126 111 93"], ["Phone with country code", "+49 30 1234 5678"]] },
  us: { name: "United States", ready: true, examples: [["Social Security number", "123-45-6789"], ["ITIN", "912-70-1234"], ["Routing number, with “routing” nearby", "021000021"], ["Phone", "+1 212 555 0100"]] },
  ca: { name: "Canada", ready: true, examples: [["Social Insurance Number", "046 454 286"], ["Phone", "+1 416 555 0100"]] },
  br: { name: "Brazil", ready: true, examples: [["CPF", "123.456.789-09"], ["Mobile", "+55 11 91234 5678"]] },
  in: { name: "India", ready: true, examples: [["Aadhaar, check digit checked", "2345 6789 0124"], ["PAN", "ABCPE1234F"], ["Mobile", "+91 98765 43210"]] },
  sg: { name: "Singapore", ready: true, examples: [["NRIC or FIN, check letter checked", "S1234567D"], ["Mobile", "+65 9123 4567"]] },
};

export const SECTORS: [string, string][] = [["banking", "Banking and payments"], ["insurance", "Insurance"], ["health", "Health"], ["telecoms", "Telecoms"], ["retail", "Retail and e-commerce"], ["other", "Something else"]];

// Onshore Cloud regions open now, from RV_CLOUD_REGIONS ("GB,DE,NG"). Each region is
// an Onshore-run install in that country, linked to the cloud console the same way an
// Enterprise customer links their own. Countries without one join the waitlist.
export function cloudRegions(): string[] {
  return (process.env.RV_CLOUD_REGIONS ?? "").split(",").map((c) => c.trim().toUpperCase()).filter((c) => /^[A-Z]{2}$/.test(c));
}

/** The laws setup suggests, each with the reasons shown beside it. */
export function suggestLaws(o: { countries: string[]; sector: string; markets: string[] }): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const add = (id: string, why: string) => {
    if (!LAWS[id]) return;
    const w = out.get(id) ?? [];
    if (!w.includes(why)) w.push(why);
    out.set(id, w);
  };
  for (const c of o.countries) for (const l of COUNTRY[c]?.laws ?? []) add(l, `Data kept in ${COUNTRY[c]!.name}`);
  const servesEU = o.markets.includes("eu") || o.countries.some((c) => COUNTRY[c]?.eu);
  if (o.sector === "banking" && o.countries.includes("NG")) add("cbn", "Payments data in Nigeria");
  if (o.sector === "banking" && servesEU) add("dora", "Financial services in the EU");
  if (o.sector === "banking" && o.countries.includes("US")) add("glba", "Financial services in the US");
  if (o.sector === "health" && o.countries.includes("US")) add("hipaa", "Health data in the US");
  for (const m of MARKETS) if (o.markets.includes(m.id)) for (const l of m.laws) add(l, `You serve ${m.label.replace("People in ", "people in ")}`);
  return out;
}

/** The packs a vault gets by default: everywhere, its own country, and the places its customers live. */
export function suggestPacks(o: { countries: string[]; markets: string[] }): string[] {
  const out = ["everywhere"];
  for (const c of o.countries) { const p = COUNTRY[c]?.pack; if (p && !out.includes(p)) out.push(p); }
  for (const m of MARKETS) if (o.markets.includes(m.id) && !out.includes(m.pack)) out.push(m.pack);
  return out;
}

// Every entity type the engine and the packs can find. Routes and pipelines list the
// ones they act on; payment references are opt-in.
export const PACK_TYPES: Record<string, string[]> = {
  everywhere: ["email", "card_pan", "person_name", "date", "payment_ref", "amount", "phone"],
  ng: ["bvn", "nin", "vnin", "ng_11_digit_id", "nuban", "phone_ng", "amount_ngn"],
  gh: ["ghana_card"], ke: ["ke_national_id", "ke_kra_pin"], za: ["za_id"], eg: ["eg_national_id"],
  ae: ["emirates_id", "iban"], sa: ["sa_national_id", "iban"], qa: ["qa_id", "iban"],
  gb: ["uk_nino", "uk_nhs", "uk_bank_account", "iban"], eu: ["iban", "eu_vat", "de_tax_id", "fr_nir"],
  us: ["us_ssn", "us_itin", "us_routing"], ca: ["ca_sin"], br: ["br_cpf"], in: ["in_aadhaar", "in_pan"], sg: ["sg_nric"],
};
export const ENTITY_TYPES = [...new Set(Object.values(PACK_TYPES).flat())];
export const DEFAULT_ENTITY_TYPES = ENTITY_TYPES.filter((t) => t !== "payment_ref");

// The vault fields a pack brings, so a vault can tokenise what its packs find.
export interface PackField { name: string; data_type: string }
export const PACK_FIELDS: Record<string, PackField[]> = {
  everywhere: [{ name: "full_name", data_type: "person_name" }, { name: "email", data_type: "email" }, { name: "date_of_birth", data_type: "date" }, { name: "phone", data_type: "phone" }, { name: "amount", data_type: "amount" }],
  ng: [{ name: "bvn", data_type: "bvn" }, { name: "nin", data_type: "nin" }, { name: "national_id_unclassified", data_type: "ng_11_digit_id" }, { name: "account_number", data_type: "nuban" }, { name: "phone_ng", data_type: "phone_ng" }, { name: "amount_ngn", data_type: "amount_ngn" }],
  gh: [{ name: "ghana_card", data_type: "ghana_card" }],
  ke: [{ name: "national_id", data_type: "ke_national_id" }, { name: "kra_pin", data_type: "ke_kra_pin" }],
  za: [{ name: "id_number", data_type: "za_id" }],
  eg: [{ name: "national_id", data_type: "eg_national_id" }],
  ae: [{ name: "emirates_id", data_type: "emirates_id" }, { name: "iban", data_type: "iban" }],
  sa: [{ name: "national_id", data_type: "sa_national_id" }, { name: "iban", data_type: "iban" }],
  qa: [{ name: "qatar_id", data_type: "qa_id" }, { name: "iban", data_type: "iban" }],
  gb: [{ name: "ni_number", data_type: "uk_nino" }, { name: "nhs_number", data_type: "uk_nhs" }, { name: "bank_account", data_type: "uk_bank_account" }, { name: "iban", data_type: "iban" }],
  eu: [{ name: "iban", data_type: "iban" }, { name: "vat_number", data_type: "eu_vat" }, { name: "german_tax_id", data_type: "de_tax_id" }, { name: "french_social_security", data_type: "fr_nir" }],
  us: [{ name: "ssn", data_type: "us_ssn" }, { name: "itin", data_type: "us_itin" }, { name: "routing_number", data_type: "us_routing" }],
  ca: [{ name: "sin", data_type: "ca_sin" }],
  br: [{ name: "cpf", data_type: "br_cpf" }],
  in: [{ name: "aadhaar", data_type: "in_aadhaar" }, { name: "pan", data_type: "in_pan" }],
  sg: [{ name: "nric", data_type: "sg_nric" }],
};

/** The fields for a vault with these packs, each name once: the first pack to name it wins. */
export function fieldsForPacks(packs: string[]): PackField[] {
  const out: PackField[] = [];
  const names = new Set<string>();
  for (const p of ["everywhere", ...packs.filter((x) => x !== "everywhere")]) {
    for (const f of PACK_FIELDS[p] ?? []) {
      if (names.has(f.name) || out.some((o) => o.data_type === f.data_type)) continue;
      names.add(f.name);
      out.push(f);
    }
  }
  return out;
}
