import { tr } from "@/lib/i18n";
/** Plain names for the detector's identifiers. The identifier itself stays visible beside them where it matters. */
const LABELS: Record<string, string> = {
  bvn: "BVN (Nigeria)", nin: "NIN (Nigeria)", vnin: "Virtual NIN (Nigeria)", ng_11_digit_id: "11-digit ID (Nigeria, type unclear)", nuban: "Bank account (Nigeria, NUBAN)", phone_ng: "Phone number (Nigeria)", amount: "Amount", email: "Email address", person_name: "Person's name",
  phone: "Phone number", name: "Person's name", card_pan: "Card number", card_cvv: "Card security code", payment_reference: "Payment reference", amount_ngn: "Amount in naira", date: "Date", date_of_birth: "Date of birth", address: "Place or address", passport: "Passport number", drivers_licence: "Driver's licence", tin: "Tax ID", rc_number: "Company number",
  ghana_card: "Ghana Card", ke_national_id: "Kenyan national ID", ke_kra_pin: "KRA PIN", za_id: "South African ID number", eg_national_id: "Egyptian national ID", emirates_id: "Emirates ID",
  sa_national_id: "Saudi ID or Iqama", qa_id: "Qatar ID", uk_nino: "National Insurance number", uk_nhs: "NHS number", uk_bank_account: "UK sort code and account", iban: "IBAN",
  eu_vat: "EU VAT number", de_tax_id: "German tax ID", fr_nir: "French social security number", us_ssn: "US Social Security number", us_itin: "US ITIN", us_routing: "US routing number",
  ca_sin: "Canadian SIN", br_cpf: "Brazilian CPF", in_aadhaar: "Aadhaar number", in_pan: "Indian PAN", sg_nric: "Singapore NRIC or FIN",
};
export const entityLabel = (id: string) => tr(LABELS[id] ?? id);

/** Rules and pipelines start by only counting what they would do. The stored value stays `shadow` or `enforcing`. */
const MODES: Record<string, string> = { shadow: "Watch only", enforcing: "Protecting", draft: "Draft", archived: "Archived" };
export const modeLabel = (m: string) => tr(MODES[m] ?? m[0]!.toUpperCase() + m.slice(1));

export const TOKEN_KINDS: Record<string, string> = { deterministic: "Same value, same token", cell: "New token each time", transient: "Expires" };
export const TOKEN_FORMATS: Record<string, string> = { opaque: "Clearly a token (tok_…)", format_preserving: "Looks like the real value" };

const DECISIONS: Record<string, string> = { plaintext: "Real value shown", masked: "Masked", token_only: "Token only", denied: "Refused" };
export const decisionLabel = (d: string) => tr(DECISIONS[d] ?? d);
export const DECISION_VALUES = Object.keys(DECISIONS);

const AREAS: Record<string, string> = { api: "API", console: "Console", logs: "Logs", ai: "AI", proxy: "Proxy", files: "Files", embed: "Secure forms", control: "Settings" };
export const areaLabel = (m: string) => tr(AREAS[m] ?? m[0]!.toUpperCase() + m.slice(1));

const ACTIONS: Record<string, string> = {
  system_declare: "Declared a system or flow", flow_update: "Changed a data flow", flow_retire: "Retired a data flow", flow_exception_request: "Requested a risk exception", flow_exception_approve: "Approved a risk exception", flow_exception_revoke: "Revoked a risk exception", remediation_create: "Added a fix to do", remediation_update: "Changed a fix to do", remediation_complete: "Completed a fix", vendor_create: "Added a vendor", map_settings: "Changed residency map settings",
  tokenize: "Protected a value", insert: "Stored a value", detokenize: "Revealed a value", reveal_denied: "Reveal refused", search: "Searched records", delete: "Erased data", export: "Exported data", login: "Signed in", compare: "Checked a value", file_redact: "Redacted a file",
  policy_publish: "Published a policy", policy_draft: "Drafted a policy", policy_archive: "Archived a policy", key_rotate: "Rotated a key", key_create: "Created a key", key_revoke: "Revoked a key", break_glass_request: "Requested emergency access", client_token_mint: "Issued a secure form token", password_change: "Changed a password",
  pipeline_create: "Created a pipeline", pipeline_update: "Changed a pipeline", ai_route_create: "Created an AI route", ai_route_update: "Changed an AI route", proxy_route_create: "Created a proxy route", proxy_route_delete: "Deleted a proxy route",
  vault_create: "Created a vault", field_create: "Added a field", field_update: "Changed a field", embed_origins_change: "Changed secure form websites", detection_settings_change: "Changed detection settings", principal_create: "Added a person", recovery_codes_replace: "Made new recovery codes", bootstrap: "Set up the organisation", network_create: "Added an approved network", scope_definition: "Changed the payment data definition", principal_update: "Changed a person", settings_update: "Changed settings",
  cloak: "Cloaked text", setup_complete: "Finished first-time setup", locations_update: "Changed locations and laws", vault_packs_update: "Changed a vault's country packs", vault_detection_models_update: "Changed language-model detection", cloak_profile_create: "Created a cloak setting", cloak_profile_update: "Changed a cloak setting", cloak_profile_delete: "Deleted a cloak setting",
  custom_entity_draft: "Drafted a detection rule", custom_entity_publish: "Published a detection rule", custom_entity_status_change: "Changed a detection rule's status",
};
/** "ai_route_create" reads as "AI route create" when no better wording exists. The exact name stays in exports. */
export function actionLabel(a: string, decision?: string | null): string {
  // Opening a person's page logs a masked read, which must not read as a reveal.
  if (a === "detokenize" && decision === "masked") return tr("Viewed a masked value");
  if (a === "detokenize" && decision === "token_only") return tr("Viewed a token");
  if (a === "detokenize" && decision === "denied") return tr("Reveal refused");
  if (ACTIONS[a]) return tr(ACTIONS[a]!);
  const t = a.replace(/_/g, " ").replace(/\bai\b/g, "AI").replace(/\bapi\b/g, "API").replace(/\bsso\b/g, "SSO");
  return t[0]!.toUpperCase() + t.slice(1);
}

/** Reasons the console writes itself, in plain words. A reason a person typed is shown as typed. */
const REASONS: Record<string, string> = { "subject page view": "Opened the person's page" };
export const reasonLabel = (r?: string | null) => (r ? (REASONS[r] ? tr(REASONS[r]) : r) : "");

/** The parts of Onshore, named by what they do. The internal name stays in exports and logs. */
const SERVICES: Record<string, string> = {
  api: "Vault API (your apps)", logs: "Log protection", ai: "AI gateway", proxy: "Web API proxy", files: "File redaction", console: "Console", embed: "Secure forms", check: "Flow checks", control: "Settings", support: "Support tool connector",
  adapters: "Support tool connector", "ai-gateway": "AI gateway", "file-redactor": "File redaction", "http-proxy": "Web API proxy", "key-service": "Key service", "log-processor": "Log protection", "vault-api": "Vault API",
};
export const serviceLabel = (m: string) => tr(SERVICES[m] ?? m[0]!.toUpperCase() + m.slice(1).replace(/[-_]/g, " "));
