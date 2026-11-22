export interface FieldTemplate {
  name: string;
  data_type: string;
  token_kind?: string;
}

const core: FieldTemplate[] = [
  { name: "bvn", data_type: "bvn" },
  { name: "nin", data_type: "nin" },
  { name: "national_id_unclassified", data_type: "ng_11_digit_id" },
  { name: "account_number", data_type: "nuban" },
  { name: "phone", data_type: "phone_ng" },
  { name: "full_name", data_type: "person_name" },
  { name: "email", data_type: "email" },
  { name: "amount", data_type: "amount_ngn" },
];

export const TEMPLATES: Record<string, { label: string; description: string; fields: FieldTemplate[] }> = {
  wallet_psp: { label: "Wallet / PSP", description: "Identifiers, account numbers, phones and amounts for a payment product.", fields: core },
  lending: { label: "Lending", description: "Adds date of birth and address for credit checks.", fields: [...core, { name: "date_of_birth", data_type: "date" }, { name: "address", data_type: "address" }] },
  microfinance: { label: "Microfinance bank", description: "Adds date of birth and address, plus short-lived OTPs.", fields: [...core, { name: "date_of_birth", data_type: "date" }, { name: "address", data_type: "address" }, { name: "otp", data_type: "free_text", token_kind: "transient" }] },
  blank: { label: "Blank", description: "Start with no fields and design your own.", fields: [] },
};

export const ROLES = ["admin", "compliance", "dpo", "engineer", "support_agent", "backend_service", "ops_lead", "contractor", "map_editor", "exception_approver", "detection_manager", "detection_approver"];

// Two starter policies; beyond them every action is default-deny. The admin role
// configures the system and sees no values: only the DPO role reveals.
export const STARTER_POLICIES: { name: string; source: object }[] = [
  {
    name: "backend-services",
    source: {
      rules: [{ id: "write-and-search", actions: ["tokenize", "insert", "search", "file_redact"], who: { roles: ["backend_service"] }, what: {}, when: {}, returns: "allow" }],
    },
  },
  {
    name: "console-access",
    source: {
      limit_per_hour: 200,
      rules: [
        { id: "browse", actions: ["search"], who: { roles: ["admin", "compliance", "dpo", "support_agent"] }, what: {}, when: {}, returns: "allow" },
        // Identifiers only, so that a tenant can grant more per field in its own
        // policy: where rules overlap, the most restrictive always wins.
        { id: "support-masked", actions: ["detokenize"], who: { roles: ["support_agent"] }, what: { data_types: ["bvn", "nin", "ng_11_digit_id", "nuban"] }, when: { purpose_required: true }, returns: "masked" },
        { id: "compliance-masked", actions: ["detokenize"], who: { roles: ["compliance"] }, what: {}, when: { purpose_required: true }, returns: "masked" },
        { id: "dpo-reveal", actions: ["detokenize"], who: { roles: ["dpo"], require_mfa: true }, what: {}, when: { purpose_required: true }, returns: "plaintext" },
        { id: "files", actions: ["file_redact"], who: { roles: ["dpo", "compliance"] }, what: {}, when: { purpose_required: true }, returns: "allow" },
        { id: "dpo-rights", actions: ["export", "delete"], who: { roles: ["dpo"], require_mfa: true }, what: {}, when: { purpose_required: true }, returns: "plaintext" },
      ],
    },
  },
];

/** The built-in catalogue, for the Detection screen. Thresholds default to 0.5. */
export const BUILT_IN_ENTITIES = [
  { slug: "bvn", name: "BVN" }, { slug: "nin", name: "NIN" }, { slug: "vnin", name: "Virtual NIN" }, { slug: "ng_11_digit_id", name: "11-digit ID" },
  { slug: "nuban", name: "Account number (NUBAN)" }, { slug: "phone_ng", name: "Nigerian phone" }, { slug: "card_pan", name: "Card number" }, { slug: "email", name: "Email" },
  { slug: "person_name", name: "Person name" }, { slug: "amount_ngn", name: "Naira amount" }, { slug: "dob", name: "Date of birth" }, { slug: "payment_ref", name: "Payment reference" },
];

/**
 * Starter templates. The spec says each format must be confirmed against its issuing body
 * before shipping, and none has been: FIRS, CAC, FRSC, INEC, NIS and NIBSS publish no
 * specification we could read. So each says so, and the console warns before adoption.
 * They are starting points for a customer who knows their own data.
 */
export const ENTITY_TEMPLATES = [
  { id: "tin", name: "Tax Identification Number (FIRS)", issuer: "FIRS", confirmed: false, kind: "pattern", definition: { regex: "\\b\\d{8}-\\d{4}\\b" }, context_positive: ["tin", "tax", "firs"], slug: "c_tin" },
  { id: "cac", name: "CAC registration number (RC / BN)", issuer: "CAC", confirmed: false, kind: "pattern", definition: { regex: "\\b(?:RC|BN)[ -]?\\d{5,8}\\b" }, context_positive: ["cac", "registration", "company"], slug: "c_cac" },
  { id: "frsc", name: "Driver's licence number (FRSC)", issuer: "FRSC", confirmed: false, kind: "pattern", definition: { regex: "\\b[A-Z]{3}[0-9A-Z]{9}\\b" }, context_positive: ["licence", "license", "frsc", "driver"], slug: "c_drivers_licence" },
  { id: "inec", name: "Voter's card number (INEC)", issuer: "INEC", confirmed: false, kind: "pattern", definition: { regex: "\\b[0-9A-Z]{19}\\b" }, context_positive: ["voter", "pvc", "inec"], slug: "c_voter_card" },
  { id: "nis", name: "International passport number (NIS)", issuer: "NIS", confirmed: false, kind: "pattern", definition: { regex: "\\b[A-Z]\\d{8}\\b" }, context_positive: ["passport", "nis"], slug: "c_passport" },
  { id: "nip", name: "NIP session ID (NIBSS)", issuer: "NIBSS", confirmed: false, kind: "pattern", definition: { regex: "\\b\\d{30}\\b" }, context_positive: ["session", "nip", "nibss"], slug: "c_nip_session" },
];
