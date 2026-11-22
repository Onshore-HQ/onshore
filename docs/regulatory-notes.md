# Regulatory notes

Research notes for counsel and your DPCO, **not legal advice and not a conclusion about compliance**. The owner reports that lawyers have signed off the scope documents; those documents have not been seen by whoever wrote these notes, so nothing here reflects them. Record the adopted definition in **Reports**, and each flow's ground on its pipeline, from what counsel signed.

## CBN circular PSS/DIR/PUB/CIR/001/004, 15 June 2026

The circular itself was not obtained. These are law firms' readings.

- **Requirement.** Data generated in relation to payment transactions in Nigeria must be stored and managed in Nigeria by 1 January 2027 ([Pavestones](https://pavestoneslegal.com/cbns-data-localisation-directive-compliance-considerations-for-payment-system-participants/)).
- **Definition.** The term is undefined. Pavestones reads it as including payer and beneficiary details, amounts, **payment references**, authentication records, settlement and routing information, and transaction logs.
- **Records named.** Core transaction databases, settlement and reconciliation records, switching logs, merchant and issuing records, audit trails, backups and disaster recovery ([Credence Law](https://www.credence-law.com/newsletter-on-the-cbn-circular-on-market-structure-data-localisation-ubo-disclosure-and-systemic-oversight-in-the-nigerian-payments-system-implications-for-financial-institutions-and-payment-servic/)).
- **Offshore copies.** Backups, logs, support copies or analytics exports replicated offshore may be a localisation issue even with a local primary (Credence Law).
- **"Managed".** May reach access management, database administration, key management and audit logging done from abroad (Pavestones).
- **Tokenization.** No source reviewed says that tokens or encryption take data out of scope. This is the product's central legal question.
- **Sanctions.** The CBN may impose supervisory sanctions; none are specified (Credence Law). A separate market-structure deadline falls on 31 December 2026.

### What the product changed because of this

| Reading | Change |
| --- | --- |
| Payment references may be in scope | A new opt-in `payment_ref` entity per pipeline. It stays off by default because refs are poor cues for everything else |
| Keys and administration count as "managed" | Report questions ask where keys are held and who administers them |
| Logs and analytics exports count | Traces and metrics are now redacted as well as logs |
| Audit trails are in scope | The SIEM setting warns that it is itself an outbound flow, to be pointed at a destination in Nigeria |

## NDPA 2023 and GAID 2025

- **Transfers.** Permitted with adequacy, an NDPC-approved instrument, or another ground in section 43. As of May 2026 the NDPC had issued no regulatory instrument ([The Trusted Advisors](https://www.legal500.com/intelligence/nigeria/privacy/cross-border-data-transfers-an-overview-of-legal-requirements-and-compliance-mechanisms-in-nigeria)). Instruments such as SCCs need the Commission's approval ([DLA Piper](https://privacymatters.dlapiper.com/2025/06/nigeria-ndpc-issues-gaid-key-compliance-insights/)).
- **Registration and audit.** Data controllers and processors of major importance register. A compliance audit is due within 15 months of starting business and annually after that. Ultra-high and extra-high level filers go through a DPCO; filing fees start with the 2026 cycle (DLA Piper).
- **Breach timing.** Not found in the sources reviewed. Confirm with your DPCO. The product reports alert times but does not assert a deadline.
- **Pseudonymisation.** No NDPC guidance was found. A 2025 CJEU ruling turned on the recipient's ability to re-identify, but it is EU law, not Nigerian.

### What the product changed because of this

Each pipeline, AI route, proxy route and support adapter records its **transfer ground**, default "not assessed", which appears in the residency report. The product does not choose a ground: that is counsel's call.

## What was learned from Skyflow and InCountry

| Their approach | Source | What the product does |
| --- | --- | --- |
| Per-token redaction on detokenize | [Skyflow](https://docs.skyflow.com/docs/tokenization/detokenize) | Added: a caller may ask for less than policy allows, never more |
| Tokens like `NAME_ABC123`, or per-entity counters, for de-identified text | [Skyflow](https://docs.skyflow.com/docs/de-identification) | AI placeholders such as `[BVN_1]` |
| Outbound URLs allow-listed per environment | [Skyflow](https://docs.skyflow.com/docs/connections) | Destinations are validated at creation, and public addresses are enforced at connect time |
| Redact and unredact rules by JSON path; "Processing" against "Processing & Storage" | [InCountry](https://docs.incountry.com/data-residency-as-a-service/web-services-proxy-portal/) | The HTTP proxy, with the same two modes |
| Automatic PII detection with excluded paths | InCountry | Proxy `dlp` and `dlp_excluded_paths` |
| Key rotation every 30, 60, 180 or 360 days | [InCountry](https://docs.incountry.com/portal/managing-encryption-keys/) | The same four periods in Settings |
| Resident functions: customer JavaScript returning results in-country | [InCountry](https://docs.incountry.com/data-residency-as-a-service/resident-functions/) | **Deliberately different.** A fixed list of checks, so no customer code runs beside the keys |
| A data firewall on IP-to-country lookups | [InCountry](https://docs.incountry.com/data-residency-as-a-service/data-firewall/) | **Deliberately different.** Approved networks decide; Geo-IP is only recorded, because a VPN defeats it |

Neither vendor's readable documentation says tokens are outside any regulation. Their pages describe how the technology works, not how regulators treat it. Their docs also don't name the CBN, NDPA or any Nigerian rule, so nothing can be inherited from them on that question.
