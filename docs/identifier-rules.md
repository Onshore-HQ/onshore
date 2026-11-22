# Identifier rules and where each one comes from

This is what the detection engine does for each Nigerian identifier, and how far each rule can be trusted. Reconcile these with NIBSS, NIMC and the CBN directly before relying on them.

| Identifier | Rule in the code | Source | Confidence |
| --- | --- | --- | --- |
| NUBAN check digit | `ABCDEF-GHIJKLMNO-P`. Weights 3,7,3 repeating over 15 digits; 10 minus the sum mod 10, with 10 becoming 0 | [CBN, Revised Standards on NUBAN (2019)](https://www.cbn.gov.ng/Out/2020/PSMD/REVISED%20STANDARDS%20ON%20NIGERIA%20UNIFORM%20BANK%20ACCOUNT%20NUMBER%20(NUBAN)%20FOR%20BANKS%20AND%20OTHER%20FINANCIAL%20INSTITUTIONS%20.pdf) | **Primary source.** Both worked examples in the standard are unit tests: `011`/`000001457` gives 9, and `50547`/`000021457` gives 9 |
| NUBAN institution code | A 3-digit DMB code takes three leading zeros (`011` becomes `000011`). A 5-digit OFI code takes a leading 9 (`50547` becomes `950547`) | Same standard | **Primary source** |
| NUBAN length | The customer sees 10 digits, unique within each institution | Same standard, section 4 | **Primary source** |
| Institution list | 272 codes in `data-plane/internal/detect/institutions.json` | [nigerianbanks.xyz](https://nigerianbanks.xyz/), a third-party aggregate. It agrees with Paystack's [bank API](https://api.paystack.co/bank?country=nigeria&perPage=100) where the two could be compared | **Third party.** Not a CBN list, and it will go stale |
| 6-digit codes | OPay `999992`, PalmPay `999991` and others are tried as they are | Not covered by the standard | **Unverified.** A Python library notes that some newer institutions use non-standard numbers, so a failed check lowers confidence and never clears a value |
| BVN | 11 digits. A nearby label decides that it is a BVN | [Didit](https://docs.didit.me/api-reference/database-validation/nigeria/bank-verification-number.md) and [guardrails-african-pii](https://pypi.org/project/guardrails-african-pii/) | **Format agreed.** No source supports the "starts with 22" claim, and the code does not use it |
| NIN | 11 digits, assigned at random. No checksum is documented | [Youverify](https://youverify.co/blog/how-to-apply-for-nin-registration-online) and others | **Vendor sources.** No NIMC technical document was reachable |
| BVN against NIN | They cannot be told apart by shape. An unlabelled 11-digit number becomes `ng_11_digit_id` and is still treated as sensitive | Sources describe both identically | **Consistent** |
| Virtual NIN | 2 letters, 12 digits, 2 letters; single use; expires after 72 hours. Needs a `vNIN` label nearby | [Dojah](https://dojah.io/blog/all-you-need-to-know-about-nin-tokenization-virtual-nin-on-dojah), [Nairametrics](https://nairametrics.com/?p=481603) | **Secondary and thin.** The exact structure rests on one vendor page, which has since moved |
| Mobile numbers | libphonenumber's NG mobile pattern, including `07[12]x` | [libphonenumber metadata](https://raw.githubusercontent.com/google/libphonenumber/master/resources/PhoneNumberMetadata.xml), checked against the [NCC table of December 2023](https://ncc.gov.ng/operators/mobile-number-allocation-table) | **Strong.** Numbers are portable, so a prefix does not identify the network |
| Verve cards | Prefixes `5060`, `5061`, `5078`, `5079`, `6500`; 16 to 19 digits; counted even when Luhn fails | [Paystack client code](https://raw.githubusercontent.com/PaystackHQ/paystack-android/master/paystack/src/main/java/co/paystack/android/model/Card.java) (which skips Luhn for Verve), [Wikipedia](https://en.wikipedia.org/wiki/Payment_card_number) (narrower ranges) | **Secondary.** The wider pattern is used, because missing a card costs more than a false match |
| Format-preserving tokens | BVN, NIN, NUBAN: `99…`. Phone: `000…` | NCC lists 060 to 069 as fixed-line area codes, so the first choice of `06…` was wrong and was replaced | **No range can be truly reserved.** NINs are random, so a real one may start 99. The detector skips a lookalike only if the token table holds it. Prefer opaque tokens |

## What the check digit can and cannot do

With 272 institution codes, nearly any 10-digit number passes for some bank, so the check digit proves little on its own. The engine uses it only against an institution named nearby. A failure then lowers confidence from 0.97 to 0.8, and never clears a value.

## What was tried and not found

- A NIMC or NIBSS technical specification for BVN or NIN.
- The institution codes as published by the CBN itself.
- Any statement on how OPay, PalmPay or Moniepoint construct account numbers. Reports that wallet numbers are often the phone number without its leading 0 are consistent with what is known of these products but were not confirmed, so a 10-digit mobile-shaped number with an account label is treated as an account.
