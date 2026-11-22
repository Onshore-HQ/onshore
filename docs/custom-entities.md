# Custom detection entities

Your own sensitive data types, such as loan IDs, wallet IDs, staff numbers or VIP names, behave like the built-in BVN and phone entities: detected, tokenized, masked, governed by policy and counted in every report.

Turn this on per vault in **Detection**. It is off by default, and needs an admin.

## The five kinds

| Kind | Use it for | Score |
| --- | --- | --- |
| Keyword list | Exact words or phrases | 0.9, then context |
| Pattern | IDs with a known shape, in RE2 | 0.6, plus 0.3 if a validator passes, then context |
| After a keyword | Whatever follows a cue, such as "PIN:" | 0.8, then context |
| Value list | A fixed set of known values, stored only as keyed hashes | Always 1.0 |
| JSON path | Fields in structured payloads | Always 1.0 |

Context words look about 40 characters either side. Positive words add up to 0.2 and negative words subtract up to 0.3.

**A pattern with no validator scores 0.6, under the default threshold of 0.7.** It matches only near a positive context word, unless you add a validator or lower the threshold. The builder says so, and your samples will show it.

## How one goes live

1. **Draft.** Matches nothing outside the test bench.
2. **Samples.** At least 3 must-match and 3 must-not-match, all passing.
3. **Request publish.** Runs the samples and a 50 MB benchmark. It is refused if the entity adds more than 0.3 ms per KB (1 ms for a value list), or matches more than 5% of benchmark lines.
4. **Approval.** A second person approves. You cannot approve a change you wrote.
5. **Shadow.** Live in every service within 30 seconds. Matches are counted and traffic is unchanged.
6. **Enforcing.** You move it there once the hits look right. Each module then applies its action.

An edit to a published entity waits beside the live version, needs the same approval, and keeps the entity's status when approved. So does a new value list.

| Status | Detected? | Action | Counted? |
| --- | --- | --- | --- |
| Draft | Test bench only | None | No |
| Shadow | Everywhere | Passes unchanged | Yes, as shadow |
| Enforcing | Everywhere | As configured per module | Yes |
| Archived | No | None | Earlier counts kept |

Archiving is blocked while a published policy names the entity. Tokens already issued keep resolving, and new ones are refused.

## Worked example: catching a bare number after `order`, `ref` or `ticket`

The built-in detectors let an 11-digit number after a word like `order`, `ref`, `ticket` or `invoice` pass, because those words usually mean a genuine order number. A customer who would rather lose those numbers than risk a BVN written that way can publish this rule:

```json
POST /control/v1/vaults/v_live_ng01/custom-entities
{
  "name": "Bare 11-digit reference",
  "slug": "c_bare_ref",
  "kind": "pattern",
  "definition": { "regex": "\\b\\d{11}\\b" },
  "context_positive": ["order", "ref", "ticket", "invoice"],
  "threshold": 0.7
}
```

The threshold is what ties it to the words: a pattern match scores 0.6, which is below 0.7 until one of the words is nearby. It catches `order 22555566671`, `{"ref": "22555566671"}`, `ref="22555566671"` in XML and `?ref=22555566671`, and leaves the same number alone with none of those words near it. **It also redacts real 11-digit order numbers**, so run it in shadow first and look at the hits. Add your own words, and tests, as the publish step requires.

## Module actions

Set tokenize, mask, drop, or pass and count separately for API, logs, AI gateway and proxy. Two things to know:

- **Logs need deterministic tokens** to stay searchable, so a cell or transient entity is masked in logs.
- **Support tool adapters and file redaction follow the API setting.** The spec names only four modules, so these two had to follow one.

A shadow entity, or one set to pass in a module, can never hide a built-in match. If a broad entity overlaps a BVN, the BVN is still redacted.

## Worked example: a loan ID pattern

Loan IDs look like `LN-00412873`.

```json
POST /control/v1/vaults/v_live_ng01/custom-entities
{
  "name": "Loan ID",
  "slug": "c_loan_id",
  "kind": "pattern",
  "definition": { "regex": "LN-\\d{8}" },
  "validator": { "type": "length", "value": 11 },
  "context_positive": ["loan", "facility", "repayment"],
  "context_negative": ["invoice"],
  "actions": { "api": "tokenize", "logs": "tokenize", "ai": "tokenize", "proxy": "mask" },
  "tests": [
    { "sample": "repayment on LN-00412873 is late", "expect_match": true },
    { "sample": "facility LN-11112222 approved", "expect_match": true },
    { "sample": "see LN-33334444", "expect_match": true },
    { "sample": "invoice INV-00412873 paid", "expect_match": false },
    { "sample": "LN-123", "expect_match": false },
    { "sample": "plain words", "expect_match": false }
  ]
}
```

Then:

```
POST /control/v1/vaults/v_live_ng01/custom-entities/ce_8f2k/publish-requests     (as the author)
POST /control/v1/publish-requests/cepr_x/approve                                  (as a second person)
POST /control/v1/vaults/v_live_ng01/custom-entities/ce_8f2k/status  {"status":"enforcing"}
```

Once enforcing, a log line `repayment on LN-00412873 is late` leaves as `repayment on tok_c_loan_id_… is late`, and the proxy sends `*******2873`.

Use it in a policy by adding `c_loan_id` to a rule's data types. With no policy, everyone gets tokens only, and plaintext is denied.

## Worked example: a VIP value list

1. Create a `value_list` entity named `c_vip`, with samples that use one of the names.
2. Upload the list:

```
POST /control/v1/vaults/v_live_ng01/custom-entities/ce_vip/values
multipart: file=vip_names.csv, column=name

{ "received": 1240, "hashed": 1231, "duplicates": 7, "rejected": 2,
  "rejected_rows": [ { "row": 88, "reason": "empty" }, { "row": 412, "reason": "over 200 characters" } ] }
```

3. Request publish and get approval. The list goes live with the approved version, and not before.

Matching ignores case, extra spaces and surrounding punctuation, so `CHIDI  benson okoro,` matches `Chidi Benson Okoro`. Values are compared by keyed hash. The original upload is kept encrypted for 30 days, then deleted.

Limits: 100,000 values per list, 1,000,000 per vault, 200 custom entities per vault, of which 50 can be patterns.

## API additions

`POST /v1/detect` takes `entities` to limit by slug and `include_shadow`, which defaults to false. Name a `vault` for custom entities to apply. Each entity gains `custom` and `entity_version`, and the response gains `ruleset_version`.

`POST /v1/vaults/{vault}/tokenize` checks a custom field against its entity's pattern and validator, and answers `validation_failed` when they fail.

## Roles

`detection_manager` creates and edits. `detection_approver` approves. Admins can do both. Nobody can approve a change they wrote.

## Starter templates

The FIRS, CAC, FRSC, INEC, NIS and NIBSS templates are **not confirmed against their issuing bodies**. The console marks them Unconfirmed. Check each against real documents, then edit its pattern and samples, before relying on it.
