# Onshore paid features

Code in any directory named `ee` is under the [Onshore Commercial Licence](LICENSE), not AGPL. You may read, change and run it for development and testing, and on test vaults. Running it in production needs Onshore Business or Enterprise, or Onshore Cloud.

| Where | What | Edition |
| --- | --- | --- |
| `data-plane/ee/vaultapi` | Data subject request tools (find, show, export, restrict), flow checks, the cloak API and digital twins, secure components, log, proxy and file internals, your own data types | Business |
| `data-plane/ee/gateway`, `logproc`, `adapters`, `filered` | The HTTP proxy, log processing, ticket adapters, file redaction (including DICOM) | Business |
| `data-plane/ee/nlp`, `ee/nlp` | Language-model detection with spaCy, transformers or Stanza: the client and the model service | Business |
| `data-plane/ee/cmd/*` | The HTTP proxy, log processor, adapters and file redactor services | Business |
| `data-plane/ee/hsm` | The PKCS#11 hardware security module key backend (`-tags hsm`) | Enterprise |
| `control-api/src/ee/routes` | Log pipelines, HTTP proxy settings, shared cloak settings, ticket adapters, the residency map, evidence reports, webhooks, page protection, your own data types and country packs, single sign-on, SCIM, language-model detection settings | Business |
| `control-api/src/ee/advanced-rules.ts` | Access rules with purposes, office hours, reveal limits, network or MFA conditions | Business |
| `control-api/src/ee/ldap.ts`, `federation*.ts`, `member.ts`, `siem.ts` | LDAP, linked installs, audit streaming to a SIEM | Enterprise |

The **AI gateway** is not paid code. The service (`data-plane/cmd/ai-gateway`), its engine (`data-plane/internal/gateway`, `internal/cloak`), its vault routes and its settings (`control-api/src/routes/ai-routes.ts`) are under AGPL with the rest of the core. Inside it, three things stay Business: language-model detection, shared cloak settings, and digital twins with the cloak API.

## How the edition is decided

- The vault reads the signed licence in `RV_LICENCE`, offline, against the key built into official releases.
- A build without that key (built from source) is a **development build**: every feature is on, for development and testing only. Production use of `ee` code still needs a subscription under the licence.
- `RV_EDITION=free` or `RV_EDITION=business` on the vault lowers the edition, to test what those customers see. It can never raise it.
- Expired licences keep their features; only updates stop. A licence never cuts access to stored data.
- Paid vault API routes are always allowed on test vaults. In the control API, reading and removing settings stays open on every edition; creating and changing them needs the edition.

The console still holds the screens for these features; they show what the API allows.
