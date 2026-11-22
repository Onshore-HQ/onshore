# Onshore

A data residency vault. It swaps national IDs, bank accounts, phone numbers, names and amounts for tokens or placeholders, so a company keeps its global tools while the real values stay in the country they belong to. Country packs cover the US, UK, EU, Canada, Brazil, India, Singapore, the Gulf and Africa; you choose a vault's country when you create it. Full design: [`Residency Vault — Full Build Spec.md`](./Residency%20Vault%20—%20Full%20Build%20Spec.md).

**It must not hold real customer data yet.** It has had an internal penetration test only, no independent one, and it has only run on one laptop against mock vendors and a mock identity provider. See [`docs/known-gaps.md`](docs/known-gaps.md), [`docs/pentest-report.md`](docs/pentest-report.md), [`docs/identifier-rules.md`](docs/identifier-rules.md) and [`docs/regulatory-notes.md`](docs/regulatory-notes.md).

## Try the sales demo in a minute

Point `rv scan` at a log file. It runs offline and changes nothing.

```sh
cd data-plane && go run ./cmd/rv scan /path/to/app.log
```

## Install

```sh
cd deploy/compose
docker compose --profile logs --profile ai --profile proxy --profile adapters --profile files --profile tools build
./rv init --host vault.example.com --country gb   # writes .env, prints the bootstrap token; the country is where this install keeps data, and is final
# Enterprise: an install in another country, linked to your main console. Get the code in Settings, Locations and laws.
./rv init --host vault.de.example.com --country de --join rvj_… --primary https://onshore.example.com
docker compose up -d keys postgres
./rv keys init                       # 5 key shares, any 3 unseal; shown once
docker compose --profile logs --profile ai --profile proxy up -d   # add --profile adapters or files as needed
./rv doctor                          # pass/fail report for your change ticket
```

Open `https://<host>/`, run first-time setup with the bootstrap token, then follow the setup guide. For a certificate of your own, put it in `certs/` and set `RV_TLS=/certs/cert.pem /certs/key.pem` in `.env`. Disable or encrypt swap on the host. After a restart the key service is sealed until key holders run `./rv keys unseal`.

A linked install joins its primary within a minute of starting and needs outbound HTTPS to it; the primary never connects in. If the primary uses a private CA, set `RV_PRIMARY_CA=/certs/primary-ca.pem`. Onshore Cloud deployments set `RV_CLOUD=1` and `RV_CLOUD_REGIONS` (for example `GB,DE,NG`) to the regions that are open.

## Layout

| Path | What it is |
| --- | --- |
| `data-plane/` | Go: vault API, detection engine, policy engine (CEL), audit chain, log processor, `rv` CLI, SQL migrations |
| `control-api/` | TypeScript, Fastify and Prisma: tenants, policies, people, pipelines, reports. Its database role cannot read the `data` schema |
| `console/` | Next.js admin console |
| SDKs | Each in its own repository under [Onshore-HQ](https://github.com/Onshore-HQ): `onshore-node`, `onshore-python`, `onshore-go`, `onshore-java`, `onshore-php`, `onshore-ios`, `onshore-android`, `onshore-react-native`. `scripts/test-sdks.sh` expects them cloned into `sdks/` |
| `deploy/` | Dockerfiles, Compose, Caddy, OpenBao config |
| `docs/` | OpenAPI files, design notes and known gaps |
| `docs-site/` | The documentation site (Nextra) for docs.onshorevault.com |
| Website | The marketing site for onshorevault.com, in [Onshore-HQ/website](https://github.com/Onshore-HQ/website) |
| `demo/` | Lagoon Pay, a fictional fintech, and the scenario engine for demos |
| `pitch/` | Deck pointers, video scripts, one-pager and data room |

The Prisma schema is generated from a migrated database. SQL in `data-plane/migrations` is the source of truth; after changing it, run `npx prisma db pull && npx prisma generate` in `control-api` with `PRISMA_DATABASE_URL` set.

## Tests

```sh
cd data-plane && go test ./...          # unit tests, including detection quality targets
scripts/test-integration.sh             # data API against real PostgreSQL
scripts/test-hsm.sh                     # the PKCS#11 backend against SoftHSM
(cd control-api && npm test)            # address and DNS checks
scripts/e2e.sh                          # customer-style install, then every SDK. Memory-hungry: the file-redactor image builds Whisper, so close other services first
scripts/pentest.mjs                     # attacks a local install; see docs/pentest-report.md
scripts/console-smoke.mjs               # the console and CSP in a real browser; needs Playwright installed outside the repo
```

`e2e.sh` destroys this project's Compose containers and volumes first. It covers tenant boundaries, default deny, the two-person rule, fail-closed behaviour with the vault down and the key service sealed, key rotation, tamper detection on a live database, and a sweep of a full `pg_dump` and every service log for the plaintext it stored.

## Residency map

Every system and vendor that holds or receives data, with each flow's status worked out from evidence. See [`docs/residency-map.md`](docs/residency-map.md). It is off per vault by default.

## Custom detection entities

Customers can define their own sensitive data types, which behave like the built-in ones. See [`docs/custom-entities.md`](docs/custom-entities.md). It is off per vault by default, and `docs/known-gaps.md` lists what is not yet built or tested.

## Secure components

Embeddable frames that collect or show a BVN, NIN or account number, so a customer's page and servers hold only a token. Served by the install itself. See [`docs/secure-components.md`](docs/secure-components.md).

## Measured performance

On a 2019 Intel MacBook with everything in Docker Desktop, through the TLS edge. Treat these as a rough floor, not as server numbers. Method, client comparison and caveats are in [`docs/performance.md`](docs/performance.md).

| Measure | Spec target | Measured p95 | Throughput | Result |
| --- | --- | --- | --- | --- |
| Tokenize, batch of 10, one client | under 30 ms | 18 to 20 ms | about 70 batches/s | Met |
| Detokenize, batch of 10, one client | under 30 ms | 7 to 8 ms | about 160 batches/s | Met |
| Tokenize, batch of 10, 10 concurrent | under 30 ms | 37 to 43 ms | 300 to 335 batches/s | **Not met**, close |
| Detokenize, batch of 10, 10 concurrent | under 30 ms | 22 to 33 ms | 525 to 620 batches/s | Borderline |
| Log processor, full path through the edge | 20,000 lines/s per 2 cores | n/a | about 29,000 lines/s, not limited to 2 cores | **Unproven** |
| Detection, 1 KB on one core (earlier run) | under 1 ms | 0.61 ms | | Met |

**The Node SDK is held back on Node 26.** Node's global `fetch` sends one request at a time there, capping one process at about 150 detokenize batches/s. Pass an undici-based client through the SDK's `fetch` option for now.

## Detection quality

On the synthetic corpus, all entity types meet the spec's targets, at 100% after tuning. That figure proves little, since the same author wrote the rules and the corpus. An untuned held-out set of awkward real-world shapes (`internal/detect/heldout_test.go`) scores 20/22. Design-partner log samples are the real test.

## Mobile SDKs, webhooks, page protection and proxy formats

| Guide | Covers |
| --- | --- |
| [`docs/mobile-sdks.md`](docs/mobile-sdks.md) | iOS, Android and React Native, and what has and has not been run on each |
| [`docs/webhooks-monitoring.md`](docs/webhooks-monitoring.md) | Signed events, service health, and metrics for Grafana or Datadog |
| [`docs/page-protection.md`](docs/page-protection.md) | Script inventory, approval and change alerts on sensitive pages |
| [`docs/proxy-formats.md`](docs/proxy-formats.md) | Forms, XML and SOAP, multipart, files and headers through the HTTP proxy |

## Licence

Onshore is open core. Copyright © 2026 Flowsplus Services.

- **Core:** [GNU AGPL-3.0](LICENSE). Free to use, change and self-host. If you offer a changed version to others as a service, you must publish your changes.
- **Paid features**, in every directory named `ee` (`data-plane/ee`, `control-api/src/ee`): [Onshore Commercial Licence](ee/LICENSE). Free for development, testing and test vaults; production needs a subscription. See [ee/README.md](ee/README.md).
- **Documentation** in `docs-site/content/`: [CC BY 4.0](docs-site/CONTENT-LICENSE).
- **SDKs:** Apache-2.0, in their own repositories.

Can't use AGPL? Business and Enterprise subscriptions include the core under the commercial licence. See [NOTICE](NOTICE), [TRADEMARKS.md](TRADEMARKS.md) and [CONTRIBUTING.md](CONTRIBUTING.md).
