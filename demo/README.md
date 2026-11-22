# The Lagoon Pay demo

A fictional fintech that leaks synthetic BVNs and account numbers into foreign tools, with Onshore put in front of it. The script for the videos and the live demo is in [`pitch/video/`](../pitch/video/).

**This wipes the Onshore install on this machine.** `./demo reset` empties its database. It refuses to run unless the stack's host is `localhost`.

## First time

The Onshore stack must be running, from an install that allows a local destination:

```sh
RV_E2E_SETUP_ONLY=1 bash scripts/e2e.sh     # from the project root
cd demo/lagoon-pay && npm install && npx prisma generate
cd ../offshore-sim && npm install
cd .. && ./demo reset
```

Then `./demo logins` prints the console sign-in, with a current code, so you need no authenticator app.

## Addresses

| What | Where |
| --- | --- |
| Lagoon Pay, customer | http://localhost:4100/signup |
| Lagoon back office | http://localhost:4100/ops/customers |
| Onshore console | https://localhost:8443 |
| Foreign tools, local stand-in | http://localhost:4200 |

## Commands

| Command | What it does |
| --- | --- |
| `./demo reset` | Wipes everything and rebuilds the starting point. About 30 seconds |
| `./demo stage <name>` | `before`, `shadow`, `enforcing`, `map`, `report`. Forward keeps what's there; going back resets first |
| `./demo traffic --rate 2/s` | Simulated customers, until stopped |
| `./demo seed-history --days 30` | Marked history, so dashboards look lived-in |
| `./demo source on` | Turns on tokenize-at-source live, for the map beat |
| `./demo chat "<message>"` | One support message, for a clean AI shot |
| `./demo fail` | One failed transfer, for a clean error shot |
| `./demo copy` | The nightly analytics copy, now |
| `./demo status` | The pre-take check |
| `./demo codes` | Sign-in details with recovery codes that never expire. Use one at the code step: "Use a recovery code instead". Running it again replaces the codes |
| `./demo selftest` | Walks the whole story from a fresh reset, and checks what arrives at each tool |
| `./demo down` | Stops the demo's own pieces |

## The four leaks

| # | Mistake | Goes to | Fix shown |
| --- | --- | --- | --- |
| L1 | Payloads logged at info level | Log tool | Collector exporter points at the Onshore log processor |
| L2 | Exception messages hold the account number | Error tracker | `beforeSend` tokenizes through the Onshore SDK, and checks the batch |
| L3 | The bot sends the profile and conversation | AI provider | Base URL moves to the AI gateway |
| L4 | A nightly job copies `customers` abroad | EU database | Tokenize at source; the job's batches are checked |

## Real tools for recording

Copy `.env.example` to `.env` and fill in what you've created, using a dedicated demo email. Anything left blank uses the stand-in, which says on every page that it isn't the real tool. Then restart: `./demo down && ./demo reset`. **These real connections have not been tested, as they need your accounts.** Do a dry run after adding each one, and save the views listed in the spec.

| Leak | Tool | Region | Saved view |
| --- | --- | --- | --- |
| L1 | Grafana Cloud | US or EU | Explore, `service="lagoon-pay"`, saved as "Lagoon Pay, raw logs" |
| L2 | Sentry | US | The "TransferFailed" issue |
| L3 | OpenAI-compatible API | Provider default | The AI gateway playground; the stand-in's `/ai` page shows the two panes |
| L4 | Neon or Supabase | EU, such as Frankfurt | Table editor on `analytics.customers` |

The Sentry DSN and OpenAI settings reach the app when it starts. The AI route and pipeline are created at reset from the same file.

## What's seeded

Customers, transfers, loans and chats come from a fixed seed (`scenario/synth.mjs`), so every reset brings back the same people. Detection history, scores and status history are marked: `seeded` in the database, and a "Demo: history is seeded" badge in the console. Say once: "History is seeded for the demo; the switch you're about to see is live."

Never use real identifiers here, including your own.

## Differences from the pitch kit spec

- **Tokenize-at-source moved from the `enforcing` stage to `./demo source on`.** The stage table turns it on at `enforcing`, but the runbook turns it on live at the map beat. The runbook wins, as that's the shot that matters.
- **The Europe copy moves to "Proving clean", not straight to green.** A flow earns green after a clean week. The `report` stage shows it green with seeded history. To support this, Onshore gained flow checks: the job has each batch checked before it leaves, and only counts are kept.
- **Fictional bank codes weren't added to the detection engine.** Their account numbers are detected already, so the spec's tenant-only change wasn't needed.
- **`ops-lead` and `contractor-abroad` are roles** (`ops_lead`, `contractor`). The contractor has no policy, so every reveal is denied.
- **Logs only.** OpenTelemetry traces aren't wired, as no leak uses them.
- **L5, the optional KYC proxy, isn't built.**
