# Residency map

A live list of every system and vendor that holds or receives payment and identity data, with one status per flow worked out from evidence. Nobody can tick a flow green. It is off per vault until an admin turns it on, under **Residency map**.

## How a flow gets on the map

- **Seen by Onshore.** Every pipeline, AI route and proxy route is a system. When one sees traffic to a host, a flow appears within about a minute. The host is matched against the vendor catalogue, and a match never confirms a location.
- **Declared by you.** Use **Add system** for anything Onshore cannot see, such as a warehouse in a foreign cloud. These flows are labelled as declared on every screen and report page.

Until someone confirms a vendor's region or declares a hosting country, a flow counts as offshore. An IP lookup is shown beside the declared value as a hint, and is never used as the answer.

## Statuses, in the order they are decided

| Status | Console word | When |
| --- | --- | --- |
| `retired` | Retired | The flow or its route has gone |
| `exception` | Accepted risk | A second person accepted the risk, and it has not expired |
| `in_country` | In Nigeria | The destination is in Nigeria, by a confirmed region or a declaration |
| `shadow` | Watch only / Proving clean | The route only counts traffic, or it switched to enforcing less than 7 days ago with nothing unprotected since |
| `leaking` | Leaking | Enforcing, but something in scope passed unprotected in the last 7 days; or declared offshore holding in-scope data |
| `protected` | Protected | Enforcing for 7 days or more, with nothing unprotected in the last 7 |
| `verified` | Verified | Protected for 30 days in a row |
| `unverified` | Unverified | Declared, with no location or nothing in scope |

One unprotected detection takes a protected or verified flow to `leaking` at the next run, and the 30-day clock restarts. The engine runs every minute, and at once when a route's mode, an exception, a declaration or an action changes. Set `RV_MAP_INTERVAL_MS` to change the interval.

## Scores

- **Flow score:** the share of in-scope flows, not counting retired ones, that are protected, verified, in Nigeria or accepted. Unverified counts against you.
- **Volume score:** the share of in-scope detections in the last 30 days that were protected or stayed in Nigeria. One big leak cannot hide behind many small clean flows.

Accepted risk counts toward the flow score, so the score without exceptions is always shown beside it.

## Closing work

- **A fix** (remediation action) has an owner, a due date and a plan. Marking it done needs evidence. A linked route puts the flow under the engine. A declared location updates it. A change reference or a file is kept as proof and does not change the status alone, because Onshore cannot see that change. For tokenizing at the source, remove the data types from the flow once they no longer travel. Deleting the data retires the flow.
- **An exception** needs someone other than the requester to approve it, and lasts at most `map_exception_max_days` (180 by default, in map settings). When it ends, the flow goes back to whatever the evidence says.

## Roles

| Role | Can |
| --- | --- |
| `admin` | Everything, and turning the map on |
| `compliance`, `map_editor` | Declare systems and flows, add fixes, request exceptions |
| `admin`, `exception_approver` | Approve and revoke exceptions, never their own |
| `dpo`, `engineer`, `exception_approver` | Read |

The spec's `map:view`, `map:edit` and `map:approve_exception` permissions became these roles, as this product has no permission layer.

## Flow checks

Some jobs can't have Onshore in their path, such as a copy to a foreign database. Such a job can send a sample of each batch to `POST /v1/vaults/{vault}/flows/{flow}/check` before it leaves (`checkFlow` in the Node SDK). Onshore keeps counts only, never the text. The first check makes the flow one Onshore sees: identifiers found count as passed, and so as a leak; tokens count as protected. This is the job's own report, so a job that stops checking isn't seen, and the flow goes quiet rather than red.

## Export

`GET /v1/map/export?format=csv&table=flows|systems|exceptions|actions`, or `format=json`. Add `signed=true` for a bundle with a SHA-256 manifest signed by the tenant's audit key. Rows have stable ids, so a GRC tool can refresh them on a schedule.

## Differences from Update Spec 02

- **Schema:** text ids and CHECK constraints, as in the rest of this schema. Beyond the seven tables: `system_history` (declaration and mode changes), `map_scores_daily` (the score series), and columns for the flow's region, its route and its IP hint.
- **The week after switching to enforcing.** Read literally, the rules turn a flow red for 7 days, because passes from watch mode are still in the window. Here, passes before the switch do not count. The flow stays `shadow`, shown as "Proving clean, day 3 of 7", which matches the spec's own API example and criterion 2. A pass after the switch is a leak at once.
- **Exception expiry.** The concepts section says the flow returns to `leaking`, while criterion 5 and the rule order say its computed status. This follows the computed status: a flow that is by then protected stays protected.
- **Proxy routes have no watch mode.** They count as enforcing from the day they were made. Support tool adapters and the file redactor are not on the map as routes.
- **`flow_id` on detection events** is filled in by the control plane after the fact, as the data plane does not know about flows.
- **The rollup runs with the engine**, not daily, replacing the last two days each time.
- **Alerts** are `events.alerts` rows, which also reach webhooks as `alert.raised`, and appear on the map. There is no email channel in this product, and no manager hierarchy, so "their manager role" became the compliance role. The audience is named in each alert's detail.
- **Added to the API:** retire a flow, bulk edit, a system's detail, map settings, map alerts, and download of a fix's proof.
- **The discovery scanner is gone,** as the spec says. `rv scan`, the offline check of one log file, stays: it reads no database or bucket.
