# Webhooks and monitoring

The Monitoring screen shows whether each service is answering, and what the product did in the last hour. Webhooks and a metrics endpoint carry the same signals to your own systems.

## Webhooks

Create one under **Monitoring > New webhook**, or `POST /control/v1/webhooks`. The signing secret is shown once.

| Event | When |
| --- | --- |
| `reveal.performed` | A value was shown in plaintext |
| `reveal.denied` | A policy refused a reveal |
| `access.denied` | A policy refused something else, such as an export or a comparison |
| `access.break_glass` | Break-glass access was requested or used |
| `key.changed` | A key was rotated, created or revoked |
| `policy.published` | A policy went live |
| `custom_entity.published` | A custom entity went live or changed status |
| `data.exported`, `data.deleted` | An export was made, or a record erased |
| `components.sites_changed` | The sites allowed to use secure components changed |
| `identity.changed` | A person, service account or sign-on setting changed |
| `alert.raised` | An alert was raised, such as a lookup spike |
| `monitor.component_down`, `monitor.component_recovered` | A service stopped or resumed answering |
| `webhook.endpoint_disabled` | Another endpoint was turned off after repeated failures |

Tokenize calls are not offered. Webhooks say that something needs attention; they are not a data feed.

```json
{ "id": "aud_8e6e…_reveal.denied", "type": "reveal.denied", "created_at": "2026-11-03T20:36:31Z", "tenant_id": "t_…",
  "data": { "audit_seq": 1508, "vault_id": "v_…", "principal_id": "p_…", "principal_kind": "service_account", "module": "api", "action": "detokenize", "field_id": "f_…", "decision": "denied", "policy_id": "default-deny", "policy_version": null, "break_glass": false, "request_id": "req_…" } }
```

**An event never holds a value, a purpose, a free-text detail, an address or a token.** The payload is an allowlist of the fields above.

### Check the signature

Do this before trusting an event, using the body exactly as received.

```js
import { verifyWebhook } from "@onshorehq/sdk";
if (!verifyWebhook(secret, rawBody, req.headers["x-rv-signature"])) return res.status(401).end();
```

```python
from onshore import verify_webhook
if not verify_webhook(secret, raw_body, request.headers["x-rv-signature"]): abort(401)
```

In any other language: the header is `t=<unix>,v1=<hex>`. Compute HMAC-SHA256 of `<t>.<body>` with the secret, compare in constant time against each `v1`, and refuse a `t` more than five minutes from now. During a rotation the old secret also signs for 24 hours, so the header holds two `v1` values, and either is enough.

### Delivery

- **At least once, in no guaranteed order.** Use `id` to ignore repeats, including `x-rv-event-id`, which is the same value.
- **A 2xx is success.** Anything else is retried after 30 seconds, 2 and 10 minutes, 30 minutes, 2, 6 and 12 hours, and 24 hours, and then the event is marked as given up. It can be sent again by hand for 30 days.
- **Redirects are not followed**, and count as failures.
- **After 100 failures in a row** the endpoint is turned off and an alert is raised. Turning it on again resumes from where it stopped.
- **Destinations must be public and https.** The check is repeated at connect time, so a host name cannot later resolve to an internal address.
- **A receiver's response is never stored.** Only its status code, or a category such as `timed out`.
- A new endpoint starts from now, and is not sent history. At most 10,000 undelivered events wait per endpoint; past that, new ones wait in the audit log until the receiver catches up.

## Metrics

`GET /control/v1/monitoring/metrics` with `Authorization: Bearer <key>`, in Prometheus text format, which Prometheus, Grafana Agent and Datadog's OpenMetrics check can read. Create the key on the Monitoring screen. It reads these numbers and does nothing else, and a tenant has one at a time. Answers are cached for 15 seconds.

```yaml
scrape_configs:
  - job_name: onshore
    scheme: https
    metrics_path: /control/v1/monitoring/metrics
    authorization: { type: Bearer, credentials_file: /etc/prometheus/rv-metrics-key }
    static_configs: [{ targets: ["vault.example.ng"] }]
```

| Metric | Meaning |
| --- | --- |
| `rv_component_up{component}` | 1 if the service answered its last health checks |
| `rv_audit_events_last_hour{module,action,decision}` | Audited operations in the last hour |
| `rv_vault_latency_p50_ms`, `rv_vault_latency_p95_ms` | Tokenize and detokenize time, last hour |
| `rv_open_alerts` | Alerts nobody has acknowledged |
| `rv_webhook_deliveries_last_day{status}` | Deliveries by outcome, last 24 hours |
| `rv_webhook_oldest_pending_seconds` | Age of the oldest undelivered webhook |
| `rv_siem_lag_events` | Audit events not yet sent to the SIEM |

These are gauges over a rolling window, not counters, so use them directly rather than through `rate()`.

## What it cannot see

- **Its own failure.** The control API does the checking. If it stops, no event is sent and the metrics endpoint stops answering. Alert on a failed scrape, and watch `/healthz` from outside the install.
- **The edge and the console.** Neither is checked from inside. An outside check of `/healthz` and the console's address covers both.
- **The database.** If Postgres stops, the control API can record nothing, so this falls under the first point.
- A service is checked every 30 seconds and reported down after two misses, so a failure takes up to about a minute to appear.
- A service that has never answered shows as "Not running here", because optional services may not be installed. **If one fails before its first answer, nothing is raised.**
