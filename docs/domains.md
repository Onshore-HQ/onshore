# Domains

The brand is Onshore and the domain is `onshorevault.com` (it was `onshore.ng`, then briefly `onshorehq.co`, on 22 Nov 2026). `onshorehq.co` is kept and redirects here. This is a plan. **The running stack still serves everything from one host using paths** (`deploy/compose/Caddyfile`), so these names need new Caddy host blocks and a test run before use.

## Names that hold no customer data

| Name | Serves | Where it runs |
| --- | --- | --- |
| `onshorevault.com` | Marketing site (`website/`) | Anywhere, CDN allowed |
| `www.onshorevault.com` | Redirect to `onshorevault.com` | Same |
| `onshorehq.co`, `www.onshorehq.co` | Permanent redirect to `onshorevault.com`, path kept | Same; renew it with the main domain |
| `docs.onshorevault.com` | Documentation | Anywhere |
| `status.onshorevault.com` | Status page | **Outside every production region**, so it stays up when they don't |
| `notify.onshorevault.com` | Sending domain for product email | Email provider |
| `sandbox.onshorevault.com` | Test install with made-up data only | Separate servers and keys |

## Onshore Cloud: one set of names per region

Each Cloud region is an install in its own country (see `RV_CLOUD_REGIONS`), so each gets its own names. `<cc>` is the country code in lower case, for example `ng`, `gb`, `de`.

| Name | Serves | Today's path |
| --- | --- | --- |
| `app.onshorevault.com` | The console for the organisation's primary install | `/` |
| `api.<cc>.onshorevault.com` | Control API of that region | `/control/*` |
| `vault.<cc>.onshorevault.com` | Vault API and secure component frames | `/v1/*`, `/embed/*` |
| `logs.<cc>.onshorevault.com` | Log processor, including OTLP over gRPC | `/logs/*` |
| `ai.<cc>.onshorevault.com` | AI gateway | `/ai/*` |
| `proxy.<cc>.onshorevault.com` | HTTP proxy | `/proxy/*` |
| `files.<cc>.onshorevault.com` | File redactor | `/files/*` |
| `connect.<cc>.onshorevault.com` | Support tool webhooks and sidebars | `/support/*` |

Every `<cc>` name resolves only to servers in that country. Later, a dedicated install for one customer: `<customer>.vault.<cc>.onshorevault.com`.

Self-hosted (free and Enterprise) installs use the customer's own domain; set `RV_HOST`.

Mailboxes the site already links to, which must exist before launch: `hello@onshorevault.com`, `security@onshorevault.com`.

## Rules

- **Do not put a data-plane name behind a foreign CDN or proxy.** Cloudflare-style proxying ends TLS at an edge that may sit in another country, so real values would leave it. Use DNS-only records for every `<cc>` name. The marketing site can use a CDN.
- **No cookies on `.onshorevault.com`.** Keep console cookies host-only on `app.onshorevault.com`, so no other name can read them.
- **Keep frames on `vault.<cc>.`, apart from the console.** Separate origins are part of how the frames and the console are isolated from each other.
- **No wildcard DNS** until dedicated installs need it, so a forgotten name cannot serve anything.
- **Lock the domain down:** registrar MFA and transfer lock, a CAA record naming your certificate authority, and SPF, DKIM and DMARC on the apex and `notify.`.
- **Publish `/.well-known/security.txt`** on `onshorevault.com`, pointing at `security@onshorevault.com`.
- Keep auto-renew on and a long registration term for both `onshorevault.com` and `onshorehq.co`. `onshorehq.co` holds only the redirect: give it a null MX record, `v=spf1 -all` and a DMARC `p=reject` record so nobody can send mail as it.
