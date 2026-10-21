# Security

What SKYLAR enforces, what it stores, what it sends, and what the operator is responsible for.

## Threat model in one paragraph

SKYLAR holds Cloudflare API tokens that can read every zone in your accounts, and it generates outbound traffic to hosts you name. The controls below exist to keep those tokens unreadable if the database leaks, keep the app's own login hard to brute-force or hijack, and make sure its probes can never be pointed at anything you did not intend.

## What is enforced

### Credentials and sessions

| Control | Detail |
| --- | --- |
| No default credentials | A fresh install shows a first-run setup screen; `POST /api/setup/admin` permanently disables itself once any user exists |
| Password strength | 12+ characters with upper, lower, digit, and symbol; common passwords rejected. Applied at setup, user creation, admin resets, and self-service change |
| Login rate limit | 5 attempts per minute per client IP (`slowapi`), using the real client address behind the nginx proxy |
| Timing-safe login | The password hash is verified even when the username does not exist |
| Sessions | JWT (HS256) signed with `SECRET_KEY`, 1-hour expiry; the UI returns to the login screen on any 401 |
| Instant revocation | Every authenticated request re-checks `is_active`; disabling a user takes effect on their next request |
| Password change | JSON body only (never query parameters), full strength validation, audited as `PASSWORD_CHANGED` |

### Secrets at rest

| Control | Detail |
| --- | --- |
| Token encryption | Cloudflare API tokens are encrypted with Fernet (AES-128-CBC + HMAC). The key is derived from `SECRET_KEY` with PBKDF2-HMAC-SHA256 (100,000 iterations) salted by `ENCRYPTION_SALT` |
| Salt migration | If `ENCRYPTION_SALT` is set on an install that previously used the built-in default, stored tokens are re-encrypted on the next start; a token that matches neither key is reported in the log and must be re-added |
| Password hashing | bcrypt via passlib |
| What is never stored | Response bodies from reachability or exposure probes. Exposure "secret pattern" hits are counted, not captured |

### Network behaviour

| Control | Detail |
| --- | --- |
| Backend not published | Only the frontend container exposes a port; the API is reached via nginx on the Compose network. uvicorn trusts `X-Forwarded-For` only because nginx is the sole path to it |
| SSRF guard | Reachability and active-verify probes resolve every A/AAAA address, reject private, loopback, link-local, reserved, and multicast ranges (one bad address blocks the host), connect to the exact validated IP (HTTPS with SNI pinning and normal certificate verification), and never follow redirects |
| Public resolver | Exposure active verify resolves through Cloudflare DoH (1.1.1.1) and records which resolver answered, so a filtered local vantage point is not mistaken for "clean" |
| Read-only against Cloudflare | SKYLAR never writes to Cloudflare. A read-only token is sufficient; mitigations are displayed, not applied |
| Probe identification | Active-verify requests carry `EXPOSURE_VERIFY_USER_AGENT` and are paced (`EXPOSURE_VERIFY_CONCURRENCY`, `_DELAY_SECONDS`, `_MAX_HOSTS`) |
| CORS | Specific origins only, never wildcards; irrelevant in the default same-origin deployment |

### Application surface

| Control | Detail |
| --- | --- |
| Security headers | CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy` on both the app shell (nginx) and API responses |
| API docs | `/docs`, `/redoc`, `/openapi.json` disabled unless `ENABLE_DOCS=true` |
| Spreadsheet formula injection | Every exported cell starting with `=`, `+`, `-`, `@`, or a tab is prefixed with `'` in CSV and XLSX exports |
| Container | Backend runs as an unprivileged user; images are rebuilt from pinned minimum versions |
| Audit log | Logins (success and failure), setup, sync and reachability runs, exposure runs and host edits, config and user changes, password changes, report presets - all with client IP, searchable by admins |

## What SKYLAR sends and where

| Destination | When | What |
| --- | --- | --- |
| `api.cloudflare.com` | Sync, token verification, exposure runs | Your API token (bearer), read-only REST and GraphQL queries |
| Your own hostnames | Reachability checks; active verify (opt-in) | GET requests from this server's egress IP |
| `rdap.org` | Exposure runs | Origin IPs, to attribute hosting providers |
| `cloudflare.com/ips-v4`, `/ips-v6` | Exposure runs | Nothing; fetches Cloudflare's published IP ranges |
| Vendor release feeds (e.g. `php.net`) | Exposure runs | Nothing identifying; fetches current version lists |
| `cloudflare-dns.com` (DoH, 1.1.1.1) | Active verify | Hostnames being probed |

No telemetry, no update checks, nothing else.

## Operator checklist

- [ ] `SECRET_KEY` and `ENCRYPTION_SALT` are random, set once, and backed up with the database (a dump without them cannot read the tokens)
- [ ] `POSTGRES_PASSWORD` is random; the database port is not published
- [ ] The Cloudflare token is **read-only** and scoped to the zones SKYLAR should see
- [ ] SKYLAR is reached over HTTPS - a Cloudflare Tunnel with an Access policy, or your own TLS-terminating proxy
- [ ] Port 8000 is not published on the host
- [ ] `ENABLE_DOCS` is unset in production
- [ ] `REACHABILITY_INTERVAL_MINUTES` is only enabled with the knowledge of whoever owns the probed hosts
- [ ] `EXPOSURE_VERIFY_USER_AGENT` identifies you, so site owners can recognise probe traffic
- [ ] Admin accounts are limited to people who need to start runs and manage users; everyone else is a regular user
- [ ] The audit log is reviewed after incidents (Audit log page, filter by action)

## Reporting a vulnerability

Open a private security advisory on the GitHub repository rather than a public issue.
