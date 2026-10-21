# SKYLAR

> **Attack surface intelligence for Cloudflare.**
> Know which of your internet-facing hosts run an affected technology, who hosts them, who can patch them, and what the edge is - and isn't - protecting.

[![CI](https://github.com/networkitout/skylar-asi/actions/workflows/ci.yml/badge.svg)](https://github.com/networkitout/skylar-asi/actions/workflows/ci.yml)

SKYLAR is a self-hosted dashboard that syncs your Cloudflare estate - zones, DNS records, security settings, traffic - into its own database and layers analysis on top: reachability probing, and an **Exposure Analysis** engine built for the night before a critical vulnerability lands. It is read-only against Cloudflare, works across multiple accounts, and hands results off as a styled Excel workbook.

Formerly *Cloudflare Reporter*.

---

## What it does

| Area | What you get |
| --- | --- |
| **Inventory** | Every zone, DNS record, and security setting across all your Cloudflare accounts, searchable and sortable; stale entries are removed on the next sync |
| **Traffic** | Hourly request / bandwidth / cache / threat buckets from the GraphQL Analytics API, with idempotent re-sync so totals stay honest |
| **Reachability** | Background HTTP + HTTPS probes of every A / AAAA / CNAME record, IPv4 and IPv6, with redirects, errors, and latency - SSRF-hardened |
| **Exposure analysis** | Pick a technology signature (e.g. *PHP critical RCE*) and a window; SKYLAR classifies every host as likely affected, misrouted, catch-all, or cleared, infers hosting from self-calls, reads version headers (opt-in probes), checks managed WAF coverage, and tracks owner / decision per host across runs |
| **Mitigations** | Each signature ships its own Cloudflare WAF expressions (per plan tier), origin config changes, and patch guidance - shown in the UI with copy buttons, never applied automatically |
| **Handoff workbook** | One click exports a branded workbook: cover sheet with KPI tiles, Action Items with an editable decision dropdown, Evidence, Cleared, Intel Gaps, Mitigations |
| **Reports** | CSV / XLSX exports of zones, DNS, reachability, security, traffic, and a PDF summary |
| **Operations** | First-run admin setup, user management, audit log, scheduled sync and reachability, encrypted tokens at rest |

---

## Quick start (Docker)

Requirements: Docker Engine with Compose v2 (or Docker Desktop). Nothing else on the host.

```bash
git clone https://github.com/networkitout/skylar-asi.git
cd skylar-asi
cp .env.example .env
```

Set the three required values in `.env`:

```bash
# Generate each one; paste into .env
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('ENCRYPTION_SALT=' + secrets.token_hex(16))"
python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(32))"
```

Then:

```bash
docker compose up -d --build
```

Open **http://localhost:3000** (or `http://<host-ip>:3000` from the LAN). On a fresh database SKYLAR shows a **first-run setup** screen where you create the admin account - there is no default password anywhere.

Full deployment guidance - production hardening, Cloudflare Tunnel, backups, upgrades, manual install - is in **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**. A step-by-step walkthrough is in **[QUICKSTART.md](QUICKSTART.md)**.

---

## First steps in the app

### 1. Create a Cloudflare API token

Cloudflare Dashboard -> **My Profile -> API Tokens -> Create Token -> Custom token** with:

- Zone · Zone · Read
- Zone · DNS · Read
- Zone · Zone Settings · Read
- Zone · Analytics · Read
- Zone · Zone WAF · Read *(optional - lets Exposure Analysis report managed WAF coverage)*

Zone resources: **All zones** (or a subset). A *Read all resources* token also works.

> Use a scoped **API Token**, not the **Global API Key** shown lower on the same page. The Global API Key uses a different auth scheme and SKYLAR will tell you so if you paste it. Account-owned tokens (`cfat_…`) are not yet supported.

### 2. Add it and sync

**Settings -> Add token**, paste the token, then **Sync**. Progress shows in the top bar from any page. Add one config per Cloudflare account; each account's data stays isolated.

### 3. Run an exposure analysis

**Exposure -> Run analysis** with a signature and a window (default 7 days). Enable **Active verify** to send GET-only probes for version headers and canary confirmation - read the warning first; probes leave this server's egress. When it finishes, fill in owner / contact / decision per host, download the workbook, and after patching run again and use **Diff vs previous**.

---

## Exposure analysis in one table

Every threshold comes from the signature file, never from code.

| Rule | Verdict | Meaning |
| --- | --- | --- |
| EXP-001 | `likely_affected` | Matching paths got origin 2xx from many distinct client IPs - real use, not scanner noise |
| EXP-002 | `catch_all` | The origin answers 2xx for impossible canary paths, so matching hits prove nothing; excluded |
| EXP-003 | `misrouted` | A record points into Cloudflare's own IP space or duplicates exist; origin status is untrusted |
| EXP-004 | info | Hosting provider inferred from the source IP of the app's self-calls via RDAP |
| EXP-005 | info / `likely_affected` | Version header classified current / behind / EOL / unknown against the vendor's release feed |
| EXP-006 | info | Zones with no managed WAF ruleset deployed - an emergency managed rule would not apply |
| EXP-007 | info | Heavy POST pressure on matching paths |
| EXP-008 | `likely_affected` | Active verify: a `.bak` / `.env`-style path returned 2xx with secret-pattern matches (counted, never stored) |

Guardrails: read-only against Cloudflare; counts come from the sampled GraphQL dataset and are labelled estimates; active verify is GET-only, never follows redirects, resolves through a public resolver, pins the connection, passes the same SSRF guard as reachability, and stores metadata only.

Adding a technology is a YAML file in `backend/signatures/` - detections, version feed, probes, and mitigations in one place. Design notes: [docs/exposure-analysis/](docs/exposure-analysis/).

---

## Configuration

All settings are environment variables. Under Docker, everything in `.env` reaches the backend.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | *required* | JWT signing key; also the root of the token-encryption key. Keep it stable |
| `ENCRYPTION_SALT` | legacy default (warns) | Salt for token encryption at rest. Set it; existing tokens are re-encrypted automatically on the next start |
| `POSTGRES_PASSWORD` | *required (Docker)* | Database password; `POSTGRES_USER` / `POSTGRES_DB` default to `cloudflare` / `cloudflare_reporter` |
| `DATABASE_URL` | compose supplies it | Set explicitly for manual installs, e.g. `sqlite:///./data/skylar.db` |
| `SKYLAR_PORT` | `3000` | Host port for the web UI (Docker) |
| `SYNC_INTERVAL_MINUTES` | `60` | Automatic sync of every active config; `0` disables |
| `REACHABILITY_INTERVAL_MINUTES` | `0` | Automatic reachability checks; off by default because probing is intrusive |
| `REACHABILITY_RETENTION_DAYS` | `90` | Prune reachability history older than this; `0` keeps everything |
| `ANALYTICS_LOOKBACK_HOURS` | `72` | Hourly buckets re-fetched per sync (72h fits the Free plan's retention) |
| `EXPOSURE_SIGNATURES_DIR` | `backend/signatures` | Where signature YAML files live |
| `EXPOSURE_VERIFY_USER_AGENT` | `SKYLAR-ExposureCheck/1.0 (+repo URL)` | Identifies active-verify probes to site owners |
| `EXPOSURE_VERIFY_CONCURRENCY` / `_DELAY_SECONDS` / `_MAX_HOSTS` | `4` / `0.25` / `300` | Probe pacing |
| `ALLOWED_ORIGINS` | localhost origins | CORS, only for split-origin deployments |
| `ENABLE_DOCS` | `false` | Expose `/docs`, `/redoc`, `/openapi.json` |
| `CF_TUNNEL_TOKEN` | - | Cloudflare Tunnel token; start with `docker compose --profile tunnel up -d` |
| `VITE_API_URL` | relative `/api` | Frontend build-time override; leave unset |

See [`.env.example`](.env.example) for the annotated template.

---

## Architecture

```
skylar-asi/
├── backend/                     FastAPI + SQLAlchemy (PostgreSQL in Docker, SQLite for dev)
│   ├── main.py                  models, routes, sync, schedulers, exports
│   ├── branding.py              product name, tagline, wordmark renderer for exports
│   ├── exposure/                network-free, unit-tested analysis engine
│   │   ├── signatures.py        YAML loader (detections, version feed, probes, mitigations)
│   │   ├── rules.py             EXP-001..008 classification
│   │   ├── collector.py         GraphQL query builders
│   │   ├── enrich.py            Cloudflare ranges, RDAP, release feeds
│   │   ├── verify.py            opt-in GET probes
│   │   └── workbook.py          handoff workbook + shared XLSX styling
│   ├── signatures/*.yaml        one file per technology
│   └── tests/                   pytest suite (SQLite, no services needed)
├── frontend/                    React 18 + Vite, served by nginx in Docker
│   └── src/
│       ├── styles/skylar.css    design tokens + every component class
│       ├── components/          Layout (top bar, sidebar), Modal, Wordmark
│       └── pages/               one file per screen
├── docs/
│   ├── DEPLOYMENT.md            production, tunnel, backups, upgrades
│   ├── SECURITY.md              what is enforced and the operator checklist
│   ├── UI_CONVENTIONS.md        tokens, status tiers, and layout rules for the frontend
│   └── exposure-analysis/       design notes and spec
├── docker-compose.yml
└── .github/workflows/ci.yml     backend tests + frontend build on every push
```

The backend is never published on the host; nginx proxies `/api` so the UI is same-origin everywhere (localhost, LAN, tunnel).

---

## API

Interactive docs at `/docs` when `ENABLE_DOCS=true`. The main groups:

- **Auth** `POST /api/auth/login` (5/min per IP) · `GET /api/auth/me` · `POST /api/auth/change-password`
- **Setup** `GET /api/setup/status` · `POST /api/setup/admin` (only while no users exist)
- **Configs** `GET|POST /api/configs` · `DELETE /api/configs/{id}` · `POST /api/configs/{id}/sync` · `POST /api/sync-all` · `GET /api/sync/progress` · `GET /api/sync/status`
- **Inventory** `GET /api/zones` · `GET /api/zones/{id}` · `GET /api/dns-records` · `GET /api/dns-records/types` · `GET /api/security-settings[/summary]`
- **Traffic** `GET /api/metrics` · `GET /api/metrics/aggregate`
- **Reachability** `POST /api/reachability/check-all` · `POST /api/reachability/check-zone/{id}` · `GET /api/reachability[/latest|/progress]`
- **Exposure** `GET /api/exposure/signatures` · `POST|GET /api/exposure/runs` · `GET /api/exposure/runs/progress` · `GET|DELETE /api/exposure/runs/{id}` · `PATCH /api/exposure/hosts/{run}/{host}` · `GET /api/exposure/runs/{id}/diff/{other}` · `GET /api/exposure/runs/{id}/export.xlsx`
- **Exports** `GET /api/export/{full|zones|dns-records|reachability|security|traffic}?format=csv|xlsx` · `GET /api/export/summary` (PDF) · report presets under `/api/report-presets`
- **Admin** `/api/users` CRUD · `GET /api/audit-logs[/actions]`
- **Health** `GET /api/health`

---

## Development

```bash
# Backend tests (throwaway SQLite; no services)
pip install -r backend/requirements-dev.txt
pytest backend/tests
pytest backend/tests -m perf          # timing-sensitive tests, excluded by default

# Frontend
cd frontend && npm ci && npm run dev  # Vite dev server on :5173, proxies /api to :8000
```

Running the backend outside Docker needs `SECRET_KEY` and `DATABASE_URL` exported in the shell - see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#manual-install). Frontend work follows [docs/UI_CONVENTIONS.md](docs/UI_CONVENTIONS.md); [CLAUDE.md](CLAUDE.md) has the conventions for contributors and coding agents.

---

## Upgrading from Cloudflare Reporter

Nothing about your data changes. Three things to know:

1. **Repository URL** is now `https://github.com/networkitout/skylar-asi.git` - update `origin` on existing clones (GitHub redirects the old name for a while).
2. **Compose project name** comes from the directory. If you re-clone into a new directory name, Compose will create a *new* database volume. To keep using the existing one, set `COMPOSE_PROJECT_NAME=cloudflare-reporter` in `.env` (or keep the directory name).
3. **`ENCRYPTION_SALT` is now honoured under Docker.** Previously only three variables reached the container. On first start with a salt configured, stored tokens are re-encrypted automatically; you will see `Re-encrypted N stored API token(s)` in the backend log.

Container names changed from `cf-reporter-*` to `skylar-*`; the database name and volume did not.

---

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| `SECRET_KEY environment variable must be set!` | Add it to `.env` (Docker) or export it in the shell (manual) |
| `Set POSTGRES_PASSWORD in .env` | Generate one and add it; for an existing database use its actual password |
| "Cloudflare rejected this API token" | You pasted the Global API Key, or the token is inactive / IP-restricted. `docker compose logs backend` shows Cloudflare's reason |
| Sync finishes but traffic shows one day | The zone's plan retains 3 days; SKYLAR uses a 72-hour window to fit. Raise `ANALYTICS_LOOKBACK_HOURS` on paid plans |
| `WARNING: ENCRYPTION_SALT not set` | Set it in `.env`; tokens migrate on restart |
| Fresh database after moving the checkout | Compose project name changed - see *Upgrading* above |
| Rate limit exceeded | 5 login attempts per minute per IP; wait a minute |
| Lost admin password | `docker compose exec backend python reset_admin_password.py` |

---

## License

SKYLAR is free software under the **GNU Affero General Public License v3.0** ([LICENSE](LICENSE)).

In plain terms: use it, run it internally, modify it, and redistribute it freely. If you distribute a modified version, or run a modified version as a service for others, you must make your modified source available under the same license. Running an unmodified copy for your own organisation carries no obligations. The About card in Settings links to this repository to satisfy section 13.

If you need SKYLAR under different terms, open an issue.
