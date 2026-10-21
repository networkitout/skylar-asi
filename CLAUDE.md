# CLAUDE.md - SKYLAR

## Project Overview
SKYLAR (formerly Cloudflare Reporter; repository `networkitout/skylar-asi`) is a self-hosted web application for monitoring and reporting on Cloudflare zones, DNS records, security settings, traffic metrics, and hostname reachability. It uses a Python/FastAPI backend with a React/Vite frontend, backed by PostgreSQL.

## Architecture

### Backend (`backend/`)
- **Single-file FastAPI app**: `backend/main.py` (~4000 lines) contains all models, routes, and logic
- **Exposure Analysis package**: `backend/exposure/` holds the network-free, unit-testable pieces of the Exposure feature (`signatures.py` YAML loader, `rules.py` pure classification rules EXP-001..008, `collector.py` GraphQL query builders + accumulator, `enrich.py` Cloudflare IP ranges / RDAP / release feed, `verify.py` active GET probes). `workbook.py` builds the XLSX handoff workbook and holds the table styling every XLSX export shares). `main.py` owns the models, orchestration (`run_exposure_analysis`), background runner, and routes. Signatures live in `backend/signatures/*.yaml`; design notes in `docs/exposure-analysis/`
- **Database**: PostgreSQL (primary) or SQLite (dev fallback), via SQLAlchemy ORM
- **Auth**: JWT tokens (HS256), bcrypt password hashing, 1-hour token expiry
- **API encryption**: Cloudflare API keys are encrypted at rest using Fernet (PBKDF2-derived from SECRET_KEY)
- **Rate limiting**: slowapi on auth endpoints
- **Key models**: `User`, `CloudflareConfig`, `Zone` (FK `config_id` -> CloudflareConfig), `DNSRecord`, `SecuritySetting`, `AuditLog`, `ReachabilityCheck`, `TrafficMetric` (one row per zone per hour bucket, unique on `(zone_id, timestamp)`; JSON columns `http_status`/`content_type`/`country` hold per-bucket breakdown maps), `ReportPreset`, `ExposureRun` / `ExposureFinding` / `ExposureHost` (handoff fields owner/contact/decision/notes are carried forward across runs by host) / `ExposureProbe` (metadata only - no body column, by design)
- **Background tasks**: Cloudflare data sync, reachability checks AND exposure analysis runs via `BackgroundTasks` (own DB session + event loop per run; endpoints return 409 if a run is already active); reachability checks are batched 20 concurrent. An asyncio scheduler in the lifespan reruns them automatically (`SYNC_INTERVAL_MINUTES`, `REACHABILITY_INTERVAL_MINUTES`; 0 disables); reachability rows older than `REACHABILITY_RETENTION_DAYS` are pruned after each run
- **Sync semantics**: hourly analytics buckets are upserted (idempotent re-sync) with a configurable lookback (`ANALYTICS_LOOKBACK_HOURS`, default 72; falls back to 24h if the zone's plan retains less) so missed syncs backfill instead of leaving gaps; after a fully successful fetch, zones/DNS records/settings absent from Cloudflare are deleted, scoped to the syncing config
- **Progress tracking**: In-memory dicts `_sync_progress`, `_reachability_progress` and `_exposure_progress` (all lock-protected) polled by frontend
- **SSRF guard**: `_ssrf_check(ips)` is the single outbound-probe gate; both `check_hostname_reachability` and Exposure active verify must route through it (do not add a second validator)
- **Migrations**: hand-rolled, inspector-guarded SQL in `run_migrations()` (runs at startup via lifespan); no Alembic

### Frontend (`frontend/`)
- **React 18** with **Vite** (not CRA)
- **Routing**: react-router-dom v6, nested under `Layout` component
- **Styling**: Single CSS file `frontend/src/styles/skylar.css` holding the design tokens and every component class. `docs/UI_CONVENTIONS.md` lists the rules every screen follows - read it before any styling, layout, or component change. Icons are `lucide-react` only (no emojis); the wordmark is `components/Wordmark.jsx`; dialogs use `Modal` / `ConfirmModal` / `NoticeModal`, never `alert()` / `confirm()`
- **Charts**: recharts (split into its own build chunk); shared time-series component at `frontend/src/components/TrafficChart.jsx`
- **Auth context**: `frontend/src/context/AuthContext.jsx`
- **API utility**: `frontend/src/utils/api.js` - relative base URL `/api` (proxied by the Vite dev server and the nginx image; `VITE_API_URL` overrides at build time), auto-attaches Bearer token
- **No component library** - all UI is custom CSS

### Pages
| Route | Component | Access |
|-------|-----------|--------|
| `/` | Dashboard | Auth |
| `/zones` | Zones | Auth |
| `/zones/:zoneId` | ZoneDetail | Auth |
| `/dns-records` | DNSRecords | Auth |
| `/security` | SecuritySettings | Auth |
| `/traffic` | TrafficMetrics | Auth |
| `/reachability` | Reachability | Auth |
| `/exposure` | Exposure | Auth (starting runs is admin-only) |
| `/reports` | Reports | Auth |
| `/users` | UserManagement | Admin |
| `/audit-log` | AuditLog | Admin |
| `/settings` | Settings | Auth |

## Build & Run

### Frontend
```bash
cd frontend
npm install
npm run dev      # dev server on :5173
npm run build    # production build to dist/
```

### Backend
```bash
cd backend
pip install -r requirements.txt
# DATABASE_URL is required; use SQLite for local dev
SECRET_KEY=<key> DATABASE_URL=sqlite:///./data/cloudflare_reporter.db uvicorn main:app --reload --port 8000
```

### Docker (full stack)
```bash
# Requires .env with SECRET_KEY and POSTGRES_PASSWORD; CF_TUNNEL_TOKEN is optional.
# cloudflared crash-loops without CF_TUNNEL_TOKEN, so name the core services:
docker compose up --build db backend frontend
```
- PostgreSQL internal to the compose network (5432 not published by default), backend on :8000, frontend (nginx, proxies /api) on :3000

## Key Environment Variables
Read through `_env_str` / `_env_int` / `_env_float` in `main.py` so blank values fall back to defaults (Compose passes the whole `.env` via `env_file`). Full reference: `docs/DEPLOYMENT.md`.
- `SECRET_KEY` (required) - JWT signing + root of the token-encryption key
- `ENCRYPTION_SALT` - salt for token encryption; `reencrypt_legacy_tokens()` migrates rows from the legacy default salt at startup. `LEGACY_ENCRYPTION_SALT` must never change
- `DATABASE_URL` (required) - explicit database connection URL; Compose supplies it
- `POSTGRES_PASSWORD` (required for Compose) - database password, without a default; `POSTGRES_USER`/`POSTGRES_DB` keep their pre-rename defaults (`cloudflare`/`cloudflare_reporter`) so existing volumes keep working
- `ALLOWED_ORIGINS` - CORS origins, comma-separated (default: localhost origins)
- `ANALYTICS_LOOKBACK_HOURS` - hours of hourly traffic buckets to (re)fetch per sync (default 72; window is hour-aligned via `analytics_window()` so it never exceeds the plan's 3-day cap)
- `SYNC_INTERVAL_MINUTES` - automatic background sync interval (default 60; 0 disables)
- `REACHABILITY_INTERVAL_MINUTES` - automatic reachability check interval (default 0 = disabled)
- `REACHABILITY_RETENTION_DAYS` - prune reachability history older than this after each run (default 90; 0 disables)
- `EXPOSURE_SIGNATURES_DIR` - directory of signature YAML files (default `backend/signatures`)
- `EXPOSURE_VERIFY_USER_AGENT`, `EXPOSURE_VERIFY_CONCURRENCY` (4), `EXPOSURE_VERIFY_DELAY_SECONDS` (0.25), `EXPOSURE_VERIFY_MAX_HOSTS` (300) - active-verify identity and pacing
- `SKYLAR_PORT` (3000), `CF_TUNNEL_TOKEN` (used by the `tunnel` compose profile), `ENABLE_DOCS` (false)

## Documentation map
- `README.md` - product front page: features, quick start, config table, API, upgrade notes
- `QUICKSTART.md` - step-by-step first run (Docker and manual)
- `docs/DEPLOYMENT.md` - production topology, tunnel/proxy, backups, upgrades, operations
- `docs/SECURITY.md` - enforced controls, outbound destinations, operator checklist
- `docs/UI_CONVENTIONS.md` - tokens, status tiers, layout rules; `docs/exposure-analysis/` - engine design notes
- Branding strings live in `backend/branding.py` and `frontend/src/components/Wordmark.jsx` (tagline kept in sync by a test); the wordmark PNG for exports is rendered by `branding.wordmark_png()`

## Code Conventions
- Backend is a single `main.py` file organized with section comments (`# ==================== Section ====================`)
- Frontend pages are standalone `.jsx` files with inline state management (no Redux/Zustand)
- CSS classes are flat and defined only in `frontend/src/styles/skylar.css`: `.stat-card`, `.badge-critical|high|medium|low|success|neutral`, `.data-table`, `.filter-group`, `.callout`, `.code-block`, etc. Legacy badge aliases (`badge-danger`, `badge-info`, ...) exist in CSS for safety but must not be used in new code
- Audit logging: use `create_audit_log()` for all state-changing user actions with action names like `VERB_NOUN` (e.g., `SYNC_SUCCESS`, `USER_CREATED`, `REACHABILITY_CHECK_SUCCESS`)
- Resource types in audit logs: `user`, `config`, `reachability`, `report`, `exposure`
- Exposure rules are pure functions in `backend/exposure/rules.py` that read every threshold from the signature; adding a technology means a new YAML in `backend/signatures/`, not new code. Never store response bodies from active verify - metadata and match counts only
- Signatures carry their own `mitigations` list (kind `cloudflare_waf` | `origin` | `patch`; WAF entries need one or more `expressions` with a `plan` label). They are display-only - surfaced via `Signature.to_dict()` on the existing endpoints and rendered by `MitigationsCard` in `Exposure.jsx`. The app must never apply them; it stays read-only against Cloudflare. `http.request.body.*` ruleset fields are Enterprise-only, so always ship a header-only variant for lower plans
- Exports: `/api/export/*` endpoints take `format=csv|xlsx` (shared `_tabular_response` helper sanitizes leading `=+-@` against spreadsheet formula injection); `/api/export/summary` renders a PDF via reportlab; saved report presets live in `ReportPreset` with CRUD under `/api/report-presets`
- `/api/dns-records` is server-side paginated/filtered/sorted (`q`, `sort_by`, `page`); it returns `{total, page, page_size, data}` with `zone_name` joined in
- Progress polling pattern: frontend polls `/api/sync/progress` or `/api/reachability/progress` every 2s when active, 10s idle

## Testing
Backend tests live in `backend/tests/` (pytest; config in `backend/pytest.ini`, deps in `backend/requirements-dev.txt`).

```bash
pip install -r backend/requirements-dev.txt
pytest backend/tests           # main suite (SQLite, no services needed)
pytest backend/tests -m perf   # timing-sensitive tests, excluded by default
```

`conftest.py` sets `SECRET_KEY` and a SQLite `DATABASE_URL` **before** importing `main` (main.py validates/connects at import time). CI runs the suite plus a frontend build on every PR (`.github/workflows/ci.yml`).

Exposure tests: `test_exposure_rules.py` (rules over `tests/fixtures/sample_graphql_groups.json` + `sample_dns.json`), `test_exposure_verify.py` (probe metadata, SSRF reuse, collector query builders), `test_exposure_api.py` (full background run with canned GraphQL, endpoints, workbook, diff). Note that RFC 5737 documentation IPs (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) are treated as private by `ipaddress` and get blocked by the SSRF guard - use a routable address (e.g. `8.8.8.8`) when a test needs a probe to go through.

## Common Patterns
- **Adding a new audit event**: Call `create_audit_log(db, action="ACTION_NAME", user_id=..., resource_type=..., details={...}, ip_address=...)` in the backend endpoint. Add badge styling in `AuditLog.jsx` `getActionBadge()` and update `resourceTypes` array if introducing a new resource type.
- **Adding a new page**: Create `frontend/src/pages/NewPage.jsx`, add route in `App.jsx`, add nav link in `Layout.jsx`
- **API endpoints**: All under `/api/` prefix. Auth via `Depends(get_current_user)` or `Depends(get_admin_user)`.
