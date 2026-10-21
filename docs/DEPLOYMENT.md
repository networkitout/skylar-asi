# Deploying SKYLAR

This is the operator's guide: how to run SKYLAR for real, keep it running, and upgrade it. For a two-minute first run see [QUICKSTART.md](../QUICKSTART.md).

## Contents

1. [Topology](#topology)
2. [Docker deployment](#docker-deployment)
3. [Exposing it: Cloudflare Tunnel or a reverse proxy](#exposing-it)
4. [Configuration reference](#configuration-reference)
5. [Backups and restore](#backups-and-restore)
6. [Upgrading](#upgrading)
7. [Operations](#operations)
8. [Manual install](#manual-install)

---

## Topology

```
browser ──► frontend (nginx :3000) ──► backend (uvicorn :8000) ──► PostgreSQL
                     │                        │
                     └── serves the SPA        ├── Cloudflare API / GraphQL (outbound)
                                               ├── RDAP, release feeds (outbound, exposure runs)
                                               └── GET probes to your own hosts (opt-in)
```

- Only the **frontend** publishes a port. nginx proxies `/api` to the backend on the Compose network, so the UI is same-origin from localhost, the LAN, or a tunnel, and the backend can trust `X-Forwarded-For` for audit logging and rate limiting.
- The **backend** runs as a non-root user, needs outbound HTTPS to Cloudflare, and (for exposure runs) to RDAP servers and vendor release feeds.
- **Egress matters for Reachability and Active verify**: probes originate from the host running the backend. Site owners will see that IP; set `EXPOSURE_VERIFY_USER_AGENT` so the traffic is identifiable.

## Docker deployment

### Requirements

- Linux host (or Docker Desktop) with Docker Engine 24+ and Compose v2.
- ~1 GB RAM; disk grows with reachability history and traffic buckets (a 200-zone estate is well under 1 GB after months).
- Outbound HTTPS.

### Install

```bash
git clone https://github.com/networkitout/skylar-asi.git
cd skylar-asi
cp .env.example .env
```

Generate and set the required secrets in `.env`:

```bash
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('ENCRYPTION_SALT=' + secrets.token_hex(16))"
python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(32))"
```

`SECRET_KEY` signs sessions **and** derives the key that encrypts Cloudflare tokens at rest; `ENCRYPTION_SALT` salts that derivation. Treat both as permanent: changing either makes stored tokens unreadable (you would re-add them in Settings).

Start it:

```bash
docker compose up -d --build
docker compose logs -f backend      # wait for "Application startup complete"
```

Open `http://<host>:3000` and complete the first-run setup. The setup endpoint disables itself once any user exists.

### What `docker compose up` creates

| Container | Role | Published |
| --- | --- | --- |
| `skylar-frontend` | nginx: SPA + `/api` proxy | `${SKYLAR_PORT:-3000}` |
| `skylar-backend` | FastAPI app, schedulers | not published |
| `skylar-db` | PostgreSQL 16 | not published |
| `skylar-tunnel` | cloudflared (only with `--profile tunnel`) | - |

Data lives in the `postgres_data` volume (named `<project>_postgres_data`, where the project is the directory name unless `COMPOSE_PROJECT_NAME` is set) and the `./data` bind mount (SQLite only; unused with PostgreSQL).

### Schedulers

The backend runs two loops, configured in `.env`:

- `SYNC_INTERVAL_MINUTES` (default 60): syncs every active config.
- `REACHABILITY_INTERVAL_MINUTES` (default 0 = off): probes every A / AAAA / CNAME record. Turn it on deliberately - it generates traffic to all your hosts.

Current schedule and next-run times are shown on the Settings page.

## Exposing it

### Cloudflare Tunnel (recommended)

No inbound ports, TLS handled by Cloudflare, and you can put Cloudflare Access in front of it.

1. Zero Trust dashboard -> **Networks -> Tunnels -> Create a tunnel** (Cloudflared connector). Copy the token.
2. Add a public hostname, e.g. `skylar.example.com`, pointing at service `http://frontend:80`.
3. In `.env`: `CF_TUNNEL_TOKEN=<token>`.
4. `docker compose --profile tunnel up -d`

Add an Access policy (Zero Trust -> Access -> Applications) so only your team can reach the hostname; SKYLAR's own login then sits behind it.

### Reverse proxy

If you terminate TLS yourself (Caddy, Traefik, nginx), proxy to `http://<host>:3000`. Pass `X-Forwarded-For` so audit logs record the real client address. Nothing else is required - the UI and API are already same-origin behind the frontend container, so `ALLOWED_ORIGINS` stays unset.

Do **not** publish port 8000; the backend trusts proxy headers only because the proxy is the sole path to it.

## Configuration reference

Every variable in `.env` is passed to the backend. Blank lines are treated as "use the default".

| Variable | Default | Notes |
| --- | --- | --- |
| `SECRET_KEY` | required | 32+ random bytes, URL-safe. Permanent |
| `ENCRYPTION_SALT` | legacy default | Set it. Startup re-encrypts existing tokens with it automatically |
| `POSTGRES_PASSWORD` | required | Hex avoids URL-reserved characters |
| `POSTGRES_USER` / `POSTGRES_DB` | `cloudflare` / `cloudflare_reporter` | Database identifiers predate the rename; keep them on existing installs |
| `SKYLAR_PORT` | `3000` | Host port for the UI |
| `SYNC_INTERVAL_MINUTES` | `60` | `0` disables |
| `REACHABILITY_INTERVAL_MINUTES` | `0` | Off by default |
| `REACHABILITY_RETENTION_DAYS` | `90` | `0` keeps all history |
| `ANALYTICS_LOOKBACK_HOURS` | `72` | Hourly buckets re-fetched each sync. The Free plan retains 3 days; raise it for Pro/Business/Enterprise zones |
| `EXPOSURE_SIGNATURES_DIR` | `backend/signatures` | Mount your own directory to add signatures without rebuilding |
| `EXPOSURE_VERIFY_USER_AGENT` | `SKYLAR-ExposureCheck/1.0 (+https://github.com/networkitout/skylar-asi)` | Shown to probed hosts |
| `EXPOSURE_VERIFY_CONCURRENCY` | `4` | Hosts probed in parallel |
| `EXPOSURE_VERIFY_DELAY_SECONDS` | `0.25` | Delay between probes to one host |
| `EXPOSURE_VERIFY_MAX_HOSTS` | `300` | Cap per run |
| `ALLOWED_ORIGINS` | localhost origins | Only for split-origin deployments |
| `ENABLE_DOCS` | `false` | Interactive API docs at `/docs` |
| `CF_TUNNEL_TOKEN` | - | Used by the `tunnel` profile |
| `COMPOSE_PROJECT_NAME` | directory name | Set to keep an existing volume after renaming the checkout |

### Adding signatures

Drop a YAML file in `backend/signatures/` (see `php-rce-2026-10.yaml` for the full schema: path patterns, canaries, self-call paths, version feed, probes, and mitigations) and restart the backend. To manage signatures outside the image:

```yaml
# docker-compose.override.yml
services:
  backend:
    volumes:
      - ./my-signatures:/app/signatures:ro
```

## Backups and restore

Everything is in PostgreSQL. Tokens are encrypted with `SECRET_KEY` + `ENCRYPTION_SALT`, so **back up `.env` alongside the database** - a dump without the keys cannot read the tokens.

```bash
# Backup
docker compose exec -T db pg_dump -U cloudflare -Fc cloudflare_reporter > skylar-$(date +%F).dump
cp .env skylar-$(date +%F).env     # store securely

# Restore into a fresh install (same .env values!)
docker compose up -d db
docker compose exec -T db pg_restore -U cloudflare -d cloudflare_reporter --clean --if-exists < skylar-2026-10-21.dump
docker compose up -d
```

For SQLite (manual installs) the database is the single file named in `DATABASE_URL`.

## Upgrading

```bash
git pull
docker compose up -d --build
```

Schema migrations run automatically at startup. Check `docker compose logs backend` after an upgrade for migration messages. Specific notes:

- **From Cloudflare Reporter (any version)**: see the *Upgrading* section of the [README](../README.md#upgrading-from-cloudflare-reporter) - repo URL, Compose project name, and the `ENCRYPTION_SALT` pass-through.
- **From v1.1 or earlier**: the first start wipes previously stored traffic metric rows (they were mislabeled samples); history rebuilds from the next sync.

Rollback is `git checkout <previous tag or sha>` followed by the same `up -d --build`; migrations are additive and older code ignores newer columns.

## Operations

| Task | Command |
| --- | --- |
| Health | `curl http://<host>:3000/api/health` |
| Logs | `docker compose logs -f backend` |
| Reset the admin password | `docker compose exec backend python reset_admin_password.py` |
| Stop / start | `docker compose stop` · `docker compose start` |
| Wipe everything (destroys data) | `docker compose down -v` |
| Run the test suite | `docker compose run --rm --no-deps -e DATABASE_URL=sqlite:////tmp/t.db -e SECRET_KEY=test -v "$PWD/backend:/app" backend sh -c "pip install -q -r requirements-dev.txt && pytest -q"` |

Things the backend log tells you:

- `Re-encrypted N stored API token(s)` - the salt migration ran (once).
- `WARNING: ENCRYPTION_SALT not set` - set it.
- `Cloudflare token verification rejected: HTTP 4xx ...` - the real reason a token was refused in Settings.
- `Analytics lookback of 72h failed ... retrying with 24h` - a zone's plan retains less than the lookback.

## Manual install

For development, or hosts without Docker. The backend reads real environment variables, not `.env`.

```bash
# Backend
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export ENCRYPTION_SALT="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
export DATABASE_URL="sqlite:///./data/skylar.db"      # or a postgresql:// URL
mkdir -p data
uvicorn main:app --host 0.0.0.0 --port 8000

# Frontend (second terminal)
cd frontend
npm ci
npm run dev                                           # http://localhost:5173, proxies /api to :8000
```

Optional: install `fonts-dejavu-core` (Debian/Ubuntu) so exported PDFs and workbooks use the proper bold wordmark; without it Pillow's built-in face is used.

For a production build without Docker: `npm run build` produces `frontend/dist/`; serve it with any static server that proxies `/api` to the backend (see `frontend/nginx.conf` for the exact rules).
