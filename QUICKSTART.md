# SKYLAR quick start

Two ways to run SKYLAR - pick one:

- **Option A: Docker (recommended)** - three `.env` values and one command. No Python or Node on your machine.
- **Option B: Manual** - run the backend and frontend directly, for development.

For production concerns (tunnel, backups, upgrades) read [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) afterwards.

---

## Option A: Docker (about two minutes)

**Prerequisite:** Docker Engine with Compose v2, or Docker Desktop.

### 1. Configure

```bash
git clone https://github.com/networkitout/skylar-asi.git
cd skylar-asi
cp .env.example .env
```

Generate the three required values and paste each line into `.env`:

```bash
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('ENCRYPTION_SALT=' + secrets.token_hex(16))"
python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(32))"
```

(No Python on the host? `openssl rand -hex 32` works for all three.)

### 2. Start

```bash
docker compose up -d --build
```

### 3. Create your admin account

Open `http://localhost:3000` (also reachable on your LAN at `http://<host-ip>:3000`). On a fresh database SKYLAR shows a **first-run setup** screen - choose a username, email, and password and you're signed in.

> Already have a database from Cloudflare Reporter? Your account still works. Lost the password: `docker compose exec backend python reset_admin_password.py`

That's the whole Docker setup. Skip to [Next steps](#next-steps).

---

## Option B: Manual install

**Prerequisites:** Python 3.11+, Node.js 20+.

### 1. Backend

The backend reads **environment variables**, not `.env` (only Compose reads that file).

```bash
cd skylar-asi/backend
python3 -m venv venv
source venv/bin/activate              # Windows: venv\Scripts\activate
pip install -r requirements.txt

export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export ENCRYPTION_SALT="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
export DATABASE_URL="sqlite:///./data/skylar.db"
mkdir -p data

uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Windows PowerShell: `$env:SECRET_KEY="..."` etc.

Keep `SECRET_KEY` and `ENCRYPTION_SALT` stable - they encrypt your stored Cloudflare tokens. Put the exports in a small `run.sh` so you don't retype them.

### 2. Frontend (new terminal)

```bash
cd skylar-asi/frontend
npm ci
npm run dev
```

Open `http://localhost:5173`; the dev server proxies `/api` to the backend on `:8000`. Complete the first-run setup.

---

## Next steps

### 1. Create a Cloudflare API token

Cloudflare Dashboard -> **My Profile -> API Tokens -> Create Token -> Custom token**:

- Zone · Zone · Read
- Zone · DNS · Read
- Zone · Zone Settings · Read
- Zone · Analytics · Read
- Zone · Zone WAF · Read *(optional, for managed-WAF coverage in exposure runs)*

Zone resources: All zones. Use a scoped **API Token** - the **Global API Key** on the same page will be rejected.

### 2. Add it to SKYLAR and sync

**Settings -> Add token** -> paste -> **Sync**. Progress appears in the top bar. The Dashboard fills in as zones arrive.

### 3. Check reachability

**Reachability -> Check now** probes every A / AAAA / CNAME record over HTTP and HTTPS from this machine.

### 4. Run an exposure analysis

**Exposure -> Run analysis**. Pick the signature and window, optionally enable Active verify, and download the handoff workbook when it finishes.

### 5. Export

**Reports** offers CSV / XLSX exports and a PDF summary.

---

## Stopping and restarting

| | Stop | Start again |
| --- | --- | --- |
| Docker | `docker compose stop` (`down -v` also wipes the database) | `docker compose start` |
| Manual | `Ctrl+C` in each terminal | re-run the backend and frontend commands above |

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `SECRET_KEY environment variable must be set!` | Docker: add it to `.env`. Manual: export it in the backend's terminal |
| `DATABASE_URL environment variable must be set!` | Manual installs must export it (Option B step 1) |
| `Set POSTGRES_PASSWORD in .env` | Generate one and add it; for an existing database use its real password |
| `error: externally-managed-environment` from pip | Create and activate the venv first (PEP 668); never use `--break-system-packages` |
| Can't log in | `docker compose exec backend python reset_admin_password.py` (manual: `python reset_admin_password.py` in `backend/` with the variables exported) |
| "Cloudflare rejected this API token" | You pasted the Global API Key, or the token is inactive / IP-filtered; `docker compose logs backend` shows why |
| Rate limit exceeded | 5 login attempts per minute per IP - wait a minute |
| Port in use | Set `SKYLAR_PORT` in `.env` (Docker) or change the Vite/uvicorn ports (manual) |

More: [README.md](README.md) · [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) · [docs/SECURITY.md](docs/SECURITY.md)
