# Exposure Analysis Module — Build Spec

A feature for **SKYLAR** (then Cloudflare Reporter) that answers: *which internet-facing
sites run an affected technology, who hosts them, and who can patch them?*
It is built for the fire-drill that happens when a critical vulnerability in a
widely deployed web runtime is announced.

Read `CONTEXT.md` first. Every requirement here traces to a real lesson there;
tags like `(CONTEXT #6)` point back to it.

Every claim about vendor behavior, API shape, or field name below is tagged
**VERIFIED** (confirmed against docs or observed in the triage), **INFERRED**
(consistent with evidence, not directly confirmed), or **VERIFY** (assumption
the implementer must check). Do not silently promote an INFERRED/VERIFY item to
fact.

## Fit with the existing app

SKYLAR is FastAPI + SQLAlchemy backend, React + Vite frontend,
SQLite or PostgreSQL, JWT auth with an audit log, Fernet-encrypted API tokens,
Dockerized. This module extends it; it does not replace anything.

Reuse, do not reinvent:
- **Config/token storage and `decrypt_token()`** for Cloudflare API access.
- **The sync pattern** (background task + `GET …/progress`, 409 if already
  running) for the new analysis run.
- **The audit-log helper** `create_audit_log(...)` — add new action types.
- **The CSV export pattern** under `/api/export/*`, extended to XLSX here.
- **The SSRF guard** already written for Reachability — the active-verification
  piece MUST call the same validation path, not a new one (CONTEXT #11, #13).
- **The 90s theme / page+route+nav** convention for the new frontend page.

New token scope required: the existing token already has **Analytics Read**,
which the GraphQL collector needs. No new scope for passive analysis.
WAF-ruleset status (EXP-006) needs **Zone WAF Read** (VERIFY the exact
permission name in the token UI) — keep it optional so the core works without
it.

## Data model (new tables)

Follow existing SQLAlchemy conventions (same `Base`, JSONB-on-Postgres /
JSON-on-SQLite handling the app already does for `audit_logs.details`).

### `exposure_runs`
One row per analysis run.
- `id` PK
- `config_id` FK → cloudflare_configs (which token/account)
- `signature_name` str — e.g. `php-rce-2026-10`
- `signature_version` str
- `window_start`, `window_end` datetime (UTC)
- `status` str — `running` | `success` | `failed`
- `coverage_note` text — e.g. "sampled dataset; counts approximate" (CONTEXT #2)
- `started_at`, `finished_at` datetime
- `error` text nullable

### `exposure_findings`
One row per host per matched rule.
- `id` PK
- `run_id` FK → exposure_runs
- `host` str (indexed)
- `rule_id` str — e.g. `EXP-001`
- `verdict` str — `likely_affected` | `catch_all` | `misrouted` | `info`
- `confidence` str — `verified` | `inferred`
- `evidence` JSON — structured, e.g.
  `{"distinct_ips": 108, "origin_2xx": 940, "sample_paths": [...]}`
- `detail` text — human sentence for the report
- `origin_status_trusted` bool — false when EXP-003 fired for this host (CONTEXT #6)

### `exposure_hosts` (enrichment, one row per host per run)
- `run_id` FK
- `host` str
- `hosting_provider` str nullable — from self-call IP whois/ASN (CONTEXT #9)
- `origin_ip` str nullable
- `detected_version` str nullable — from version header (CONTEXT #10)
- `version_status` str nullable — `current` | `behind` | `eol` | `unknown`
- `owner` str nullable — user-editable, carried across runs
- `contact` str nullable — user-editable
- `decision` str nullable — `patch` | `restrict` | `offline` | `n/a` (user-editable)
- `notes` text nullable — user-editable

> `owner`/`contact`/`decision`/`notes` are the handoff fields (CONTEXT #14).
> They persist across runs keyed by host, so a later run doesn't wipe them.

## Pipeline

### Stage 1 — Collect (GraphQL, aggregated)
See `graphql/http_requests_groups.graphql`.

- Use `httpRequestsAdaptiveGroups` **VERIFY exact dataset name and that it
  accepts the `clientRequestPath_like` filter** — the app already uses
  `httpRequests1hGroups` for traffic, so the GraphQL client, auth header, and
  zone iteration are solved; this is a new query against the same endpoint.
- Group by the dimensions the signature needs: at minimum
  `clientRequestHTTPHost`, `clientRequestPath`, `edgeResponseStatus`,
  `originResponseStatus`, `clientIP`. **VERIFY** which of these are valid
  group-by dimensions in the adaptive dataset; some may only be filterable.
  If `clientIP` is not groupable, fall back to `count` plus a separate
  distinct-IP query, or accept a coarser signal and lower the confidence.
- Chunk the time window to respect per-query limits (**VERIFY** the max
  window and row limit for the account's plan). Default window: 7 days,
  queried in daily chunks, summed in code.
- Set `exposure_runs.coverage_note` to flag sampling on the free dataset
  (CONTEXT #2). If the account has the Log Explorer add-on and SQL datasets,
  a future enhancement can use the unsampled `http_requests` table; keep the
  collector behind an interface so that swap is clean. (INFERRED: Log Explorer
  SQL is unsampled and 30-day retention; VERIFY before relying on it.)

### Stage 2 — Classify (rules, pure functions)
Each rule is a pure function `(host_rows, signature, dns_context) -> Finding | None`
so it is unit-testable against fixtures with no network. Rules:

- **EXP-001 Likely affected** — matches `signature.path_patterns`, origin 2xx
  (only if `origin_status_trusted`), distinct client IPs ≥
  `signature.min_distinct_ips`. Confidence `verified` if the version header
  later confirms (EXP-005), else `inferred`. (CONTEXT #3, #5)
- **EXP-002 Catch-all** — origin 2xx on ≥ N of `signature.canary_paths`
  (impossible paths). Verdict `catch_all`; such hosts are **excluded** from
  EXP-001. (CONTEXT #4)
- **EXP-003 Misrouted record** — a DNS A/AAAA record for the host points into
  a Cloudflare IP range, OR duplicate A/AAAA records exist for the name. Sets
  `origin_status_trusted = false` on every finding for that host and emits a
  `misrouted` finding noting that deleting the bad record raises exposure
  (CONTEXT #6, #7). Needs the DNS records the app already syncs plus the
  current published Cloudflare IP ranges (fetch from
  `https://www.cloudflare.com/ips-v4` / `ips-v6`, cache daily — VERIFY URLs).
- **EXP-004 Hosting attribution** — for each `signature.self_call_paths`
  (e.g. `/wp-cron.php`), take the request source IP and enrich with whois/ASN.
  Writes `exposure_hosts.hosting_provider` + `origin_ip`. (CONTEXT #9)
- **EXP-005 Version currency** — from the version header captured in Stage 3
  (or passed in), compare to `signature.version_feed`. Classify current /
  behind / eol / unknown. (CONTEXT #10)
- **EXP-006 Edge coverage** (optional) — WAF managed ruleset enabled for the
  zone? Reports zones where an emergency managed rule would NOT apply.
  (CONTEXT: only ~2% of probe traffic was mitigated.)

Rules read thresholds and patterns from the **signature file**, never
hardcoded. Adding a technology = adding a signature (CONTEXT: reusability).

### Stage 3 — Verify (active, optional, opt-in)
Off by default. When enabled for a run:
- GET/HEAD only. Never POST, never follow redirects. (This mirrors the
  Reachability probe contract.)
- **Resolve the host via a public resolver and pin the connection to that IP**
  (`--resolve` equivalent), recording which resolver answered. Distinguish
  "didn't resolve / blocked here" from "host down". (CONTEXT #11)
- **Route through the SAME SSRF validation the Reachability feature uses.** Do
  not write a second validator. (CONTEXT #11, #13)
- For each host: fetch a random baseline path plus the signature's suspect and
  canary paths. Record status, size, content_type, title, truncated sha256,
  and the **count** of `signature.secret_patterns` matches. **Never store the
  body.** (CONTEXT #13)
- Only compute size/hash/title/counts **when bytes were received** (status != 0).
  (CONTEXT #12 — this is the regression-test case.)
- Capture the version header here to feed EXP-005.

### Stage 4 — Report
- XLSX export mirroring the existing CSV export endpoints, with tabs:
  **Summary, Action Items, Evidence, Cleared, Intel Gaps**. (This matches the
  handoff workbook the team already produces by hand.) Use `openpyxl`; add it
  to `requirements.txt` if not present.
- Each Action Item row carries its `rule_id` and `confidence`.
- **Diff vs. previous run** for the same signature: new hosts, version changes,
  records appeared/disappeared, decisions still open. Powers the post-patch
  recheck. (CONTEXT #14)

## API endpoints (follow existing style, admin-gated like sync)

- `POST /api/exposure/runs` — body `{config_id, signature_name, window_days,
  verify: bool}`. Starts a background run; 409 if one is already running
  (mirror the sync lock). Writes an audit log `EXPOSURE_RUN_STARTED`.
- `GET /api/exposure/runs/progress` — live progress, same shape as
  `/api/sync/progress`.
- `GET /api/exposure/runs` — list past runs.
- `GET /api/exposure/runs/{id}` — run detail: findings + hosts joined.
- `PATCH /api/exposure/hosts/{run_id}/{host}` — update owner/contact/decision/
  notes. Audit log `EXPOSURE_HOST_UPDATED`.
- `GET /api/exposure/runs/{id}/export.xlsx` — workbook.
- `GET /api/exposure/signatures` — list available signature files.
- `GET /api/exposure/runs/{id}/diff/{other_id}` — diff view.

Add the new audit action types to the frontend `AuditLog.jsx` style map.

## Frontend (new page, existing conventions)

- New page `Exposure.jsx`, route, and sidebar item (90s theme, matching the
  other pages).
- Start-run form: config dropdown, signature dropdown, window, verify toggle
  (with a short warning that verify sends GET probes from the server's egress).
- Live progress using the existing progress-polling pattern.
- Results table grouped by verdict (Likely affected / Catch-all / Misrouted /
  Info), with the editable owner/contact/decision/notes cells.
- "Download workbook" and "Diff against previous run" buttons.

## Security / guardrails (non-negotiable)

- Read-only against Cloudflare. No WAF/DNS/Access writes. (CONTEXT: not an
  auto-remediator.)
- Active verify is GET/HEAD only, no redirects, no payloads, SSRF-guarded,
  rate-limited, with an identifiable User-Agent (configurable). (CONTEXT #11)
- Store metadata only; never response bodies; secret matches are counts, not
  values. (CONTEXT #13)
- Respect the existing token encryption; never log decrypted tokens.
- The active-verify egress and its results must be distinguishable from the
  passive data so a filtered/blocked vantage point isn't mistaken for "clean"
  (CONTEXT #11).

## Acceptance criteria (write these as tests first)

Use the existing `backend/tests` + pytest setup; rules are pure functions over
fixtures (`fixtures/sample_graphql_groups.json`, `fixtures/sample_dns.json`).

1. **Catch-all excluded.** A host with origin 2xx on canary paths is verdict
   `catch_all` and never `likely_affected`. (CONTEXT #4)
2. **Real PHP detected.** A host with 2xx `.php` from ≥ `min_distinct_ips`
   distinct IPs is `likely_affected`. (CONTEXT #5)
3. **Misrouted untrust.** A host whose DNS points into a Cloudflare range, or
   has duplicate A records, gets `origin_status_trusted = false`, and EXP-001
   does not fire on its (untrusted) origin 2xx. (CONTEXT #6, #7)
4. **Hosting attribution.** Given self-call rows from a known IP, the host's
   `hosting_provider` is populated. (CONTEXT #9)
5. **Version currency.** `PHP/8.3.33` against a feed whose 8.3 current is
   `8.3.35` classifies `behind`; a stripped header classifies `unknown`, never
   `current`. (CONTEXT #10)
6. **No-bytes-no-hash.** An active check with status 0 records no size/hash/
   title and no secret counts. (CONTEXT #12 — the scripting-bug regression.)
7. **Body never stored.** No evidence field or table column ever contains a
   response body; secret detection is a count. (CONTEXT #13)
8. **Sampling flagged.** A run over the free dataset sets a non-empty
   `coverage_note`. (CONTEXT #2)
9. **Handoff persistence.** owner/contact/decision/notes set on a host survive
   a subsequent run for the same host. (CONTEXT #14)
10. **SSRF reuse.** Active verify rejects a host resolving to a private address
    via the same guard the Reachability tests assert. (CONTEXT #11, #13)

## Build order (smallest valuable slices)

1. Data model + migration (tables above).
2. GraphQL collector (Stage 1) + `exposure_runs` writing, reusing the existing
   GraphQL client. Ship with the coverage_note.
3. Rules EXP-001/002/003 as pure functions + their fixtures and tests
   (1,2,3). These are what saved the most time in the real triage.
4. API: start run, progress, run detail. Wire the audit log.
5. Frontend page with results grouped by verdict.
6. EXP-004 (hosting) + EXP-005 (version). Tests 4,5.
7. XLSX export (Stage 4) reusing the export pattern.
8. Active verify (Stage 3) reusing the SSRF guard. Tests 6,7,10.
9. Diff view + EXP-006 edge coverage.

Each slice is shippable. Stop after step 5 and the tool already replaces the
night's worst manual work.
