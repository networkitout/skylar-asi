# Exposure Analysis — design notes for SKYLAR

This folder is the design brief behind the **Exposure Analysis** feature. It
is kept with the code so that reviewers can trace every rule back to the
lesson that produced it, and so the next "critical bug in X" can be handled by
adding a signature file rather than re-deriving the design.

It turns the overnight PHP fire-drill — *which internet-facing sites run the
affected tech, who hosts them, who can patch them* — into a repeatable feature.

## Files

| File | Purpose |
|---|---|
| `CONTEXT.md` | Why the feature works the way it does. Every design rule traces to a specific lesson from the real triage. Read first. |
| `SPEC.md` | The build spec: data model, pipeline, rules, API, frontend, guardrails, acceptance tests, build order. |
| `graphql/http_requests_groups.graphql` | The original Stage-1 query template with its VERIFY notes. The shipped collector issues three narrower grouped queries per zone/chunk instead (see below). |

## Where the implementation lives

| Piece | Location |
|---|---|
| Signature files (one per technology) | `backend/signatures/*.yaml` — first one is `php-rce-2026-10.yaml` |
| Signature loader | `backend/exposure/signatures.py` |
| Stage 1 collector (GraphQL query builders + accumulator) | `backend/exposure/collector.py` |
| Stage 2 rules EXP-001 … EXP-008 (pure functions) | `backend/exposure/rules.py` |
| External lookups (Cloudflare ranges, RDAP, release feed) | `backend/exposure/enrich.py` |
| Stage 3 active verify (GET-only, pinned, metadata only) | `backend/exposure/verify.py` |
| Models, orchestration, background runner, routes, XLSX, diff | `backend/main.py` — sections *Exposure Analysis Service* and *Exposure Analysis Routes* |
| Frontend page | `frontend/src/pages/Exposure.jsx` (route `/exposure`) |
| Fixtures for rule tests | `backend/tests/fixtures/sample_graphql_groups.json`, `sample_dns.json` |
| Tests (acceptance criteria 1–10) | `backend/tests/test_exposure_rules.py`, `test_exposure_verify.py`, `test_exposure_api.py` |

## VERIFY items from the spec — resolved 2026-10-20

- **Dataset and group-by dimensions.** `httpRequestsAdaptiveGroups` exposes
  `clientRequestHTTPHost`, `clientRequestPath`, `clientRequestHTTPMethodName`,
  `edgeResponseStatus`, `originResponseStatus` and `clientIP` as dimensions, and
  supports `clientRequestPath_like` / `_in` and `originResponseStatus_geq/_lt`
  filters. **VERIFIED** against Cloudflare's published schema notes.
- **Row cap / window.** To stay under the per-query limit the collector issues
  three grouped queries per zone per chunk — `paths` (host/path/method/status),
  `ips` (host/clientIP for origin-2xx matching paths → true distinct-IP count),
  `self_calls` (host/path/clientIP for `self_call_paths`) — and reads the zone's
  `settings { httpRequestsAdaptiveGroups { maxDuration notOlderThan maxPageSize } }`
  node to size chunks and clamp the window to the plan's retention. Chunks that
  hit the limit and zones that were clamped are named in `coverage_note`.
- **Cloudflare IP ranges.** `https://www.cloudflare.com/ips-v4` and `/ips-v6`
  (plain text, one CIDR per line). **VERIFIED**; cached 24h with a bundled
  fallback list.
- **PHP release feed.** `https://www.php.net/releases/active` returns
  `{major: {branch: {version, …}}}` for every supported branch, so a branch
  that is absent is EOL. **VERIFIED**; the parser also accepts the
  `index.php?json` shape (latest per major only, absence = unknown).
- **Hosting attribution.** RDAP via `https://rdap.org/ip/{ip}` (redirects to
  the owning RIR); registrant `fn` is preferred, network `name` is the
  fallback. **VERIFIED** on a GoDaddy address.
- **WAF ruleset read (EXP-006).** `GET /zones/{id}/rulesets/phases/http_request_firewall_managed/entrypoint`;
  404 = nothing deployed, 403/other = `unknown`. The token permission is
  **Zone → Zone WAF → Read** (optional; the rest of the feature works without it).
- **Log Explorer SQL (unsampled)** is still **INFERRED** and not used; the
  collector is behind `ExposureCollector` so it can be swapped later.

## Deviations from the spec worth knowing

- The YAML's top-level revision key is `signature_version` (the spec sketch used
  `version` twice, which YAML cannot represent).
- Two informational rules were added beyond the spec: **EXP-007** (POST
  pressure on matching paths — the brute-force case in the fixture) and
  **EXP-008** (active verify found secret-pattern matches on a `.bak`/`.env`
  path; counts only). Active verify also upgrades EXP-002 to `verified` when
  randomized canaries return 2xx.
- EXP-002 still fires on a misrouted host but carries
  `origin_status_trusted = false` and says so; EXP-001 never fires on an
  untrusted host (it degrades to an `info` finding that lands in *Intel Gaps*).

## What this deliberately does not do

Read-only against Cloudflare. No WAF/DNS/Access changes. Active verification is
GET-only, no redirects, no payloads, SSRF-guarded through the app's existing
`_ssrf_check` validator, and stores metadata only — never response bodies. It
is not a vulnerability scanner and not an auto-remediator.
