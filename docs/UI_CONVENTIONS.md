# UI conventions

The frontend is a dense, dark, flat operator dashboard. The tokens and every component class live in `frontend/src/styles/skylar.css`; this page is the short list of rules a contributor needs so new screens look like the existing ones.

## Tokens, not values

Use the CSS variables and classes from `skylar.css`. No raw hex, rgba, or pixel values in components; no inline `<style>`; no gradients, shadows, or decorative animation.

## Color means something

- `--brand-orange` marks the wordmark, the single primary action on a page, the active nav item, and one headline KPI per page. Nothing else.
- `--brand-blue` is informational: links, secondary accents, progress fills.
- Status colors appear only for the states below. Everything else is a neutral grey.

| Badge class | Tier | Used for |
| --- | --- | --- |
| `badge-critical` | critical | exposure verdict `likely_affected`; version `eol`; failed sync / run / check; host unreachable; config inactive; login failure |
| `badge-high` | high | exposure verdict `misrouted`; version `behind`; probe 4xx / 5xx |
| `badge-medium` | medium | redirect warnings; managed WAF disabled; a protective setting that is off; undecided action items |
| `badge-low` | low | exposure verdict `catch_all`; version `unknown`; informational findings; admin role |
| `badge-success` | success | sync succeeded; token verified; host reachable; version current; WAF enabled; config active |
| `badge-neutral` | - | categorical labels: zone names, record types, confidence, mitigation kind |

Add a row here before giving a new state a color. Badge text is the full word (`LIKELY AFFECTED`, not `LIKELY`).

## Layout patterns

- Page: `.page-header` with a Lucide icon + sentence-case title, optional `.page-subtitle`, actions on the right.
- KPIs: `.stats-grid` of `.stat-card`, four per row; exactly one carries `headline`.
- Panels: `.card` > `.card-header` > `.card-title`; a `.table-container` placed directly inside renders flush.
- Tables: `.data-table`; hostnames `cell-host`, identifiers / IPs `cell-mono`, numbers `cell-num` with `th.num`, timestamps `cell-time`. Sortable headers use `.sortable` and `getSortIndicator`.
- Forms: `.form-field` with a `<label>` (never placeholder-as-label), `.form-help` under the input; filters in `.filters-bar`.
- Messages: `.callout` (`-caution`, `-success`, `-critical`); dismissable with `.callout-row` + `.btn-icon`.
- Anything the user will paste elsewhere goes in a `.code-block` with a copy button.
- Dialogs: `Modal`, `ConfirmModal`, `NoticeModal` from `components/Modal.jsx`. Never `alert()` or `confirm()`.

## Text

- Sentence case everywhere ("DNS records", "Add token"). Uppercase only comes from CSS (table headers, badges, labels).
- Numbers get thousands separators via `formatNumber`; `formatCompact` is for chart axes only.
- Monospace is for identifiers and code, not prose.

## Icons

`lucide-react` only - no emojis, no other icon sets. Nav icons: Dashboard `layout-dashboard`, Zones `globe`, DNS records `list`, Security `shield`, Traffic `activity`, Reachability `radio`, Exposure `scan-search`, Reports `file-down`, Users `users`, Audit log `scroll-text`, Settings `settings`.

## Exports

PDF and XLSX exports apply the same palette as accents on white (they get printed and forwarded). The shared styling lives in `backend/exposure/workbook.py`; the wordmark and tagline come from `backend/branding.py`, which must stay in sync with `frontend/src/components/Wordmark.jsx` (a test enforces this).
