# Contributing to SKYLAR

Thanks for helping. SKYLAR is small enough that a good pull request is usually the whole conversation; this page is just what you need to know before opening one.

## Sign your commits (DCO)

SKYLAR uses the [Developer Certificate of Origin](https://developercertificate.org/) rather than a contributor agreement. Add a `Signed-off-by` line to each commit to certify that you wrote the change or otherwise have the right to submit it under the project's license:

```bash
git commit -s -m "Describe the change"
```

That adds `Signed-off-by: Your Name <you@example.com>` automatically from your git identity. Nothing else is required.

## Before you open a pull request

```bash
# Backend tests (throwaway SQLite, no services needed)
pip install -r backend/requirements-dev.txt
pytest backend/tests

# Frontend build
cd frontend && npm ci && npm run build
```

CI runs both on every pull request. A change that touches the UI should follow [docs/UI_CONVENTIONS.md](docs/UI_CONVENTIONS.md) - tokens from `skylar.css`, Lucide icons only, status colours only for the states listed there, sentence case.

## Adding a technology to Exposure Analysis

This is the contribution the project most wants, and it needs no Python: copy `backend/signatures/php-rce-2026-10.yaml`, change the patterns, thresholds, version feed, probes, and mitigations, and open a PR. The loader validates the file on startup and `backend/tests/test_exposure_rules.py` shows how each field is exercised. Please include:

- where the canary paths and suspect paths came from (a scanner wordlist, an advisory, a real triage)
- a mitigation for every Cloudflare plan tier where the precise rule needs Enterprise-only fields

## Scope

Things SKYLAR deliberately does not do, so PRs adding them will be declined:

- write to Cloudflare (WAF, DNS, Access) - it stays read-only
- send payloads, POST to probed hosts, or follow redirects during verification
- store response bodies from probes

## Reporting security issues

Use GitHub's private vulnerability reporting on the repository rather than a public issue.

## License

By contributing you agree that your contributions are licensed under the [GNU AGPL-3.0](LICENSE), the same as the rest of the project.
