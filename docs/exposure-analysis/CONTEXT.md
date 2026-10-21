# Exposure Analysis — Context and Lessons

Read this before `SPEC.md`. It explains *why* the module works the way it does.
Every rule in the spec traces back to something that went wrong, or nearly
went wrong, during a real triage.

## The triage that motivated this

A critical, pre-announced vulnerability in a widely deployed web runtime
(PHP) was due to be disclosed the next morning. The security team needed to
answer one question overnight:

> Which of our internet-facing sites actually run the affected technology,
> who hosts them, and who can patch them?

The organization fronts dozens of zones with Cloudflare, many of them
inherited through acquisitions and hosted on third-party infrastructure
(shared hosting, managed WordPress platforms, cPanel servers). There was no
up-to-date inventory of which sites ran PHP.

The investigation used the Cloudflare dashboard's log search, manual exports,
and ad-hoc `curl` checks. It took several hours. Every manual step below is
something this module should do in seconds.

## What went wrong, and the rule each lesson became

### 1. Raw event exports hit row caps
Dashboard exports stopped at 1,000 and then 2,000 rows. A "7-day" export
actually covered between 40 minutes and 18 hours. Hosts were silently
missing.

→ **Collect aggregated groups through the GraphQL Analytics API, never raw
events.** One row per host/status/path, with counts.

### 2. The free dataset is sampled
The HTTP requests dataset available without the Log Explorer add-on uses
adaptive sampling. Counts are estimates, and low-traffic sites can drop out
entirely.

→ **Label every count as estimated.** Never treat "not seen" as "not present."
The report must state its coverage limits.

### 3. Every host receives `.php` probes
Internet scanners request `/wp-login.php`, `/phpinfo.php`, `/.env`, and similar
paths on every hostname. A `.php` path in the logs says nothing about whether
the host runs PHP.

→ **Presence of matching paths is not evidence.** Origin responses and
client diversity are.

### 4. Origin 2xx is not evidence either: catch-all routes
Several single-page-app hosts returned origin 200 for *every* path, including
impossible ones like `/phpinfo.php~` and `/cakephp/.env`. A redirect-everything
host returned 302 for all 51 probed paths. The first heuristic tried,
"many distinct `.php` paths with 200 means PHP", was wrong and flagged these
as positives.

→ **Canary paths.** Use the scanners' own wordlist against them: paths that
cannot legitimately exist. A host returning 2xx for those is a catch-all
(rule EXP-002) and is excluded from technology detection.

### 5. Real usage looks different from scanner hits
Real PHP sites showed `.php` requests with origin 2xx from 100+ distinct
client IPs. Scanner-only hosts showed one to three IPs hitting many paths.

→ **Distinct client IPs on 2xx responses** is the strongest passive signal
(EXP-001).

### 6. Origin status was wrong for misrouted records
Several hostnames had a DNS record pointing at a Cloudflare IP, which produces
Cloudflare **Error 1000** ("DNS points to prohibited IP"). The sampled dataset
logged those Cloudflare-generated pages as `originResponseStatus = 200`. This
was confirmed by matching the team's own test requests to log entries.

→ **Misrouted-record detection (EXP-003) marks a host's origin status as
untrusted.** Rules that depend on origin status must check that flag.

### 7. Duplicate records cause nondeterministic responses
Some names had two records: one pointing at a Cloudflare IP (Error 1000), one
at a real origin. Each request landed on one or the other, so identical checks
returned different results on different runs. A live cPanel login and webmail
were hiding behind the broken record. The first conclusion, "no origin," was
wrong.

→ **Detect duplicate A/AAAA records for the same name.** Flag that **deleting
the bad record increases exposure**, because the real origin then answers
every request. The fix must be paired with access restriction.

### 8. Many scanners appear as Cloudflare IPs
A large share of probe traffic came from Cloudflare's own address space
(Workers or WARP-proxied scanners) or from public cloud ranges.

→ **Tag client IPs that fall in Cloudflare ranges.** Count them separately,
and note in reports that IP blocklists are ineffective against them.

### 9. Self-calls reveal hosting
WordPress triggers `wp-cron.php` by POSTing to its own site. The source IP of
those requests is usually the origin server. A whois lookup on it identified
the hosting provider (GoDaddy) without any access to the site.

→ **Self-call attribution (EXP-004)**: the signature defines self-call paths,
and the module enriches the source IP with ASN/registrant data.

### 10. Version headers are informative when present, absent otherwise
One host exposed `X-Powered-By: PHP/8.3.33`, a security release behind the
current 8.3.35. Another showed only `X-Powered-By: WP Engine` (a managed
platform, which is useful in itself). A third stripped the header entirely.

→ **Version currency (EXP-005)** classifies hosts as current, behind, EOL, or
**unknown**. Unknown is not safe; it goes to the owner as a question.

### 11. Vantage point distorts active checks
Checks run from inside the corporate network failed DNS resolution for some
hosts (internal filtering) and were blocked by the WAF for others. The
external view is what matters.

→ **Active verification pins DNS to the publicly resolved address**, runs from
a configurable egress, and records the resolver used. Results from a filtered
vantage point must be distinguishable from real failures.

### 12. A scripting bug produced false evidence
The ad-hoc check loop hashed a temp file after a failed request. curl never
wrote the file, so the hash came from the *previous* host's response, and
every failed host appeared to return identical content.

→ **Only compute size/hash/title when bytes were actually received.** Status 0
means no hash. This is a required regression test.

### 13. Nothing sensitive should ever be stored
Checking whether `/config.php.bak` leaked credentials required looking at the
response without printing or saving it.

→ **Store metadata only**: status, size, content type, title, truncated hash,
and *counts* of secret-pattern matches. Never bodies.

### 14. Ownership was the real bottleneck
By the end, the technical picture was clear. What blocked action was not
knowing who owned each site, who hosted it, and who could patch it.

→ **Reports include owner, hosting, and contact columns** (pre-filled where
inferred, blank otherwise). The diff view supports a quick post-patch
recheck.

## What the module is not

- Not an exploitation or vulnerability scanner. It never sends payloads,
  never POSTs, and never follows redirects.
- Not an auto-remediator. It is read-only against Cloudflare and makes no WAF,
  DNS, or Access changes.
- Not a substitute for the vendor advisory. When details are published,
  the signature file is updated and the run repeated.

## Reusability

The PHP case is the first signature, not the design. The next "critical bug
in X" (a Java framework, a specific CMS, an appliance web UI) should be a new
YAML file in `signatures/`, not new code.
