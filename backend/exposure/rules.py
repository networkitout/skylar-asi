"""Stage 2 classification rules (pure functions, no network, no database).

Input is a list of normalized aggregated groups as the collector produces
them (one dict per host/path/method/status combination):

    {"host", "path", "method", "edge_status", "origin_status", "count",
     "distinct_client_ips" (optional), "source_ip" (optional)}

plus optional per-host stats from the distinct-IP query, DNS records for
EXP-003, and enrichment lookups for EXP-004/005. Every threshold comes from
the signature (CONTEXT: reusability).
"""

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .signatures import Signature

VERDICT_LIKELY = "likely_affected"
VERDICT_CATCH_ALL = "catch_all"
VERDICT_MISROUTED = "misrouted"
VERDICT_INFO = "info"

# Higher wins when a host has several findings.
VERDICT_RANK = {VERDICT_LIKELY: 3, VERDICT_MISROUTED: 2, VERDICT_CATCH_ALL: 1, VERDICT_INFO: 0}

CONF_VERIFIED = "verified"
CONF_INFERRED = "inferred"

VERSION_CURRENT = "current"
VERSION_BEHIND = "behind"
VERSION_EOL = "eol"
VERSION_UNKNOWN = "unknown"

# Canary entries containing this token are substituted at probe time and can
# never appear in passive logs, so EXP-002 ignores them.
RANDOM_CANARY_TOKEN = "RANDOM"


@dataclass
class Finding:
    host: str
    rule_id: str
    verdict: str
    confidence: str
    detail: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    origin_status_trusted: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HostSummary:
    host: str
    matching_requests: int = 0
    origin_2xx: int = 0
    distinct_ips_2xx: int = 0
    cf_range_ips_2xx: int = 0
    post_requests: int = 0
    canary_hits: int = 0
    sample_paths: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ClassificationResult:
    findings: List[Finding]
    hosts: Dict[str, HostSummary]
    origin_trust: Dict[str, bool]
    hosting: Dict[str, Dict[str, Optional[str]]]


# ---------------------------------------------------------------- helpers

def is_2xx(status) -> bool:
    try:
        return 200 <= int(status) < 300
    except (TypeError, ValueError):
        return False


def path_matches(path: str, patterns: Sequence[str]) -> bool:
    """Shell-style match of a request path against signature path patterns."""
    if not path:
        return False
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def passive_canary_paths(signature: Signature) -> List[str]:
    return [p for p in signature.canary_paths if RANDOM_CANARY_TOKEN not in p]


def parse_networks(cidrs: Iterable[str]) -> List[Any]:
    networks = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr.strip(), strict=False))
        except ValueError:
            continue
    return networks


def ip_in_networks(ip: str, networks: Sequence[Any]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def group_rows_by_host(groups: Iterable[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    by_host: Dict[str, List[Dict[str, Any]]] = {}
    for row in groups:
        host = (row.get("host") or "").strip().lower()
        if not host:
            continue
        by_host.setdefault(host, []).append(row)
    return by_host


def summarize_host(host: str, rows: List[Dict[str, Any]], signature: Signature,
                   host_stats: Optional[Dict[str, Any]] = None) -> HostSummary:
    summary = HostSummary(host=host)
    canaries = set(passive_canary_paths(signature))
    canary_seen = set()
    max_ips = 0
    for row in rows:
        if row.get("kind") == "self_call":
            continue
        path = row.get("path") or ""
        count = int(row.get("count") or 0)
        if path_matches(path, signature.path_patterns):
            summary.matching_requests += count
            if is_2xx(row.get("origin_status")):
                summary.origin_2xx += count
                max_ips = max(max_ips, int(row.get("distinct_client_ips") or 0))
                if path not in summary.sample_paths and len(summary.sample_paths) < 10:
                    summary.sample_paths.append(path)
            if (row.get("method") or "").upper() == "POST":
                summary.post_requests += count
        if path in canaries and is_2xx(row.get("origin_status")):
            canary_seen.add(path)
    summary.canary_hits = len(canary_seen)
    # The distinct-IP query gives a true per-host union; without it the best
    # conservative estimate is the largest single-path count (IPs overlap
    # across paths, so summing would overstate).
    stats = (host_stats or {}).get(host) or {}
    summary.distinct_ips_2xx = int(stats.get("distinct_ips_2xx") or max_ips)
    summary.cf_range_ips_2xx = int(stats.get("cf_range_ips_2xx") or 0)
    return summary


# ------------------------------------------------------------------ rules

def exp003_misrouted(host: str, dns_records: Sequence[Dict[str, Any]],
                     cf_networks: Sequence[Any]) -> Optional[Finding]:
    """A/AAAA record pointing into Cloudflare space (Error 1000 producer) or
    duplicate A/AAAA records for the name. Either makes origin status in the
    sampled logs untrustworthy (CONTEXT #6, #7)."""
    host_l = host.lower()
    own = [r for r in dns_records
           if (r.get("host") or r.get("name") or "").lower() == host_l
           and (r.get("type") or "").upper() in ("A", "AAAA")]
    if not own:
        return None

    cf_pointed = [r.get("content") for r in own if ip_in_networks(r.get("content") or "", cf_networks)]
    by_type: Dict[str, int] = {}
    for r in own:
        by_type[r["type"].upper()] = by_type.get(r["type"].upper(), 0) + 1
    duplicates = {t: n for t, n in by_type.items() if n > 1}

    if not cf_pointed and not duplicates:
        return None

    reasons = []
    if cf_pointed:
        reasons.append(f"{len(cf_pointed)} record(s) point into Cloudflare IP space (produces Error 1000, logged as origin 200)")
    if duplicates:
        dup_text = ", ".join(f"{n}x {t}" for t, n in duplicates.items())
        reasons.append(f"duplicate records ({dup_text}) make responses nondeterministic")
    detail = f"{host}: " + "; ".join(reasons) + ". Origin status for this host is untrusted."
    if cf_pointed and len(own) > len(cf_pointed):
        detail += (" Deleting the bad record INCREASES exposure: the real origin then answers every "
                   "request. Pair the fix with access restriction.")

    return Finding(
        host=host,
        rule_id="EXP-003",
        verdict=VERDICT_MISROUTED,
        confidence=CONF_VERIFIED if cf_pointed else CONF_INFERRED,
        detail=detail,
        evidence={
            "records": [{"type": r.get("type"), "content": r.get("content"), "proxied": r.get("proxied")} for r in own],
            "cloudflare_pointed": cf_pointed,
            "duplicates": duplicates,
        },
        origin_status_trusted=False,
    )


def exp002_catch_all(host: str, rows: List[Dict[str, Any]], signature: Signature,
                     origin_trusted: bool = True) -> Optional[Finding]:
    """Origin 2xx on >= min_canary_hits impossible paths => the host answers
    everything; .php 2xx there says nothing (CONTEXT #4)."""
    canaries = set(passive_canary_paths(signature))
    hits: Dict[str, int] = {}
    for row in rows:
        if row.get("kind") == "self_call":
            continue
        path = row.get("path") or ""
        if path in canaries and is_2xx(row.get("origin_status")):
            hits[path] = hits.get(path, 0) + int(row.get("count") or 0)
    if len(hits) < signature.min_canary_hits:
        return None
    detail = (f"{host} returned origin 2xx for {len(hits)} impossible path(s) "
              f"({', '.join(sorted(hits))}); treated as catch-all and excluded from technology detection.")
    if not origin_trusted:
        detail += " Origin status is untrusted for this host (see EXP-003), so this may be a Cloudflare error page."
    return Finding(
        host=host,
        rule_id="EXP-002",
        verdict=VERDICT_CATCH_ALL,
        confidence=CONF_INFERRED,
        detail=detail,
        evidence={"canary_hits": hits, "threshold": signature.min_canary_hits},
        origin_status_trusted=origin_trusted,
    )


def exp001_likely_affected(host: str, summary: HostSummary, signature: Signature,
                           origin_trusted: bool = True, is_catch_all: bool = False) -> Optional[Finding]:
    """Matching paths with origin 2xx from >= min_distinct_ips clients
    (CONTEXT #3, #5). Only trusted origin status counts; catch-all hosts are
    excluded."""
    if is_catch_all or summary.origin_2xx <= 0:
        return None
    if summary.distinct_ips_2xx < signature.min_distinct_ips:
        return None
    evidence = {
        "distinct_ips": summary.distinct_ips_2xx,
        "cf_range_ips": summary.cf_range_ips_2xx,
        "origin_2xx": summary.origin_2xx,
        "matching_requests": summary.matching_requests,
        "sample_paths": summary.sample_paths,
        "threshold": signature.min_distinct_ips,
        "counts_estimated": True,
    }
    if not origin_trusted:
        return Finding(
            host=host,
            rule_id="EXP-001",
            verdict=VERDICT_INFO,
            confidence=CONF_INFERRED,
            detail=(f"{host} shows ~{summary.origin_2xx} origin 2xx on matching paths from ~{summary.distinct_ips_2xx} "
                    f"client IPs, but origin status is untrusted (EXP-003). Not counted as affected; verify actively."),
            evidence=evidence,
            origin_status_trusted=False,
        )
    detail = (f"{host}: ~{summary.origin_2xx} origin 2xx responses on matching paths from ~{summary.distinct_ips_2xx} "
              f"distinct client IPs (threshold {signature.min_distinct_ips}); counts are sampled estimates.")
    if summary.cf_range_ips_2xx:
        detail += f" {summary.cf_range_ips_2xx} of those IPs fall in Cloudflare ranges (Workers/WARP); IP blocklists will not stop them."
    return Finding(
        host=host,
        rule_id="EXP-001",
        verdict=VERDICT_LIKELY,
        confidence=CONF_INFERRED,
        detail=detail,
        evidence=evidence,
        origin_status_trusted=True,
    )


def exp004_hosting(host: str, rows: List[Dict[str, Any]], signature: Signature,
                   enrichment: Optional[Dict[str, Dict[str, Any]]] = None
                   ) -> Tuple[Optional[Dict[str, Optional[str]]], Optional[Finding]]:
    """Source IP of the app's self-calls (e.g. wp-cron POST) is usually the
    origin; whois/ASN on it names the host (CONTEXT #9)."""
    if not signature.self_call_paths:
        return None, None
    self_paths = set(signature.self_call_paths)
    ip_counts: Dict[str, int] = {}
    for row in rows:
        if (row.get("path") or "") not in self_paths:
            continue
        ip = row.get("source_ip")
        if not ip:
            continue
        ip_counts[ip] = ip_counts.get(ip, 0) + int(row.get("count") or 0)
    if not ip_counts:
        return None, None
    origin_ip = max(ip_counts, key=ip_counts.get)
    info = (enrichment or {}).get(origin_ip) or {}
    provider = info.get("provider") or info.get("name")
    attribution = {"origin_ip": origin_ip, "hosting_provider": provider}
    detail = f"{host}: self-calls to {', '.join(sorted(self_paths))} originate from {origin_ip}"
    detail += f" ({provider})." if provider else " (hosting lookup unavailable)."
    finding = Finding(
        host=host,
        rule_id="EXP-004",
        verdict=VERDICT_INFO,
        confidence=CONF_INFERRED,
        detail=detail,
        evidence={"source_ips": ip_counts, "origin_ip": origin_ip, "hosting_provider": provider,
                  "asn": info.get("asn"), "rdap_name": info.get("name")},
    )
    return attribution, finding


def _version_tuple(version: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version)[:3])


def parse_version_feed(data: Any) -> Dict[str, Any]:
    """Normalize a release feed into {"branches": {"8.3": "8.3.35"}, "complete": bool}.

    Accepts php.net's /releases/active shape ({major: {branch: {version}}}),
    which lists every supported branch (complete=True), and the
    /releases/index.php?json shape ({major: {version}}), which only gives the
    newest release per major (complete=False).
    """
    branches: Dict[str, str] = {}
    complete = False
    if isinstance(data, dict):
        for major, entry in data.items():
            if not isinstance(entry, dict):
                continue
            if "version" in entry and isinstance(entry["version"], str):
                v = entry["version"]
                branches[".".join(v.split(".")[:2])] = v
            else:
                for branch, release in entry.items():
                    if isinstance(release, dict) and isinstance(release.get("version"), str):
                        v = release["version"]
                        branches[".".join(v.split(".")[:2])] = v
                        complete = True
    return {"branches": branches, "complete": complete}


def exp005_version_currency(host: str, header_value: Optional[str], signature: Signature,
                            feed: Optional[Dict[str, Any]] = None
                            ) -> Tuple[Optional[str], str, Optional[Finding]]:
    """Classify a captured version header as current/behind/eol/unknown.
    Unknown is not safe (CONTEXT #10)."""
    spec = signature.version_spec
    managed = [p for p in (signature.report or {}).get("managed_platforms", [])
               if header_value and p.lower() in header_value.lower()]
    if not header_value or not spec.extract:
        detail = f"{host}: no version header exposed; version unknown - ask the owner."
        if managed:
            detail = f"{host}: header identifies managed platform {managed[0]}; vendor patches the runtime. Version unknown."
        return None, VERSION_UNKNOWN, Finding(
            host=host, rule_id="EXP-005", verdict=VERDICT_INFO, confidence=CONF_INFERRED,
            detail=detail, evidence={"header": header_value, "managed_platform": managed[0] if managed else None,
                                     "version_status": VERSION_UNKNOWN})
    match = re.search(spec.extract, header_value)
    if not match:
        detail = f"{host}: header '{header_value[:60]}' carries no parseable version."
        if managed:
            detail = f"{host}: header identifies managed platform {managed[0]}; vendor patches the runtime. Version unknown."
        return None, VERSION_UNKNOWN, Finding(
            host=host, rule_id="EXP-005", verdict=VERDICT_INFO, confidence=CONF_INFERRED,
            detail=detail, evidence={"header": header_value[:120], "managed_platform": managed[0] if managed else None,
                                     "version_status": VERSION_UNKNOWN})

    detected = match.group(1) if match.groups() else match.group(0)
    branch = ".".join(detected.split(".")[:2])
    feed = feed or {"branches": {}, "complete": False}
    latest = feed["branches"].get(branch)
    if branch in spec.eol_branches or branch.split(".")[0] in spec.eol_branches:
        status = VERSION_EOL
    elif latest:
        status = VERSION_CURRENT if _version_tuple(detected) >= _version_tuple(latest) else VERSION_BEHIND
    elif feed.get("complete"):
        status = VERSION_EOL
    else:
        status = VERSION_UNKNOWN

    labels = {
        VERSION_CURRENT: f"{host} reports {detected}, the current {branch} release.",
        VERSION_BEHIND: f"{host} reports {detected}; current {branch} release is {latest}. Patch pending.",
        VERSION_EOL: f"{host} reports {detected} on branch {branch}, which has no upstream fix (EOL).",
        VERSION_UNKNOWN: f"{host} reports {detected}; branch {branch} not in the release feed - currency unknown.",
    }
    verdict = VERDICT_LIKELY if status in (VERSION_BEHIND, VERSION_EOL) else VERDICT_INFO
    finding = Finding(
        host=host, rule_id="EXP-005", verdict=verdict, confidence=CONF_VERIFIED,
        detail=labels[status],
        evidence={"header": header_value[:120], "detected_version": detected, "branch": branch,
                  "latest": latest, "version_status": status},
    )
    return detected, status, finding


def exp006_edge_coverage(zone_name: str, managed_waf: str, detail_extra: str = "") -> Optional[Finding]:
    """Report zones where an emergency managed WAF rule would NOT apply."""
    if managed_waf == "enabled":
        return None
    if managed_waf == "disabled":
        detail = f"Zone {zone_name}: no managed WAF ruleset deployed; an emergency managed rule would not apply."
    else:
        detail = f"Zone {zone_name}: managed WAF state could not be read (token may lack Zone WAF Read)."
    if detail_extra:
        detail += f" {detail_extra}"
    return Finding(
        host=zone_name, rule_id="EXP-006", verdict=VERDICT_INFO, confidence=CONF_VERIFIED if managed_waf == "disabled" else CONF_INFERRED,
        detail=detail, evidence={"managed_waf": managed_waf},
    )


def exp007_post_pressure(host: str, summary: HostSummary, rows: List[Dict[str, Any]],
                         signature: Signature) -> Optional[Finding]:
    """Informational: heavy POST traffic to matching paths (login/xmlrpc
    brute force). Not CVE evidence, but worth a line in the handoff."""
    threshold = int((signature.report or {}).get("post_pressure_threshold") or 50)
    if summary.post_requests < threshold:
        return None
    post_paths: Dict[str, int] = {}
    for row in rows:
        if row.get("kind") == "self_call":
            continue
        if (row.get("method") or "").upper() == "POST" and path_matches(row.get("path") or "", signature.path_patterns):
            post_paths[row["path"]] = post_paths.get(row["path"], 0) + int(row.get("count") or 0)
    return Finding(
        host=host, rule_id="EXP-007", verdict=VERDICT_INFO, confidence=CONF_INFERRED,
        detail=f"{host}: ~{summary.post_requests} POSTs to matching paths ({', '.join(sorted(post_paths))}); "
               f"credential-stuffing or xmlrpc abuse signal, consider restricting at the edge.",
        evidence={"post_requests": summary.post_requests, "paths": post_paths},
    )


def active_findings(host: str, probes: Sequence[Dict[str, Any]], signature: Signature) -> List[Finding]:
    """Findings derived from active-verify probe metadata (never bodies).

    - EXP-002 (verified): >= min_canary_hits canary paths answered 2xx.
    - EXP-008: a canary/suspect path answered 2xx with secret-pattern or
      debug-page matches, and its content differs from the baseline (so it is
      not just the catch-all page again).
    """
    out: List[Finding] = []
    received = [p for p in probes if p.get("status")]
    if not received:
        return out
    baseline = next((p for p in received if p.get("kind") == "baseline"), None)
    baseline_hash = baseline.get("sha256_prefix") if baseline else None

    canary_2xx = [p["path"] for p in received if p.get("kind") == "canary" and is_2xx(p.get("status"))]
    if len(canary_2xx) >= signature.min_canary_hits:
        out.append(Finding(
            host=host, rule_id="EXP-002", verdict=VERDICT_CATCH_ALL, confidence=CONF_VERIFIED,
            detail=f"{host} answered 2xx for {len(canary_2xx)} randomized/impossible path(s) during active verify; "
                   f"confirmed catch-all.",
            evidence={"canary_2xx": canary_2xx, "baseline_status": baseline.get("status") if baseline else None,
                      "active": True},
        ))

    for p in received:
        if p.get("kind") == "baseline" or not is_2xx(p.get("status")):
            continue
        secrets_n = int(p.get("secret_match_count") or 0)
        debug_n = int(p.get("debug_marker_count") or 0)
        if secrets_n == 0 and debug_n == 0:
            continue
        if baseline_hash and p.get("sha256_prefix") == baseline_hash:
            continue
        what = []
        if secrets_n:
            what.append(f"{secrets_n} secret-pattern match(es)")
        if debug_n:
            what.append(f"{debug_n} framework debug marker(s)")
        out.append(Finding(
            host=host, rule_id="EXP-008", verdict=VERDICT_LIKELY, confidence=CONF_VERIFIED,
            detail=f"{host}{p['path']} returned {p['status']} with {' and '.join(what)}; "
                   f"treat as credential/config exposure. Counts only - no content was stored.",
            evidence={"path": p["path"], "status": p["status"], "size": p.get("size"),
                      "content_type": p.get("content_type"), "title": p.get("title"),
                      "secret_match_count": secrets_n, "debug_marker_count": debug_n, "active": True},
        ))
    return out


# --------------------------------------------------------------- pipeline

def classify(groups: Iterable[Dict[str, Any]], signature: Signature,
             dns_records: Optional[Sequence[Dict[str, Any]]] = None,
             cf_ranges: Optional[Iterable[str]] = None,
             host_stats: Optional[Dict[str, Dict[str, Any]]] = None,
             enrichment: Optional[Dict[str, Dict[str, Any]]] = None) -> ClassificationResult:
    """Run the passive rules over every host in the collected groups."""
    cf_networks = parse_networks(cf_ranges or [])
    records_by_name: Dict[str, List[Dict[str, Any]]] = {}
    for record in dns_records or []:
        name = (record.get("host") or record.get("name") or "").lower()
        if name:
            records_by_name.setdefault(name, []).append(record)
    by_host = group_rows_by_host(groups)

    findings: List[Finding] = []
    summaries: Dict[str, HostSummary] = {}
    origin_trust: Dict[str, bool] = {}
    hosting: Dict[str, Dict[str, Optional[str]]] = {}

    for host in sorted(by_host):
        rows = by_host[host]
        summary = summarize_host(host, rows, signature, host_stats)
        summaries[host] = summary

        misrouted = exp003_misrouted(host, records_by_name.get(host, []), cf_networks)
        trusted = misrouted is None
        origin_trust[host] = trusted
        if misrouted:
            findings.append(misrouted)

        catch_all = exp002_catch_all(host, rows, signature, origin_trusted=trusted)
        if catch_all:
            findings.append(catch_all)

        likely = exp001_likely_affected(host, summary, signature, origin_trusted=trusted,
                                        is_catch_all=catch_all is not None)
        if likely:
            findings.append(likely)

        attribution, hosting_finding = exp004_hosting(host, rows, signature, enrichment)
        if attribution:
            hosting[host] = attribution
        if hosting_finding:
            hosting_finding.origin_status_trusted = trusted
            findings.append(hosting_finding)

        pressure = exp007_post_pressure(host, summary, rows, signature)
        if pressure:
            pressure.origin_status_trusted = trusted
            findings.append(pressure)

    # Misrouted DNS is worth reporting even when the host had no matching
    # traffic in the window: the exposure exists regardless of what we saw.
    for name, own_records in records_by_name.items():
        if name in by_host or name.startswith("*"):
            continue
        misrouted = exp003_misrouted(name, own_records, cf_networks)
        if misrouted:
            findings.append(misrouted)
            origin_trust[name] = False
            summaries.setdefault(name, HostSummary(host=name))

    return ClassificationResult(findings=findings, hosts=summaries, origin_trust=origin_trust, hosting=hosting)
