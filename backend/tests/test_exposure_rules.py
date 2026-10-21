"""Exposure Analysis Stage 2 rules against the synthetic fixtures.

Acceptance criteria 1-5 from docs/exposure-analysis/SPEC.md. Rules are pure
functions, so nothing here touches the network or the database.
"""
import json
import os

import pytest
import yaml

from exposure import rules, signatures

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SIGNATURE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "signatures", "php-rce-2026-10.yaml")


@pytest.fixture()
def signature():
    return signatures.load_signature_file(SIGNATURE_PATH)


@pytest.fixture()
def groups():
    with open(os.path.join(FIXTURES, "sample_graphql_groups.json")) as fh:
        return json.load(fh)["groups"]


@pytest.fixture()
def dns():
    with open(os.path.join(FIXTURES, "sample_dns.json")) as fh:
        return json.load(fh)


@pytest.fixture()
def classified(signature, groups, dns):
    return rules.classify(groups, signature, dns["records"], dns["cloudflare_ranges_stub"])


def by_rule(result, host, rule_id):
    return [f for f in result.findings if f.host == host and f.rule_id == rule_id]


def verdicts(result, host):
    return {f.verdict for f in result.findings if f.host == host}


# 1. Catch-all excluded (CONTEXT #4)
def test_catch_all_host_is_never_likely_affected(classified):
    assert rules.VERDICT_CATCH_ALL in verdicts(classified, "spa.example.com")
    assert rules.VERDICT_LIKELY not in verdicts(classified, "spa.example.com")
    hits = by_rule(classified, "spa.example.com", "EXP-002")[0].evidence["canary_hits"]
    assert set(hits) == {"/phpinfo.php~", "/cakephp/.env"}


def test_catch_all_needs_min_canary_hits(signature):
    one_hit = [{"host": "x.example.com", "path": "/phpinfo.php~", "method": "GET",
                "edge_status": 200, "origin_status": 200, "distinct_client_ips": 1, "count": 1}]
    assert rules.exp002_catch_all("x.example.com", one_hit, signature) is None


def test_random_canary_is_ignored_passively(signature):
    assert "/zz-RANDOM.php" in signature.canary_paths
    assert all("RANDOM" not in p for p in rules.passive_canary_paths(signature))


# 2. Real PHP detected (CONTEXT #5)
def test_real_php_host_is_likely_affected(classified):
    finding = by_rule(classified, "realwp.example.com", "EXP-001")[0]
    assert finding.verdict == rules.VERDICT_LIKELY
    assert finding.confidence == rules.CONF_INFERRED
    assert finding.origin_status_trusted is True
    assert finding.evidence["distinct_ips"] == 108
    assert finding.evidence["counts_estimated"] is True


def test_scanner_only_host_below_threshold_is_not_flagged(signature):
    scanner = [{"host": "quiet.example.com", "path": f"/{i}.php", "method": "GET",
                "edge_status": 200, "origin_status": 200, "distinct_client_ips": 2, "count": 3}
               for i in range(30)]
    result = rules.classify(scanner, signature)
    assert rules.VERDICT_LIKELY not in verdicts(result, "quiet.example.com")
    # Many paths from two IPs must not be summed into a false positive
    assert result.hosts["quiet.example.com"].distinct_ips_2xx == 2


def test_host_stats_union_overrides_per_row_estimate(signature):
    rows = [{"host": "h.example.com", "path": "/index.php", "method": "GET",
             "edge_status": 200, "origin_status": 200, "distinct_client_ips": 3, "count": 50}]
    result = rules.classify(rows, signature, host_stats={"h.example.com": {"distinct_ips_2xx": 40, "cf_range_ips_2xx": 5}})
    finding = by_rule(result, "h.example.com", "EXP-001")[0]
    assert finding.evidence["distinct_ips"] == 40
    assert finding.evidence["cf_range_ips"] == 5
    assert "Cloudflare ranges" in finding.detail


# 3. Misrouted untrust (CONTEXT #6, #7)
def test_misrouted_host_has_untrusted_origin_and_no_exp001(classified):
    assert classified.origin_trust["webmail.example.com"] is False
    misrouted = by_rule(classified, "webmail.example.com", "EXP-003")[0]
    assert misrouted.verdict == rules.VERDICT_MISROUTED
    assert misrouted.origin_status_trusted is False
    assert misrouted.evidence["cloudflare_pointed"] == ["104.21.15.127"]
    assert misrouted.evidence["duplicates"] == {"A": 2}
    assert "INCREASES exposure" in misrouted.detail
    assert all(not f.origin_status_trusted for f in classified.findings if f.host == "webmail.example.com")
    assert rules.VERDICT_LIKELY not in verdicts(classified, "webmail.example.com")


def test_exp001_does_not_fire_on_untrusted_origin_even_with_many_ips(signature):
    rows = [{"host": "broken.example.com", "path": "/wp-login.php", "method": "GET",
             "edge_status": 200, "origin_status": 200, "distinct_client_ips": 500, "count": 900}]
    dns = [{"host": "broken.example.com", "type": "A", "content": "104.21.1.1"}]
    result = rules.classify(rows, signature, dns, ["104.21.0.0/16"])
    exp001 = by_rule(result, "broken.example.com", "EXP-001")
    assert exp001 and exp001[0].verdict == rules.VERDICT_INFO
    assert exp001[0].origin_status_trusted is False
    assert rules.VERDICT_LIKELY not in verdicts(result, "broken.example.com")


def test_duplicate_records_alone_are_misrouted_but_inferred(signature):
    dns = [{"host": "dup.example.com", "type": "A", "content": "198.51.100.1"},
           {"host": "dup.example.com", "type": "A", "content": "198.51.100.2"}]
    finding = rules.exp003_misrouted("dup.example.com", dns, rules.parse_networks(["104.21.0.0/16"]))
    assert finding.confidence == rules.CONF_INFERRED
    assert finding.evidence["cloudflare_pointed"] == []


def test_misrouted_dns_reported_without_traffic(signature):
    dns = [{"host": "silent.example.com", "type": "AAAA", "content": "2606:4700::1"}]
    result = rules.classify([], signature, dns, ["2606:4700::/32"])
    assert by_rule(result, "silent.example.com", "EXP-003")
    assert "silent.example.com" in result.hosts


def test_clean_host_is_trusted(classified):
    assert classified.origin_trust["realwp.example.com"] is True
    assert not by_rule(classified, "realwp.example.com", "EXP-003")


# 4. Hosting attribution (CONTEXT #9)
def test_self_call_source_ip_attributes_hosting(signature, groups):
    enrichment = {"203.0.113.37": {"provider": "GoDaddy.com, LLC", "name": "GO-DADDY-COM-LLC", "asn": "26496"}}
    result = rules.classify(groups, signature, enrichment=enrichment)
    assert result.hosting["realwp.example.com"] == {"origin_ip": "203.0.113.37", "hosting_provider": "GoDaddy.com, LLC"}
    finding = by_rule(result, "realwp.example.com", "EXP-004")[0]
    assert finding.verdict == rules.VERDICT_INFO
    assert "GoDaddy" in finding.detail


def test_self_call_without_enrichment_still_records_origin_ip(signature, groups):
    result = rules.classify(groups, signature)
    assert result.hosting["realwp.example.com"]["origin_ip"] == "203.0.113.37"
    assert result.hosting["realwp.example.com"]["hosting_provider"] is None


def test_self_call_rows_do_not_double_count_traffic(signature):
    rows = [
        {"host": "h.example.com", "path": "/wp-cron.php", "method": "POST", "edge_status": 200, "origin_status": 200, "count": 10},
        {"host": "h.example.com", "path": "/wp-cron.php", "method": "POST", "source_ip": "203.0.113.9", "count": 10, "kind": "self_call"},
    ]
    result = rules.classify(rows, signature)
    assert result.hosts["h.example.com"].matching_requests == 10


# 5. Version currency (CONTEXT #10)
FEED = {"branches": {"8.2": "8.2.34", "8.3": "8.3.35", "8.4": "8.4.18", "8.5": "8.5.11"}, "complete": True}


def test_behind_version(signature):
    detected, status, finding = rules.exp005_version_currency("h", "PHP/8.3.33", signature, FEED)
    assert (detected, status) == ("8.3.33", rules.VERSION_BEHIND)
    assert finding.verdict == rules.VERDICT_LIKELY
    assert finding.confidence == rules.CONF_VERIFIED
    assert "8.3.35" in finding.detail


def test_current_version(signature):
    assert rules.exp005_version_currency("h", "PHP/8.3.35", signature, FEED)[1] == rules.VERSION_CURRENT


def test_stripped_header_is_unknown_never_current(signature):
    detected, status, finding = rules.exp005_version_currency("h", None, signature, FEED)
    assert detected is None
    assert status == rules.VERSION_UNKNOWN
    assert "ask the owner" in finding.detail


def test_eol_branch_from_signature_list(signature):
    assert rules.exp005_version_currency("h", "PHP/7.4.33", signature, FEED)[1] == rules.VERSION_EOL
    assert rules.exp005_version_currency("h", "PHP/8.1.31", signature, FEED)[1] == rules.VERSION_EOL


def test_branch_missing_from_complete_feed_is_eol(signature):
    feed = {"branches": {"8.5": "8.5.11"}, "complete": True}
    assert rules.exp005_version_currency("h", "PHP/8.4.1", signature, feed)[1] == rules.VERSION_EOL


def test_branch_missing_from_partial_feed_is_unknown(signature):
    feed = {"branches": {"8.5": "8.5.11"}, "complete": False}
    assert rules.exp005_version_currency("h", "PHP/8.4.1", signature, feed)[1] == rules.VERSION_UNKNOWN


def test_managed_platform_header_is_unknown_with_note(signature):
    detected, status, finding = rules.exp005_version_currency("h", "WP Engine", signature, FEED)
    assert status == rules.VERSION_UNKNOWN
    assert finding.evidence["managed_platform"] == "WP Engine"


def test_parse_version_feed_shapes():
    active = {"8": {"8.3": {"version": "8.3.35"}, "8.4": {"version": "8.4.18"}}}
    parsed = rules.parse_version_feed(active)
    assert parsed == {"branches": {"8.3": "8.3.35", "8.4": "8.4.18"}, "complete": True}
    latest_only = {"8": {"version": "8.5.11", "supported_versions": ["8.2"]}, "7": {"version": "7.4.33"}}
    parsed = rules.parse_version_feed(latest_only)
    assert parsed == {"branches": {"8.5": "8.5.11", "7.4": "7.4.33"}, "complete": False}
    assert rules.parse_version_feed(None) == {"branches": {}, "complete": False}


# EXP-006 / EXP-007 / active findings
def test_edge_coverage_only_reports_gaps():
    assert rules.exp006_edge_coverage("a.com", "enabled") is None
    disabled = rules.exp006_edge_coverage("a.com", "disabled")
    assert disabled.confidence == rules.CONF_VERIFIED and "would not apply" in disabled.detail
    assert rules.exp006_edge_coverage("a.com", "unknown").confidence == rules.CONF_INFERRED


def test_post_pressure_is_informational(classified):
    finding = by_rule(classified, "managedwp.example.com", "EXP-007")[0]
    assert finding.verdict == rules.VERDICT_INFO
    assert finding.evidence["paths"] == {"/wp-login.php": 119}
    assert rules.VERDICT_LIKELY not in verdicts(classified, "managedwp.example.com")


def test_active_findings_confirm_catch_all_and_flag_secrets(signature):
    probes = [
        {"kind": "baseline", "path": "/abc", "status": 200, "sha256_prefix": "aaaa", "secret_match_count": 0, "debug_marker_count": 0},
        {"kind": "canary", "path": "/phpinfo.php~", "status": 200, "sha256_prefix": "aaaa", "secret_match_count": 0, "debug_marker_count": 0},
        {"kind": "canary", "path": "/zz-deadbeef.php", "status": 200, "sha256_prefix": "aaaa", "secret_match_count": 0, "debug_marker_count": 0},
        {"kind": "suspect", "path": "/config.php.bak", "status": 200, "sha256_prefix": "bbbb", "secret_match_count": 3, "debug_marker_count": 0},
        {"kind": "suspect", "path": "/same-as-baseline", "status": 200, "sha256_prefix": "aaaa", "secret_match_count": 2, "debug_marker_count": 0},
        {"kind": "suspect", "path": "/nothing", "status": 0, "sha256_prefix": None, "secret_match_count": None, "debug_marker_count": None},
    ]
    found = rules.active_findings("h.example.com", probes, signature)
    by_id = {f.rule_id: f for f in found}
    assert by_id["EXP-002"].confidence == rules.CONF_VERIFIED
    assert by_id["EXP-008"].evidence["path"] == "/config.php.bak"
    assert by_id["EXP-008"].verdict == rules.VERDICT_LIKELY
    # Same hash as the catch-all baseline is not a distinct exposure
    assert sum(1 for f in found if f.rule_id == "EXP-008") == 1
    # Body never appears in evidence
    assert all("body" not in f.evidence for f in found)


def test_active_findings_with_no_bytes_received(signature):
    assert rules.active_findings("h", [{"kind": "canary", "path": "/x", "status": 0}], signature) == []


# Signature loading
def test_signature_file_parses_with_thresholds(signature):
    assert signature.name == "php-rce-2026-10"
    assert signature.version == "2"
    assert signature.min_distinct_ips == 10
    assert signature.min_canary_hits == 2
    assert signature.self_call_paths == ["/wp-cron.php"]
    assert signature.version_spec.header == "x-powered-by"
    assert "8.1" in signature.version_spec.eol_branches
    assert signature.verify.secret_patterns


def test_signature_file_ships_mitigations_for_every_plan_tier(signature):
    kinds = {m.kind for m in signature.mitigations}
    assert kinds == {"cloudflare_waf", "origin", "patch"}
    waf = [m for m in signature.mitigations if m.kind == "cloudflare_waf"]
    plans = " ".join(e.plan or "" for m in waf for e in m.expressions)
    assert "Enterprise" in plans and "Free" in plans
    # The exploit field name must appear in the precise rule, and the
    # lower-plan rule must not depend on Enterprise-only body fields.
    precise = next(m for m in waf if m.id == "waf-block-upload-progress-field")
    assert all("PHP_SESSION_UPLOAD_PROGRESS" in e.expression for e in precise.expressions)
    coarse = next(m for m in waf if m.id == "waf-challenge-multipart-uploads")
    assert all("http.request.body" not in e.expression for e in coarse.expressions)
    origin = next(m for m in signature.mitigations if m.kind == "origin")
    assert "session.upload_progress.enabled = 0" in origin.snippet
    assert signature.to_dict()["mitigations"][0]["id"] == precise.id


def test_mitigations_are_optional_and_validated():
    base = {"name": "ok", "path_patterns": ["*.php"]}
    assert signatures.parse_signature(base).mitigations == []

    good = dict(base, mitigations=[{
        "id": "m1", "kind": "cloudflare_waf", "title": "Block it", "action": "Block",
        "expressions": [{"plan": "Enterprise", "expression": "http.request.method eq \"POST\""}],
        "steps": ["Open WAF", "Paste"],
    }])
    parsed = signatures.parse_signature(good).mitigations
    assert parsed[0].expressions[0].plan == "Enterprise"
    assert parsed[0].steps == ["Open WAF", "Paste"]

    with pytest.raises(signatures.SignatureError, match="kind"):
        signatures.parse_signature(dict(base, mitigations=[{"id": "m1", "kind": "magic", "title": "x"}]))
    with pytest.raises(signatures.SignatureError, match="no expressions"):
        signatures.parse_signature(dict(base, mitigations=[{"id": "m1", "kind": "cloudflare_waf", "title": "x"}]))
    with pytest.raises(signatures.SignatureError, match="duplicates"):
        signatures.parse_signature(dict(base, mitigations=[
            {"id": "m1", "kind": "patch", "title": "a"}, {"id": "m1", "kind": "patch", "title": "b"},
        ]))
    with pytest.raises(signatures.SignatureError, match="'expression' string"):
        signatures.parse_signature(dict(base, mitigations=[
            {"id": "m1", "kind": "cloudflare_waf", "title": "x", "expressions": [{"plan": "Enterprise"}]},
        ]))


def test_signature_rejects_bad_name_and_regex():
    with pytest.raises(signatures.SignatureError):
        signatures.parse_signature({"name": "Bad Name!", "path_patterns": ["*.php"]})
    with pytest.raises(signatures.SignatureError):
        signatures.parse_signature({"name": "ok", "path_patterns": ["*.php"], "version": {"extract": "(["}})
    with pytest.raises(signatures.SignatureError):
        signatures.parse_signature({"name": "ok", "path_patterns": []})


def test_list_signatures_skips_malformed_files(tmp_path):
    (tmp_path / "good.yaml").write_text(yaml.safe_dump({"name": "good", "path_patterns": ["*.jsp"]}))
    (tmp_path / "bad.yaml").write_text("name: [unclosed")
    found = signatures.list_signatures(str(tmp_path))
    assert list(found) == ["good"]
    assert found["good"].path_patterns == ["*.jsp"]
