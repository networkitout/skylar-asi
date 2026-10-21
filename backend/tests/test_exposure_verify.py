"""Exposure Analysis Stage 3 (active verify) and Stage 1 (collector).

Acceptance criteria 6 (no-bytes-no-hash), 7 (body never stored) and
10 (SSRF guard reuse) from docs/exposure-analysis/SPEC.md.
"""
import json
import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

import main
from exposure import collector, enrich, rules, signatures, verify

SIGNATURE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "signatures", "php-rce-2026-10.yaml")


@pytest.fixture()
def signature():
    return signatures.load_signature_file(SIGNATURE_PATH)


# 6. No-bytes-no-hash (CONTEXT #12)
def test_status_zero_records_no_derived_fields(signature):
    out = verify.summarize_response(0, None, {}, signature.verify.secret_patterns, signature.verify.debug_markers)
    assert out["status"] == 0
    assert out["size"] is None
    assert out["sha256_prefix"] is None
    assert out["title"] is None
    assert out["secret_match_count"] is None
    assert out["debug_marker_count"] is None


def test_received_bytes_produce_metadata_only(signature):
    body = b"<html><title> Config  dump </title>DB_PASSWORD=hunter2\nDB_USERNAME=root\nwhoops"
    out = verify.summarize_response(200, body, {"Content-Type": "text/html"},
                                    signature.verify.secret_patterns, signature.verify.debug_markers)
    assert out["size"] == len(body)
    assert out["content_type"] == "text/html"
    assert out["title"] == "Config dump"
    assert len(out["sha256_prefix"]) == 16
    assert out["secret_match_count"] == 2
    assert out["debug_marker_count"] == 1
    # 7. Body never stored: no field carries the content
    assert "hunter2" not in json.dumps(out)
    assert "body" not in out


def test_probe_table_has_no_body_column():
    columns = {c.name for c in main.ExposureProbe.__table__.columns}
    assert "body" not in columns and "content" not in columns
    assert {"status", "size", "sha256_prefix", "secret_match_count"} <= columns


# 10. SSRF reuse (CONTEXT #11, #13)
async def test_verify_rejects_private_address_via_shared_guard(signature):
    async def fake_resolve(hostname, client):
        return {"ips": ["8.8.8.8", "10.0.0.5"], "resolver": "cloudflare-doh(1.1.1.1)", "error": None}

    async def fail_probe(*args, **kwargs):
        raise AssertionError("no probe may be sent to a host with a private answer")

    with patch.object(verify, "resolve_public", fake_resolve), patch.object(verify, "probe", fail_probe):
        result = await verify.verify_host("internal.example.com", signature, main._ssrf_check, delay_between=0)

    assert result["blocked"] is True
    assert result["resolve_error"] == main.SSRF_BLOCKED_MESSAGE
    assert result["probes"] == []
    # The same message the Reachability feature returns for a blocked host
    assert main._ssrf_check(["127.0.0.1"]) == main.SSRF_BLOCKED_MESSAGE
    assert main._ssrf_check(["8.8.8.8"]) is None


async def test_verify_pins_ip_records_resolver_and_captures_version_header(signature):
    seen = []

    # Note: RFC 5737 documentation ranges count as private to ipaddress, so
    # a routable address is needed to get past the SSRF gate here.
    async def fake_resolve(hostname, client):
        return {"ips": ["2001:4860:4860::8888", "8.8.8.8"], "resolver": "cloudflare-doh(1.1.1.1)", "error": None}

    async def fake_probe(client, hostname, ip, path, user_agent, max_bytes=0, scheme="https"):
        seen.append((ip, path, user_agent))
        status = 200 if path.endswith(".bak") else 404
        return {"status": status, "body": b"define('DB_PASSWORD', 'x');" if status == 200 else b"nope",
                "headers": {"X-Powered-By": "PHP/8.3.33", "Content-Type": "text/plain"}, "error": None, "elapsed_ms": 3}

    with patch.object(verify, "resolve_public", fake_resolve), patch.object(verify, "probe", fake_probe):
        result = await verify.verify_host("site.example.com", signature, main._ssrf_check,
                                          user_agent="UA-test", delay_between=0)

    assert result["resolved_ip"] == "8.8.8.8"  # IPv4 preferred when dual-stack
    assert result["resolver"] == "cloudflare-doh(1.1.1.1)"
    assert result["version_header"] == "PHP/8.3.33"
    assert seen and all(ip == "8.8.8.8" and ua == "UA-test" for ip, _path, ua in seen)
    kinds = {p["kind"] for p in result["probes"]}
    assert kinds == {"baseline", "canary", "suspect"}
    # Randomized canary was substituted
    assert not any("RANDOM" in p["path"] for p in result["probes"])
    bak = next(p for p in result["probes"] if p["path"].endswith("config.php.bak"))
    # "DB_PASSWORD" and "define\(.?DB_" both match the body: counts, never values
    assert bak["status"] == 200 and bak["secret_match_count"] == 2
    assert "body" not in json.dumps(result)
    assert "hunter" not in json.dumps(result) and "define(" not in json.dumps(result)


def test_doc_ranges_are_blocked_by_guard():
    """Regression note: TEST-NET addresses are special-purpose and must not be probed"""
    assert main._ssrf_check(["198.51.100.7"]) == main.SSRF_BLOCKED_MESSAGE


async def test_verify_falls_back_to_http_when_tls_refused(signature):
    schemes = []

    async def fake_resolve(hostname, client):
        return {"ips": ["8.8.8.8"], "resolver": "system", "error": None}

    async def fake_probe(client, hostname, ip, path, user_agent, max_bytes=0, scheme="https"):
        schemes.append(scheme)
        if scheme == "https":
            return {"status": 0, "body": None, "headers": {}, "error": "Connection failed or SSL error", "elapsed_ms": 1}
        return {"status": 404, "body": b"x", "headers": {}, "error": None, "elapsed_ms": 1}

    with patch.object(verify, "resolve_public", fake_resolve), patch.object(verify, "probe", fake_probe):
        result = await verify.verify_host("plain.example.com", signature, main._ssrf_check, delay_between=0)

    assert schemes[0] == "https" and set(schemes[1:]) == {"http"}
    assert result["scheme"] == "http"
    assert all(p["status"] == 404 and p["scheme"] == "http" for p in result["probes"])


async def test_verify_unresolvable_host_is_distinguishable_from_down(signature):
    async def fake_resolve(hostname, client):
        return {"ips": [], "resolver": None, "error": "public resolver returned no A/AAAA answers; system resolver also failed"}

    with patch.object(verify, "resolve_public", fake_resolve):
        result = await verify.verify_host("gone.example.com", signature, main._ssrf_check, delay_between=0)

    assert result["resolved_ip"] is None
    assert "resolver" in result["resolve_error"]
    assert result["probes"] == []


async def test_resolve_public_parses_doh_answers():
    class FakeResp:
        def __init__(self, payload):
            self.status_code = 200
            self._payload = payload

        def json(self):
            return self._payload

    class FakeClient:
        async def get(self, url, params=None, headers=None, timeout=None):
            if params["type"] == "A":
                return FakeResp({"Answer": [{"type": 5, "data": "cname.example.com."},
                                            {"type": 1, "data": "203.0.113.4"}]})
            return FakeResp({"Answer": [{"type": 28, "data": "2001:db8::4"}]})

    out = await verify.resolve_public("www.example.com", FakeClient())
    assert out["ips"] == ["203.0.113.4", "2001:db8::4"]
    assert out["resolver"] == verify.DOH_RESOLVER_LABEL


def test_reachability_still_uses_shared_guard():
    """Refactor regression: the reachability probe must route through _ssrf_check"""
    import inspect
    assert "_ssrf_check(ips)" in inspect.getsource(main.check_hostname_reachability)


# Stage 1 collector
def test_glob_to_like():
    assert collector.glob_to_like("*.php") == "%.php"
    assert collector.glob_to_like("/api/?.php") == "/api/_.php"
    assert collector.glob_to_like("100%_x") == "100\\%\\_x"


def test_query_builders_include_patterns_and_canaries(signature):
    start = datetime(2026, 10, 13)
    end = start + timedelta(days=1)
    q = collector.build_paths_query("zone1", start, end, signature)
    assert 'clientRequestPath_like: "%.php"' in q
    assert '"/phpinfo.php~"' in q and "/zz-RANDOM.php" not in q
    assert "originResponseStatus" in q and "clientRequestHTTPHost" in q
    ips = collector.build_ips_query("zone1", start, end, signature)
    assert "originResponseStatus_geq: 200" in ips and "clientIP" in ips
    assert "/phpinfo.php~" not in ips
    calls = collector.build_self_call_query("zone1", start, end, signature)
    assert 'clientRequestPath_in: ["/wp-cron.php"]' in calls


def test_extract_groups_handles_authz_and_errors():
    with pytest.raises(collector.GraphQLAuthzError):
        collector.extract_groups({"errors": [{"message": "no", "extensions": {"code": "authz"}}]})
    with pytest.raises(Exception):
        collector.extract_groups({"errors": [{"message": "boom"}]})
    assert collector.extract_groups({"data": {"viewer": {"zones": []}}}) == []


def graphql_fake(paths=None, ips=None, calls=None, settings=None):
    """Route canned responses by query shape so the collector can be driven offline"""
    async def fake(query, variables=None):
        def wrap(groups):
            return {"data": {"viewer": {"zones": [{collector.DATASET: groups}]}}}
        if "settings" in query:
            return {"data": {"viewer": {"zones": [{"settings": {collector.DATASET: settings or {}}}]}}}
        if "originResponseStatus_geq" in query:
            return wrap(ips or [])
        if "OR: [" not in query and "clientRequestPath_in" in query:
            return wrap(calls or [])
        return wrap(paths or [])
    return fake


def group(host, path, method="GET", edge=200, origin=200, count=1, ip=None, interval=1):
    dims = {"clientRequestHTTPHost": host, "clientRequestPath": path, "clientRequestHTTPMethodName": method,
            "edgeResponseStatus": edge, "originResponseStatus": origin}
    if ip:
        dims["clientIP"] = ip
    return {"count": count, "avg": {"sampleInterval": interval}, "dimensions": dims}


async def test_collector_sums_chunks_and_unions_ips(signature):
    fake = graphql_fake(
        paths=[group("Real.example.com", "/wp-login.php", count=5, interval=10)],
        ips=[{"count": 1, "dimensions": {"clientRequestHTTPHost": "real.example.com", "clientIP": "203.0.113.1"}},
             {"count": 1, "dimensions": {"clientRequestHTTPHost": "real.example.com", "clientIP": "104.21.9.9"}}],
        calls=[{"count": 2, "dimensions": {"clientRequestHTTPHost": "real.example.com", "clientRequestPath": "/wp-cron.php",
                                           "clientRequestHTTPMethodName": "POST", "clientIP": "203.0.113.37"}}],
        settings={"maxDuration": 86400, "notOlderThan": 7 * 86400, "maxPageSize": 10000},
    )
    c = collector.ExposureCollector(fake, signature, cf_ranges=["104.21.0.0/16"])
    end = datetime(2026, 10, 20)
    await c.collect_zone("z1", "example.com", end - timedelta(days=2), end)

    groups = c.groups()
    path_rows = [g for g in groups if g["kind"] == "path"]
    assert len(path_rows) == 1 and path_rows[0]["count"] == 10  # two daily chunks summed
    assert path_rows[0]["host"] == "real.example.com"           # host lowercased
    self_rows = [g for g in groups if g["kind"] == "self_call"]
    assert self_rows[0]["source_ip"] == "203.0.113.37" and self_rows[0]["count"] == 4
    assert c.host_stats()["real.example.com"] == {"distinct_ips_2xx": 2, "cf_range_ips_2xx": 1}
    assert c.sampled is True
    assert c.host_zone("real.example.com") == ("z1", "example.com")
    assert "estimates" in c.coverage_note()


async def test_collector_clamps_window_to_retention_and_notes_it(signature):
    seen_starts = []

    base = graphql_fake(settings={"notOlderThan": 86400})

    async def fake(query, variables=None):
        if "datetime_geq" in query:
            seen_starts.append(query.split('datetime_geq: "')[1][:20])
        return await base(query)

    c = collector.ExposureCollector(fake, signature)
    end = datetime(2026, 10, 20)
    await c.collect_zone("z1", "example.com", end - timedelta(days=7), end)
    assert all(s >= "2026-10-19T00:00:00Z" for s in seen_starts)
    assert any("retention" in n for n in c.notes)


async def test_collector_skips_zone_without_access(signature):
    async def fake(query, variables=None):
        if "settings" in query:
            return {"data": {"viewer": {"zones": [{"settings": {}}]}}}
        return {"errors": [{"message": "denied", "extensions": {"code": "authz"}}]}

    c = collector.ExposureCollector(fake, signature)
    await c.collect_zone("z1", "example.com", datetime(2026, 10, 19), datetime(2026, 10, 20))
    assert "example.com" in c.zone_errors and "no analytics access" in c.zone_errors["example.com"]
    assert "skipped" in c.coverage_note()


# Enrichment helpers
def test_parse_rdap_prefers_registrant():
    data = {"name": "GO-DADDY-COM-LLC", "handle": "NET-1",
            "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "GoDaddy.com, LLC"]]]}],
            "links": [{"href": "https://rdap.arin.net/registry/autnum/26496"}]}
    out = enrich.parse_rdap(data)
    assert out["provider"] == "GoDaddy.com, LLC" and out["asn"] == "26496"
    assert enrich.parse_rdap({"name": "SOME-NET"})["provider"] == "SOME-NET"


async def test_cloudflare_ranges_fallback_on_failure():
    class Boom:
        async def get(self, url):
            raise RuntimeError("offline")

        async def aclose(self):
            pass

    enrich._ranges_cache.update(fetched_at=0, ranges=None)
    ranges, note = await enrich.get_cloudflare_ranges(client=Boom(), force=True)
    assert "104.16.0.0/13" in ranges
    assert note and "fallback" in note
