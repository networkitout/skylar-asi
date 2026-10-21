"""Reachability checks: resolution, SSRF guard, pinning, redirect handling."""
import socket
from unittest.mock import MagicMock, patch

import main


def addrinfo(*ips):
    """Build a socket.getaddrinfo-style result for the given IPs"""
    result = []
    for ip in ips:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sockaddr = (ip, 0, 0, 0) if ":" in ip else (ip, 0)
        result.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
    return result


def ok_response(status_code=200, headers=None):
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    return response


async def test_ipv6_only_host_is_checked():
    calls = []

    async def fake_get(self, url, **kwargs):
        calls.append(url)
        return ok_response()

    with patch("socket.getaddrinfo", return_value=addrinfo("2001:4860:4860::8888")), \
         patch("httpx.AsyncClient.get", fake_get):
        result = await main.check_hostname_reachability("v6only.example.com")

    assert result["resolved_ip"] == "2001:4860:4860::8888"
    assert result["http_error"] is None
    assert result["http_status_code"] == 200
    # IPv6 literals must be bracketed in the URL
    assert all("[2001:4860:4860::8888]" in url for url in calls)


async def test_dual_stack_prefers_ipv4():
    async def fake_get(self, url, **kwargs):
        return ok_response()

    with patch("socket.getaddrinfo", return_value=addrinfo("2001:4860:4860::8888", "8.8.8.8")), \
         patch("httpx.AsyncClient.get", fake_get):
        result = await main.check_hostname_reachability("dual.example.com")

    assert result["resolved_ip"] == "8.8.8.8"


async def test_private_and_special_addresses_blocked():
    for blocked_ip in ("127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.10.10", "224.0.0.1", "::1", "0.0.0.0"):
        async def fail_get(self, url, **kwargs):
            raise AssertionError(f"request must not be sent for {url}")

        with patch("socket.getaddrinfo", return_value=addrinfo(blocked_ip)), \
             patch("httpx.AsyncClient.get", fail_get):
            result = await main.check_hostname_reachability("internal.example.com")

        assert result["http_error"] == "Access to private or local network resources is blocked.", blocked_ip
        assert result["http_status_code"] is None


async def test_mixed_public_and_private_answers_blocked():
    async def fail_get(self, url, **kwargs):
        raise AssertionError("request must not be sent")

    with patch("socket.getaddrinfo", return_value=addrinfo("8.8.8.8", "10.0.0.5")), \
         patch("httpx.AsyncClient.get", fail_get):
        result = await main.check_hostname_reachability("sneaky.example.com")

    assert result["https_error"] == "Access to private or local network resources is blocked."


async def test_redirect_recorded_as_reachable_with_location():
    async def fake_get(self, url, **kwargs):
        return ok_response(301, {"location": "https://www.example.com/"})

    with patch("socket.getaddrinfo", return_value=addrinfo("8.8.8.8")), \
         patch("httpx.AsyncClient.get", fake_get):
        result = await main.check_hostname_reachability("example.com")

    assert result["http_status_code"] == 301
    assert result["http_error"] is None
    assert result["http_redirect_location"] == "https://www.example.com/"
    assert result["https_redirect_location"] == "https://www.example.com/"


async def test_unresolvable_hostname():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror(socket.EAI_NONAME, "no such host")):
        result = await main.check_hostname_reachability("nope.invalid")

    assert result["http_error"] == "Could not resolve hostname."
    assert result["resolved_ip"] is None


async def test_https_pins_ip_and_presents_sni_hostname():
    seen = {}

    async def fake_get(self, url, **kwargs):
        if url.startswith("https://"):
            seen["url"] = url
            seen["extensions"] = kwargs.get("extensions")
            seen["host_header"] = (kwargs.get("headers") or {}).get("Host")
        return ok_response()

    with patch("socket.getaddrinfo", return_value=addrinfo("8.8.8.8")), \
         patch("httpx.AsyncClient.get", fake_get):
        await main.check_hostname_reachability("pinned.example.com")

    # Connects to the validated IP, not the hostname (no second DNS lookup)
    assert seen["url"].startswith("https://8.8.8.8")
    assert seen["extensions"] == {"sni_hostname": "pinned.example.com"}
    assert seen["host_header"] == "pinned.example.com"


def test_wildcard_records_excluded_from_background_run(db, monkeypatch):
    """Wildcard names are not resolvable hostnames; probing them would record
    phantom DNS failures and skew the error stats."""
    db.add(main.Zone(zone_id="z1", name="a.com"))
    db.add(main.DNSRecord(record_id="r1", zone_id="z1", name="www.a.com", type="A", content="192.0.2.1"))
    db.add(main.DNSRecord(record_id="r2", zone_id="z1", name="*.a.com", type="A", content="192.0.2.1"))
    db.commit()

    checked = []

    async def fake_check(hostname, timeout=10.0):
        checked.append(hostname)
        return {
            "resolved_ip": "192.0.2.1",
            "http_status_code": 200, "https_status_code": 200,
            "http_response_time_ms": 5, "https_response_time_ms": 5,
            "http_error": None, "https_error": None,
            "http_redirect_location": None, "https_redirect_location": None,
        }

    monkeypatch.setattr(main, "check_hostname_reachability", fake_check)
    main.run_reachability_in_background(None, user_id=1, ip_address=None)

    assert checked == ["www.a.com"]
    assert [c.hostname for c in db.query(main.ReachabilityCheck).all()] == ["www.a.com"]


def test_history_endpoint_returns_ascending(client, db, admin_user, auth_headers):
    from datetime import datetime, timedelta
    db.add(main.Zone(zone_id="z1", name="a.com"))
    db.add(main.DNSRecord(record_id="r1", zone_id="z1", name="www.a.com", type="A", content="192.0.2.1"))
    now = datetime.utcnow()
    for hours_ago, ms in ((3, 120), (1, 80), (2, 100)):
        db.add(main.ReachabilityCheck(
            dns_record_id="r1", zone_id="z1", hostname="www.a.com",
            http_status_code=200, http_response_time_ms=ms,
            checked_at=now - timedelta(hours=hours_ago),
        ))
    # Another record's checks must not leak in
    db.add(main.ReachabilityCheck(dns_record_id="r2", zone_id="z1", hostname="other.a.com",
                                  checked_at=now))
    db.commit()

    resp = client.get("/api/reachability/history?dns_record_id=r1", headers=auth_headers)
    assert resp.status_code == 200
    times = [c["http_response_time_ms"] for c in resp.json()]
    assert times == [120, 100, 80]  # oldest first


def test_retention_prunes_old_checks(db, monkeypatch):
    from datetime import datetime, timedelta
    db.add(main.Zone(zone_id="z1", name="a.com"))
    db.add(main.DNSRecord(record_id="r1", zone_id="z1", name="www.a.com", type="A", content="192.0.2.1"))
    db.add(main.ReachabilityCheck(
        dns_record_id="r1", zone_id="z1", hostname="www.a.com",
        checked_at=datetime.utcnow() - timedelta(days=120),
    ))
    db.commit()

    async def fake_check(hostname, timeout=10.0):
        return {
            "resolved_ip": "192.0.2.1",
            "http_status_code": 200, "https_status_code": 200,
            "http_response_time_ms": 5, "https_response_time_ms": 5,
            "http_error": None, "https_error": None,
            "http_redirect_location": None, "https_redirect_location": None,
        }

    monkeypatch.setattr(main, "check_hostname_reachability", fake_check)
    monkeypatch.setattr(main, "REACHABILITY_RETENTION_DAYS", 90)
    main.run_reachability_in_background(None, user_id=1, ip_address=None)

    remaining = db.query(main.ReachabilityCheck).all()
    # The 120-day-old row is pruned; the fresh check from this run remains
    assert len(remaining) == 1
    assert remaining[0].http_status_code == 200
