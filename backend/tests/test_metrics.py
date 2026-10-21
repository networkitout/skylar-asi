"""Traffic metrics: GraphQL parsing and aggregation semantics."""
from datetime import datetime, timedelta

import pytest

import main


def test_parse_analytics_response_buckets():
    response = {
        "data": {"viewer": {"zones": [{"httpRequests1hGroups": [
            {"dimensions": {"datetime": "2026-07-04T10:00:00Z"},
             "sum": {"requests": 5}, "uniq": {"uniques": 2}},
            {"dimensions": {"datetime": "2026-07-04T11:00:00Z"},
             "sum": {"requests": 7}, "uniq": {"uniques": 3}},
        ]}]}}
    }
    buckets = main.parse_analytics_response(response, "z1")
    assert [b["datetime"] for b in buckets] == ["2026-07-04T10:00:00Z", "2026-07-04T11:00:00Z"]
    assert buckets[0]["sum"]["requests"] == 5


def test_parse_analytics_response_authz_returns_empty():
    response = {"errors": [{"message": "denied", "extensions": {"code": "authz"}}]}
    assert main.parse_analytics_response(response, "z1") == []


def test_parse_analytics_response_no_zones_returns_empty():
    assert main.parse_analytics_response({"data": {"viewer": {"zones": []}}}, "z1") == []


@pytest.mark.parametrize("now", [
    datetime(2026, 10, 21, 2, 15, 24),   # mid-hour: the case Cloudflare rejected
    datetime(2026, 10, 21, 2, 0, 1),     # just past the hour
    datetime(2026, 10, 21, 2, 59, 59),   # worst case just before the next hour
])
def test_analytics_window_never_exceeds_lookback(now):
    hours = 72
    start, end = main.analytics_window(hours, now=now)

    assert end == now
    assert end - start <= timedelta(hours=hours)
    assert (start.minute, start.second, start.microsecond) == (0, 0, 0)
    # 72 hourly bucket starts fall in [start, end): the current partial hour
    # plus the 71 full hours before it
    assert start == datetime(2026, 10, 18, 3, 0, 0)
    bucket_starts = [start + timedelta(hours=i) for i in range(hours)]
    assert all(start <= b < end for b in bucket_starts)
    assert bucket_starts[-1] == now.replace(minute=0, second=0, microsecond=0)


def test_parse_analytics_response_raises_on_real_errors():
    with pytest.raises(Exception):
        main.parse_analytics_response({"errors": [{"message": "boom"}]}, "z1")


def insert_bucket(db, zone_id, hours_ago, requests=0, cached=0, bandwidth=0, threats=0, uniques=0,
                  http_status=None, content_type=None, country=None):
    ts = (datetime.utcnow() - timedelta(hours=hours_ago)).replace(minute=0, second=0, microsecond=0)
    db.add(main.TrafficMetric(
        zone_id=zone_id,
        timestamp=ts,
        requests_all=requests,
        requests_cached=cached,
        requests_uncached=requests - cached,
        bandwidth_all=bandwidth,
        threats_all=threats,
        uniques_all=uniques,
        http_status=http_status,
        content_type=content_type,
        country=country,
    ))


def test_aggregate_sums_buckets_and_peaks_uniques(client, db, admin_user, auth_headers):
    for zone_id in ("z1", "z2"):
        db.add(main.Zone(zone_id=zone_id, name=f"{zone_id}.com"))
    # z1: two hours of traffic; z2: one hour
    insert_bucket(db, "z1", 1, requests=100, cached=50, bandwidth=1000, threats=2, uniques=30)
    insert_bucket(db, "z1", 2, requests=200, cached=100, bandwidth=2000, threats=1, uniques=45)
    insert_bucket(db, "z2", 1, requests=50, cached=10, bandwidth=500, threats=0, uniques=10)
    # Outside the 24h window: must not count
    insert_bucket(db, "z1", 30, requests=99999, uniques=99999)
    db.commit()

    resp = client.get("/api/metrics/aggregate?hours=24", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["total_requests"] == 350
    assert data["total_cached"] == 160
    assert data["total_bandwidth"] == 3500
    assert data["total_threats"] == 3
    # Uniques: per-zone hourly peak summed across zones (45 + 10), NOT 30+45+10
    assert data["total_uniques"] == 55
    assert data["uniques_approximate"] is True
    assert data["cache_ratio"] == pytest.approx(160 / 350 * 100)


def test_aggregate_respects_zone_filter(client, db, admin_user, auth_headers):
    for zone_id in ("z1", "z2"):
        db.add(main.Zone(zone_id=zone_id, name=f"{zone_id}.com"))
    insert_bucket(db, "z1", 1, requests=100, cached=50, bandwidth=1000, threats=2, uniques=30)
    insert_bucket(db, "z2", 1, requests=50, cached=10, bandwidth=500, threats=1, uniques=10)
    db.commit()

    resp = client.get("/api/metrics/aggregate?hours=24&zone_id=z1", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_requests"] == 100
    assert data["total_bandwidth"] == 1000
    assert data["total_threats"] == 2
    assert data["total_uniques"] == 30


def test_breakdown_merges_json_maps(client, db, admin_user, auth_headers):
    db.add(main.Zone(zone_id="z1", name="z1.com"))
    db.add(main.Zone(zone_id="z2", name="z2.com"))
    insert_bucket(db, "z1", 1, http_status={"200": 90, "404": 10}, country={"US": 70}, content_type={"html": 60})
    insert_bucket(db, "z1", 2, http_status={"200": 50, "500": 5}, country={"US": 30, "DE": 20}, content_type=None)
    insert_bucket(db, "z2", 1, http_status={"200": 10}, country={"FR": 10}, content_type={"json": 10})
    # Outside window
    insert_bucket(db, "z1", 30, http_status={"200": 99999})
    db.commit()

    resp = client.get("/api/metrics/breakdown?hours=24", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["http_status"] == {"200": 150, "404": 10, "500": 5}
    assert data["country"] == {"US": 100, "DE": 20, "FR": 10}
    assert data["content_type"] == {"html": 60, "json": 10}

    # Zone-scoped
    resp = client.get("/api/metrics/breakdown?hours=24&zone_id=z2", headers=auth_headers)
    assert resp.json()["http_status"] == {"200": 10}


def test_metrics_list_reports_full_total(client, db, admin_user, auth_headers):
    db.add(main.Zone(zone_id="z1", name="z1.com"))
    for h in range(5):
        insert_bucket(db, "z1", h + 1, requests=10)
    db.commit()

    resp = client.get("/api/metrics?hours=24&page=1&page_size=2", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 5
    assert len(body["data"]) == 2
