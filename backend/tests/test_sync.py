"""Sync correctness: upsert idempotency, config scoping, stale-data deletion."""
import asyncio

import main


def make_zone(zone_id, name):
    return {"id": zone_id, "name": name, "status": "active"}


def make_record(record_id, name):
    return {"id": record_id, "name": name, "type": "A", "content": "192.0.2.1"}


SETTINGS_RESPONSE = {"result": [{"id": "waf", "value": "on"}, {"id": "ssl", "value": "full"}]}

ANALYTICS_BUCKETS = [
    {
        "datetime": "2026-07-04T10:00:00Z",
        "sum": {"requests": 100, "cachedRequests": 40, "bytes": 5000, "cachedBytes": 2000,
                "threats": 1, "pageViews": 80, "encryptedRequests": 90,
                "responseStatusMap": [{"edgeResponseStatus": 200, "requests": 90},
                                       {"edgeResponseStatus": 404, "requests": 10}],
                "countryMap": [{"clientCountryName": "US", "requests": 70},
                                {"clientCountryName": "DE", "requests": 30}],
                "contentTypeMap": [{"edgeResponseContentTypeName": "html", "requests": 60}]},
        "uniq": {"uniques": 25},
    },
    {
        "datetime": "2026-07-04T11:00:00Z",
        "sum": {"requests": 200, "cachedRequests": 90, "bytes": 9000, "cachedBytes": 4000,
                "threats": 0, "pageViews": 150, "encryptedRequests": 180},
        "uniq": {"uniques": 40},
    },
]


class FakeClient:
    def __init__(self, zones, records_by_zone, settings=SETTINGS_RESPONSE, analytics=None):
        self._zones = zones
        self._records = records_by_zone
        self._settings = settings
        self._analytics = analytics or []

    async def list_all_zones(self):
        return self._zones

    async def list_all_dns_records(self, zone_id):
        return self._records.get(zone_id, [])

    async def get_zone_settings(self, zone_id):
        if isinstance(self._settings, Exception):
            raise self._settings
        return self._settings

    async def get_zone_analytics(self, zone_id, hours=24):
        return self._analytics


def run_sync(db, config, fake_client, monkeypatch):
    monkeypatch.setattr(main, "CloudflareClient", lambda token: fake_client)
    asyncio.run(main.sync_cloudflare_data(db, config))


def add_config(db, name):
    config = main.CloudflareConfig(name=name, api_token=main.encrypt_token(f"token-{name}"))
    db.add(config)
    db.commit()
    db.refresh(config)
    return config


def test_sync_is_idempotent(db, monkeypatch):
    config = add_config(db, "cfg")
    client = FakeClient(
        [make_zone("z1", "example.com")],
        {"z1": [make_record("r1", "example.com"), make_record("r2", "www.example.com")]},
        analytics=ANALYTICS_BUCKETS,
    )

    for _ in range(3):
        run_sync(db, config, client, monkeypatch)

    assert db.query(main.Zone).count() == 1
    assert db.query(main.DNSRecord).count() == 2
    assert db.query(main.SecuritySetting).count() == 2
    # One row per hourly bucket, not per sync
    assert db.query(main.TrafficMetric).count() == 2

    metric = db.query(main.TrafficMetric).order_by(main.TrafficMetric.timestamp).first()
    assert metric.requests_all == 100
    assert metric.requests_uncached == 60
    assert metric.ssl_unencrypted == 10
    # Breakdown maps are stored as {dimension: requests}
    assert metric.http_status == {"200": 90, "404": 10}
    assert metric.country == {"US": 70, "DE": 30}
    assert metric.content_type == {"html": 60}


def test_stale_zone_and_record_deleted(db, monkeypatch):
    config = add_config(db, "cfg")
    run_sync(db, config, FakeClient(
        [make_zone("z1", "a.com"), make_zone("z2", "b.com")],
        {"z1": [make_record("r1", "a.com"), make_record("r2", "www.a.com")],
         "z2": [make_record("r3", "b.com")]},
    ), monkeypatch)
    assert db.query(main.Zone).count() == 2
    assert db.query(main.DNSRecord).count() == 3

    # z2 and r2 disappear from Cloudflare
    run_sync(db, config, FakeClient(
        [make_zone("z1", "a.com")],
        {"z1": [make_record("r1", "a.com")]},
    ), monkeypatch)

    assert [z.zone_id for z in db.query(main.Zone).all()] == ["z1"]
    assert [r.record_id for r in db.query(main.DNSRecord).all()] == ["r1"]
    # Children of the deleted zone are gone too
    assert db.query(main.SecuritySetting).filter_by(zone_id="z2").count() == 0


def test_configs_do_not_delete_each_others_zones(db, monkeypatch):
    config_a = add_config(db, "a")
    config_b = add_config(db, "b")

    run_sync(db, config_a, FakeClient([make_zone("zA", "a.com")], {"zA": [make_record("rA", "a.com")]}), monkeypatch)
    run_sync(db, config_b, FakeClient([make_zone("zB", "b.com")], {"zB": [make_record("rB", "b.com")]}), monkeypatch)

    zones = {z.zone_id: z.config_id for z in db.query(main.Zone).all()}
    assert zones == {"zA": config_a.id, "zB": config_b.id}

    # Re-syncing config A must not touch config B's zone
    run_sync(db, config_a, FakeClient([make_zone("zA", "a.com")], {"zA": [make_record("rA", "a.com")]}), monkeypatch)
    assert sorted(z.zone_id for z in db.query(main.Zone).all()) == ["zA", "zB"]


def test_settings_survive_failed_settings_fetch(db, monkeypatch):
    config = add_config(db, "cfg")
    run_sync(db, config, FakeClient([make_zone("z1", "a.com")], {"z1": []}), monkeypatch)
    assert db.query(main.SecuritySetting).count() == 2

    # Settings fetch fails transiently: existing settings must not be wiped
    run_sync(db, config, FakeClient([make_zone("z1", "a.com")], {"z1": []},
                                    settings=Exception("boom")), monkeypatch)
    assert db.query(main.SecuritySetting).count() == 2

    # A setting genuinely removed upstream is deleted
    run_sync(db, config, FakeClient([make_zone("z1", "a.com")], {"z1": []},
                                    settings={"result": [{"id": "waf", "value": "on"}]}), monkeypatch)
    assert [s.setting_name for s in db.query(main.SecuritySetting).all()] == ["waf"]


def test_security_setting_enabled_classification():
    cases = [
        ("waf", "on", True),
        ("waf", "off", False),
        ("security_level", "essentially_off", False),
        ("security_level", "high", True),
        ("minify", {"css": "off", "html": "off", "js": "off"}, False),
        ("minify", {"css": "on", "html": "off", "js": "off"}, True),
        ("challenge_ttl", 1800, True),
        ("ssl", None, False),
        ("ssl", "", False),
    ]
    for name, value, expected in cases:
        assert main.is_security_setting_enabled(name, value) is expected, (name, value)
