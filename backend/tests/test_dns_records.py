"""DNS records endpoint: server-side pagination, filtering, search, sorting."""
import main


def seed_records(db):
    db.add(main.Zone(zone_id="z1", name="alpha.com"))
    db.add(main.Zone(zone_id="z2", name="beta.com"))
    rows = [
        ("r1", "z1", "api.alpha.com", "A", "192.0.2.1", True),
        ("r2", "z1", "www.alpha.com", "CNAME", "alpha.com", True),
        ("r3", "z1", "Mail.alpha.com", "MX", "mx.alpha.com", False),
        ("r4", "z2", "beta.com", "A", "192.0.2.50", False),
        ("r5", "z2", "txt.beta.com", "TXT", "v=spf1 -all", False),
    ]
    for record_id, zone_id, name, rtype, content, proxied in rows:
        db.add(main.DNSRecord(record_id=record_id, zone_id=zone_id, name=name,
                              type=rtype, content=content, proxied=proxied, ttl=300))
    db.commit()


def test_pagination_and_total(client, db, admin_user, auth_headers):
    seed_records(db)
    resp = client.get("/api/dns-records?page=1&page_size=2", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 5
    assert len(body["data"]) == 2

    resp2 = client.get("/api/dns-records?page=3&page_size=2", headers=auth_headers)
    assert len(resp2.json()["data"]) == 1


def test_filters_and_search(client, db, admin_user, auth_headers):
    seed_records(db)
    resp = client.get("/api/dns-records?record_type=A&proxied=true", headers=auth_headers)
    body = resp.json()
    assert body["total"] == 1
    assert body["data"][0]["record_id"] == "r1"

    # Search matches name OR content, case-insensitively
    resp = client.get("/api/dns-records?q=SPF1", headers=auth_headers)
    assert [r["record_id"] for r in resp.json()["data"]] == ["r5"]


def test_sort_case_insensitive_and_zone_name(client, db, admin_user, auth_headers):
    seed_records(db)
    resp = client.get("/api/dns-records?sort_by=name&sort_order=asc", headers=auth_headers)
    names = [r["name"] for r in resp.json()["data"]]
    # "Mail.alpha.com" must not sort before lowercase names just for its case
    assert names == ["api.alpha.com", "beta.com", "Mail.alpha.com", "txt.beta.com", "www.alpha.com"]

    resp = client.get("/api/dns-records?sort_by=zone_name&sort_order=desc", headers=auth_headers)
    zone_names = [r["zone_name"] for r in resp.json()["data"]]
    assert zone_names[0] == "beta.com" and zone_names[-1] == "alpha.com"


def test_unknown_sort_falls_back_to_name(client, db, admin_user, auth_headers):
    seed_records(db)
    resp = client.get("/api/dns-records?sort_by=evil_column", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 5
