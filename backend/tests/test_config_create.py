"""POST /api/configs: token verification gives actionable, non-leaking errors."""
import httpx

import main


VALID_TOKEN = "a" * 40
GLOBAL_API_KEY = "c2547eb745079dac9320b638f5e225cf483cc"


class FakeClient:
    def __init__(self, outcome):
        self._outcome = outcome

    async def verify_token(self):
        if isinstance(self._outcome, Exception):
            raise self._outcome
        return self._outcome


def http_error(status_code, body):
    request = httpx.Request("GET", "https://api.cloudflare.com/client/v4/user/tokens/verify")
    response = httpx.Response(status_code, text=body, request=request)
    return httpx.HTTPStatusError("rejected", request=request, response=response)


def post_config(client, auth_headers, token, name="cfg"):
    return client.post("/api/configs", json={"name": name, "api_token": token}, headers=auth_headers)


def install_fake(monkeypatch, outcome, seen):
    def factory(token):
        seen.append(token)
        return FakeClient(outcome)
    monkeypatch.setattr(main, "CloudflareClient", factory)


def test_active_token_is_stored_stripped(client, auth_headers, db, monkeypatch):
    seen = []
    install_fake(monkeypatch, {"success": True, "result": {"status": "active"}}, seen)

    resp = post_config(client, auth_headers, f"  {VALID_TOKEN}\n")

    assert resp.status_code == 200, resp.text
    assert seen == [VALID_TOKEN]
    stored = db.query(main.CloudflareConfig).one()
    assert main.decrypt_token(stored.api_token) == VALID_TOKEN


def test_global_api_key_rejected_before_calling_cloudflare(client, auth_headers, db, monkeypatch):
    seen = []
    install_fake(monkeypatch, {"success": True, "result": {"status": "active"}}, seen)

    resp = post_config(client, auth_headers, GLOBAL_API_KEY)

    assert resp.status_code == 400
    assert "Global API Key" in resp.json()["detail"]
    assert seen == []
    assert db.query(main.CloudflareConfig).count() == 0


def test_cloudflare_rejection_does_not_leak_upstream_body(client, auth_headers, db, monkeypatch):
    upstream_body = '{"errors":[{"code":6111,"message":"Invalid format for Authorization header"}]}'
    install_fake(monkeypatch, http_error(400, upstream_body), [])

    resp = post_config(client, auth_headers, VALID_TOKEN)

    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert "rejected" in detail
    assert "6111" not in detail
    assert "Authorization header" not in detail
    assert db.query(main.CloudflareConfig).count() == 0


def test_network_failure_is_distinguished_from_rejection(client, auth_headers, db, monkeypatch):
    install_fake(monkeypatch, httpx.ConnectError("name resolution failed"), [])

    resp = post_config(client, auth_headers, VALID_TOKEN)

    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert "Could not reach" in detail
    assert "name resolution" not in detail
    assert db.query(main.CloudflareConfig).count() == 0


def test_inactive_token_status_is_reported(client, auth_headers, db, monkeypatch):
    install_fake(monkeypatch, {"success": True, "result": {"status": "expired"}}, [])

    resp = post_config(client, auth_headers, VALID_TOKEN)

    assert resp.status_code == 400
    assert "expired" in resp.json()["detail"]
    assert db.query(main.CloudflareConfig).count() == 0
