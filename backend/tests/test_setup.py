"""First-run setup: initial admin creation via the API."""
import main
from conftest import ADMIN_PASSWORD

SETUP_PAYLOAD = {
    "email": "owner@example.com",
    "username": "owner",
    "full_name": "The Owner",
    "password": "FirstAdmin123!x",
}


def test_setup_status_true_on_empty_database(client):
    resp = client.get("/api/setup/status")
    assert resp.status_code == 200
    assert resp.json() == {"needs_setup": True}


def test_setup_creates_admin_and_logs_in(client, db):
    resp = client.post("/api/setup/admin", json=SETUP_PAYLOAD)
    assert resp.status_code == 200
    token = resp.json()["access_token"]

    # The created user is an active admin
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    body = me.json()
    assert body["username"] == "owner"
    assert body["is_admin"] is True
    assert body["is_active"] is True

    # Normal login works with the chosen credentials
    login = client.post("/api/auth/login", json={"username": "owner", "password": SETUP_PAYLOAD["password"]})
    assert login.status_code == 200

    # Setup is now finished and audited
    assert client.get("/api/setup/status").json() == {"needs_setup": False}
    assert db.query(main.AuditLog).filter(main.AuditLog.action == "SETUP_ADMIN_CREATED").count() == 1


def test_setup_disabled_once_any_user_exists(client, admin_user):
    assert client.get("/api/setup/status").json() == {"needs_setup": False}
    resp = client.post("/api/setup/admin", json=SETUP_PAYLOAD)
    assert resp.status_code == 403


def test_setup_rejects_weak_password(client):
    weak = dict(SETUP_PAYLOAD, password="weak")
    resp = client.post("/api/setup/admin", json=weak)
    assert resp.status_code == 422
    # Nothing was created, setup still pending
    assert client.get("/api/setup/status").json() == {"needs_setup": True}
