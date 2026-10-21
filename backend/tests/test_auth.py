"""Auth flow: login, token validation, inactive accounts, change-password."""
import main
from conftest import ADMIN_PASSWORD


def test_login_success_and_me(client, admin_user):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert resp.status_code == 200
    token = resp.json()["access_token"]

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["username"] == "admin"


def test_login_wrong_password(client, admin_user):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "WrongPass123!x"})
    assert resp.status_code == 401


def test_requests_without_token_rejected(client):
    assert client.get("/api/zones").status_code in (401, 403)


def test_inactive_user_rejected(client, db):
    user = main.User(
        email="ghost@test.local",
        username="ghost",
        hashed_password=main.get_password_hash(ADMIN_PASSWORD),
        is_admin=False,
        is_active=False,
    )
    db.add(user)
    db.commit()

    # Login is refused outright
    resp = client.post("/api/auth/login", json={"username": "ghost", "password": ADMIN_PASSWORD})
    assert resp.status_code == 403

    # A token minted before deactivation is also refused
    token = main.create_access_token({"sub": "ghost"})
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_change_password_happy_path(client, db, admin_user, auth_headers):
    new_password = "BrandNewPass1!x"
    resp = client.post(
        "/api/auth/change-password",
        json={"old_password": ADMIN_PASSWORD, "new_password": new_password},
        headers=auth_headers,
    )
    assert resp.status_code == 200

    # Old password no longer works, new one does
    assert client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": new_password}).status_code == 200

    # The change is audit-logged
    assert db.query(main.AuditLog).filter(main.AuditLog.action == "PASSWORD_CHANGED").count() == 1


def test_change_password_rejects_weak_password(client, admin_user, auth_headers):
    resp = client.post(
        "/api/auth/change-password",
        json={"old_password": ADMIN_PASSWORD, "new_password": "short"},
        headers=auth_headers,
    )
    assert resp.status_code == 422


def test_change_password_rejects_wrong_old_password(client, admin_user, auth_headers):
    resp = client.post(
        "/api/auth/change-password",
        json={"old_password": "NotTheRealOne1!", "new_password": "BrandNewPass1!x"},
        headers=auth_headers,
    )
    assert resp.status_code == 400
