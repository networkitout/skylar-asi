import os
import sys
import tempfile

# main.py validates SECRET_KEY and connects to the database at import time,
# so the environment must be prepared before it is imported.
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-pytest")
_tmpdir = tempfile.mkdtemp(prefix="skylar-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmpdir}/test.db"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture(autouse=True)
def clean_state():
    """Empty every table and reset in-memory state before each test"""
    session = main.SessionLocal()
    try:
        for table in reversed(main.Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()
    finally:
        session.close()
    main.invalidate_stats_cache()
    try:
        main.app.state.limiter.reset()
    except Exception:
        pass
    yield


@pytest.fixture()
def db():
    session = main.SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client():
    # No context manager: skip lifespan so tests control their own users
    return TestClient(main.app)


ADMIN_PASSWORD = "AdminPass123!x"


@pytest.fixture()
def admin_user(db):
    user = main.User(
        email="admin@test.local",
        username="admin",
        hashed_password=main.get_password_hash(ADMIN_PASSWORD),
        full_name="Test Admin",
        is_admin=True,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture()
def auth_headers(admin_user):
    token = main.create_access_token({"sub": admin_user.username})
    return {"Authorization": f"Bearer {token}"}
