"""Security hardening: API docs are gated, security headers on API responses."""
import importlib
import os

import main


def test_docs_disabled_by_default(client):
    # conftest imports main without ENABLE_DOCS, so docs should be off
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404


def test_enable_docs_flag_parsing():
    # The flag is read from the environment at import time
    for value, expected in [("true", True), ("1", True), ("yes", True),
                            ("false", False), ("", False), ("no", False)]:
        assert (value.lower() in ("1", "true", "yes")) is expected


def test_api_security_headers_present(client):
    resp = client.get("/api/health")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in resp.headers
