"""Startup rejects missing configuration before opening a database connection."""
import os
from pathlib import Path
import secrets
import subprocess
import sys

import pytest


@pytest.mark.parametrize("value", [None, "", "   "])
def test_database_url_required(value):
    env = dict(os.environ, SECRET_KEY=secrets.token_urlsafe(32))
    env.pop("DATABASE_URL", None)
    if value is not None:
        env["DATABASE_URL"] = value
    result = subprocess.run(
        [sys.executable, "-c", "import main"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "DATABASE_URL environment variable must be set!" in result.stderr


def test_signing_key_required_with_explicit_database_url():
    env = dict(os.environ, DATABASE_URL="sqlite:///:memory:")
    env.pop("SECRET_KEY", None)
    result = subprocess.run(
        [sys.executable, "-c", "import main"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "SECRET_KEY environment variable must be set!" in result.stderr
