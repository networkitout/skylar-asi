"""Token encryption: configured salt, legacy-salt fallback, startup re-encryption."""
import pytest
from cryptography.fernet import InvalidToken

import main


@pytest.fixture
def legacy_row(db, monkeypatch):
    """A config whose token was stored before ENCRYPTION_SALT was configured."""
    monkeypatch.delenv("ENCRYPTION_SALT", raising=False)
    config = main.CloudflareConfig(name="old", api_token=main.encrypt_token("cf-token-123"))
    db.add(config)
    db.commit()
    db.refresh(config)
    return config


def test_decrypt_falls_back_to_legacy_salt_when_salt_is_newly_configured(db, legacy_row, monkeypatch):
    monkeypatch.setenv("ENCRYPTION_SALT", "a-brand-new-salt")
    assert main.decrypt_token(legacy_row.api_token) == "cf-token-123"
    # ...but a token that matches neither key still fails loudly
    with pytest.raises(InvalidToken):
        main.decrypt_token(main.encrypt_token("x")[:-4] + "AAAA")


def test_startup_reencrypts_legacy_rows_with_the_configured_salt(db, legacy_row, monkeypatch):
    monkeypatch.setenv("ENCRYPTION_SALT", "a-brand-new-salt")
    before = legacy_row.api_token
    assert main.reencrypt_legacy_tokens(db) == 1
    db.refresh(legacy_row)
    assert legacy_row.api_token != before
    # now decrypts with the configured key directly, no fallback needed
    assert main.get_encryption_key().decrypt(legacy_row.api_token.encode()).decode() == "cf-token-123"
    # idempotent
    assert main.reencrypt_legacy_tokens(db) == 0


def test_reencrypt_is_a_noop_without_a_configured_salt(db, legacy_row, monkeypatch):
    monkeypatch.delenv("ENCRYPTION_SALT", raising=False)
    assert main.reencrypt_legacy_tokens(db) == 0


def test_blank_env_values_fall_back_to_defaults(monkeypatch):
    monkeypatch.setenv("SYNC_INTERVAL_MINUTES", "")
    monkeypatch.setenv("EXPOSURE_VERIFY_DELAY_SECONDS", "   ")
    monkeypatch.setenv("ALLOWED_ORIGINS", " https://skylar.example.com , ")
    assert main._env_int("SYNC_INTERVAL_MINUTES", 60) == 60
    assert main._env_float("EXPOSURE_VERIFY_DELAY_SECONDS", 0.25) == 0.25
    assert main._env_int("NOT_SET_AT_ALL", 7) == 7
    origins = [o.strip() for o in main._env_str("ALLOWED_ORIGINS", "x").split(",") if o.strip()]
    assert origins == ["https://skylar.example.com"]
