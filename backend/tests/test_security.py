
from datetime import timedelta

import pytest

from app.core.security import (
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def test_password_hash_is_generated():
    password = "SentinelTest@2026"
    hashed = hash_password(password)

    assert hashed != password
    assert hashed.startswith("$argon2id$")


def test_correct_password_is_verified():
    password = "SentinelTest@2026"
    hashed = hash_password(password)

    assert verify_password(password, hashed) is True


def test_wrong_password_is_rejected():
    hashed = hash_password("SentinelTest@2026")

    assert verify_password("WrongPassword@2026", hashed) is False


def test_empty_password_is_rejected():
    with pytest.raises(ValueError):
        hash_password("")


def test_access_token_contains_subject():
    token = create_access_token({"sub": "sentinel-test"})
    payload = decode_access_token(token)

    assert payload["sub"] == "sentinel-test"
    assert "exp" in payload
    assert "iat" in payload


def test_invalid_token_is_rejected():
    with pytest.raises(TokenError):
        decode_access_token("invalid.sentinel.token")


def test_non_positive_token_expiry_is_rejected():
    with pytest.raises(ValueError):
        create_access_token(
            {"sub": "sentinel-test"},
            expires_delta=timedelta(seconds=0),
        )
