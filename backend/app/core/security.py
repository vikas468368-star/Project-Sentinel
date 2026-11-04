"""Security utilities for Project Sentinel.

Provides Argon2id password hashing and PyJWT token generation and verification.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
import jwt

from app.core.config import settings


class TokenError(ValueError):
    """Exception raised when a JWT token is invalid, expired, or cannot be decoded."""

    pass


# Default PasswordHasher uses Argon2id with RFC 9106 recommended parameters
_password_hasher = PasswordHasher()


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using Argon2id.

    Args:
        plain_password: The plaintext password to hash.

    Returns:
        str: The encoded Argon2id password hash.

    Raises:
        ValueError: If plain_password is empty.
    """
    if not plain_password:
        raise ValueError("Password cannot be empty.")
    return _password_hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against an Argon2id hash.

    Args:
        plain_password: The candidate plaintext password.
        hashed_password: The stored Argon2id hash string.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return _password_hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token.

    Args:
        data: Payload claims dictionary to encode into the token.
        expires_delta: Optional custom token expiration delta.

    Returns:
        str: The signed JWT string.

    Raises:
        ValueError: If JWT_SECRET_KEY is empty or unconfigured.
    """
    if not settings.JWT_SECRET_KEY:
        raise ValueError("JWT_SECRET_KEY is not configured.")

    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta is not None:
        if expires_delta.total_seconds() <= 0:
            raise ValueError("Token expiry must be greater than zero.")
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and validate a signed JWT access token.

    Args:
        token: The encoded JWT token string.

    Returns:
        dict: The decoded token claims payload.

    Raises:
        ValueError: If JWT_SECRET_KEY is empty or unconfigured.
        TokenError: If the token signature is invalid, expired, or malformed.
    """
    if not settings.JWT_SECRET_KEY:
        raise ValueError("JWT_SECRET_KEY is not configured.")

    try:
        payload: Dict[str, Any] = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise TokenError("Token has expired.")
    except jwt.PyJWTError:
        raise TokenError("Invalid token.")
