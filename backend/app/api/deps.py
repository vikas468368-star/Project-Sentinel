"""API dependency providers for Project Sentinel.

Provides authentication and authorization dependencies including JWT token
validation, user resolution, and account state checks.
"""

import uuid
from typing import Any, Dict

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import TokenError, decode_access_token
from app.models.user import User

# OAuth2 bearer token extractor pointing to the authentication login endpoint
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Validate bearer token and resolve the authenticated User.

    Args:
        token: Bearer JWT token from the Authorization header.
        db: Active SQLAlchemy database session.

    Returns:
        User: The authenticated SQLAlchemy User instance.

    Raises:
        HTTPException: 401 Unauthorized if the token is missing, invalid,
            expired, contains a malformed subject, or the user does not exist.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload: Dict[str, Any] = decode_access_token(token)
        if not isinstance(payload, dict):
            raise credentials_exception

        subject: Any = payload.get("sub")
        if not subject or not isinstance(subject, str) or not subject.strip():
            raise credentials_exception

        user_uuid = uuid.UUID(subject)
    except (TokenError, ValueError, TypeError):
        raise credentials_exception

    user = db.get(User, user_uuid)
    if user is None:
        raise credentials_exception

    return user


def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Verify that the authenticated user's account is active.

    Args:
        current_user: The authenticated User resolved by get_current_user.

    Returns:
        User: The active User instance.

    Raises:
        HTTPException: 403 Forbidden if the account is deactivated or inactive.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )
    return current_user
