"""Authentication service for Project Sentinel.

Handles user registration, credential authentication, audit logging,
and JWT token generation.
"""

from typing import Any, Dict

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password, verify_password
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.auth import Token, UserCreate, UserLogin

# Used to reduce login timing differences for unknown email addresses.
_DUMMY_PASSWORD_HASH = hash_password("sentinel-dummy-password-check")


def _record_login_failure(db: Session) -> None:
    """Record an unauthenticated login failure audit event without logging sensitive data.

    Never stores attempted email addresses, passwords, hashes, or tokens.
    Rolls back and propagates any database errors that occur.
    """
    try:
        failure_log = AuditLog(
            actor_user_id=None,
            action="user.login.failure",
            resource_type="user",
            resource_id=None,
            audit_metadata={},
        )
        db.add(failure_log)
        db.commit()
    except Exception:
        db.rollback()
        raise


def register_user(db: Session, user_in: UserCreate) -> User:
    """Register a new platform user and record a registration audit event.

    Args:
        db: Active SQLAlchemy database session.
        user_in: Validated user registration schema.

    Returns:
        User: The newly created and committed User ORM instance.

    Raises:
        HTTPException: 409 Conflict if the email address is already registered.
    """
    # 1. Pre-check for existing normalized email
    stmt = select(User).where(User.email == user_in.email)
    existing_user = db.execute(stmt).scalar_one_or_none()
    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # 2. Hash plaintext password with Argon2id
    hashed_password = hash_password(user_in.password)

    # 3. Create User instance
    user = User(
        full_name=user_in.full_name,
        email=user_in.email,
        password_hash=hashed_password,
        is_active=True,
    )
    db.add(user)

    try:
        # Flush to generate user.id for the audit entry within the same transaction
        db.flush()

        # 4. Create registration audit log in the same transaction
        audit_log = AuditLog(
            actor_user_id=user.id,
            action="user.register",
            resource_type="user",
            resource_id=str(user.id),
            audit_metadata={},
        )
        db.add(audit_log)

        db.commit()
        db.refresh(user)
        return user
    except IntegrityError as exc:
        db.rollback()
        diag = getattr(getattr(exc, "orig", None), "diag", None)
        constraint_name = getattr(diag, "constraint_name", None) if diag else None
        if constraint_name == "uq_users_email_lower":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )
        raise
    except Exception:
        db.rollback()
        raise


def authenticate_user(db: Session, credentials: UserLogin) -> User:
    """Authenticate user credentials, verify account state, and record audit logs.

    Args:
        db: Active SQLAlchemy database session.
        credentials: User login credentials containing normalized email and password.

    Returns:
        User: The authenticated SQLAlchemy User instance.

    Raises:
        HTTPException: 401 Unauthorized if email is not found or password verification fails.
        HTTPException: 403 Forbidden if the user account is inactive.
    """
    generic_401 = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Query user by normalized email (database exceptions are not caught as 401)
    stmt = select(User).where(User.email == credentials.email)
    user = db.execute(stmt).scalar_one_or_none()

    # 2. Constant-error verification: check user existence and password validity
    if user is None:
        verify_password(credentials.password, _DUMMY_PASSWORD_HASH)
        _record_login_failure(db)
        raise generic_401

    if not verify_password(credentials.password, user.password_hash):
        _record_login_failure(db)
        raise generic_401

    # 3. Enforce active account status after password verification
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )

    # 4. Record successful login audit event
    try:
        audit_log = AuditLog(
            actor_user_id=user.id,
            action="user.login.success",
            resource_type="user",
            resource_id=str(user.id),
            audit_metadata={},
        )
        db.add(audit_log)
        db.commit()
    except Exception:
        db.rollback()
        raise

    return user


def create_user_token(user: User) -> Token:
    """Generate a signed JWT access token for an authenticated user.

    Args:
        user: Authenticated SQLAlchemy User instance.

    Returns:
        Token: The OAuth2 compatible token schema containing the access_token.
    """
    token_str = create_access_token(data={"sub": str(user.id)})
    return Token(access_token=token_str, token_type="bearer")
