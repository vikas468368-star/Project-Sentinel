"""Service-level unit and integration tests for app.services.auth_service.

Tests registration, duplicate email handling, credential authentication,
account state checks, token creation, and transaction rollback mechanics.
"""

import uuid
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.auth import UserCreate, UserLogin
from app.services.auth_service import (
    _record_login_failure,
    authenticate_user,
    create_user_token,
    register_user,
)


def _unique_email(prefix: str = "svc") -> str:
    """Generate a unique email address for test isolation."""
    return f"{prefix}_{uuid.uuid4().hex[:8]}@example.com"


def test_register_user_success(db: Session):
    """register_user creates a user record and an audit log in a single transaction."""
    email = _unique_email("reg_svc")
    user_in = UserCreate(
        full_name="Service Test User",
        email=email,
        password="SecurePassword123!",
    )

    user = register_user(db, user_in)
    assert user.id is not None
    assert user.email == email.lower()
    assert user.full_name == "Service Test User"
    assert user.is_active is True
    assert user.password_hash.startswith("$argon2id$")

    # Verify registration audit log
    stmt = select(AuditLog).where(
        AuditLog.action == "user.register",
        AuditLog.actor_user_id == user.id,
    )
    log = db.execute(stmt).scalar_one_or_none()
    assert log is not None
    assert log.resource_type == "user"
    assert log.resource_id == str(user.id)


def test_register_user_duplicate_email_precheck(db: Session):
    """register_user rejects existing email via pre-check with HTTP 409."""
    email = _unique_email("dup_pre")
    user_in = UserCreate(
        full_name="Original User",
        email=email,
        password="SecurePassword123!",
    )
    register_user(db, user_in)

    duplicate_in = UserCreate(
        full_name="Duplicate User",
        email=email,
        password="AnotherPassword123!",
    )
    with pytest.raises(HTTPException) as exc_info:
        register_user(db, duplicate_in)

    assert exc_info.value.status_code == status.HTTP_409_CONFLICT
    assert exc_info.value.detail == "Email already registered"


def test_register_user_unique_constraint_conflict(db: Session, monkeypatch: pytest.MonkeyPatch):
    """register_user catches PostgreSQL uq_users_email_lower constraint and raises HTTP 409."""
    email = _unique_email("race_dup")
    user_in = UserCreate(
        full_name="Race User",
        email=email,
        password="SecurePassword123!",
    )

    # Simulate race condition where pre-check passed but commit hits unique constraint
    orig_mock = MagicMock()
    diag_mock = MagicMock()
    diag_mock.constraint_name = "uq_users_email_lower"
    orig_mock.diag = diag_mock
    simulated_integrity_error = IntegrityError("duplicate key", params=None, orig=orig_mock)

    def mock_commit():
        raise simulated_integrity_error

    monkeypatch.setattr(db, "commit", mock_commit)

    with pytest.raises(HTTPException) as exc_info:
        register_user(db, user_in)

    assert exc_info.value.status_code == status.HTTP_409_CONFLICT
    assert exc_info.value.detail == "Email already registered"


def test_register_user_unrelated_integrity_error_reraises(db: Session, monkeypatch: pytest.MonkeyPatch):
    """register_user rolls back and re-raises non-email IntegrityError exceptions."""
    email = _unique_email("other_integ")
    user_in = UserCreate(
        full_name="Other Integ User",
        email=email,
        password="SecurePassword123!",
    )

    orig_mock = MagicMock()
    diag_mock = MagicMock()
    diag_mock.constraint_name = "some_foreign_key_constraint"
    orig_mock.diag = diag_mock
    simulated_error = IntegrityError("fk violation", params=None, orig=orig_mock)

    def mock_commit():
        raise simulated_error

    rollback_called = False
    original_rollback = db.rollback

    def tracking_rollback():
        nonlocal rollback_called
        rollback_called = True
        original_rollback()

    monkeypatch.setattr(db, "commit", mock_commit)
    monkeypatch.setattr(db, "rollback", tracking_rollback)

    with pytest.raises(IntegrityError):
        register_user(db, user_in)

    assert rollback_called is True


def test_authenticate_user_success(db: Session):
    """authenticate_user succeeds with valid credentials and logs user.login.success."""
    email = _unique_email("auth_ok")
    password = "CorrectPassword123!"
    registered = register_user(
        db,
        UserCreate(full_name="Auth Success User", email=email, password=password),
    )

    credentials = UserLogin(email=email, password=password)
    authenticated = authenticate_user(db, credentials)

    assert authenticated.id == registered.id
    assert authenticated.email == registered.email

    # Verify audit log
    stmt = select(AuditLog).where(
        AuditLog.action == "user.login.success",
        AuditLog.actor_user_id == registered.id,
    )
    log = db.execute(stmt).scalar_one_or_none()
    assert log is not None
    assert log.resource_type == "user"


def test_authenticate_user_wrong_password(db: Session):
    """authenticate_user fails with wrong password, raises 401 and logs failure."""
    email = _unique_email("auth_wrong_pw")
    password = "CorrectPassword123!"
    register_user(
        db,
        UserCreate(full_name="Wrong PW User", email=email, password=password),
    )

    credentials = UserLogin(email=email, password="IncorrectPassword123!")
    with pytest.raises(HTTPException) as exc_info:
        authenticate_user(db, credentials)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Incorrect email or password"

    # Verify failure audit log
    stmt = select(AuditLog).where(AuditLog.action == "user.login.failure")
    logs = db.execute(stmt).scalars().all()
    assert len(logs) >= 1
    assert logs[-1].actor_user_id is None


def test_authenticate_user_unknown_email(db: Session):
    """authenticate_user fails for non-existent email, raises 401 and logs failure."""
    credentials = UserLogin(
        email=_unique_email("ghost_user"),
        password="AnyPassword123!",
    )
    with pytest.raises(HTTPException) as exc_info:
        authenticate_user(db, credentials)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Incorrect email or password"

    stmt = select(AuditLog).where(AuditLog.action == "user.login.failure")
    logs = db.execute(stmt).scalars().all()
    assert len(logs) >= 1


def test_authenticate_user_inactive_account(db: Session):
    """authenticate_user rejects inactive account with HTTP 403 Forbidden."""
    email = _unique_email("auth_inactive")
    password = "SecurePassword123!"
    user = register_user(
        db,
        UserCreate(full_name="Inactive Svc User", email=email, password=password),
    )

    # Deactivate account
    user.is_active = False
    db.commit()

    credentials = UserLogin(email=email, password=password)
    with pytest.raises(HTTPException) as exc_info:
        authenticate_user(db, credentials)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Inactive user account"


def test_create_user_token(db: Session):
    """create_user_token produces a signed JWT bearer token containing user UUID."""
    email = _unique_email("token_svc")
    user = register_user(
        db,
        UserCreate(full_name="Token Svc User", email=email, password="SecurePassword123!"),
    )

    token = create_user_token(user)
    assert token.token_type == "bearer"
    assert isinstance(token.access_token, str)

    payload = decode_access_token(token.access_token)
    assert payload["sub"] == str(user.id)
    assert "exp" in payload


def test_failed_login_audit_rollback_on_db_error(db: Session, monkeypatch: pytest.MonkeyPatch):
    """_record_login_failure rolls back and propagates if commit raises exception."""
    rollback_called = False
    original_rollback = db.rollback

    def mock_rollback():
        nonlocal rollback_called
        rollback_called = True
        original_rollback()

    def mock_commit():
        raise RuntimeError("DB connection dropped")

    monkeypatch.setattr(db, "commit", mock_commit)
    monkeypatch.setattr(db, "rollback", mock_rollback)

    with pytest.raises(RuntimeError) as exc_info:
        _record_login_failure(db)

    assert str(exc_info.value) == "DB connection dropped"
    assert rollback_called is True


def test_successful_login_audit_failure_rolls_back(db: Session, monkeypatch: pytest.MonkeyPatch):
    """authenticate_user rolls back and propagates if audit log commit fails."""
    email = _unique_email("audit_fail_login")
    password = "CorrectPassword123!"
    register_user(
        db,
        UserCreate(full_name="Audit Fail User", email=email, password=password),
    )

    rollback_called = False
    original_rollback = db.rollback

    def mock_rollback():
        nonlocal rollback_called
        rollback_called = True
        original_rollback()

    def mock_commit():
        raise RuntimeError("Audit disk full")

    credentials = UserLogin(email=email, password=password)

    monkeypatch.setattr(db, "commit", mock_commit)
    monkeypatch.setattr(db, "rollback", mock_rollback)

    with pytest.raises(RuntimeError) as exc_info:
        authenticate_user(db, credentials)

    assert str(exc_info.value) == "Audit disk full"
    assert rollback_called is True
