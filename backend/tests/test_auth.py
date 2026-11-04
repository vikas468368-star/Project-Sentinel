"""Authentication API tests for Project Sentinel.

Covers registration, login, token handling, user profile (/me),
security validations, and audit record generation.
"""

import uuid
from typing import Dict

from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import create_access_token
from app.models.audit_log import AuditLog
from app.models.user import User


def _random_email(prefix: str = "test") -> str:
    """Generate a unique random email for test isolation."""
    return f"{prefix}_{uuid.uuid4().hex[:8]}@example.com"


# =====================================================================
# Registration Tests
# =====================================================================

def test_registration_success_returns_201(client: TestClient):
    """Successful registration returns HTTP 201 Created."""
    email = _random_email("reg_success")
    payload = {
        "full_name": "Valid Test User",
        "email": email,
        "password": "SecurePassword123!",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == status.HTTP_201_CREATED


def test_registration_response_fields(client: TestClient):
    """Response contains user ID, email, and full name."""
    email = _random_email("reg_fields")
    payload = {
        "full_name": "Field Check User",
        "email": email,
        "password": "SecurePassword123!",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()

    assert "id" in data
    # Verify ID is a valid UUID
    uuid.UUID(data["id"])
    assert data["email"] == email.lower()
    assert data["full_name"] == "Field Check User"
    assert data["is_active"] is True
    assert "created_at" in data
    assert "updated_at" in data


def test_registration_never_returns_password_hash(client: TestClient):
    """Password hash or plaintext password must never be returned in response."""
    email = _random_email("reg_sec")
    payload = {
        "full_name": "Security User",
        "email": email,
        "password": "SecurePassword123!",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()

    assert "password_hash" not in data
    assert "password" not in data


def test_registration_duplicate_email_returns_409(client: TestClient):
    """Duplicate email registration returns HTTP 409 Conflict."""
    email = _random_email("reg_dup")
    payload = {
        "full_name": "First User",
        "email": email,
        "password": "SecurePassword123!",
    }
    first_res = client.post("/api/v1/auth/register", json=payload)
    assert first_res.status_code == status.HTTP_201_CREATED

    duplicate_payload = {
        "full_name": "Second User",
        "email": email,
        "password": "DifferentPassword123!",
    }
    second_res = client.post("/api/v1/auth/register", json=duplicate_payload)
    assert second_res.status_code == status.HTTP_409_CONFLICT
    assert second_res.json()["detail"] == "Email already registered"


def test_registration_email_normalization(client: TestClient):
    """Email normalization trims whitespace and converts to lowercase."""
    email_base = _random_email("norm")
    raw_email = f"  {email_base.upper()}  "
    payload = {
        "full_name": "Normalized User",
        "email": raw_email,
        "password": "SecurePassword123!",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == email_base.lower()

    # Attempt registration with clean lowercase email -> should conflict
    conflict_res = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Another User",
            "email": email_base.lower(),
            "password": "SecurePassword123!",
        },
    )
    assert conflict_res.status_code == status.HTTP_409_CONFLICT


def test_registration_invalid_email_returns_422(client: TestClient):
    """Invalid email formats return HTTP 422 Unprocessable Entity."""
    payload = {
        "full_name": "Invalid Email User",
        "email": "not-an-email",
        "password": "SecurePassword123!",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


def test_registration_weak_password_returns_422(client: TestClient):
    """Passwords shorter than 8 characters return HTTP 422 Unprocessable Entity."""
    payload = {
        "full_name": "Weak Pass User",
        "email": _random_email("weak"),
        "password": "short",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


def test_registration_whitespace_only_name_rejected(client: TestClient):
    """Whitespace-only full_name values are rejected with HTTP 422."""
    payload = {
        "full_name": "   ",
        "email": _random_email("whitespace_name"),
        "password": "SecurePassword123!",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# =====================================================================
# Login Tests
# =====================================================================

def test_login_correct_credentials_returns_200(client: TestClient):
    """Correct credentials return HTTP 200 OK."""
    email = _random_email("login_ok")
    password = "CorrectPassword123!"
    reg_res = client.post(
        "/api/v1/auth/register",
        json={"full_name": "Login User", "email": email, "password": password},
    )
    assert reg_res.status_code == status.HTTP_201_CREATED

    response = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": password},
    )
    assert response.status_code == status.HTTP_200_OK


def test_login_response_contains_access_token_and_bearer_type(client: TestClient):
    """Successful login returns access token and 'bearer' token_type."""
    email = _random_email("login_token")
    password = "CorrectPassword123!"
    client.post(
        "/api/v1/auth/register",
        json={"full_name": "Token User", "email": email, "password": password},
    )

    response = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": password},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert "access_token" in data
    assert isinstance(data["access_token"], str)
    assert len(data["access_token"]) > 0
    assert data["token_type"] == "bearer"


def test_login_incorrect_password_returns_401(client: TestClient):
    """Incorrect password returns HTTP 401 Unauthorized with WWW-Authenticate header."""
    email = _random_email("wrong_pw")
    password = "RealPassword123!"
    client.post(
        "/api/v1/auth/register",
        json={"full_name": "Wrong Pass User", "email": email, "password": password},
    )

    response = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": "WrongPassword123!"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.headers.get("www-authenticate") == "Bearer"
    assert response.json()["detail"] == "Incorrect email or password"


def test_login_unknown_email_returns_401_generic(client: TestClient):
    """Unknown email returns generic HTTP 401 identical to incorrect password."""
    response = client.post(
        "/api/v1/auth/login",
        data={"username": _random_email("nonexistent"), "password": "SomePassword123!"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.headers.get("www-authenticate") == "Bearer"
    assert response.json()["detail"] == "Incorrect email or password"


def test_login_inactive_account_returns_403(client: TestClient, db: Session):
    """Inactive account login attempt returns HTTP 403 Forbidden."""
    email = _random_email("inactive_login")
    password = "Password123!"
    client.post(
        "/api/v1/auth/register",
        json={"full_name": "Inactive User", "email": email, "password": password},
    )

    # Deactivate account in database
    user = db.execute(select(User).where(User.email == email)).scalar_one()
    user.is_active = False
    db.commit()

    response = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": password},
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["detail"] == "Inactive user account"


def test_login_missing_fields_returns_422(client: TestClient):
    """Missing required login form fields returns HTTP 422."""
    # Missing password
    res1 = client.post("/api/v1/auth/login", data={"username": "user@example.com"})
    assert res1.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    # Missing username
    res2 = client.post("/api/v1/auth/login", data={"password": "password123"})
    assert res2.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# =====================================================================
# Current User (/me) Tests
# =====================================================================

def test_current_user_valid_jwt_returns_200(client: TestClient):
    """Valid JWT returns current user profile with HTTP 200 OK."""
    email = _random_email("me_ok")
    password = "Password123!"
    client.post(
        "/api/v1/auth/register",
        json={"full_name": "Current User Test", "email": email, "password": password},
    )
    login_res = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": password},
    )
    token = login_res.json()["access_token"]

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["email"] == email.lower()
    assert data["full_name"] == "Current User Test"
    assert "password_hash" not in data


def test_current_user_unauthenticated_returns_401(client: TestClient):
    """Unauthenticated request to /me returns HTTP 401 Unauthorized."""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_current_user_invalid_jwt_returns_401(client: TestClient):
    """Invalid JWT bearer token returns HTTP 401 Unauthorized."""
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid.jwt.signature"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Could not validate credentials"


def test_current_user_malformed_jwt_subject_returns_401(client: TestClient):
    """Token with malformed non-UUID subject returns HTTP 401 Unauthorized."""
    token = create_access_token({"sub": "not-a-valid-uuid"})
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Could not validate credentials"


def test_current_user_nonexistent_user_returns_401(client: TestClient):
    """Token referencing a deleted or nonexistent UUID returns HTTP 401 Unauthorized."""
    nonexistent_id = str(uuid.uuid4())
    token = create_access_token({"sub": nonexistent_id})
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Could not validate credentials"


def test_current_user_inactive_cannot_access_me(client: TestClient, db: Session):
    """Inactive user receives HTTP 403 Forbidden when requesting /me."""
    email = _random_email("inactive_me")
    password = "Password123!"
    client.post(
        "/api/v1/auth/register",
        json={"full_name": "Inactive Me User", "email": email, "password": password},
    )
    login_res = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": password},
    )
    token = login_res.json()["access_token"]

    # Deactivate user in database
    user = db.execute(select(User).where(User.email == email)).scalar_one()
    user.is_active = False
    db.commit()

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["detail"] == "Inactive user account"


# =====================================================================
# Security and Auditing Tests
# =====================================================================

def test_registration_stores_argon2id_hash(client: TestClient, db: Session):
    """Registration creates a user record storing an Argon2id password hash."""
    email = _random_email("argon_check")
    raw_password = "SecurePassword123!"
    client.post(
        "/api/v1/auth/register",
        json={"full_name": "Argon User", "email": email, "password": raw_password},
    )

    user = db.execute(select(User).where(User.email == email)).scalar_one()
    assert user.password_hash.startswith("$argon2id$")
    assert user.password_hash != raw_password


def test_failed_login_enumeration_prevention(client: TestClient):
    """Failed login reveals no distinction between existent and non-existent accounts."""
    email = _random_email("enum_test")
    password = "ValidPassword123!"
    client.post(
        "/api/v1/auth/register",
        json={"full_name": "Enum User", "email": email, "password": password},
    )

    # 1. Real account, wrong password
    res_wrong_pw = client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": "WrongPassword123!"},
    )

    # 2. Non-existent account, same wrong password
    res_unknown_email = client.post(
        "/api/v1/auth/login",
        data={"username": _random_email("ghost"), "password": "WrongPassword123!"},
    )

    assert res_wrong_pw.status_code == status.HTTP_401_UNAUTHORIZED
    assert res_unknown_email.status_code == status.HTTP_401_UNAUTHORIZED
    assert res_wrong_pw.json() == res_unknown_email.json()
    assert res_wrong_pw.json()["detail"] == "Incorrect email or password"


def test_failed_login_creates_audit_record(client: TestClient, db: Session):
    """Failed login attempts record an unauthenticated audit entry without sensitive data."""
    unknown_email = _random_email("audit_fail")
    secret_password = "AttemptedSecret123!"

    client.post(
        "/api/v1/auth/login",
        data={"username": unknown_email, "password": secret_password},
    )

    stmt = select(AuditLog).where(AuditLog.action == "user.login.failure")
    audit_entries = db.execute(stmt).scalars().all()
    assert len(audit_entries) >= 1

    latest_fail = audit_entries[-1]
    assert latest_fail.actor_user_id is None
    assert latest_fail.resource_type == "user"
    assert latest_fail.resource_id is None

    # Verify no credentials or emails are present in metadata
    metadata_str = str(latest_fail.audit_metadata)
    assert secret_password not in metadata_str
    assert unknown_email not in metadata_str


def test_registration_and_login_generate_audit_records(client: TestClient, db: Session):
    """Registration and successful login generate appropriate audit records."""
    email = _random_email("audit_success")
    password = "SecurePassword123!"

    reg_res = client.post(
        "/api/v1/auth/register",
        json={"full_name": "Audit Track User", "email": email, "password": password},
    )
    user_id = reg_res.json()["id"]

    client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": password},
    )

    # Check registration audit log
    reg_stmt = select(AuditLog).where(
        AuditLog.action == "user.register",
        AuditLog.resource_id == str(user_id),
    )
    reg_log = db.execute(reg_stmt).scalar_one_or_none()
    assert reg_log is not None
    assert str(reg_log.actor_user_id) == str(user_id)
    assert reg_log.resource_type == "user"
    assert password not in str(reg_log.audit_metadata)

    # Check login success audit log
    login_stmt = select(AuditLog).where(
        AuditLog.action == "user.login.success",
        AuditLog.resource_id == str(user_id),
    )
    login_log = db.execute(login_stmt).scalar_one_or_none()
    assert login_log is not None
    assert str(login_log.actor_user_id) == str(user_id)
    assert login_log.resource_type == "user"
    assert password not in str(login_log.audit_metadata)
