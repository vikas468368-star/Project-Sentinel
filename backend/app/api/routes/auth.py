"""Authentication API routes for Project Sentinel.

Provides endpoints for user registration, OAuth2 password login,
and authenticated user profile retrieval.
"""

from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.database import get_db
from app.models.user import User
from app.schemas.auth import Token, UserCreate, UserLogin, UserResponse
from app.services.auth_service import (
    authenticate_user,
    create_user_token,
    register_user,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
def register(
    user_in: UserCreate,
    db: Session = Depends(get_db),
) -> User:
    """Register a new user account with validated credentials.

    Args:
        user_in: Validated registration payload (full name, email, password).
        db: Active SQLAlchemy database session.

    Returns:
        User: Newly registered user profile (excluding sensitive fields).
    """
    return register_user(db, user_in)


@router.post(
    "/login",
    response_model=Token,
    summary="Authenticate user and return access token",
)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> Token:
    """Authenticate user with OAuth2 password request form and issue a JWT bearer token.

    Args:
        form_data: OAuth2 form containing username (email) and password.
        db: Active SQLAlchemy database session.

    Returns:
        Token: OAuth2 access token response.
    """
    credentials = UserLogin(email=form_data.username, password=form_data.password)
    user = authenticate_user(db, credentials)
    return create_user_token(user)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user profile",
)
def read_current_user(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Retrieve profile information for the currently authenticated active user.

    Args:
        current_user: The authenticated and active User resolved from the bearer token.

    Returns:
        User: Current authenticated user profile (excluding sensitive fields).
    """
    return current_user
