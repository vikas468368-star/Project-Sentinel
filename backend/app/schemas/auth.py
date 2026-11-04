"""Authentication and user Pydantic schemas for Project Sentinel."""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class UserCreate(BaseModel):
    """Schema for registering a new user."""

    full_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Full name of the user.",
    )
    email: EmailStr = Field(
        ...,
        max_length=255,
        description="Unique email address for authentication.",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Plaintext password (minimum 8 characters, maximum 128 characters).",
    )

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        """Trim surrounding whitespace and convert email address to lowercase."""
        if isinstance(v, str):
            return v.strip().lower()
        return v

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        """Trim whitespace from full name and ensure it is not empty."""
        stripped = v.strip()
        if not stripped:
            raise ValueError("Full name cannot be empty or whitespace only.")
        return stripped


class UserLogin(BaseModel):
    """Schema for user authentication and login."""

    email: EmailStr = Field(
        ...,
        max_length=255,
        description="Registered email address.",
    )
    password: str = Field(
        ...,
        min_length=1,
        description="Account plaintext password.",
    )

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        """Trim surrounding whitespace and convert email address to lowercase."""
        if isinstance(v, str):
            return v.strip().lower()
        return v


class UserResponse(BaseModel):
    """Public user profile response schema. Never exposes password_hash."""

    id: uuid.UUID
    email: EmailStr
    full_name: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    """OAuth2 compatible bearer token response schema."""

    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Payload claims extracted from a decoded JWT access token."""

    sub: Optional[str] = None
    exp: Optional[datetime] = None
