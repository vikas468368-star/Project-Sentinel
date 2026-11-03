"""SQLAlchemy model for platform users."""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List

from sqlalchemy import Boolean, DateTime, Index, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.audit_log import AuditLog
    from app.models.document import Document
    from app.models.organization_member import OrganizationMember
    from app.models.revocation_record import RevocationRecord
    from app.models.verification_record import VerificationRecord


class User(Base):
    """User entity representing platform actors, administrators, and subjects."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    full_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("true"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )

    __table_args__ = (
        Index(
            "uq_users_email_lower",
            func.lower(email),
            unique=True,
        ),
    )

    @validates("email")
    def validate_and_normalize_email(self, key: str, value: str) -> str:
        """Normalize email address to lowercase and trim surrounding whitespace."""
        if value is not None:
            return value.strip().lower()
        return value

    # Relationships
    memberships: Mapped[List["OrganizationMember"]] = relationship(
        "OrganizationMember",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    subject_documents: Mapped[List["Document"]] = relationship(
        "Document",
        back_populates="subject_user",
        foreign_keys="[Document.subject_user_id]",
    )
    verifications: Mapped[List["VerificationRecord"]] = relationship(
        "VerificationRecord",
        back_populates="verifier_user",
        foreign_keys="[VerificationRecord.verifier_user_id]",
    )
    revocations: Mapped[List["RevocationRecord"]] = relationship(
        "RevocationRecord",
        back_populates="revoker",
        foreign_keys="[RevocationRecord.revoked_by]",
    )
    audit_logs: Mapped[List["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="actor_user",
        foreign_keys="[AuditLog.actor_user_id]",
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email='{self.email}', is_active={self.is_active})>"
