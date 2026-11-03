"""SQLAlchemy model for issued documents and credentials."""

import enum
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.revocation_record import RevocationRecord
    from app.models.user import User
    from app.models.verification_record import VerificationRecord


class DocumentStatus(str, enum.Enum):
    """Document lifecycle status."""

    ISSUED = "issued"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Document(Base):
    """Document entity representing tamper-proof records issued by organizations."""

    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    issuer_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    subject_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    document_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    file_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    hash_algorithm: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="sha256",
        server_default=text("'sha256'"),
    )
    storage_reference: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    status: Mapped[DocumentStatus] = mapped_column(
        Enum(
            DocumentStatus,
            native_enum=False,
            values_callable=lambda obj: [e.value for e in obj],
            name="document_status_enum",
        ),
        nullable=False,
        default=DocumentStatus.ISSUED,
        index=True,
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
        UniqueConstraint(
            "issuer_organization_id",
            "file_hash",
            "hash_algorithm",
            name="uq_document_issuer_hash_algo",
        ),
        Index("ix_documents_type_status", "document_type", "status"),
        CheckConstraint(
            "status IN ('issued', 'active', 'revoked', 'expired')",
            name="ck_documents_status",
        ),
    )

    # Relationships
    issuer_organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="issued_documents",
        foreign_keys=[issuer_organization_id],
    )
    subject_user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="subject_documents",
        foreign_keys=[subject_user_id],
    )
    verification_records: Mapped[List["VerificationRecord"]] = relationship(
        "VerificationRecord",
        back_populates="document",
    )
    revocation_records: Mapped[List["RevocationRecord"]] = relationship(
        "RevocationRecord",
        back_populates="document",
    )

    def __repr__(self) -> str:
        return (
            f"<Document(id={self.id}, title='{self.title}', type='{self.document_type}', "
            f"status='{self.status.value}', file_hash='{self.file_hash[:12]}...')>"
        )
