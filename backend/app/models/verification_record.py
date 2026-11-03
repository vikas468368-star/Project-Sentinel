"""SQLAlchemy model for document verification logs."""

import enum
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import CheckConstraint, DateTime, Enum, ForeignKey, String, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.document import Document
    from app.models.user import User


class VerificationResult(str, enum.Enum):
    """Result status of a document verification attempt."""

    VERIFIED = "verified"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class VerificationRecord(Base):
    """Verification log capturing each verification attempt against a document hash."""

    __tablename__ = "verification_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    document_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("documents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    verifier_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    submitted_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    result: Mapped[VerificationResult] = mapped_column(
        Enum(
            VerificationResult,
            native_enum=False,
            values_callable=lambda obj: [e.value for e in obj],
            name="verification_result_enum",
        ),
        nullable=False,
        index=True,
    )
    checks: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )

    __table_args__ = (
        CheckConstraint(
            "result IN ('verified', 'failed', 'inconclusive')",
            name="ck_verification_records_result",
        ),
    )

    # Relationships
    document: Mapped[Optional["Document"]] = relationship(
        "Document",
        back_populates="verification_records",
        foreign_keys=[document_id],
    )
    verifier_user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="verifications",
        foreign_keys=[verifier_user_id],
    )

    def __repr__(self) -> str:
        return (
            f"<VerificationRecord(id={self.id}, result='{self.result.value}', "
            f"submitted_hash='{self.submitted_hash[:12]}...', verified_at={self.verified_at})>"
        )
