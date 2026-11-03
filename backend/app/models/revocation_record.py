"""SQLAlchemy model for document revocation records."""

import enum
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, Enum, ForeignKey, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.document import Document
    from app.models.user import User


class RevocationStatus(str, enum.Enum):
    """Status of the revocation record."""

    PENDING = "pending"
    CONFIRMED = "confirmed"
    PROCESSED = "processed"


class RevocationRecord(Base):
    """Historical ledger entry recording document revocations."""

    __tablename__ = "revocation_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("documents.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    revoked_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    reason_code: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )
    status: Mapped[RevocationStatus] = mapped_column(
        Enum(
            RevocationStatus,
            native_enum=False,
            values_callable=lambda obj: [e.value for e in obj],
            name="revocation_status_enum",
        ),
        nullable=False,
        default=RevocationStatus.CONFIRMED,
        server_default=text("'confirmed'"),
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'confirmed', 'processed')",
            name="ck_revocation_records_status",
        ),
    )

    # Relationships
    document: Mapped["Document"] = relationship(
        "Document",
        back_populates="revocation_records",
        foreign_keys=[document_id],
    )
    revoker: Mapped["User"] = relationship(
        "User",
        back_populates="revocations",
        foreign_keys=[revoked_by],
    )

    def __repr__(self) -> str:
        status_val = self.status.value if isinstance(self.status, RevocationStatus) else self.status
        return (
            f"<RevocationRecord(id={self.id}, document_id={self.document_id}, "
            f"revoked_by={self.revoked_by}, reason_code='{self.reason_code}', status='{status_val}')>"
        )
