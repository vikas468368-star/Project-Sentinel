"""SQLAlchemy model for organization memberships."""

import enum
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.user import User


class MemberRole(str, enum.Enum):
    """Role within an organization."""

    ADMIN = "admin"
    ISSUER = "issuer"
    VERIFIER = "verifier"


class MemberStatus(str, enum.Enum):
    """Membership status within an organization."""

    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"


class OrganizationMember(Base):
    """Association entity linking a User to an Organization with role and status."""

    __tablename__ = "organization_members"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[MemberRole] = mapped_column(
        Enum(
            MemberRole,
            native_enum=False,
            values_callable=lambda obj: [e.value for e in obj],
            name="member_role_enum",
        ),
        nullable=False,
        default=MemberRole.VERIFIER,
    )
    status: Mapped[MemberStatus] = mapped_column(
        Enum(
            MemberStatus,
            native_enum=False,
            values_callable=lambda obj: [e.value for e in obj],
            name="member_status_enum",
        ),
        nullable=False,
        default=MemberStatus.PENDING,
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
            "user_id",
            "organization_id",
            name="uq_organization_member_user_org",
        ),
        CheckConstraint(
            "role IN ('admin', 'issuer', 'verifier')",
            name="ck_organization_members_role",
        ),
        CheckConstraint(
            "status IN ('pending', 'active', 'suspended')",
            name="ck_organization_members_status",
        ),
    )

    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="memberships",
    )
    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="members",
    )

    def __repr__(self) -> str:
        return (
            f"<OrganizationMember(id={self.id}, user_id={self.user_id}, "
            f"organization_id={self.organization_id}, role='{self.role.value}', status='{self.status.value}')>"
        )
