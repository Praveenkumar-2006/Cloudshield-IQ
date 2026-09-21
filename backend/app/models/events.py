"""
CloudShield IQ — Security Event Database Model
=============================================
SQLAlchemy ORM model for storing normalized multi-cloud security telemetry.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SecurityEventModel(Base):
    """
    Normalized multi-cloud security event storage table.
    Indexes optimize multi-tenant, time-series, and provider-specific dashboard queries.
    """

    __tablename__ = "security_events"

    event_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    cloud_provider: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    event_source: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        default="audit_logs",
    )
    resource_type: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    resource_id: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
        index=True,
    )
    raw_action: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
    )
    canonical_action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    actor_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    actor_name: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
    )
    source_ip: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    region: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        default="global",
    )
    mfa_used: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    outcome: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="Success",
    )
    session_duration_s: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    has_session: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    metadata_payload: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    # Composite indices optimized for primary dashboard and analytic query patterns
    __table_args__ = (
        Index("ix_events_provider_timestamp", "cloud_provider", "timestamp"),
        Index("ix_events_provider_resource", "cloud_provider", "resource_type"),
        Index("ix_events_actor_canonical", "actor_type", "canonical_action"),
    )

    def __repr__(self) -> str:
        return f"<SecurityEventModel(id='{self.event_id}', provider='{self.cloud_provider}', action='{self.canonical_action}')>"
