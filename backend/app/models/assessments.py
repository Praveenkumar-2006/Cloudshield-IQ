"""
CloudShield IQ — Assessment & Finding Database Models
====================================================
SQLAlchemy ORM models for storing ML risk assessments, SHAP attribution scores,
and deterministic compliance check outcomes.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RiskAssessmentModel(Base):
    """
    ML evaluation results table.
    Stores continuous risk score, probabilistic anomaly classification, and SHAP weights.
    """

    __tablename__ = "risk_assessments"

    assessment_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        index=True,
    )
    event_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    resource_id: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
        index=True,
    )
    cloud_provider: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    anomaly_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    is_anomaly: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    shap_values: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    top_feature: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    top_feature_impact: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    model_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="v0.1.0",
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    __table_args__ = (
        Index("ix_assessments_provider_severity", "cloud_provider", "severity"),
        Index("ix_assessments_evaluated_at", "evaluated_at"),
    )


class SecurityFindingModel(Base):
    """
    Actionable security findings with automated remediation commands.
    """

    __tablename__ = "security_findings"

    finding_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
    )
    cloud_provider: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    resource_id: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        index=True,
    )
    category: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    shap_top_feature: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    shap_impact: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    compliance_violations: Mapped[list[Any]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    remediation_guidance: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    cli_remediation_command: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    terraform_remediation_snippet: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="OPEN",
        index=True,
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class ComplianceResultModel(Base):
    """
    Deterministic compliance check evaluation result table.
    """

    __tablename__ = "compliance_results"

    result_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        index=True,
    )
    control_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    control_name: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
    )
    framework: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    cloud_provider: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    evaluated_resources: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    failed_resources: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    failed_resource_ids: Mapped[list[Any]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )
