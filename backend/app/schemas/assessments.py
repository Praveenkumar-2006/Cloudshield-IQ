"""
CloudShield IQ — Assessment & Security Finding Schemas
=====================================================
Pydantic v2 schemas for ML risk assessment outputs, SHAP explainability attributions,
and actionable remediation findings.
"""

from datetime import datetime, timezone
from typing import Any, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.taxonomy import CloudProvider, SeverityLevel


class RiskAssessment(BaseModel):
    """
    ML evaluation result for an ingested event or cloud asset.
    Strictly decoupled from raw telemetry inputs.
    """

    model_config = ConfigDict(from_attributes=True)

    assessment_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique assessment identifier.",
    )
    event_id: Optional[str] = Field(
        default=None,
        description="Reference ID of the evaluated event (if evaluated per event).",
    )
    resource_id: Optional[str] = Field(
        default=None,
        description="Target resource ARN or ID.",
    )
    cloud_provider: CloudProvider = Field(
        ...,
        description="Cloud provider where the risk is located.",
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Composite risk score on a continuous scale of 0.0 to 100.0.",
    )
    anomaly_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Probabilistic anomaly score produced by Isolation Forest / autoencoder (0.0 to 1.0).",
    )
    is_anomaly: bool = Field(
        ...,
        description="Binary classification threshold outcome (anomaly_score >= threshold).",
    )
    severity: SeverityLevel = Field(
        ...,
        description="Categorical severity derived from risk score brackets.",
    )
    shap_values: dict[str, float] = Field(
        default_factory=dict,
        description="SHAP attribution weights for key features driving the risk prediction.",
    )
    top_feature: Optional[str] = Field(
        default=None,
        description="Single feature name with highest absolute SHAP impact.",
    )
    top_feature_impact: Optional[float] = Field(
        default=None,
        description="Signed impact of the top feature on the risk score.",
    )
    model_version: str = Field(
        default="v0.1.0",
        description="Identifier of the ML model that computed this assessment.",
    )
    evaluated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when assessment was computed in UTC.",
    )


class SecurityFindingBase(BaseModel):
    """Core attributes of an actionable security finding."""

    title: str = Field(
        ...,
        max_length=256,
        description="Brief summary title of the security issue.",
    )
    cloud_provider: CloudProvider = Field(
        ...,
        description="Target cloud platform.",
    )
    resource_id: str = Field(
        ...,
        max_length=512,
        description="Affected cloud resource identifier.",
    )
    category: str = Field(
        ...,
        max_length=64,
        description="Security domain (IAM, Storage, Network, Compute, Encryption, Logging).",
    )
    severity: SeverityLevel = Field(
        ...,
        description="Severity classification of the finding.",
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Associated risk score.",
    )
    shap_top_feature: Optional[str] = Field(
        default=None,
        description="Top ML feature contributing to finding.",
    )
    shap_impact: Optional[float] = Field(
        default=None,
        description="SHAP contribution magnitude.",
    )
    compliance_violations: list[str] = Field(
        default_factory=list,
        description="List of violated compliance control IDs (e.g. ['CIS-AWS-1.1', 'NIST-AC-2']).",
    )
    remediation_guidance: str = Field(
        ...,
        description="Natural-language remediation instructions.",
    )
    cli_remediation_command: Optional[str] = Field(
        default=None,
        description="CLI command to remediate the vulnerability.",
    )
    terraform_remediation_snippet: Optional[str] = Field(
        default=None,
        description="Infrastructure-as-Code Terraform snippet for automated fix.",
    )

    @field_validator("cloud_provider", mode="before")
    @classmethod
    def normalize_cloud_provider(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.lower()
        return v

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.lower()
        return v


class SecurityFindingCreate(SecurityFindingBase):
    """Input schema for recording a new security finding."""

    finding_id: Optional[str] = Field(
        default_factory=lambda: f"FND-{uuid.uuid4().hex[:8].upper()}",
        description="Optional custom finding identifier.",
    )


class SecurityFinding(SecurityFindingBase):
    """Full security finding representation."""

    model_config = ConfigDict(from_attributes=True)

    finding_id: str = Field(..., description="Unique finding ID.")
    status: str = Field(
        default="OPEN",
        description="Finding status (OPEN, IN_REMEDIATION, RESOLVED, SUPPRESSED).",
    )
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Detection timestamp in UTC.",
    )
    resolved_at: Optional[datetime] = Field(
        default=None,
        description="Resolution timestamp if resolved.",
    )
