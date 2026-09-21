"""
CloudShield IQ — Compliance Framework & Evaluation Schemas
=========================================================
Pydantic v2 schemas for deterministic rule-based compliance evaluation.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field

from app.core.taxonomy import CloudProvider, SeverityLevel


class ComplianceFramework(str, Enum):
    """Supported cybersecurity compliance benchmarks."""

    CIS_AWS_1_4 = "CIS AWS 1.4"
    CIS_AZURE_2_0 = "CIS Azure 2.0"
    CIS_GCP_1_3 = "CIS GCP 1.3"
    NIST_800_53 = "NIST 800-53"
    ISO_27001 = "ISO 27001"
    PCI_DSS_4_0 = "PCI-DSS 4.0"


class ComplianceStatus(str, Enum):
    """Evaluation status of a compliance check."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ComplianceControlResult(BaseModel):
    """Evaluation outcome for a single security control rule."""

    model_config = ConfigDict(from_attributes=True)

    result_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique evaluation result ID.",
    )
    control_id: str = Field(
        ...,
        max_length=64,
        description="Standard control identifier (e.g., 'CIS-AWS-1.1', 'NIST-AC-2').",
    )
    control_name: str = Field(
        ...,
        max_length=256,
        description="Short description of the control requirement.",
    )
    framework: ComplianceFramework = Field(
        ...,
        description="Associated compliance standard.",
    )
    cloud_provider: CloudProvider = Field(
        ...,
        description="Cloud provider evaluated.",
    )
    status: ComplianceStatus = Field(
        ...,
        description="Deterministic evaluation status (PASS, FAIL, PARTIAL).",
    )
    severity: SeverityLevel = Field(
        ...,
        description="Risk severity if control fails.",
    )
    evaluated_resources: int = Field(
        default=0,
        ge=0,
        description="Total count of assets evaluated under this control.",
    )
    failed_resources: int = Field(
        default=0,
        ge=0,
        description="Count of assets violating this control.",
    )
    failed_resource_ids: list[str] = Field(
        default_factory=list,
        description="List of specific resource IDs violating this control.",
    )
    evaluated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Evaluation timestamp in UTC.",
    )


class ComplianceSummary(BaseModel):
    """Aggregated compliance score summary for dashboard reporting."""

    overall_pass_rate: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Percentage of evaluated controls passing (0.0 to 100.0%).",
    )
    total_controls: int = Field(..., ge=0)
    passed_controls: int = Field(..., ge=0)
    failed_controls: int = Field(..., ge=0)
    partial_controls: int = Field(..., ge=0)
    framework_scores: dict[str, float] = Field(
        default_factory=dict,
        description="Mapping of framework name to its percentage compliance score.",
    )
    evaluated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Summary generation timestamp in UTC.",
    )
