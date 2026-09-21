"""
CloudShield IQ — Recommendation Engine Schemas
==============================================
Pydantic v2 schemas for automated remediation playbooks, prioritized recommendations,
multi-platform IaC & CLI countermeasures, and remediation simulations.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field

from app.core.taxonomy import CloudProvider, SeverityLevel
from app.schemas.assessments import SecurityFinding, SecurityFindingBase
from app.schemas.events import CloudSecurityEvent


class EffortLevel(str, Enum):
    """Estimated operational effort required to deploy remediation."""

    LOW = "LOW"        # < 15 minutes (e.g., enable flag, attach managed policy)
    MEDIUM = "MEDIUM"  # 1-2 hours (e.g., configure private endpoint, IAM role refactor)
    HIGH = "HIGH"      # Multi-team / architecture migration (e.g., Workload Identity migration)


class ActionType(str, Enum):
    """Type of remediation countermeasure action."""

    CLI = "CLI"
    TERRAFORM = "TERRAFORM"
    PYTHON_SDK = "PYTHON_SDK"
    MANUAL_STEP = "MANUAL_STEP"


class RemediationStep(BaseModel):
    """Individual execution step within a remediation playbook."""

    step_number: int = Field(..., ge=1, description="Sequential step index.")
    title: str = Field(..., max_length=256, description="Action title.")
    description: str = Field(..., description="Detailed instructions for the security engineer.")
    action_type: ActionType = Field(default=ActionType.CLI, description="Automation format.")
    command_or_code: str = Field(..., description="Executable CLI command, Terraform HCL, or script snippet.")
    verification_command: Optional[str] = Field(
        default=None,
        description="CLI query or probe to verify that the remediation succeeded.",
    )
    rollback_command: Optional[str] = Field(
        default=None,
        description="Command or procedure to revert the change if adverse impact occurs.",
    )


class RemediationPlaybook(BaseModel):
    """
    Standardized multi-cloud security remediation playbook containing
    remediation steps and multi-language automation snippets.
    """

    model_config = ConfigDict(from_attributes=True)

    playbook_id: str = Field(..., description="Unique playbook identifier (e.g. PB-AWS-IAM-001).")
    title: str = Field(..., max_length=256, description="Human-readable title of the playbook.")
    category: str = Field(..., max_length=64, description="Security category (IAM, Storage, Network, Logging, KMS).")
    cloud_provider: CloudProvider = Field(..., description="Applicable cloud provider.")
    target_technique: Optional[str] = Field(
        default=None,
        description="Associated MITRE ATT&CK technique (e.g., T1078.004).",
    )
    target_controls: list[str] = Field(
        default_factory=list,
        description="List of compliance controls resolved by this playbook (e.g. CIS-AWS-1.1, NIST-AC-2).",
    )
    target_shap_features: list[str] = Field(
        default_factory=list,
        description="ML features whose risk attribution this playbook mitigates (e.g. actor_type_root, mfa_used).",
    )
    summary: str = Field(..., description="Executive summary and threat context.")
    effort_level: EffortLevel = Field(default=EffortLevel.LOW, description="Estimated implementation effort.")
    estimated_risk_reduction: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Expected reduction in risk score points upon successful remediation.",
    )
    steps: list[RemediationStep] = Field(
        default_factory=list,
        description="Step-by-step procedural instructions.",
    )
    cli_command: str = Field(
        ...,
        description="Primary vendor CLI command to remediate the vulnerability.",
    )
    terraform_snippet: str = Field(
        ...,
        description="Production-grade declarative Terraform HCL configuration.",
    )
    python_script: str = Field(
        ...,
        description="Executable Python SDK automation script (boto3, azure-mgmt, google-cloud).",
    )


class RecommendationRequest(BaseModel):
    """Request payload for generating targeted recommendations."""

    finding_id: Optional[str] = Field(default=None, description="ID of an existing security finding.")
    finding: Optional[SecurityFindingBase] = Field(default=None, description="Ad-hoc finding object.")
    event: Optional[CloudSecurityEvent] = Field(default=None, description="Raw cloud security event.")
    shap_drivers: list[str] = Field(
        default_factory=list,
        description="List of positive SHAP feature names driving risk (e.g., ['actor_type_root', 'mfa_used']).",
    )
    target_resource_override: Optional[str] = Field(
        default=None,
        description="Optional resource identifier to substitute into the playbook templates.",
    )


class RecommendationResponse(BaseModel):
    """Actionable recommendation with priority ranking and customized playbook."""

    recommendation_id: str = Field(
        default_factory=lambda: f"REC-{uuid.uuid4().hex[:8].upper()}",
        description="Unique recommendation ID.",
    )
    finding_id: Optional[str] = Field(default=None, description="Referenced finding ID.")
    priority_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Calculated priority score (higher means more urgent remediation).",
    )
    priority_rank: int = Field(default=1, ge=1, description="Rank within evaluated batch.")
    target_resource: str = Field(..., description="Resource ARN or identifier being remediated.")
    cloud_provider: CloudProvider = Field(..., description="Cloud platform.")
    playbook: RemediationPlaybook = Field(..., description="Customized remediation playbook.")
    original_risk_score: float = Field(..., ge=0.0, le=100.0, description="Pre-remediation risk score.")
    projected_risk_score: float = Field(..., ge=0.0, le=100.0, description="Projected post-remediation risk score.")
    risk_reduction_points: float = Field(..., ge=0.0, description="Risk score points reduced.")
    risk_reduction_pct: float = Field(..., ge=0.0, le=100.0, description="Percentage risk reduction.")
    mitigated_shap_features: list[str] = Field(
        default_factory=list,
        description="List of SHAP risk drivers addressed by this recommendation.",
    )
    compliance_controls_resolved: list[str] = Field(
        default_factory=list,
        description="Compliance controls brought into compliance by this recommendation.",
    )
    is_quick_win: bool = Field(
        default=False,
        description="True if remediation effort is LOW and risk reduction is >= 25 points.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when recommendation was synthesized in UTC.",
    )


class BatchPrioritizeRequest(BaseModel):
    """Batch input of security findings to rank by remediation priority."""

    findings: list[SecurityFinding] = Field(..., description="List of findings to prioritize.")


class BatchPrioritizeResponse(BaseModel):
    """Ranked remediation queue with summary statistics."""

    recommendations: list[RecommendationResponse] = Field(..., description="Ordered recommendations (highest priority first).")
    total_findings: int = Field(..., ge=0)
    quick_wins_count: int = Field(..., ge=0)
    total_potential_risk_reduction: float = Field(..., ge=0.0)


class RemediationSimulationRequest(BaseModel):
    """Input parameters for simulating multi-finding remediation impact."""

    finding_ids_to_remediate: list[str] = Field(
        ...,
        description="List of finding IDs to simulate fixing.",
    )
    current_findings: list[SecurityFinding] = Field(
        default_factory=list,
        description="Current active findings. If empty, engine uses active memory corpus.",
    )


class RemediationSimulationResult(BaseModel):
    """Simulation outcomes projecting overall perimeter posture improvement."""

    original_average_risk: float = Field(..., ge=0.0, le=100.0)
    projected_average_risk: float = Field(..., ge=0.0, le=100.0)
    overall_risk_reduction_pct: float = Field(..., ge=0.0, le=100.0)
    findings_remediated_count: int = Field(..., ge=0)
    remaining_critical_count: int = Field(..., ge=0)
    remaining_high_count: int = Field(..., ge=0)
    simulation_summary: str = Field(..., description="Executive narrative of posture improvement.")


class RecommendationStats(BaseModel):
    """Global metrics on available playbooks and remediation coverage."""

    total_playbooks: int = Field(..., ge=0)
    playbooks_by_provider: dict[str, int] = Field(default_factory=dict)
    playbooks_by_category: dict[str, int] = Field(default_factory=dict)
    playbooks_by_effort: dict[str, int] = Field(default_factory=dict)
    average_risk_reduction_points: float = Field(..., ge=0.0)
    covered_compliance_controls: list[str] = Field(default_factory=list)
    mitigated_shap_features: list[str] = Field(default_factory=list)
