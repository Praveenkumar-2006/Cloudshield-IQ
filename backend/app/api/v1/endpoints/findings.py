"""
CloudShield IQ — Security Findings Endpoints
============================================
REST API endpoints for querying and triaging actionable multi-cloud security findings.
"""

from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import (
    get_db_session,
    is_db_available,
    mark_db_unavailable,
    reset_db_availability,
)
from app.core.logging import get_logger
from app.repositories.findings import FindingRepository
from app.services.ingestion import get_ingestion_store

logger = get_logger(__name__)
router = APIRouter()


class FindingStatusUpdateRequest(BaseModel):
    status: str = Field(..., description="Target status: OPEN, IN_PROGRESS, or RESOLVED")


class FindingResponse(BaseModel):
    finding_id: str
    title: str
    cloud_provider: str
    resource_id: str
    category: str
    severity: str
    risk_score: float
    shap_top_feature: Optional[str] = None
    shap_impact: Optional[float] = None
    compliance_violations: list[Any] = []
    remediation_guidance: str
    cli_remediation_command: Optional[str] = None
    terraform_remediation_snippet: Optional[str] = None
    status: str
    detected_at: Optional[str] = None
    resolved_at: Optional[str] = None


# Baseline fallback findings for resilient dev/offline mode
FALLBACK_FINDINGS = [
    {
        "finding_id": "FND-AWS-1049",
        "title": "IAM Root User Account Has Active Access Keys Without MFA Enforcement",
        "cloud_provider": "AWS",
        "resource_id": "arn:aws:iam::123456789012:root",
        "category": "IAM",
        "severity": "CRITICAL",
        "risk_score": 96.4,
        "shap_top_feature": "iam_root_access_key_active",
        "shap_impact": 0.42,
        "compliance_violations": ["CIS AWS 1.1", "NIST AC-2(1)", "ISO 27001 A.9.2.1"],
        "remediation_guidance": "Delete active root access keys immediately and enforce hardware token multi-factor authentication (MFA).",
        "cli_remediation_command": "aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE",
        "terraform_remediation_snippet": 'resource "aws_iam_account_password_policy" "strict" {\n  require_symbols = true\n}',
        "status": "OPEN",
    },
    {
        "finding_id": "FND-AWS-2081",
        "title": "S3 Bucket with Sensitive Financial Artifacts Has Public Read/List ACLs Enabled",
        "cloud_provider": "AWS",
        "resource_id": "arn:aws:s3:::cloudshield-prod-analytics-exports",
        "category": "Storage",
        "severity": "CRITICAL",
        "risk_score": 98.2,
        "shap_top_feature": "s3_public_read_acl_enabled",
        "shap_impact": 0.48,
        "compliance_violations": ["CIS AWS 2.1.1", "PCI-DSS 3.4", "NIST SC-28"],
        "remediation_guidance": "Enable S3 Block Public Access at the bucket level and attach explicit restrictive bucket policies.",
        "cli_remediation_command": "aws s3api put-public-access-block --bucket cloudshield-prod-analytics-exports --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        "terraform_remediation_snippet": 'resource "aws_s3_bucket_public_access_block" "block_all" {\n  bucket = "cloudshield-prod-analytics-exports"\n  block_public_acls = true\n}',
        "status": "OPEN",
    },
]


@router.get("", response_model=dict[str, Any])
async def list_security_findings(
    cloud: Optional[str] = Query(None, description="Cloud provider filter (AWS, Azure, GCP)"),
    severity: Optional[str] = Query(None, description="Severity filter (CRITICAL, HIGH, MEDIUM, LOW)"),
    category: Optional[str] = Query(None, description="Category filter (IAM, Storage, Network, etc.)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Lifecycle status (OPEN, IN_PROGRESS, RESOLVED)"),
    search: Optional[str] = Query(None, description="Search term across title, ID, or ARN"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """
    List security findings with multi-cloud filtering, severity sorting, and full-text search.
    Prioritizes PostgreSQL database persistence, falls back to ingested in-memory telemetry,
    and labels data_source clearly.
    """
    if is_db_available():
        try:
            repo = FindingRepository(db)
            items, total = await repo.list_findings(
                cloud_provider=cloud,
                severity=severity,
                category=category,
                status=status_filter,
                search_query=search,
                offset=offset,
                limit=limit,
            )
            reset_db_availability()
            if total > 0:
                return {
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                    "data_source": "database",
                    "findings": [
                        {
                            "finding_id": f.finding_id,
                            "title": f.title,
                            "cloud_provider": f.cloud_provider,
                            "resource_id": f.resource_id,
                            "category": f.category,
                            "severity": f.severity,
                            "risk_score": f.risk_score,
                            "shap_top_feature": f.shap_top_feature,
                            "shap_impact": f.shap_impact,
                            "compliance_violations": f.compliance_violations,
                            "remediation_guidance": f.remediation_guidance,
                            "cli_remediation_command": f.cli_remediation_command,
                            "terraform_remediation_snippet": f.terraform_remediation_snippet,
                            "status": f.status,
                            "detected_at": f.detected_at.isoformat() if f.detected_at else None,
                            "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
                        }
                        for f in items
                    ],
                }
        except Exception as exc:
            mark_db_unavailable()
            logger.warning("Database query failed, checking in-memory store", error=str(exc))

    # Check in-memory ingestion store (from uploaded files or loaded samples)
    store = get_ingestion_store()
    if store.findings:
        filtered = list(store.findings)
        if cloud and cloud.upper() != "ALL":
            filtered = [
                f for f in filtered
                if (f.cloud_provider.value if hasattr(f.cloud_provider, "value") else str(f.cloud_provider)).upper() == cloud.upper()
            ]
        if severity and severity.upper() != "ALL":
            filtered = [
                f for f in filtered
                if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper() == severity.upper()
            ]
        if category and category.upper() != "ALL":
            filtered = [f for f in filtered if f.category.upper() == category.upper()]
        if status_filter and status_filter.upper() != "ALL":
            filtered = [f for f in filtered if "OPEN" == status_filter.upper()]
        if search:
            term = search.lower()
            filtered = [
                f for f in filtered
                if term in f.title.lower() or term in f.finding_id.lower() or term in f.resource_id.lower()
            ]

        page = filtered[offset : offset + limit]
        return {
            "total": len(filtered),
            "offset": offset,
            "limit": limit,
            "data_source": "ingested_memory",
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "cloud_provider": f.cloud_provider.value if hasattr(f.cloud_provider, "value") else str(f.cloud_provider),
                    "resource_id": f.resource_id,
                    "category": f.category,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "risk_score": f.risk_score,
                    "shap_top_feature": f.shap_top_feature,
                    "shap_impact": f.shap_impact,
                    "compliance_violations": f.compliance_violations,
                    "remediation_guidance": f.remediation_guidance,
                    "cli_remediation_command": f.cli_remediation_command,
                    "terraform_remediation_snippet": f.terraform_remediation_snippet,
                    "status": "OPEN",
                }
                for f in page
            ],
        }

    # Dev fallback mode when no data has been uploaded yet
    filtered = FALLBACK_FINDINGS
    if cloud and cloud.upper() != "ALL":
        filtered = [f for f in filtered if f["cloud_provider"].upper() == cloud.upper()]
    if severity and severity.upper() != "ALL":
        filtered = [f for f in filtered if f["severity"].upper() == severity.upper()]

    return {
        "total": len(filtered),
        "offset": 0,
        "limit": limit,
        "data_source": "offline_fallback",
        "findings": filtered,
    }


@router.get("/{finding_id}", response_model=dict[str, Any])
async def get_finding_by_id(
    finding_id: str,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Fetch details and remediation guidance for a specific security finding."""
    if is_db_available():
        try:
            repo = FindingRepository(db)
            finding = await repo.get_by_id(finding_id)
            reset_db_availability()
            if finding:
                return {
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "cloud_provider": finding.cloud_provider,
                    "resource_id": finding.resource_id,
                    "category": finding.category,
                    "severity": finding.severity,
                    "risk_score": finding.risk_score,
                    "shap_top_feature": finding.shap_top_feature,
                    "shap_impact": finding.shap_impact,
                    "compliance_violations": finding.compliance_violations,
                    "remediation_guidance": finding.remediation_guidance,
                    "cli_remediation_command": finding.cli_remediation_command,
                    "terraform_remediation_snippet": finding.terraform_remediation_snippet,
                    "status": finding.status,
                }
        except Exception as exc:
            mark_db_unavailable()
            logger.warning("Database query failed for finding_id", finding_id=finding_id, error=str(exc))

    # Check in-memory store
    store = get_ingestion_store()
    for f in store.findings:
        if f.finding_id == finding_id:
            return {
                "finding_id": f.finding_id,
                "title": f.title,
                "cloud_provider": f.cloud_provider.value if hasattr(f.cloud_provider, "value") else str(f.cloud_provider),
                "resource_id": f.resource_id,
                "category": f.category,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "risk_score": f.risk_score,
                "shap_top_feature": f.shap_top_feature,
                "shap_impact": f.shap_impact,
                "compliance_violations": f.compliance_violations,
                "remediation_guidance": f.remediation_guidance,
                "cli_remediation_command": f.cli_remediation_command,
                "terraform_remediation_snippet": f.terraform_remediation_snippet,
                "status": "OPEN",
            }

    for f in FALLBACK_FINDINGS:
        if f["finding_id"] == finding_id:
            return f

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding '{finding_id}' not found.")


@router.patch("/{finding_id}/status", response_model=dict[str, Any])
async def update_finding_triage_status(
    finding_id: str,
    payload: FindingStatusUpdateRequest,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Update finding triage status (OPEN, IN_PROGRESS, RESOLVED)."""
    target_status = payload.status.upper()
    if target_status not in {"OPEN", "IN_PROGRESS", "RESOLVED"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Status must be one of: OPEN, IN_PROGRESS, RESOLVED",
        )

    if is_db_available():
        try:
            repo = FindingRepository(db)
            updated = await repo.update_status(finding_id, target_status)
            reset_db_availability()
            if updated:
                return {
                    "finding_id": updated.finding_id,
                    "status": updated.status,
                    "resolved_at": updated.resolved_at.isoformat() if updated.resolved_at else None,
                    "message": f"Finding '{finding_id}' updated to {target_status}.",
                }
        except Exception as exc:
            mark_db_unavailable()
            logger.warning("Database update failed for finding_id", finding_id=finding_id, error=str(exc))

    return {
        "finding_id": finding_id,
        "status": target_status,
        "message": f"Finding '{finding_id}' triage status set to {target_status} (Dev Mode).",
    }


@router.post("/{finding_id}/explain", response_model=dict[str, Any])
async def generate_finding_explanation(
    finding_id: str,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """
    Generate a grounded human-readable security explanation for a specific finding.
    Consumes verified pipeline evidence (telemetry, ML scores, SHAP factors, compliance violations,
    and remediation guidance) through the GroundedExplanationService.
    Guarantees 100% grounding, anti-hallucination protection, and zero cloud writes.
    """
    from app.services.llm import GroundedExplanationService

    target_finding: Optional[dict[str, Any]] = None

    if is_db_available():
        try:
            repo = FindingRepository(db)
            finding = await repo.get_by_id(finding_id)
            reset_db_availability()
            if finding:
                target_finding = {
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "cloud_provider": finding.cloud_provider,
                    "resource_id": finding.resource_id,
                    "category": finding.category,
                    "severity": finding.severity,
                    "risk_score": finding.risk_score,
                    "shap_top_feature": finding.shap_top_feature,
                    "shap_impact": finding.shap_impact,
                    "compliance_violations": finding.compliance_violations,
                    "remediation_guidance": finding.remediation_guidance,
                    "cli_remediation_command": finding.cli_remediation_command,
                    "terraform_remediation_snippet": finding.terraform_remediation_snippet,
                    "status": finding.status,
                }
        except Exception as exc:
            mark_db_unavailable()
            logger.warning("Database query failed during explain for finding_id", finding_id=finding_id, error=str(exc))

    if not target_finding:
        store = get_ingestion_store()
        for f in store.findings:
            if f.finding_id == finding_id:
                target_finding = {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "cloud_provider": f.cloud_provider.value if hasattr(f.cloud_provider, "value") else str(f.cloud_provider),
                    "resource_id": f.resource_id,
                    "category": f.category,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "risk_score": f.risk_score,
                    "shap_top_feature": f.shap_top_feature,
                    "shap_impact": f.shap_impact,
                    "compliance_violations": f.compliance_violations,
                    "remediation_guidance": f.remediation_guidance,
                    "cli_remediation_command": f.cli_remediation_command,
                    "terraform_remediation_snippet": f.terraform_remediation_snippet,
                    "status": "OPEN",
                }
                break

    if not target_finding:
        for f in FALLBACK_FINDINGS:
            if f["finding_id"] == finding_id:
                target_finding = f
                break

    if not target_finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding '{finding_id}' not found.")

    evidence_pack = GroundedExplanationService.build_evidence_pack(target_finding)
    explanation = await GroundedExplanationService.generate_explanation(evidence_pack)
    return explanation.model_dump()

