"""
CloudShield IQ — Compliance API Endpoints
==========================================
REST endpoints for deterministic compliance benchmark assessment, regulatory
framework inquiries, and compliance audit reporting.
"""

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.compliance import get_compliance_engine
from app.core.logging import get_logger
from app.core.taxonomy import CloudProvider, SeverityLevel
from app.schemas.compliance import (
    ComplianceControlResult,
    ComplianceFramework,
    ComplianceSummary,
)
from app.schemas.events import CloudSecurityEvent, CloudSecurityEventCreate
from app.services.ingestion import get_ingestion_store

logger = get_logger(__name__)
router = APIRouter()


class ControlDetailResponse(BaseModel):
    """Metadata response describing a registered compliance control."""

    control_id: str
    control_name: str
    framework: ComplianceFramework
    cloud_provider: CloudProvider
    severity: SeverityLevel
    description: str
    remediation_guidance: str
    cli_command: Optional[str] = None
    terraform_snippet: Optional[str] = None


class ComplianceEvaluationResponse(BaseModel):
    """Response payload containing control evaluations and overall summary."""

    total_controls: int
    results: list[ComplianceControlResult]
    summary: ComplianceSummary


@router.get(
    "/frameworks",
    summary="List Supported Compliance Frameworks",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
)
async def list_frameworks() -> list[dict[str, Any]]:
    """
    Retrieve metadata for all supported compliance frameworks (CIS, NIST, ISO, PCI-DSS).
    """
    engine = get_compliance_engine()
    return engine.list_frameworks()


@router.get(
    "/controls",
    summary="List Compliance Controls Catalog",
    response_model=list[ControlDetailResponse],
    status_code=status.HTTP_200_OK,
)
async def list_controls(
    framework: Optional[ComplianceFramework] = Query(None, description="Filter by compliance framework"),
    cloud_provider: Optional[CloudProvider] = Query(None, description="Filter by cloud provider"),
) -> list[ControlDetailResponse]:
    """
    Retrieve the catalog of all registered compliance controls.
    """
    engine = get_compliance_engine()
    controls = engine.list_controls(framework=framework, cloud_provider=cloud_provider)
    return [
        ControlDetailResponse(
            control_id=c.control_id,
            control_name=c.control_name,
            framework=c.framework,
            cloud_provider=c.cloud_provider,
            severity=c.severity,
            description=c.description,
            remediation_guidance=c.remediation_guidance,
            cli_command=c.cli_command,
            terraform_snippet=c.terraform_snippet,
        )
        for c in controls
    ]


@router.get(
    "/evaluations",
    summary="Get Evaluated Compliance Status Against Current Telemetry",
    response_model=ComplianceEvaluationResponse,
    status_code=status.HTTP_200_OK,
)
async def get_compliance_evaluations(
    framework: Optional[ComplianceFramework] = Query(None, description="Filter evaluations by framework"),
    cloud_provider: Optional[CloudProvider] = Query(None, description="Filter evaluations by cloud provider"),
) -> ComplianceEvaluationResponse:
    """
    Retrieve deterministic compliance evaluation results computed against currently ingested telemetry.
    If no telemetry has been ingested yet, returns an empty evaluation list and zero pass rate.
    """
    store = get_ingestion_store()
    engine = get_compliance_engine()
    results = engine.evaluate(
        events=store.events,
        framework=framework,
        cloud_provider=cloud_provider,
    )
    summary = engine.calculate_summary(results)
    return ComplianceEvaluationResponse(
        total_controls=len(results),
        results=results,
        summary=summary,
    )


@router.post(
    "/evaluate",
    summary="Evaluate Compliance Against Security Events",
    response_model=ComplianceEvaluationResponse,
    status_code=status.HTTP_200_OK,
)
async def evaluate_compliance(
    events: list[CloudSecurityEventCreate],
    framework: Optional[ComplianceFramework] = Query(None, description="Evaluate specific framework only"),
    cloud_provider: Optional[CloudProvider] = Query(None, description="Filter by cloud provider"),
) -> ComplianceEvaluationResponse:
    """
    Execute deterministic compliance evaluation on a batch of normalized security events.
    """
    if not events:
        return ComplianceEvaluationResponse(
            total_controls=0,
            results=[],
            summary=ComplianceSummary(
                overall_pass_rate=0.0,
                total_controls=0,
                passed_controls=0,
                failed_controls=0,
                partial_controls=0,
                framework_scores={},
                evaluated_at=datetime.now(timezone.utc),
            ),
        )

    engine = get_compliance_engine()

    # Convert event create objects to full CloudSecurityEvents
    full_events: list[CloudSecurityEvent] = []
    for evt in events:
        if isinstance(evt, CloudSecurityEvent):
            full_events.append(evt)
        else:
            full_events.append(CloudSecurityEvent.from_create(evt))

    results = engine.evaluate(
        events=full_events,
        framework=framework,
        cloud_provider=cloud_provider,
    )
    summary = engine.calculate_summary(results)

    logger.info(
        "Compliance evaluation completed",
        total_controls=len(results),
        pass_rate=summary.overall_pass_rate,
        events_evaluated=len(full_events),
    )

    return ComplianceEvaluationResponse(
        total_controls=len(results),
        results=results,
        summary=summary,
    )


@router.get(
    "/summary",
    summary="Get Overall Compliance Posture Summary",
    response_model=ComplianceSummary,
    status_code=status.HTTP_200_OK,
)
async def get_compliance_summary(
    framework: Optional[ComplianceFramework] = Query(None, description="Filter summary by framework"),
) -> ComplianceSummary:
    """
    Compute and retrieve the current compliance posture score across all registered frameworks.
    If no telemetry has been ingested, returns 0.0% with zero controls.
    """
    store = get_ingestion_store()
    engine = get_compliance_engine()
    results = engine.evaluate(events=store.events, framework=framework)
    return engine.calculate_summary(results)


@router.get(
    "/report",
    summary="Generate Formal Compliance Audit Report",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
)
async def generate_audit_report(
    framework: Optional[ComplianceFramework] = Query(None, description="Filter report by framework"),
) -> dict[str, Any]:
    """
    Generate an enterprise compliance audit report containing full control breakdowns.
    """
    store = get_ingestion_store()
    engine = get_compliance_engine()
    results = engine.evaluate(events=store.events, framework=framework)
    return engine.export_audit_report(results)

