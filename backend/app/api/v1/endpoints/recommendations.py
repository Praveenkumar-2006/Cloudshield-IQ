"""
CloudShield IQ — Recommendation API Endpoints
==============================================
REST endpoints for multi-cloud remediation playbooks, prioritized recommendations,
and perimeter posture improvement simulations.
"""

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, status

from app.core.logging import get_logger
from app.core.taxonomy import CloudProvider
from app.recommendations import get_recommendation_engine
from app.schemas.recommendations import (
    BatchPrioritizeRequest,
    BatchPrioritizeResponse,
    EffortLevel,
    RecommendationRequest,
    RecommendationResponse,
    RecommendationStats,
    RemediationPlaybook,
    RemediationSimulationRequest,
    RemediationSimulationResult,
)

logger = get_logger(__name__)
router = APIRouter()


@router.get(
    "/playbooks",
    summary="List Remediation Playbooks",
    response_model=list[RemediationPlaybook],
    status_code=status.HTTP_200_OK,
)
async def list_playbooks(
    provider: Optional[str] = Query(
        default=None,
        description="Filter playbooks by cloud provider (AWS, AZURE, GCP).",
    ),
    category: Optional[str] = Query(
        default=None,
        description="Filter playbooks by security category (IAM, Storage, Network, Logging, KMS).",
    ),
    effort: Optional[str] = Query(
        default=None,
        description="Filter playbooks by implementation effort (LOW, MEDIUM, HIGH).",
    ),
) -> list[RemediationPlaybook]:
    """
    Retrieve catalog of standardized multi-cloud remediation playbooks with optional filters.
    """
    engine = get_recommendation_engine()
    return engine.list_playbooks(
        cloud_provider=provider,
        category=category,
        effort_level=effort,
    )


@router.get(
    "/playbooks/{playbook_id}",
    summary="Get Single Remediation Playbook",
    response_model=RemediationPlaybook,
    status_code=status.HTTP_200_OK,
)
async def get_playbook(playbook_id: str) -> RemediationPlaybook:
    """
    Retrieve full playbook details including CLI commands, Terraform snippets, and Python SDK script.
    """
    engine = get_recommendation_engine()
    pb = engine.get_playbook(playbook_id)
    if pb is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook with identifier '{playbook_id}' not found.",
        )
    return pb


@router.post(
    "/generate",
    summary="Generate Context-Aware Recommendation",
    response_model=RecommendationResponse,
    status_code=status.HTTP_200_OK,
)
async def generate_recommendation(
    request: RecommendationRequest,
) -> RecommendationResponse:
    """
    Generate a tailored remediation recommendation, injecting affected resource IDs and parameters
    into multi-language automation templates and calculating priority score and projected risk drop.
    """
    try:
        engine = get_recommendation_engine()
        return engine.generate_recommendation(request)
    except Exception as exc:
        logger.exception("Failed to generate recommendation", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Recommendation synthesis failed: {exc}",
        )


@router.post(
    "/prioritize",
    summary="Batch Prioritize Security Findings",
    response_model=BatchPrioritizeResponse,
    status_code=status.HTTP_200_OK,
)
async def prioritize_findings(
    request: BatchPrioritizeRequest,
) -> BatchPrioritizeResponse:
    """
    Evaluate and rank a collection of security findings into a prioritized remediation queue,
    identifying high-ROI quick wins and total potential risk reduction.
    """
    try:
        engine = get_recommendation_engine()
        return engine.prioritize_findings(request.findings)
    except Exception as exc:
        logger.exception("Failed to prioritize findings", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch prioritization failed: {exc}",
        )


@router.post(
    "/simulate",
    summary="Simulate Remediation Posture Impact",
    response_model=RemediationSimulationResult,
    status_code=status.HTTP_200_OK,
)
async def simulate_remediation(
    request: RemediationSimulationRequest,
) -> RemediationSimulationResult:
    """
    Simulate the execution of specific remediation playbooks and calculate projected perimeter
    risk score reduction and remaining critical finding exposure.
    """
    try:
        engine = get_recommendation_engine()
        return engine.simulate_remediation(request)
    except Exception as exc:
        logger.exception("Failed to simulate remediation", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Remediation simulation failed: {exc}",
        )


@router.get(
    "/stats",
    summary="Get Playbook Catalog Statistics",
    response_model=RecommendationStats,
    status_code=status.HTTP_200_OK,
)
async def get_stats() -> RecommendationStats:
    """
    Retrieve global metrics on available remediation playbooks, effort distributions, and coverage.
    """
    engine = get_recommendation_engine()
    return engine.get_stats()
