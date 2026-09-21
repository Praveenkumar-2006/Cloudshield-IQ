"""
CloudShield IQ — Health Endpoints
===================================
/api/v1/health/live   — liveness: is the process running?
/api/v1/health/ready  — readiness: can the process serve requests?

These endpoints are intentionally unauthenticated so that:
- Docker HEALTHCHECK can call them without credentials
- Load balancers can use them for routing decisions
- Monitoring systems can poll them freely

They must never return sensitive configuration details.
"""

from typing import Literal

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text

from app.core.database import async_session_factory
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()


class HealthStatus(BaseModel):
    status: Literal["ok", "degraded", "unavailable"]
    service: str
    version: str
    checks: dict[str, str] = {}


@router.get(
    "",
    summary="Health check",
    description="Returns 200 if the process is alive. Does not check dependencies.",
    response_model=HealthStatus,
)
@router.get(
    "/live",
    summary="Liveness probe",
    description="Returns 200 if the process is alive. Does not check dependencies.",
    response_model=HealthStatus,
)
async def liveness() -> HealthStatus:
    return HealthStatus(
        status="ok",
        service="cloudshield-iq",
        version="0.1.0",
    )


@router.get(
    "/ready",
    summary="Readiness probe",
    description="Returns 200 only when all dependencies are reachable.",
    response_model=HealthStatus,
)
async def readiness() -> JSONResponse:
    """
    Check that all required dependencies are reachable.

    Currently checks:
    - PostgreSQL database connectivity

    Returns 200 if all checks pass, 503 if any fail.
    """
    checks: dict[str, str] = {}
    overall_status: Literal["ok", "degraded", "unavailable"] = "ok"

    # Database check
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        logger.warning("Readiness check: database unavailable", error=str(exc))
        checks["database"] = "unavailable"
        overall_status = "unavailable"

    http_status = (
        status.HTTP_200_OK
        if overall_status == "ok"
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )

    return JSONResponse(
        status_code=http_status,
        content=HealthStatus(
            status=overall_status,
            service="cloudshield-iq",
            version="0.1.0",
            checks=checks,
        ).model_dump(),
    )
