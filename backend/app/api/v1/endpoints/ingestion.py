"""
CloudShield IQ — Ingestion API Endpoints
========================================
Endpoints for uploading telemetry datasets (CSV, JSON, CloudTrail),
ingesting stream batches, loading sample benchmarks, and querying ingested metrics.
"""

from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, UploadFile, status

from app.core.config import get_settings
from app.core.database import (
    async_session_factory,
    is_db_available,
    mark_db_unavailable,
    reset_db_availability,
)
from app.core.logging import get_logger
from app.repositories.events import EventRepository
from app.schemas.events import CloudSecurityEvent
from app.services.ingestion import (
    IngestionPipeline,
    IngestionResult,
    IngestionStats,
    get_ingestion_store,
)

logger = get_logger(__name__)
router = APIRouter()
pipeline = IngestionPipeline()
store = get_ingestion_store()


async def _persist_events_safely(events: list[CloudSecurityEvent]) -> None:
    """Asynchronously persist events to EventRepository when database is online."""
    if not events or not is_db_available():
        return
    try:
        async with async_session_factory() as session:
            repo = EventRepository(session)
            await repo.create_batch_from_schemas(events)
            await session.commit()
            reset_db_availability()
    except Exception as exc:
        mark_db_unavailable()
        logger.debug("Database event persistence skipped (offline mode)", error=str(exc))


@router.post(
    "/upload",
    summary="Upload and ingest cloud security telemetry file",
    description="Accepts CSV or JSON security telemetry log exports, normalizes records, and evaluates risk.",
    response_model=IngestionResult,
    status_code=status.HTTP_200_OK,
)
async def upload_telemetry_file(
    file: UploadFile = File(..., description="CSV or JSON log file export"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
) -> IngestionResult:
    settings = get_settings()

    filename = file.filename or "uploaded_telemetry"
    ext = Path(filename).suffix.lower()

    if ext not in settings.ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format '{ext}'. Allowed extensions: {settings.ALLOWED_UPLOAD_EXTENSIONS}",
        )

    content = await file.read()
    if len(content) > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB}MB.",
        )

    if ext == ".csv":
        result = pipeline.parse_csv_bytes(content, filename=filename)
    else:
        result = pipeline.parse_json_bytes(content, filename=filename)

    logger.info(
        "File ingested successfully",
        filename=filename,
        events_count=result.successful_events,
        anomalies=result.risk_summary["anomalies_detected"],
    )
    if result.successful_events > 0 and store.events:
        background_tasks.add_task(_persist_events_safely, store.events[-result.successful_events:])
    return result


@router.post(
    "/events",
    summary="Ingest batch of JSON telemetry event records",
    description="Directly ingest a list of raw event dictionaries for normalization and risk evaluation.",
    response_model=IngestionResult,
    status_code=status.HTTP_200_OK,
)
async def ingest_event_batch(
    records: list[dict[str, Any]],
    background_tasks: BackgroundTasks = BackgroundTasks(),
) -> IngestionResult:
    if not records:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must contain at least one event record.",
        )
    result = pipeline.process_raw_records(records, filename="api_batch")
    if result.successful_events > 0 and store.events:
        background_tasks.add_task(_persist_events_safely, store.events[-result.successful_events:])
    return result


@router.post(
    "/sample/{sample_type}",
    summary="Load standard sample benchmark dataset",
    description="Loads pre-configured synthetic or sample cloud security logs (synthetic, cloudtrail, azure, gcp, attack_scenario).",
    response_model=IngestionResult,
    status_code=status.HTTP_200_OK,
)
async def load_sample_dataset(
    sample_type: Literal["synthetic", "cloudtrail", "azure", "gcp", "attack_scenario"],
    limit: Optional[int] = Query(None, ge=1, le=50000, description="Optional cap on records to ingest"),
) -> IngestionResult:
    # Try reading from datasets directory if present
    base_dir = Path(__file__).resolve().parent.parent.parent.parent.parent.parent
    synthetic_dir = base_dir / "datasets" / "synthetic"

    if sample_type == "synthetic":
        synthetic_csv = synthetic_dir / "cloud_security_events.csv"
        if synthetic_csv.exists():
            with open(synthetic_csv, "rb") as f:
                content = f.read()
            return pipeline.parse_csv_bytes(content, filename="cloud_security_events.csv")

    elif sample_type == "cloudtrail":
        ct_file = synthetic_dir / "aws_cloudtrail_events.json"
        if ct_file.exists():
            with open(ct_file, "rb") as f:
                content = f.read()
            return pipeline.parse_json_bytes(content, filename="aws_cloudtrail_events.json")

    elif sample_type == "azure":
        az_file = synthetic_dir / "azure_activity_events.json"
        if az_file.exists():
            with open(az_file, "rb") as f:
                content = f.read()
            return pipeline.parse_json_bytes(content, filename="azure_activity_events.json")

    elif sample_type == "gcp":
        gcp_file = synthetic_dir / "gcp_audit_events.json"
        if gcp_file.exists():
            with open(gcp_file, "rb") as f:
                content = f.read()
            return pipeline.parse_json_bytes(content, filename="gcp_audit_events.json")

    elif sample_type == "attack_scenario":
        atk_file = synthetic_dir / "multi_stage_attack_scenario.json"
        if atk_file.exists():
            with open(atk_file, "rb") as f:
                content = f.read()
            return pipeline.parse_json_bytes(content, filename="multi_stage_attack_scenario.json")

    # Fallback to inline representative samples if files are missing
    if sample_type == "cloudtrail":
        samples = [
            {
                "eventID": "trail-001",
                "eventTime": "2026-09-01T12:00:00Z",
                "eventName": "DeleteTrail",
                "eventSource": "cloudtrail.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "198.51.100.24",
                "userIdentity": {"type": "IAMUser", "userName": "attacker_session", "mfaAuthenticated": "false"},
                "resources": [{"ARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/security-trail"}],
            },
            {
                "eventID": "trail-002",
                "eventTime": "2026-09-01T12:05:00Z",
                "eventName": "PutBucketPolicy",
                "eventSource": "s3.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.88",
                "userIdentity": {"type": "Root", "userName": "root", "mfaAuthenticated": "false"},
                "resources": [{"ARN": "arn:aws:s3:::cloudshield-prod-financial-data"}],
            },
            {
                "eventID": "trail-003",
                "eventTime": "2026-09-01T12:10:00Z",
                "eventName": "GetObject",
                "eventSource": "s3.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "10.0.1.15",
                "userIdentity": {"type": "IAMUser", "userName": "app_worker", "mfaAuthenticated": "true"},
                "resources": [{"ARN": "arn:aws:s3:::cloudshield-prod-analytics"}],
            },
        ]
    elif sample_type == "azure":
        samples = [
            {
                "correlationId": "azr-001",
                "eventTimestamp": "2026-09-01T12:15:00Z",
                "operationName": "Microsoft.Network/networkSecurityGroups/securityRules/write",
                "caller": "devops_admin@contoso.com",
                "resourceId": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-core",
                "status": "Succeeded",
            },
            {
                "correlationId": "azr-002",
                "eventTimestamp": "2026-09-01T12:20:00Z",
                "operationName": "Microsoft.Authorization/roleAssignments/write",
                "caller": "svc-automation-principal",
                "resourceId": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/role-owner",
                "status": "Succeeded",
            },
        ]
    else:  # synthetic / gcp / attack_scenario fallback
        samples = [
            {
                "event_id": "syn-001",
                "timestamp": "2026-09-01T12:30:00Z",
                "cloud_provider": "aws",
                "action": "DisableKey",
                "actor_type": "root",
                "actor_name": "root",
                "resource_type": "AWS::KMS::Key",
                "resource_id": "arn:aws:kms:us-east-1:123456789012:key/key-7788",
                "outcome": "Success",
                "mfa_used": False,
            },
            {
                "event_id": "syn-002",
                "timestamp": "2026-09-01T12:35:00Z",
                "cloud_provider": "gcp",
                "action": "storage.buckets.setIamPolicy",
                "actor_type": "user",
                "actor_name": "security_engineer@gcp.com",
                "resource_type": "storage.googleapis.com/Bucket",
                "resource_id": "projects/_/buckets/cloudshield-reports",
                "outcome": "Success",
                "mfa_used": True,
            },
            {
                "event_id": "syn-003",
                "timestamp": "2026-09-01T12:40:00Z",
                "cloud_provider": "azure",
                "action": "Microsoft.Compute/virtualMachines/write",
                "actor_type": "user",
                "actor_name": "developer_bob@contoso.com",
                "resource_type": "Microsoft.Compute/virtualMachines",
                "resource_id": "/subscriptions/sub-1/resourceGroups/rg-prod/virtualMachines/vm-app-01",
                "outcome": "Success",
                "mfa_used": True,
            },
        ]

    return pipeline.process_raw_records(samples, filename=f"sample_{sample_type}.json")


@router.get(
    "/stats",
    summary="Get aggregated ingestion statistics",
    description="Returns total events ingested, provider distribution, anomalies detected, and severity breakdowns.",
    response_model=IngestionStats,
    status_code=status.HTTP_200_OK,
)
async def get_ingestion_statistics() -> IngestionStats:
    return store.stats


@router.get(
    "/events",
    summary="List ingested events",
    description="Paginated list of normalized canonical security telemetry events.",
)
async def list_ingested_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    provider: Optional[str] = None,
) -> dict[str, Any]:
    filtered = store.events
    if provider:
        filtered = [e for e in filtered if e.cloud_provider.value.lower() == provider.lower()]

    page = filtered[offset : offset + limit]
    return {
        "total": len(filtered),
        "limit": limit,
        "offset": offset,
        "events": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "cloud_provider": e.cloud_provider.value,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "raw_action": e.raw_action,
                "canonical_action": e.canonical_action.value,
                "actor_type": e.actor_type.value,
                "actor_name": e.actor_name,
                "outcome": e.outcome.value,
                "mfa_used": e.mfa_used,
            }
            for e in page
        ],
    }


@router.get(
    "/findings",
    summary="List security findings generated from ingested telemetry",
    description="Returns actionable security findings with remediation guidance.",
)
async def list_ingested_findings(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
) -> dict[str, Any]:
    filtered = store.findings
    if severity:
        filtered = [f for f in filtered if f.severity.value.lower() == severity.lower()]

    page = filtered[offset : offset + limit]
    return {
        "total": len(filtered),
        "limit": limit,
        "offset": offset,
        "findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "cloud_provider": f.cloud_provider.value,
                "resource_id": f.resource_id,
                "category": f.category,
                "severity": f.severity.value,
                "risk_score": f.risk_score,
                "compliance_violations": f.compliance_violations,
                "remediation_guidance": f.remediation_guidance,
                "cli_remediation_command": f.cli_remediation_command,
                "terraform_remediation_snippet": f.terraform_remediation_snippet,
            }
            for f in page
        ],
    }
