"""
CloudShield IQ — Cloud Security Event Schemas
============================================
Pydantic v2 schemas for raw ingestion, canonical validation, and event representation.
"""

from datetime import datetime, timezone
from typing import Any, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.taxonomy import (
    ActorType,
    CanonicalAction,
    CloudProvider,
    OutcomeType,
    SeverityLevel,
    resolve_canonical_action,
)


class CloudSecurityEventBase(BaseModel):
    """Core attributes common to all security telemetry events."""

    timestamp: datetime = Field(
        ...,
        description="Event generation timestamp in UTC (ISO 8601).",
    )
    cloud_provider: CloudProvider = Field(
        ...,
        description="Target cloud platform (aws, azure, gcp).",
    )
    event_source: str = Field(
        default="audit_logs",
        max_length=128,
        description="Source telemetry stream (e.g., CloudTrail, AzureActivity, GcpAudit).",
    )
    resource_type: str = Field(
        ...,
        max_length=128,
        description="Type of the affected cloud asset (e.g., S3Bucket, VirtualMachine, IAMRole).",
    )
    resource_id: Optional[str] = Field(
        default=None,
        max_length=512,
        description="Unique identifier / ARN / Resource URI of the affected resource.",
    )
    raw_action: str = Field(
        ...,
        max_length=256,
        description="Original provider-specific API action name.",
    )
    actor_type: ActorType = Field(
        ...,
        description="Principal type that initiated the action.",
    )
    actor_name: str = Field(
        ...,
        max_length=256,
        description="Pseudonymized or canonical name/ID of the actor principal.",
    )
    source_ip: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Origin IP address (IPv4 or IPv6).",
    )
    region: Optional[str] = Field(
        default="global",
        max_length=64,
        description="Cloud region identifier.",
    )
    mfa_used: bool = Field(
        default=False,
        description="Whether multi-factor authentication was present.",
    )
    outcome: OutcomeType = Field(
        default=OutcomeType.SUCCESS,
        description="Execution status of the operation (Success, Failure, Denied).",
    )
    session_duration_s: Optional[int] = Field(
        default=None,
        ge=0,
        description="Active session duration in seconds (Nullable for service principals/API keys).",
    )
    metadata_payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary additional context or raw parameters from log payload.",
    )


class CloudSecurityEventCreate(CloudSecurityEventBase):
    """Payload schema for ingesting new events."""

    event_id: Optional[str] = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Optional custom event UUID, generated automatically if omitted.",
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_datetime(cls, v: Any) -> datetime:
        if isinstance(v, str):
            # Parse ISO 8601 strings
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v

    @field_validator("session_duration_s", mode="before")
    @classmethod
    def handle_null_session(cls, v: Any) -> Optional[int]:
        if v is None or v == "" or (isinstance(v, float) and v != v):  # NaN check
            return None
        return int(float(v))


class CloudSecurityEvent(CloudSecurityEventBase):
    """Canonical event model with resolved standardized action."""

    model_config = ConfigDict(from_attributes=True)

    event_id: str = Field(..., description="Unique event identifier.")
    canonical_action: CanonicalAction = Field(
        ...,
        description="Standardized action resolved via the CloudShield IQ taxonomy.",
    )
    has_session: bool = Field(
        ...,
        description="Derived boolean indicator representing whether session_duration_s was present.",
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Server ingestion timestamp in UTC.",
    )

    @property
    def additional_context(self) -> dict[str, Any]:
        """Backward-compatible alias for metadata_payload."""
        return self.metadata_payload

    @classmethod
    def from_create(cls, create_obj: CloudSecurityEventCreate) -> "CloudSecurityEvent":
        """Factory method to construct canonical event from raw input."""
        canonical_act = resolve_canonical_action(
            create_obj.raw_action, create_obj.cloud_provider
        )
        return cls(
            event_id=create_obj.event_id or str(uuid.uuid4()),
            timestamp=create_obj.timestamp,
            cloud_provider=create_obj.cloud_provider,
            event_source=create_obj.event_source,
            resource_type=create_obj.resource_type,
            resource_id=create_obj.resource_id,
            raw_action=create_obj.raw_action,
            canonical_action=canonical_act,
            actor_type=create_obj.actor_type,
            actor_name=create_obj.actor_name,
            source_ip=create_obj.source_ip,
            region=create_obj.region,
            mfa_used=create_obj.mfa_used,
            outcome=create_obj.outcome,
            session_duration_s=create_obj.session_duration_s,
            has_session=create_obj.session_duration_s is not None,
            metadata_payload=create_obj.metadata_payload,
            created_at=datetime.now(timezone.utc),
        )


class CloudSecurityEventBatch(BaseModel):
    """Batch ingestion wrapper for streaming multi-event payloads."""

    events: list[CloudSecurityEventCreate] = Field(
        ...,
        description="List of security events to ingest (max 1000 per request).",
    )
    batch_source: Optional[str] = Field(
        default=None,
        description="Optional tag identifying batch ingestion run.",
    )
