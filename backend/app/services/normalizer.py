"""
CloudShield IQ — Multi-Cloud Telemetry Normalization Service
===========================================================
Translates heterogeneous raw cloud security audit logs into the CloudShield IQ
canonical event schema.
"""

from datetime import datetime, timezone
from typing import Any
import uuid

from app.core.logging import get_logger
from app.core.taxonomy import (
    ActorType,
    CloudProvider,
    OutcomeType,
    resolve_canonical_action,
)
from app.schemas.events import CloudSecurityEvent, CloudSecurityEventCreate

logger = get_logger(__name__)


class TelemetryNormalizer:
    """
    Normalizes multi-cloud log records into standardized CloudSecurityEvent objects.
    """

    @classmethod
    def normalize_synthetic_record(cls, row: dict[str, Any]) -> CloudSecurityEvent:
        """
        Normalize a row dictionary from the synthetic security events dataset.
        """
        raw_action = str(row.get("action", "unknown"))
        provider_str = str(row.get("cloud_provider", "aws")).lower()
        provider = CloudProvider(provider_str) if provider_str in CloudProvider._value2member_map_ else CloudProvider.AWS

        actor_str = str(row.get("actor_type", "user")).lower()
        actor_type = ActorType(actor_str) if actor_str in ActorType._value2member_map_ else ActorType.USER

        outcome_str = str(row.get("outcome", "Success"))
        outcome = OutcomeType(outcome_str) if outcome_str in OutcomeType._value2member_map_ else OutcomeType.SUCCESS

        session_dur = row.get("session_duration_s")
        if session_dur is None or session_dur == "" or (isinstance(session_dur, float) and session_dur != session_dur):
            parsed_session = None
        else:
            try:
                parsed_session = int(float(session_dur))
            except (ValueError, TypeError):
                parsed_session = None

        raw_ts = row.get("timestamp")
        if isinstance(raw_ts, str):
            ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        elif isinstance(raw_ts, datetime):
            ts = raw_ts
        else:
            ts = datetime.utcnow()

        event_create = CloudSecurityEventCreate(
            event_id=str(row.get("event_id", uuid.uuid4())),
            timestamp=ts,
            cloud_provider=provider,
            event_source=row.get("event_source", "synthetic_stream"),
            resource_type=str(row.get("resource_type", "UnknownResource")),
            resource_id=row.get("resource_id") or f"res-{uuid.uuid4().hex[:8]}",
            raw_action=raw_action,
            actor_type=actor_type,
            actor_name=str(row.get("actor_name", "unknown_principal")),
            source_ip=str(row.get("source_ip", "127.0.0.1")),
            region=str(row.get("region", "global")),
            mfa_used=bool(row.get("mfa_used", False)),
            outcome=outcome,
            session_duration_s=parsed_session,
            metadata_payload={
                k: v for k, v in row.items()
                if k not in (
                    "event_id", "timestamp", "cloud_provider", "resource_type",
                    "action", "actor_type", "actor_name", "source_ip", "region",
                    "mfa_used", "outcome", "session_duration_s"
                )
            },
        )
        return CloudSecurityEvent.from_create(event_create)

    @classmethod
    def normalize_aws_cloudtrail(cls, record: dict[str, Any]) -> CloudSecurityEvent:
        """
        Extract and normalize native AWS CloudTrail log event.
        """
        user_identity = record.get("userIdentity", {})
        principal_type = user_identity.get("type", "IAMUser").lower()
        
        if "root" in principal_type:
            actor_type = ActorType.ROOT
        elif "assumedrole" in principal_type or "role" in principal_type:
            actor_type = ActorType.ASSUMED_ROLE
        elif "service" in principal_type:
            actor_type = ActorType.SERVICE_ACCOUNT
        else:
            actor_type = ActorType.USER

        actor_name = user_identity.get("userName") or user_identity.get("principalId") or "unknown_aws_actor"
        raw_action = record.get("eventName", "UnknownAWSAction")
        event_time = record.get("eventTime")

        if isinstance(event_time, str):
            ts = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        else:
            ts = datetime.now(timezone.utc)

        error_code = record.get("errorCode")
        outcome = OutcomeType.DENIED if error_code in ("AccessDenied", "UnauthorizedOperation") else (
            OutcomeType.FAILURE if error_code else OutcomeType.SUCCESS
        )

        resources = record.get("resources", [{}])
        resource_id = resources[0].get("ARN") if resources else None
        resource_type = resources[0].get("type") or record.get("eventSource", "AWSResource")

        event_create = CloudSecurityEventCreate(
            event_id=record.get("eventID") or str(uuid.uuid4()),
            timestamp=ts,
            cloud_provider=CloudProvider.AWS,
            event_source="CloudTrail",
            resource_type=resource_type,
            resource_id=resource_id,
            raw_action=raw_action,
            actor_type=actor_type,
            actor_name=actor_name,
            source_ip=record.get("sourceIPAddress"),
            region=record.get("awsRegion", "us-east-1"),
            mfa_used=bool(user_identity.get("mfaAuthenticated") == "true"),
            outcome=outcome,
            session_duration_s=None,
            metadata_payload=record.get("requestParameters") or {},
        )
        return CloudSecurityEvent.from_create(event_create)

    @classmethod
    def normalize_azure_activity_log(cls, record: dict[str, Any]) -> CloudSecurityEvent:
        """
        Extract and normalize native Azure Activity Log event.
        """
        caller = record.get("caller") or "unknown_azure_principal"
        actor_type = ActorType.SERVICE_ACCOUNT if ("@" not in caller and "-" in caller) else ActorType.USER

        operation_name = (
            record.get("operationName", {}).get("value")
            if isinstance(record.get("operationName"), dict)
            else str(record.get("operationName", "Microsoft.Compute/virtualMachines/write"))
        )

        status_str = (
            record.get("status", {}).get("value")
            if isinstance(record.get("status"), dict)
            else str(record.get("status", "Succeeded"))
        )
        if "succeed" in status_str.lower() or "success" in status_str.lower():
            outcome = OutcomeType.SUCCESS
        elif "denied" in status_str.lower() or "forbidden" in status_str.lower():
            outcome = OutcomeType.DENIED
        else:
            outcome = OutcomeType.FAILURE

        event_time = record.get("eventTimestamp") or record.get("submissionTimestamp")
        if isinstance(event_time, str):
            ts = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        else:
            ts = datetime.now(timezone.utc)

        resource_id = record.get("resourceId") or f"/subscriptions/sub-1/resourceGroups/rg-prod/{operation_name.split('/')[-1]}"
        resource_type = record.get("resourceType", {}).get("value") if isinstance(record.get("resourceType"), dict) else record.get("resourceType", "AzureResource")

        event_create = CloudSecurityEventCreate(
            event_id=record.get("correlationId") or record.get("eventDataId") or str(uuid.uuid4()),
            timestamp=ts,
            cloud_provider=CloudProvider.AZURE,
            event_source="AzureActivityLog",
            resource_type=str(resource_type),
            resource_id=str(resource_id),
            raw_action=str(operation_name),
            actor_type=actor_type,
            actor_name=str(caller),
            source_ip=record.get("httpRequest", {}).get("clientIpAddress") if isinstance(record.get("httpRequest"), dict) else record.get("callerIpAddress"),
            region=record.get("resourceLocation", "eastus"),
            mfa_used=bool(record.get("claims", {}).get("amr") == "mfa") if isinstance(record.get("claims"), dict) else False,
            outcome=outcome,
            session_duration_s=None,
            metadata_payload=record.get("properties") if isinstance(record.get("properties"), dict) else {},
        )
        return CloudSecurityEvent.from_create(event_create)

    @classmethod
    def normalize_gcp_audit_log(cls, record: dict[str, Any]) -> CloudSecurityEvent:
        """
        Extract and normalize native GCP Cloud Audit Log event.
        """
        proto_payload = record.get("protoPayload", {})
        auth_info = proto_payload.get("authenticationInfo", {})
        principal_email = auth_info.get("principalEmail", "unknown_gcp_actor")

        actor_type = (
            ActorType.SERVICE_ACCOUNT
            if ("gserviceaccount.com" in principal_email or "serviceAccount" in principal_email)
            else ActorType.USER
        )

        method_name = proto_payload.get("methodName", "v1.compute.instances.insert")
        status_code = proto_payload.get("status", {}).get("code", 0)
        outcome = (
            OutcomeType.DENIED if status_code in (7, 403)
            else (OutcomeType.FAILURE if status_code != 0 else OutcomeType.SUCCESS)
        )

        ts_str = record.get("timestamp")
        if isinstance(ts_str, str):
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        else:
            ts = datetime.now(timezone.utc)

        resource_name = proto_payload.get("resourceName") or record.get("resource", {}).get("labels", {}).get("instance_id") or "gcp-asset"
        resource_type = record.get("resource", {}).get("type", "GcpResource")

        event_create = CloudSecurityEventCreate(
            event_id=record.get("insertId") or str(uuid.uuid4()),
            timestamp=ts,
            cloud_provider=CloudProvider.GCP,
            event_source="GcpAuditLog",
            resource_type=str(resource_type),
            resource_id=str(resource_name),
            raw_action=str(method_name),
            actor_type=actor_type,
            actor_name=str(principal_email),
            source_ip=proto_payload.get("requestMetadata", {}).get("callerIp"),
            region=record.get("resource", {}).get("labels", {}).get("zone", "us-central1"),
            mfa_used=False,
            outcome=outcome,
            session_duration_s=None,
            metadata_payload=proto_payload.get("request") or {},
        )
        return CloudSecurityEvent.from_create(event_create)

    @classmethod
    def normalize_record(cls, record: dict[str, Any]) -> CloudSecurityEvent:
        """
        Auto-detect format (Synthetic CSV/JSON, AWS CloudTrail, Azure Activity, GCP Audit)
        and normalize to canonical CloudSecurityEvent.
        """
        if "eventName" in record or "userIdentity" in record:
            return cls.normalize_aws_cloudtrail(record)
        if "operationName" in record or "caller" in record or "correlationId" in record:
            return cls.normalize_azure_activity_log(record)
        if "protoPayload" in record or "insertId" in record:
            return cls.normalize_gcp_audit_log(record)
        # Default to synthetic / generic structure
        return cls.normalize_synthetic_record(record)

