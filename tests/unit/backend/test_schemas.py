"""
CloudShield IQ — Schema & Normalization Unit Tests
=================================================
Tests for Pydantic v2 schemas, canonical action taxonomy mapping,
and multi-cloud telemetry normalizer.
"""

from datetime import datetime
import pytest
from pydantic import ValidationError

from app.core.taxonomy import (
    ActorType,
    CanonicalAction,
    CloudProvider,
    OutcomeType,
    SeverityLevel,
    resolve_canonical_action,
)
from app.schemas.assessments import RiskAssessment, SecurityFinding, SecurityFindingCreate
from app.schemas.compliance import (
    ComplianceControlResult,
    ComplianceFramework,
    ComplianceStatus,
    ComplianceSummary,
)
from app.schemas.events import (
    CloudSecurityEvent,
    CloudSecurityEventBatch,
    CloudSecurityEventCreate,
)
from app.services.normalizer import TelemetryNormalizer


class TestCanonicalTaxonomy:
    """Test multi-cloud action resolution to canonical security vocabulary."""

    def test_aws_action_mapping(self):
        assert resolve_canonical_action("RunInstances", "aws") == CanonicalAction.COMPUTE_INSTANCE_LAUNCH
        assert resolve_canonical_action("PutBucketPolicy", "aws") == CanonicalAction.STORAGE_POLICY_MODIFY
        assert resolve_canonical_action("CreateAccessKey", "aws") == CanonicalAction.IAM_KEY_CREATE
        assert resolve_canonical_action("DisableKey", "aws") == CanonicalAction.KMS_KEY_DISABLE

    def test_azure_action_mapping(self):
        assert resolve_canonical_action(
            "Microsoft.Compute/virtualMachines/write", "azure"
        ) == CanonicalAction.COMPUTE_INSTANCE_LAUNCH
        assert resolve_canonical_action(
            "Microsoft.Authorization/roleAssignments/write", "azure"
        ) == CanonicalAction.IAM_POLICY_ATTACH

    def test_gcp_action_mapping(self):
        assert resolve_canonical_action(
            "compute.instances.insert", "gcp"
        ) == CanonicalAction.COMPUTE_INSTANCE_LAUNCH
        assert resolve_canonical_action(
            "storage.buckets.setIamPolicy", "gcp"
        ) == CanonicalAction.STORAGE_POLICY_MODIFY

    def test_heuristic_fallback(self):
        assert resolve_canonical_action("DescribeVpcs", "aws") == CanonicalAction.GENERIC_READ
        assert resolve_canonical_action("UpdateRoutingTable", "aws") == CanonicalAction.GENERIC_WRITE
        assert resolve_canonical_action("completely_unknown_action_xyz", "aws") == CanonicalAction.UNKNOWN_OR_CUSTOM


class TestEventSchemas:
    """Test Pydantic v2 CloudSecurityEvent creation and validation."""

    def test_valid_event_creation(self):
        payload = {
            "timestamp": "2025-06-01T12:00:00Z",
            "cloud_provider": "aws",
            "resource_type": "AWS::S3::Bucket",
            "resource_id": "arn:aws:s3:::my-bucket",
            "raw_action": "PutBucketPolicy",
            "actor_type": "user",
            "actor_name": "admin_user",
            "outcome": "Success",
            "session_duration_s": 3600,
        }
        create_schema = CloudSecurityEventCreate(**payload)
        assert create_schema.cloud_provider == CloudProvider.AWS
        assert create_schema.session_duration_s == 3600

        canonical_event = CloudSecurityEvent.from_create(create_schema)
        assert canonical_event.canonical_action == CanonicalAction.STORAGE_POLICY_MODIFY
        assert canonical_event.has_session is True
        assert canonical_event.event_id is not None

    def test_null_session_duration(self):
        payload = {
            "timestamp": "2025-06-01T12:00:00Z",
            "cloud_provider": "azure",
            "resource_type": "Microsoft.Compute/virtualMachines",
            "raw_action": "Microsoft.Compute/virtualMachines/write",
            "actor_type": "service_account",
            "actor_name": "sp-deployer",
            "session_duration_s": None,
        }
        create_schema = CloudSecurityEventCreate(**payload)
        canonical_event = CloudSecurityEvent.from_create(create_schema)
        assert canonical_event.session_duration_s is None
        assert canonical_event.has_session is False

    def test_invalid_provider_raises_error(self):
        payload = {
            "timestamp": "2025-06-01T12:00:00Z",
            "cloud_provider": "invalid_cloud_provider",
            "resource_type": "Unknown",
            "raw_action": "DoSomething",
            "actor_type": "user",
            "actor_name": "someone",
        }
        with pytest.raises(ValidationError):
            CloudSecurityEventCreate(**payload)

    def test_batch_event_schema(self):
        events = [
            CloudSecurityEventCreate(
                timestamp=datetime.utcnow(),
                cloud_provider=CloudProvider.AWS,
                resource_type="IAMUser",
                raw_action="CreateUser",
                actor_type=ActorType.ROOT,
                actor_name="root",
            ),
            CloudSecurityEventCreate(
                timestamp=datetime.utcnow(),
                cloud_provider=CloudProvider.GCP,
                resource_type="StorageBucket",
                raw_action="storage.buckets.create",
                actor_type=ActorType.USER,
                actor_name="dev@company.com",
            ),
        ]
        batch = CloudSecurityEventBatch(events=events, batch_source="test_stream")
        assert len(batch.events) == 2


class TestAssessmentSchemas:
    """Test ML risk assessment and security finding schemas."""

    def test_valid_risk_assessment(self):
        assessment = RiskAssessment(
            cloud_provider=CloudProvider.AWS,
            risk_score=85.5,
            anomaly_score=0.92,
            is_anomaly=True,
            severity=SeverityLevel.HIGH,
            shap_values={"iam_root_access_key_active": 0.42, "mfa_used": -0.15},
            top_feature="iam_root_access_key_active",
            top_feature_impact=0.42,
        )
        assert assessment.is_anomaly is True
        assert assessment.severity == SeverityLevel.HIGH
        assert assessment.risk_score == 85.5

    def test_risk_score_bounds_validation(self):
        with pytest.raises(ValidationError):
            RiskAssessment(
                cloud_provider=CloudProvider.AWS,
                risk_score=150.0,  # Out of [0, 100] bounds
                anomaly_score=0.5,
                is_anomaly=False,
                severity=SeverityLevel.MEDIUM,
            )

    def test_security_finding_schema(self):
        finding_data = SecurityFindingCreate(
            title="Root Access Key Active Without MFA",
            cloud_provider=CloudProvider.AWS,
            resource_id="arn:aws:iam::123456789012:root",
            category="IAM",
            severity=SeverityLevel.CRITICAL,
            risk_score=96.4,
            compliance_violations=["CIS-AWS-1.1", "NIST-AC-2"],
            remediation_guidance="Delete active root access key.",
            cli_remediation_command="aws iam delete-access-key --access-key-id AKIAEXAMPLE",
        )
        finding = SecurityFinding(**finding_data.model_dump())
        assert finding.finding_id.startswith("FND-")
        assert finding.status == "OPEN"
        assert len(finding.compliance_violations) == 2


class TestComplianceSchemas:
    """Test deterministic compliance result schemas."""

    def test_compliance_control_result(self):
        result = ComplianceControlResult(
            control_id="CIS-AWS-1.1",
            control_name="Maintain active contact info and security questions",
            framework=ComplianceFramework.CIS_AWS_1_4,
            cloud_provider=CloudProvider.AWS,
            status=ComplianceStatus.PASS,
            severity=SeverityLevel.LOW,
            evaluated_resources=1,
            failed_resources=0,
        )
        assert result.status == ComplianceStatus.PASS
        assert result.failed_resources == 0

    def test_compliance_summary(self):
        summary = ComplianceSummary(
            overall_pass_rate=75.0,
            total_controls=4,
            passed_controls=3,
            failed_controls=1,
            partial_controls=0,
            framework_scores={"CIS AWS 1.4": 75.0},
        )
        assert summary.overall_pass_rate == 75.0


class TestTelemetryNormalizer:
    """Test normalization service against synthetic and cloud records."""

    def test_synthetic_row_normalization(self):
        row = {
            "event_id": "evt-001",
            "timestamp": "2025-05-15T08:30:00Z",
            "cloud_provider": "aws",
            "resource_type": "AWS::IAM::AccessKey",
            "action": "CreateAccessKey",
            "actor_type": "root",
            "actor_name": "root_account",
            "source_ip": "198.51.100.24",
            "region": "us-east-1",
            "mfa_used": False,
            "outcome": "Success",
            "session_duration_s": None,
        }
        event = TelemetryNormalizer.normalize_synthetic_record(row)
        assert event.event_id == "evt-001"
        assert event.canonical_action == CanonicalAction.IAM_KEY_CREATE
        assert event.actor_type == ActorType.ROOT
        assert event.has_session is False

    def test_aws_cloudtrail_record_normalization(self):
        record = {
            "eventID": "trail-uuid-1234",
            "eventTime": "2025-05-15T14:22:00Z",
            "eventName": "RunInstances",
            "eventSource": "ec2.amazonaws.com",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "203.0.113.195",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "alice_developer",
                "mfaAuthenticated": "true",
            },
            "resources": [{"ARN": "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0"}],
            "requestParameters": {"instanceType": "t3.micro"},
        }
        event = TelemetryNormalizer.normalize_aws_cloudtrail(record)
        assert event.event_id == "trail-uuid-1234"
        assert event.canonical_action == CanonicalAction.COMPUTE_INSTANCE_LAUNCH
        assert event.mfa_used is True
        assert event.cloud_provider == CloudProvider.AWS
        assert event.actor_name == "alice_developer"
