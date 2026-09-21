"""
Unit Tests — Compliance Controls Catalog
========================================
Tests deterministic evaluation of individual compliance controls across
CIS AWS, Azure, GCP, NIST 800-53, ISO 27001, and PCI-DSS 4.0.
"""

from datetime import datetime, timezone
import pytest

from app.compliance.controls.catalog import (
    CisAwsCloudTrailEnabledControl,
    CisAwsMfaConsoleControl,
    CisAwsRootAccountControl,
    CisAwsS3PublicReadControl,
    CisAzureMfaPrivilegedControl,
    CisAzureSshRestrictedControl,
    CisAzureStorageNetworkAccessControl,
    CisGcpCorporateCredentialsControl,
    CisGcpKmsKeyAccessControl,
    CisGcpStorageUniformAccessControl,
    IsoA942SecureLogonControl,
    IsoA124AuditLoggingControl,
    NistAc2AccountManagementControl,
    NistAu2EventLoggingControl,
    NistSc28ProtectionAtRestControl,
    PciDss34CardholderDataProtectionControl,
    PciDss83MultiFactorAuthControl,
)
from app.core.taxonomy import (
    ActorType,
    CanonicalAction,
    CloudProvider,
    OutcomeType,
    SeverityLevel,
)
from app.schemas.compliance import ComplianceFramework, ComplianceStatus
from app.schemas.events import CloudSecurityEvent


def make_sample_event(
    provider: CloudProvider = CloudProvider.AWS,
    actor_type: ActorType = ActorType.USER,
    actor_name: str = "alice",
    mfa_used: bool = True,
    action: CanonicalAction = CanonicalAction.COMPUTE_INSTANCE_LAUNCH,
    raw_action: str = "RunInstances",
    resource_type: str = "ec2:Instance",
    resource_id: str = "i-0123456789abcdef0",
    additional_context: dict = None,
) -> CloudSecurityEvent:
    return CloudSecurityEvent(
        event_id="evt-sample-01",
        timestamp=datetime.now(timezone.utc),
        cloud_provider=provider,
        resource_type=resource_type,
        resource_id=resource_id,
        canonical_action=action,
        raw_action=raw_action,
        actor_type=actor_type,
        actor_name=actor_name,
        source_ip="10.0.0.1",
        mfa_used=mfa_used,
        outcome=OutcomeType.SUCCESS,
        session_duration_s=3600,
        has_session=True,
        metadata_payload=additional_context or {},
    )


class TestCisAwsControls:
    def test_root_account_control_pass(self):
        ctrl = CisAwsRootAccountControl()
        assert ctrl.framework == ComplianceFramework.CIS_AWS_1_4
        assert ctrl.severity == SeverityLevel.CRITICAL
        event = make_sample_event(actor_type=ActorType.USER, actor_name="admin")
        result = ctrl.evaluate([event])
        assert result.status == ComplianceStatus.PASS
        assert result.failed_resources == 0

    def test_root_account_control_fail(self):
        ctrl = CisAwsRootAccountControl()
        event = make_sample_event(actor_type=ActorType.ROOT, actor_name="root")
        result = ctrl.evaluate([event])
        assert result.status == ComplianceStatus.FAIL
        assert result.failed_resources == 1
        assert "i-0123456789abcdef0" in result.failed_resource_ids

    def test_mfa_console_control(self):
        ctrl = CisAwsMfaConsoleControl()
        event_mfa = make_sample_event(actor_type=ActorType.USER, mfa_used=True)
        assert ctrl.evaluate([event_mfa]).status == ComplianceStatus.PASS

        event_no_mfa = make_sample_event(actor_type=ActorType.USER, mfa_used=False)
        res = ctrl.evaluate([event_no_mfa])
        assert res.status in (ComplianceStatus.FAIL, ComplianceStatus.PARTIAL)
        assert res.failed_resources == 1

    def test_s3_public_read_control(self):
        ctrl = CisAwsS3PublicReadControl()
        clean_event = make_sample_event(resource_type="s3:Bucket", action=CanonicalAction.STORAGE_BUCKET_CREATE)
        assert ctrl.evaluate([clean_event]).status == ComplianceStatus.PASS

        violating_event = make_sample_event(
            resource_type="s3:Bucket",
            action=CanonicalAction.STORAGE_ACL_MODIFY,
            additional_context={"public": True},
        )
        res = ctrl.evaluate([violating_event])
        assert res.status == ComplianceStatus.FAIL
        assert res.failed_resources == 1

    def test_cloudtrail_enabled_control(self):
        ctrl = CisAwsCloudTrailEnabledControl()
        clean_event = make_sample_event(action=CanonicalAction.GENERIC_WRITE, raw_action="StartLogging")
        assert ctrl.evaluate([clean_event]).status == ComplianceStatus.PASS

        stopped_event = make_sample_event(action=CanonicalAction.LOGGING_CONFIG_DISABLE, raw_action="StopLogging")
        res = ctrl.evaluate([stopped_event])
        assert res.status == ComplianceStatus.FAIL
        assert res.failed_resources == 1


class TestCisAzureControls:
    def test_azure_mfa_privileged_control(self):
        ctrl = CisAzureMfaPrivilegedControl()
        assert ctrl.framework == ComplianceFramework.CIS_AZURE_2_0
        event_ok = make_sample_event(provider=CloudProvider.AZURE, mfa_used=True)
        assert ctrl.evaluate([event_ok]).status == ComplianceStatus.PASS

        event_fail = make_sample_event(provider=CloudProvider.AZURE, mfa_used=False)
        assert ctrl.evaluate([event_fail]).status == ComplianceStatus.FAIL

    def test_azure_ssh_restricted_control(self):
        ctrl = CisAzureSshRestrictedControl()
        clean_event = make_sample_event(provider=CloudProvider.AZURE, action=CanonicalAction.NETWORK_SECURITY_GROUP_MODIFY)
        res = ctrl.evaluate([clean_event])
        assert res.status == ComplianceStatus.FAIL  # Action triggers evaluation of NSG modification

        safe_event = make_sample_event(provider=CloudProvider.AZURE, action=CanonicalAction.COMPUTE_INSTANCE_LAUNCH)
        assert ctrl.evaluate([safe_event]).status == ComplianceStatus.PASS


class TestCisGcpControls:
    def test_gcp_corporate_credentials_control(self):
        ctrl = CisGcpCorporateCredentialsControl()
        corp_event = make_sample_event(provider=CloudProvider.GCP, actor_name="admin@enterprise.com")
        assert ctrl.evaluate([corp_event]).status == ComplianceStatus.PASS

        gmail_event = make_sample_event(provider=CloudProvider.GCP, actor_name="badactor@gmail.com")
        res = ctrl.evaluate([gmail_event])
        assert res.status == ComplianceStatus.FAIL
        assert res.failed_resources == 1

    def test_gcp_kms_key_access_control(self):
        ctrl = CisGcpKmsKeyAccessControl()
        clean_event = make_sample_event(provider=CloudProvider.GCP, action=CanonicalAction.KMS_KEY_CREATE)
        assert ctrl.evaluate([clean_event]).status == ComplianceStatus.PASS

        deleted_key = make_sample_event(provider=CloudProvider.GCP, action=CanonicalAction.KMS_KEY_SCHEDULE_DELETE)
        assert ctrl.evaluate([deleted_key]).status == ComplianceStatus.FAIL


class TestNistAndIsoControls:
    def test_nist_ac_2_control(self):
        ctrl = NistAc2AccountManagementControl()
        clean_event = make_sample_event(actor_type=ActorType.USER, actor_name="developer", mfa_used=True)
        assert ctrl.evaluate([clean_event]).status == ComplianceStatus.PASS

        root_event = make_sample_event(actor_type=ActorType.ROOT, actor_name="root")
        assert ctrl.evaluate([root_event]).status == ComplianceStatus.FAIL

    def test_iso_a942_control(self):
        ctrl = IsoA942SecureLogonControl()
        mfa_event = make_sample_event(mfa_used=True)
        assert ctrl.evaluate([mfa_event]).status == ComplianceStatus.PASS

        no_mfa_event = make_sample_event(mfa_used=False)
        assert ctrl.evaluate([no_mfa_event]).status == ComplianceStatus.FAIL


class TestPciDssControls:
    def test_pci_dss_34_control(self):
        ctrl = PciDss34CardholderDataProtectionControl()
        clean = make_sample_event(resource_type="s3:Bucket", action=CanonicalAction.STORAGE_BUCKET_CREATE)
        assert ctrl.evaluate([clean]).status == ComplianceStatus.PASS

        violating = make_sample_event(
            resource_type="s3:Bucket",
            action=CanonicalAction.STORAGE_ACL_MODIFY,
            additional_context={"financial": True},
        )
        assert ctrl.evaluate([violating]).status == ComplianceStatus.FAIL

    def test_pci_dss_83_mfa_control(self):
        ctrl = PciDss83MultiFactorAuthControl()
        mfa_event = make_sample_event(mfa_used=True)
        assert ctrl.evaluate([mfa_event]).status == ComplianceStatus.PASS

        no_mfa_event = make_sample_event(mfa_used=False)
        assert ctrl.evaluate([no_mfa_event]).status == ComplianceStatus.FAIL
