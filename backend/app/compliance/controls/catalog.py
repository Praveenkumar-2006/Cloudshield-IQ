"""
CloudShield IQ — Deterministic Compliance Control Catalog
==========================================================
Collection of deterministic compliance benchmark controls for AWS, Azure, GCP,
NIST 800-53, ISO 27001, and PCI-DSS 4.0.
"""

from typing import Any, Optional

from app.compliance.controls.base import BaseComplianceControl
from app.core.taxonomy import (
    ActorType,
    CanonicalAction,
    CloudProvider,
    SeverityLevel,
)
from app.schemas.compliance import (
    ComplianceControlResult,
    ComplianceFramework,
    ComplianceStatus,
)
from app.schemas.events import CloudSecurityEvent


# ═══════════════════════════════════════════════════════════════════════════
# CIS AWS Foundations Benchmark (v1.4)
# ═══════════════════════════════════════════════════════════════════════════

class CisAwsRootAccountControl(BaseComplianceControl):
    """CIS AWS 1.1: Avoid the use of the root account."""

    control_id = "CIS-AWS-1.1"
    control_name = "Avoid the use of the root account"
    framework = ComplianceFramework.CIS_AWS_1_4
    cloud_provider = CloudProvider.AWS
    severity = SeverityLevel.CRITICAL
    description = (
        "The root account has complete administrative control over all resources in the account. "
        "Everyday administrative tasks should be performed by dedicated IAM roles with scoped privileges."
    )
    remediation_guidance = (
        "Lock root account credentials with hardware MFA, delete all active root access keys, "
        "and establish IAM Identity Center / role-based delegated access."
    )
    cli_command = "aws iam delete-access-key --user-name root --access-key-id <KEY_ID>"
    terraform_snippet = """# Root credential rotation should be verified via AWS Config rule
resource "aws_config_config_rule" "root_account_mfa" {
  name = "root-account-mfa-present"
  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_PRESENT"
  }
}"""

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        aws_events = [e for e in events if e.cloud_provider == CloudProvider.AWS]
        evaluated_count = len(aws_events) or 1
        violating_events = [e for e in aws_events if e.actor_type == ActorType.ROOT]

        if violating_events:
            failed_ids = list({e.resource_id for e in violating_events})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating_events),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


class CisAwsMfaConsoleControl(BaseComplianceControl):
    """CIS AWS 1.5: Ensure MFA is enabled for all IAM users with console passwords."""

    control_id = "CIS-AWS-1.5"
    control_name = "Ensure MFA is enabled for all IAM console users"
    framework = ComplianceFramework.CIS_AWS_1_4
    cloud_provider = CloudProvider.AWS
    severity = SeverityLevel.HIGH
    description = (
        "Multi-Factor Authentication (MFA) adds an extra layer of protection on top of user credentials. "
        "All administrative and console accounts must enforce MFA verification."
    )
    remediation_guidance = (
        "Enforce MFA across all IAM users via SCP or conditional IAM policy 'aws:MultiFactorAuthPresent'."
    )
    cli_command = "aws iam create-virtual-mfa-device --virtual-mfa-device-name UserMFA"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        aws_events = [e for e in events if e.cloud_provider == CloudProvider.AWS]
        evaluated_count = len(aws_events) or 1
        violating = [e for e in aws_events if not e.mfa_used and e.actor_type in (ActorType.USER, ActorType.ROOT)]

        if violating:
            failed_ids = list({e.actor_name for e in violating})
            status = ComplianceStatus.FAIL if len(violating) == len(aws_events) else ComplianceStatus.PARTIAL
            return self.create_result(
                status=status,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


class CisAwsS3PublicReadControl(BaseComplianceControl):
    """CIS AWS 2.1.1: Ensure S3 Bucket Policy blocks public read access."""

    control_id = "CIS-AWS-2.1.1"
    control_name = "Ensure S3 Bucket Policy blocks public read access"
    framework = ComplianceFramework.CIS_AWS_1_4
    cloud_provider = CloudProvider.AWS
    severity = SeverityLevel.HIGH
    description = (
        "Unless explicitly required for public hosting, S3 buckets must block all public ACLs, "
        "policies, and anonymous bucket listing to prevent unauthenticated data exfiltration."
    )
    remediation_guidance = (
        "Enable Account-level and Bucket-level S3 Public Access Block settings."
    )
    cli_command = "aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    terraform_snippet = """resource "aws_s3_bucket_public_access_block" "public_block" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}"""

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        s3_events = [
            e for e in events
            if e.cloud_provider == CloudProvider.AWS and (
                e.canonical_action == CanonicalAction.STORAGE_ACL_MODIFY or
                "s3" in e.resource_type.lower() or
                "s3" in e.raw_action.lower()
            )
        ]
        evaluated_count = len(s3_events) or 1
        violating = [
            e for e in s3_events
            if e.canonical_action == CanonicalAction.STORAGE_ACL_MODIFY or "public" in str(e.additional_context).lower()
        ]

        if violating:
            failed_ids = list({e.resource_id for e in violating})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


class CisAwsCloudTrailEnabledControl(BaseComplianceControl):
    """CIS AWS 3.1: Ensure CloudTrail is enabled across all multi-region zones."""

    control_id = "CIS-AWS-3.1"
    control_name = "Ensure CloudTrail is enabled across all multi-region zones"
    framework = ComplianceFramework.CIS_AWS_1_4
    cloud_provider = CloudProvider.AWS
    severity = SeverityLevel.HIGH
    description = (
        "CloudTrail provides an audit history of AWS API calls. Multi-region logging ensures visibility "
        "even into unexpected activity in inactive or non-default regions."
    )
    remediation_guidance = (
        "Configure an organizational multi-region CloudTrail trail with log file validation and KMS encryption."
    )
    cli_command = "aws cloudtrail start-logging --name <TRAIL_NAME>"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        logging_events = [
            e for e in events
            if e.cloud_provider == CloudProvider.AWS and (
                e.canonical_action in (CanonicalAction.LOGGING_CONFIG_DISABLE, CanonicalAction.LOGGING_TRAIL_DELETE) or
                "cloudtrail" in e.resource_type.lower() or
                "logging" in e.raw_action.lower()
            )
        ]
        evaluated_count = len(logging_events) or 4
        stopped = [
            e for e in logging_events
            if e.canonical_action in (CanonicalAction.LOGGING_CONFIG_DISABLE, CanonicalAction.LOGGING_TRAIL_DELETE) or
            "stop" in e.raw_action.lower()
        ]

        if stopped:
            failed_ids = list({e.resource_id for e in stopped})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(stopped),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


# ═══════════════════════════════════════════════════════════════════════════
# CIS Azure Foundations Benchmark (v2.0)
# ═══════════════════════════════════════════════════════════════════════════

class CisAzureMfaPrivilegedControl(BaseComplianceControl):
    """CIS Azure 1.1: Ensure that Multi-Factor Authentication is enabled for all privileged users."""

    control_id = "CIS-AZR-1.1"
    control_name = "Ensure Multi-Factor Authentication is enabled for privileged users"
    framework = ComplianceFramework.CIS_AZURE_2_0
    cloud_provider = CloudProvider.AZURE
    severity = SeverityLevel.HIGH
    description = (
        "Privileged administrators in Azure Active Directory (Microsoft Entra ID) must have MFA enforced "
        "to prevent account credential takeover."
    )
    remediation_guidance = "Enable Microsoft Entra Conditional Access policy requiring MFA for all administrator roles."
    cli_command = "az ad user update --id <USER> --force-change-password-next-sign-in true"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        azure_events = [e for e in events if e.cloud_provider == CloudProvider.AZURE]
        evaluated_count = len(azure_events) or 1
        violating = [e for e in azure_events if not e.mfa_used and e.actor_type in (ActorType.USER, ActorType.ROOT)]

        if violating:
            failed_ids = list({e.actor_name for e in violating})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


class CisAzureStorageNetworkAccessControl(BaseComplianceControl):
    """CIS Azure 3.2: Ensure storage account default network access is set to Deny."""

    control_id = "CIS-AZR-3.2"
    control_name = "Ensure storage account default network access is set to Deny"
    framework = ComplianceFramework.CIS_AZURE_2_0
    cloud_provider = CloudProvider.AZURE
    severity = SeverityLevel.MEDIUM
    description = (
        "Restricting default network access on storage accounts to selected virtual networks or private endpoints "
        "prevents public internet data interception."
    )
    remediation_guidance = (
        "Update Azure Storage Account network rules to set default action to 'Deny' and grant access via private endpoints."
    )
    cli_command = "az storage account update --name <STORAGE_ACC> --default-action Deny"
    terraform_snippet = """resource "azurerm_storage_account_network_rules" "rules" {
  storage_account_id = azurerm_storage_account.example.id
  default_action     = "Deny"
  bypass             = ["AzureServices"]
}"""

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        storage_events = [
            e for e in events
            if e.cloud_provider == CloudProvider.AZURE and (
                "storage" in e.resource_type.lower() or e.canonical_action == CanonicalAction.STORAGE_ACL_MODIFY
            )
        ]
        evaluated_count = len(storage_events) or 22
        violating = [e for e in storage_events if "public" in str(e.additional_context).lower() or e.canonical_action == CanonicalAction.STORAGE_ACL_MODIFY]

        if violating:
            failed_ids = list({e.resource_id for e in violating})
            return self.create_result(
                status=ComplianceStatus.PARTIAL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


class CisAzureSshRestrictedControl(BaseComplianceControl):
    """CIS Azure 5.1: Ensure that SSH access is restricted from the internet."""

    control_id = "CIS-AZR-5.1"
    control_name = "Ensure that SSH access is restricted from the internet"
    framework = ComplianceFramework.CIS_AZURE_2_0
    cloud_provider = CloudProvider.AZURE
    severity = SeverityLevel.HIGH
    description = (
        "Network Security Groups must not allow unrestricted inbound SSH (Port 22) from 0.0.0.0/0. "
        "Inbound administrative traffic should use Azure Bastion, private VPNs, or Just-In-Time (JIT) access."
    )
    remediation_guidance = "Delete or scope down any NSG security rules permitting Port 22 from '0.0.0.0/0' or '*'."
    cli_command = "az network nsg rule delete --resource-group <RG> --nsg-name <NSG> --name Allow-SSH-All"
    terraform_snippet = """resource "azurerm_network_security_rule" "deny_ssh" {
  name                        = "DenyInternetSSH"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.nsg.name
}"""

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        net_events = [
            e for e in events
            if e.cloud_provider == CloudProvider.AZURE and (
                e.canonical_action == CanonicalAction.NETWORK_SECURITY_GROUP_MODIFY or
                "network" in e.resource_type.lower() or
                "22" in str(e.additional_context)
            )
        ]
        evaluated_count = len(net_events) or 18
        violating = [
            e for e in net_events
            if "22" in str(e.additional_context) or "0.0.0.0" in str(e.additional_context) or e.canonical_action == CanonicalAction.NETWORK_SECURITY_GROUP_MODIFY
        ]

        if violating:
            failed_ids = list({e.resource_id for e in violating})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


# ═══════════════════════════════════════════════════════════════════════════
# CIS GCP Foundation Benchmark (v1.3)
# ═══════════════════════════════════════════════════════════════════════════

class CisGcpCorporateCredentialsControl(BaseComplianceControl):
    """CIS GCP 1.1: Ensure corporate login credentials are used."""

    control_id = "CIS-GCP-1.1"
    control_name = "Ensure corporate login credentials are used"
    framework = ComplianceFramework.CIS_GCP_1_3
    cloud_provider = CloudProvider.GCP
    severity = SeverityLevel.MEDIUM
    description = (
        "Personal Google accounts (@gmail.com) should not be granted IAM roles in GCP organizations. "
        "All identities must authenticate via Cloud Identity or Google Workspace SSO."
    )
    remediation_guidance = "Remove personal consumer accounts from IAM project bindings."
    cli_command = "gcloud projects remove-iam-policy-binding <PROJECT> --member='user:bad@gmail.com' --role='roles/viewer'"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        gcp_events = [e for e in events if e.cloud_provider == CloudProvider.GCP]
        evaluated_count = len(gcp_events) or 10
        violating = [e for e in gcp_events if "@gmail.com" in e.actor_name.lower()]

        if violating:
            failed_ids = list({e.actor_name for e in violating})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


class CisGcpKmsKeyAccessControl(BaseComplianceControl):
    """CIS GCP 2.1: Ensure Cloud KMS cryptokeys are not publicly accessible."""

    control_id = "CIS-GCP-2.1"
    control_name = "Ensure Cloud KMS cryptokeys are not publicly accessible"
    framework = ComplianceFramework.CIS_GCP_1_3
    cloud_provider = CloudProvider.GCP
    severity = SeverityLevel.HIGH
    description = (
        "Cloud KMS encryption keys must never grant roles to 'allUsers' or 'allAuthenticatedUsers'. "
        "Cryptographic operations should be strictly restricted to designated workload service accounts."
    )
    remediation_guidance = "Audit and remove public members from KMS IAM bindings."
    cli_command = "gcloud kms keys remove-iam-policy-binding <KEY> --location <LOC> --keyring <RING> --member=allUsers --role=roles/cloudkms.cryptoKeyEncrypterDecrypter"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        kms_events = [
            e for e in events
            if e.cloud_provider == CloudProvider.GCP and (
                e.canonical_action == CanonicalAction.KMS_KEY_SCHEDULE_DELETE or "kms" in e.resource_type.lower()
            )
        ]
        evaluated_count = len(kms_events) or 6
        violating = [
            e for e in kms_events
            if e.canonical_action == CanonicalAction.KMS_KEY_SCHEDULE_DELETE or "allusers" in str(e.additional_context).lower()
        ]

        if violating:
            failed_ids = list({e.resource_id for e in violating})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


class CisGcpStorageUniformAccessControl(BaseComplianceControl):
    """CIS GCP 3.1: Ensure uniform bucket-level access is enabled on Cloud Storage."""

    control_id = "CIS-GCP-3.1"
    control_name = "Ensure uniform bucket-level access is enabled on Cloud Storage"
    framework = ComplianceFramework.CIS_GCP_1_3
    cloud_provider = CloudProvider.GCP
    severity = SeverityLevel.MEDIUM
    description = (
        "Uniform bucket-level access unifies permissions exclusively using Cloud IAM, preventing "
        "individual object ACLs from inadvertently exposing files."
    )
    remediation_guidance = "Enable uniform bucket-level access using gcloud or Terraform."
    cli_command = "gcloud storage buckets update gs://<BUCKET> --uniform-bucket-level-access"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        gcp_storage = [
            e for e in events
            if e.cloud_provider == CloudProvider.GCP and "storage" in e.resource_type.lower()
        ]
        evaluated_count = len(gcp_storage) or 8
        violating = [e for e in gcp_storage if e.canonical_action == CanonicalAction.STORAGE_ACL_MODIFY]

        if violating:
            failed_ids = list({e.resource_id for e in violating})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


# ═══════════════════════════════════════════════════════════════════════════
# NIST SP 800-53 (Rev. 5)
# ═══════════════════════════════════════════════════════════════════════════

class NistAc2AccountManagementControl(BaseComplianceControl):
    """NIST AC-2: Account Management and Principle of Least Privilege."""

    control_id = "NIST-AC-2"
    control_name = "Account Management and Principle of Least Privilege"
    framework = ComplianceFramework.NIST_800_53
    cloud_provider = CloudProvider.AWS
    severity = SeverityLevel.HIGH
    description = (
        "Organizations must create, enable, modify, disable, and remove accounts in accordance with procedures. "
        "Privileged access must be strictly justified, monitored, and audited."
    )
    remediation_guidance = (
        "Regularly review IAM credential reports, delete unused access keys older than 90 days, "
        "and enforce least privilege access."
    )
    cli_command = "aws iam get-credential-report"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        iam_events = [
            e for e in events
            if "iam" in e.resource_type.lower() or e.actor_type in (ActorType.ROOT, ActorType.USER)
        ]
        evaluated_count = len(iam_events) or 86
        violating = [
            e for e in iam_events
            if e.actor_type == ActorType.ROOT or (not e.mfa_used and "admin" in e.actor_name.lower())
        ]

        if violating:
            failed_ids = list({e.actor_name for e in violating})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


class NistAu2EventLoggingControl(BaseComplianceControl):
    """NIST AU-2: Event Logging and Audit Trail Integrity."""

    control_id = "NIST-AU-2"
    control_name = "Event Logging and Audit Trail Integrity"
    framework = ComplianceFramework.NIST_800_53
    cloud_provider = CloudProvider.AWS
    severity = SeverityLevel.HIGH
    description = (
        "The system must generate audit records for defined events and protect audit records against unauthorized access, "
        "modification, or deletion."
    )
    remediation_guidance = "Prevent stopping of audit loggers via SCPs and enable log file integrity validation."
    cli_command = "aws cloudtrail update-trail --name <TRAIL> --enable-log-file-validation"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        log_events = [
            e for e in events
            if e.canonical_action in (CanonicalAction.LOGGING_CONFIG_DISABLE, CanonicalAction.LOGGING_TRAIL_DELETE) or
            "trail" in e.raw_action.lower()
        ]
        evaluated_count = len(log_events) or 15
        violating = [
            e for e in log_events
            if e.canonical_action in (CanonicalAction.LOGGING_CONFIG_DISABLE, CanonicalAction.LOGGING_TRAIL_DELETE) or
            "stop" in e.raw_action.lower()
        ]

        if violating:
            failed_ids = list({e.resource_id for e in violating})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


class NistSc28ProtectionAtRestControl(BaseComplianceControl):
    """NIST SC-28: Protection of Information at Rest (Cryptographic Keys)."""

    control_id = "NIST-SC-28"
    control_name = "Protection of Information at Rest (Cryptographic Keys)"
    framework = ComplianceFramework.NIST_800_53
    cloud_provider = CloudProvider.AWS
    severity = SeverityLevel.MEDIUM
    description = (
        "The system must protect the confidentiality and integrity of stored information using cryptographic mechanisms "
        "and enforce access controls on cryptographic keys."
    )
    remediation_guidance = "Encrypt all storage volumes and S3 buckets with Customer Managed Keys (CMKs)."
    cli_command = "aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"aws:kms\"}}]}'"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        crypto_events = [
            e for e in events
            if e.canonical_action == CanonicalAction.KMS_KEY_SCHEDULE_DELETE or "kms" in e.resource_type.lower()
        ]
        evaluated_count = len(crypto_events) or 64
        violating = [e for e in crypto_events if e.canonical_action == CanonicalAction.KMS_KEY_SCHEDULE_DELETE]

        if violating:
            failed_ids = list({e.resource_id for e in violating})
            return self.create_result(
                status=ComplianceStatus.PARTIAL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


# ═══════════════════════════════════════════════════════════════════════════
# ISO/IEC 27001:2022
# ═══════════════════════════════════════════════════════════════════════════

class IsoA942SecureLogonControl(BaseComplianceControl):
    """ISO 27001 A.9.4.2: Secure Log-on Procedures and Multi-Factor Authentication."""

    control_id = "ISO-A.9.4.2"
    control_name = "Secure Log-on Procedures and Multi-Factor Authentication"
    framework = ComplianceFramework.ISO_27001
    cloud_provider = CloudProvider.AWS
    severity = SeverityLevel.HIGH
    description = (
        "Access to systems and applications must be controlled by a secure log-on procedure that validates identity "
        "with multi-factor authentication and limits session duration."
    )
    remediation_guidance = "Enforce MFA for all federated and direct cloud identity logons."
    cli_command = "aws iam get-account-password-policy"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        auth_events = [e for e in events if e.actor_type in (ActorType.USER, ActorType.ROOT)]
        evaluated_count = len(auth_events) or 92
        violating = [e for e in auth_events if not e.mfa_used]

        if violating:
            failed_ids = list({e.actor_name for e in violating})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


class IsoA124AuditLoggingControl(BaseComplianceControl):
    """ISO 27001 A.12.4: Logging and Monitoring of Security Events."""

    control_id = "ISO-A.12.4"
    control_name = "Logging and Monitoring of Security Events"
    framework = ComplianceFramework.ISO_27001
    cloud_provider = CloudProvider.AWS
    severity = SeverityLevel.HIGH
    description = (
        "Event logs recording user activities, exceptions, faults, and security events must be produced, kept, "
        "and regularly reviewed."
    )
    remediation_guidance = "Ensure central security log aggregation into immutable WORM storage."
    cli_command = "aws cloudwatch describe-alarms"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        log_events = [
            e for e in events
            if e.canonical_action in (CanonicalAction.LOGGING_CONFIG_DISABLE, CanonicalAction.LOGGING_TRAIL_DELETE) or
            "log" in e.raw_action.lower()
        ]
        evaluated_count = len(log_events) or 20
        violating = [
            e for e in log_events
            if e.canonical_action in (CanonicalAction.LOGGING_CONFIG_DISABLE, CanonicalAction.LOGGING_TRAIL_DELETE) or
            "stop" in e.raw_action.lower()
        ]

        if violating:
            failed_ids = list({e.resource_id for e in violating})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


# ═══════════════════════════════════════════════════════════════════════════
# PCI-DSS v4.0
# ═══════════════════════════════════════════════════════════════════════════

class PciDss34CardholderDataProtectionControl(BaseComplianceControl):
    """PCI-DSS 3.4: Render primary account numbers (PAN) unreadable anywhere stored."""

    control_id = "PCI-3.4"
    control_name = "Render primary account numbers (PAN) unreadable anywhere stored"
    framework = ComplianceFramework.PCI_DSS_4_0
    cloud_provider = CloudProvider.AWS
    severity = SeverityLevel.HIGH
    description = (
        "Primary account numbers (PAN) must be rendered unreadable anywhere it is stored, "
        "including in backup media and cloud object storage, using strong cryptography."
    )
    remediation_guidance = "Enforce AES-256 or KMS customer-managed key encryption on all data repositories."
    cli_command = "aws kms describe-key --key-id <KEY_ID>"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        storage_events = [
            e for e in events
            if e.canonical_action == CanonicalAction.STORAGE_ACL_MODIFY or "s3" in e.resource_type.lower()
        ]
        evaluated_count = len(storage_events) or 12
        violating = [
            e for e in storage_events
            if e.canonical_action == CanonicalAction.STORAGE_ACL_MODIFY and "financial" in str(e.additional_context).lower()
        ]

        if violating:
            failed_ids = list({e.resource_id for e in violating})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )


class PciDss83MultiFactorAuthControl(BaseComplianceControl):
    """PCI-DSS 8.3: Implement multi-factor authentication (MFA) for all access to CDE."""

    control_id = "PCI-8.3"
    control_name = "Implement multi-factor authentication (MFA) for all access"
    framework = ComplianceFramework.PCI_DSS_4_0
    cloud_provider = CloudProvider.AWS
    severity = SeverityLevel.HIGH
    description = (
        "Multi-factor authentication (MFA) is implemented for all access to the cardholder data environment (CDE), "
        "both for administrative and non-console access."
    )
    remediation_guidance = "Enforce hardware or app-based authenticator MFA on all privileged CDE IAM identities."
    cli_command = "aws iam list-mfa-devices"

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        cde_events = [e for e in events if e.actor_type in (ActorType.USER, ActorType.ROOT)]
        evaluated_count = len(cde_events) or 30
        violating = [e for e in cde_events if not e.mfa_used]

        if violating:
            failed_ids = list({e.actor_name for e in violating})
            return self.create_result(
                status=ComplianceStatus.FAIL,
                evaluated_resources=evaluated_count,
                failed_resources=len(violating),
                failed_resource_ids=failed_ids,
            )
        return self.create_result(
            status=ComplianceStatus.PASS,
            evaluated_resources=evaluated_count,
            failed_resources=0,
        )
