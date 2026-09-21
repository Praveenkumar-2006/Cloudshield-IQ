"""
CloudShield IQ — Deterministic Security Risk Rule Catalog
=========================================================
Catalog of standard heuristic rules mapping security telemetry events to
threat models, MITRE ATT&CK techniques, and remediation guidance.
"""

from typing import Optional

from app.core.taxonomy import ActorType, CanonicalAction, OutcomeType
from app.ml.rules.base import BaseRiskRule, RuleMatch
from app.schemas.events import CloudSecurityEvent


class RootActivityRule(BaseRiskRule):
    """Detects any control plane activity performed by the root/account owner account."""

    rule_id = "RULE-IAM-001"
    title = "Root Account Activity Detected"
    category = "IAM"
    base_penalty = 40.0
    mitre_technique = "T1078.004"
    compliance_violations = ["CIS-AWS-1.1", "CIS-AWS-1.7", "NIST-AC-2", "PCI-DSS-7.1"]
    remediation_guidance = (
        "Root account usage poses significant risk. Lock the root user credentials with hardware MFA, "
        "delete root access keys, and create dedicated IAM roles for administrative duties."
    )
    cli_remediation_command = "aws iam get-account-summary && aws iam delete-access-key --user-name root"

    def evaluate(self, event: CloudSecurityEvent) -> Optional[RuleMatch]:
        if event.actor_type == ActorType.ROOT:
            return RuleMatch(
                rule_id=self.rule_id,
                title=self.title,
                category=self.category,
                penalty=self.base_penalty,
                description=f"Action '{event.raw_action}' executed using Root credentials on resource '{event.resource_id}'.",
                mitre_technique=self.mitre_technique,
                compliance_violations=self.compliance_violations,
                remediation_guidance=self.remediation_guidance,
                cli_remediation_command=self.cli_remediation_command,
                context={"actor_name": event.actor_name, "raw_action": event.raw_action},
            )
        return None


class PrivilegeEscalationNoMfaRule(BaseRiskRule):
    """Detects high-privilege IAM modifications performed without MFA."""

    rule_id = "RULE-IAM-002"
    title = "IAM Privilege Modification Without MFA"
    category = "IAM"
    base_penalty = 35.0
    mitre_technique = "T1098"
    compliance_violations = ["CIS-AWS-1.5", "CIS-AWS-1.16", "SOC2-CC6.1", "NIST-AC-3"]
    remediation_guidance = (
        "Require Multi-Factor Authentication (MFA) for all IAM policy attachments, user creations, "
        "and access key generation operations via conditional IAM policies."
    )
    terraform_remediation_snippet = (
        'resource "aws_iam_policy" "enforce_mfa" {\n'
        '  name = "EnforceMFAForAdminActions"\n'
        '  policy = jsonencode({\n'
        '    Version = "2012-10-17",\n'
        '    Statement = [{\n'
        '      Effect = "Deny",\n'
        '      Action = ["iam:*"],\n'
        '      Resource = "*",\n'
        '      Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } }\n'
        '    }]\n'
        '  })\n'
        '}'
    )

    _SENSITIVE_ACTIONS = {
        CanonicalAction.IAM_POLICY_ATTACH,
        CanonicalAction.IAM_KEY_CREATE,
        CanonicalAction.IAM_USER_CREATE,
        CanonicalAction.IAM_ROLE_ASSUME,
    }

    def evaluate(self, event: CloudSecurityEvent) -> Optional[RuleMatch]:
        if not event.mfa_used and event.canonical_action in self._SENSITIVE_ACTIONS:
            return RuleMatch(
                rule_id=self.rule_id,
                title=self.title,
                category=self.category,
                penalty=self.base_penalty,
                description=(
                    f"Sensitive IAM action '{event.raw_action}' performed by actor '{event.actor_name}' "
                    f"without multi-factor authentication (MFA)."
                ),
                mitre_technique=self.mitre_technique,
                compliance_violations=self.compliance_violations,
                remediation_guidance=self.remediation_guidance,
                terraform_remediation_snippet=self.terraform_remediation_snippet,
                context={"actor_name": event.actor_name, "mfa_used": str(event.mfa_used)},
            )
        return None


class LoggingTamperingRule(BaseRiskRule):
    """Detects modification or deletion of audit logs and telemetry sinks."""

    rule_id = "RULE-LOG-001"
    title = "Audit Logging Disabled or Deleted"
    category = "Logging"
    base_penalty = 50.0
    mitre_technique = "T1562.001"
    compliance_violations = ["CIS-AWS-3.1", "CIS-AWS-3.2", "SOC2-CC7.2", "NIST-AU-2"]
    remediation_guidance = (
        "Immediately re-enable cloud audit logging (CloudTrail / Azure Activity Log / GCP Audit). "
        "Enforce organizational Service Control Policies (SCPs) preventing any principal from stopping logging."
    )
    cli_remediation_command = "aws cloudtrail start-logging --name <trail-name>"

    _LOGGING_ACTIONS = {
        CanonicalAction.LOGGING_CONFIG_DISABLE,
        CanonicalAction.LOGGING_TRAIL_DELETE,
    }

    def evaluate(self, event: CloudSecurityEvent) -> Optional[RuleMatch]:
        if event.canonical_action in self._LOGGING_ACTIONS:
            return RuleMatch(
                rule_id=self.rule_id,
                title=self.title,
                category=self.category,
                penalty=self.base_penalty,
                description=(
                    f"Audit logging mechanism tampered with: '{event.raw_action}' executed on resource '{event.resource_id}' "
                    f"by actor '{event.actor_name}'."
                ),
                mitre_technique=self.mitre_technique,
                compliance_violations=self.compliance_violations,
                remediation_guidance=self.remediation_guidance,
                cli_remediation_command=self.cli_remediation_command,
                context={"resource_id": str(event.resource_id), "actor_name": event.actor_name},
            )
        return None


class KmsDestructionRule(BaseRiskRule):
    """Detects disabling or deletion of cryptographic keys."""

    rule_id = "RULE-KMS-001"
    title = "Cryptographic Key Disabled or Scheduled for Deletion"
    category = "Cryptography"
    base_penalty = 45.0
    mitre_technique = "T1485"
    compliance_violations = ["CIS-AWS-3.7", "PCI-DSS-3.5", "NIST-SC-12"]
    remediation_guidance = (
        "Cancel pending KMS key deletion if unauthorized. Enable key rotation and enforce strict IAM KMS key policies."
    )
    cli_remediation_command = "aws kms cancel-key-deletion --key-id <key-id>"

    _KMS_ACTIONS = {
        CanonicalAction.KMS_KEY_DISABLE,
        CanonicalAction.KMS_KEY_SCHEDULE_DELETE,
    }

    def evaluate(self, event: CloudSecurityEvent) -> Optional[RuleMatch]:
        if event.canonical_action in self._KMS_ACTIONS:
            return RuleMatch(
                rule_id=self.rule_id,
                title=self.title,
                category=self.category,
                penalty=self.base_penalty,
                description=(
                    f"KMS Cryptographic key action '{event.raw_action}' triggered for key '{event.resource_id}' "
                    f"by principal '{event.actor_name}'."
                ),
                mitre_technique=self.mitre_technique,
                compliance_violations=self.compliance_violations,
                remediation_guidance=self.remediation_guidance,
                cli_remediation_command=self.cli_remediation_command,
                context={"resource_id": str(event.resource_id), "raw_action": event.raw_action},
            )
        return None


class PublicStorageExposureRule(BaseRiskRule):
    """Detects modification of storage policies or ACLs which may expose data publicly."""

    rule_id = "RULE-STR-001"
    title = "Cloud Storage Policy or ACL Modification"
    category = "Storage"
    base_penalty = 30.0
    mitre_technique = "T1530"
    compliance_violations = ["CIS-AWS-2.1.1", "CIS-AWS-2.1.2", "SOC2-CC6.3", "NIST-AC-6"]
    remediation_guidance = (
        "Ensure S3 Public Access Block is enabled at the account and bucket levels. Review bucket policy "
        "statements to ensure no Principal '*' or wildcard actions exist without VPC/IP restrictions."
    )
    cli_remediation_command = (
        "aws s3control put-public-access-block --account-id <account-id> "
        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    )

    _STORAGE_POLICY_ACTIONS = {
        CanonicalAction.STORAGE_POLICY_MODIFY,
        CanonicalAction.STORAGE_ACL_MODIFY,
    }

    def evaluate(self, event: CloudSecurityEvent) -> Optional[RuleMatch]:
        if event.canonical_action in self._STORAGE_POLICY_ACTIONS:
            return RuleMatch(
                rule_id=self.rule_id,
                title=self.title,
                category=self.category,
                penalty=self.base_penalty,
                description=(
                    f"Bucket access control modified via '{event.raw_action}' on '{event.resource_id}' "
                    f"by actor '{event.actor_name}'."
                ),
                mitre_technique=self.mitre_technique,
                compliance_violations=self.compliance_violations,
                remediation_guidance=self.remediation_guidance,
                cli_remediation_command=self.cli_remediation_command,
                context={"resource_id": str(event.resource_id), "actor_name": event.actor_name},
            )
        return None


class NetworkSecurityTamperingRule(BaseRiskRule):
    """Detects modification of firewall security groups or network routes."""

    rule_id = "RULE-NET-001"
    title = "Network Security Group or Routing Modification"
    category = "Network"
    base_penalty = 25.0
    mitre_technique = "T1562.007"
    compliance_violations = ["CIS-AWS-5.1", "CIS-AWS-5.2", "PCI-DSS-1.2", "NIST-SC-7"]
    remediation_guidance = (
        "Review newly created or modified security group ingress rules. Remove rules opening administrative "
        "ports (SSH: 22, RDP: 3389) to 0.0.0.0/0."
    )

    _NETWORK_ACTIONS = {
        CanonicalAction.NETWORK_SECURITY_GROUP_MODIFY,
        CanonicalAction.NETWORK_ROUTE_MODIFY,
    }

    def evaluate(self, event: CloudSecurityEvent) -> Optional[RuleMatch]:
        if event.canonical_action in self._NETWORK_ACTIONS:
            return RuleMatch(
                rule_id=self.rule_id,
                title=self.title,
                category=self.category,
                penalty=self.base_penalty,
                description=(
                    f"Firewall or network routing altered via '{event.raw_action}' on '{event.resource_id}' "
                    f"by principal '{event.actor_name}'."
                ),
                mitre_technique=self.mitre_technique,
                compliance_violations=self.compliance_violations,
                remediation_guidance=self.remediation_guidance,
                context={"resource_id": str(event.resource_id), "raw_action": event.raw_action},
            )
        return None


class DeniedPrivilegedActionRule(BaseRiskRule):
    """Detects unauthorized access attempts / permission denied on sensitive resources."""

    rule_id = "RULE-ACT-001"
    title = "Permission Denied on Privileged Operation"
    category = "Authorization"
    base_penalty = 20.0
    mitre_technique = "T1078"
    compliance_violations = ["NIST-AC-2", "SOC2-CC6.6"]
    remediation_guidance = (
        "Investigate principal for potential compromised credentials or unauthorized reconnaissance activity."
    )

    _SENSITIVE_ACTIONS = {
        CanonicalAction.IAM_POLICY_ATTACH,
        CanonicalAction.IAM_KEY_CREATE,
        CanonicalAction.STORAGE_POLICY_MODIFY,
        CanonicalAction.KMS_KEY_DISABLE,
        CanonicalAction.LOGGING_TRAIL_DELETE,
    }

    def evaluate(self, event: CloudSecurityEvent) -> Optional[RuleMatch]:
        if event.outcome == OutcomeType.DENIED and event.canonical_action in self._SENSITIVE_ACTIONS:
            return RuleMatch(
                rule_id=self.rule_id,
                title=self.title,
                category=self.category,
                penalty=self.base_penalty,
                description=(
                    f"Access Denied on privileged action '{event.raw_action}' for principal '{event.actor_name}' "
                    f"targeting resource '{event.resource_id}'."
                ),
                mitre_technique=self.mitre_technique,
                compliance_violations=self.compliance_violations,
                remediation_guidance=self.remediation_guidance,
                context={"actor_name": event.actor_name, "raw_action": event.raw_action},
            )
        return None


def get_default_rules() -> list[BaseRiskRule]:
    """Return an instantiated list of all active standard risk rules."""
    return [
        RootActivityRule(),
        PrivilegeEscalationNoMfaRule(),
        LoggingTamperingRule(),
        KmsDestructionRule(),
        PublicStorageExposureRule(),
        NetworkSecurityTamperingRule(),
        DeniedPrivilegedActionRule(),
    ]
