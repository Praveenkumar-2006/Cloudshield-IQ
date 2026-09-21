"""
CloudShield IQ — Canonical Action Taxonomy & Provider Mapping
============================================================
Standardized vocabulary for multi-cloud security telemetry.

Normalizes provider-specific API calls (AWS CloudTrail, Azure Activity Logs,
GCP Cloud Audit Logs) into unified canonical security actions for ML anomaly
detection and deterministic compliance rules.
"""

from enum import Enum


class CloudProvider(str, Enum):
    """Supported cloud infrastructure providers."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class ActorType(str, Enum):
    """Categorization of security principals initiating actions."""

    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    ASSUMED_ROLE = "assumed_role"
    API_KEY = "api_key"
    ROOT = "root"


class OutcomeType(str, Enum):
    """Execution result of the cloud API action."""

    SUCCESS = "Success"
    FAILURE = "Failure"
    DENIED = "Denied"


class SeverityLevel(str, Enum):
    """Security risk severity classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CanonicalAction(str, Enum):
    """
    Standardized, vendor-agnostic representation of cloud control-plane actions.
    """

    # --- Identity & Access Management (IAM) ---
    IAM_USER_CREATE = "IAM_USER_CREATE"
    IAM_USER_DELETE = "IAM_USER_DELETE"
    IAM_POLICY_ATTACH = "IAM_POLICY_ATTACH"
    IAM_POLICY_DETACH = "IAM_POLICY_DETACH"
    IAM_KEY_CREATE = "IAM_KEY_CREATE"
    IAM_KEY_DELETE = "IAM_KEY_DELETE"
    IAM_ROLE_ASSUME = "IAM_ROLE_ASSUME"
    IAM_PASSWORD_CHANGE = "IAM_PASSWORD_CHANGE"

    # --- Object & Blob Storage ---
    STORAGE_BUCKET_CREATE = "STORAGE_BUCKET_CREATE"
    STORAGE_BUCKET_DELETE = "STORAGE_BUCKET_DELETE"
    STORAGE_POLICY_MODIFY = "STORAGE_POLICY_MODIFY"
    STORAGE_ACL_MODIFY = "STORAGE_ACL_MODIFY"
    STORAGE_OBJECT_READ = "STORAGE_OBJECT_READ"
    STORAGE_OBJECT_WRITE = "STORAGE_OBJECT_WRITE"
    STORAGE_OBJECT_DELETE = "STORAGE_OBJECT_DELETE"

    # --- Virtual Networking & Firewalls ---
    NETWORK_SECURITY_GROUP_MODIFY = "NETWORK_SECURITY_GROUP_MODIFY"
    NETWORK_ROUTE_MODIFY = "NETWORK_ROUTE_MODIFY"
    NETWORK_GATEWAY_ATTACH = "NETWORK_GATEWAY_ATTACH"
    NETWORK_VPC_PEERING_CREATE = "NETWORK_VPC_PEERING_CREATE"

    # --- Virtual Compute & Workloads ---
    COMPUTE_INSTANCE_LAUNCH = "COMPUTE_INSTANCE_LAUNCH"
    COMPUTE_INSTANCE_STOP = "COMPUTE_INSTANCE_STOP"
    COMPUTE_INSTANCE_TERMINATE = "COMPUTE_INSTANCE_TERMINATE"
    COMPUTE_SNAPSHOT_CREATE = "COMPUTE_SNAPSHOT_CREATE"

    # --- Cryptographic Keys (KMS) ---
    KMS_KEY_CREATE = "KMS_KEY_CREATE"
    KMS_KEY_DISABLE = "KMS_KEY_DISABLE"
    KMS_KEY_SCHEDULE_DELETE = "KMS_KEY_SCHEDULE_DELETE"

    # --- Auditing & Telemetry ---
    LOGGING_CONFIG_DISABLE = "LOGGING_CONFIG_DISABLE"
    LOGGING_TRAIL_DELETE = "LOGGING_TRAIL_DELETE"

    # --- General / Fallback ---
    GENERIC_READ = "GENERIC_READ"
    GENERIC_WRITE = "GENERIC_WRITE"
    UNKNOWN_OR_CUSTOM = "UNKNOWN_OR_CUSTOM"


# Provider-specific API action mapping tables
_AWS_ACTION_MAP: dict[str, CanonicalAction] = {
    "CreateUser": CanonicalAction.IAM_USER_CREATE,
    "DeleteUser": CanonicalAction.IAM_USER_DELETE,
    "AttachRolePolicy": CanonicalAction.IAM_POLICY_ATTACH,
    "AttachUserPolicy": CanonicalAction.IAM_POLICY_ATTACH,
    "DetachRolePolicy": CanonicalAction.IAM_POLICY_DETACH,
    "CreateAccessKey": CanonicalAction.IAM_KEY_CREATE,
    "DeleteAccessKey": CanonicalAction.IAM_KEY_DELETE,
    "AssumeRole": CanonicalAction.IAM_ROLE_ASSUME,
    "ChangePassword": CanonicalAction.IAM_PASSWORD_CHANGE,
    "CreateBucket": CanonicalAction.STORAGE_BUCKET_CREATE,
    "DeleteBucket": CanonicalAction.STORAGE_BUCKET_DELETE,
    "PutBucketPolicy": CanonicalAction.STORAGE_POLICY_MODIFY,
    "DeleteBucketPolicy": CanonicalAction.STORAGE_POLICY_MODIFY,
    "PutBucketAcl": CanonicalAction.STORAGE_ACL_MODIFY,
    "GetObject": CanonicalAction.STORAGE_OBJECT_READ,
    "PutObject": CanonicalAction.STORAGE_OBJECT_WRITE,
    "DeleteObject": CanonicalAction.STORAGE_OBJECT_DELETE,
    "AuthorizeSecurityGroupIngress": CanonicalAction.NETWORK_SECURITY_GROUP_MODIFY,
    "RevokeSecurityGroupIngress": CanonicalAction.NETWORK_SECURITY_GROUP_MODIFY,
    "CreateRoute": CanonicalAction.NETWORK_ROUTE_MODIFY,
    "RunInstances": CanonicalAction.COMPUTE_INSTANCE_LAUNCH,
    "StopInstances": CanonicalAction.COMPUTE_INSTANCE_STOP,
    "TerminateInstances": CanonicalAction.COMPUTE_INSTANCE_TERMINATE,
    "CreateSnapshot": CanonicalAction.COMPUTE_SNAPSHOT_CREATE,
    "CreateKey": CanonicalAction.KMS_KEY_CREATE,
    "DisableKey": CanonicalAction.KMS_KEY_DISABLE,
    "ScheduleKeyDeletion": CanonicalAction.KMS_KEY_SCHEDULE_DELETE,
    "StopLogging": CanonicalAction.LOGGING_CONFIG_DISABLE,
    "DeleteTrail": CanonicalAction.LOGGING_TRAIL_DELETE,
}

_AZURE_ACTION_MAP: dict[str, CanonicalAction] = {
    "Microsoft.Authorization/roleAssignments/write": CanonicalAction.IAM_POLICY_ATTACH,
    "Microsoft.Authorization/roleAssignments/delete": CanonicalAction.IAM_POLICY_DETACH,
    "Microsoft.Storage/storageAccounts/write": CanonicalAction.STORAGE_BUCKET_CREATE,
    "Microsoft.Storage/storageAccounts/delete": CanonicalAction.STORAGE_BUCKET_DELETE,
    "Microsoft.Storage/storageAccounts/blobServices/containers/write": CanonicalAction.STORAGE_POLICY_MODIFY,
    "Microsoft.Network/networkSecurityGroups/securityRules/write": CanonicalAction.NETWORK_SECURITY_GROUP_MODIFY,
    "Microsoft.Network/networkSecurityGroups/securityRules/delete": CanonicalAction.NETWORK_SECURITY_GROUP_MODIFY,
    "Microsoft.Compute/virtualMachines/write": CanonicalAction.COMPUTE_INSTANCE_LAUNCH,
    "Microsoft.Compute/virtualMachines/restart/action": CanonicalAction.COMPUTE_INSTANCE_STOP,
    "Microsoft.Compute/virtualMachines/delete": CanonicalAction.COMPUTE_INSTANCE_TERMINATE,
    "Microsoft.KeyVault/vaults/keys/write": CanonicalAction.KMS_KEY_CREATE,
    "Microsoft.KeyVault/vaults/keys/delete": CanonicalAction.KMS_KEY_SCHEDULE_DELETE,
    "Microsoft.Insights/diagnosticSettings/delete": CanonicalAction.LOGGING_CONFIG_DISABLE,
}

_GCP_ACTION_MAP: dict[str, CanonicalAction] = {
    "v1.iam.serviceAccounts.create": CanonicalAction.IAM_USER_CREATE,
    "v1.iam.serviceAccountKeys.create": CanonicalAction.IAM_KEY_CREATE,
    "SetIamPolicy": CanonicalAction.IAM_POLICY_ATTACH,
    "storage.buckets.create": CanonicalAction.STORAGE_BUCKET_CREATE,
    "storage.buckets.delete": CanonicalAction.STORAGE_BUCKET_DELETE,
    "storage.buckets.setIamPolicy": CanonicalAction.STORAGE_POLICY_MODIFY,
    "storage.objects.get": CanonicalAction.STORAGE_OBJECT_READ,
    "storage.objects.create": CanonicalAction.STORAGE_OBJECT_WRITE,
    "compute.firewalls.insert": CanonicalAction.NETWORK_SECURITY_GROUP_MODIFY,
    "compute.firewalls.patch": CanonicalAction.NETWORK_SECURITY_GROUP_MODIFY,
    "compute.instances.insert": CanonicalAction.COMPUTE_INSTANCE_LAUNCH,
    "compute.instances.stop": CanonicalAction.COMPUTE_INSTANCE_STOP,
    "compute.instances.delete": CanonicalAction.COMPUTE_INSTANCE_TERMINATE,
    "cloudkms.cryptoKeys.create": CanonicalAction.KMS_KEY_CREATE,
    "cloudkms.cryptoKeys.destroy": CanonicalAction.KMS_KEY_SCHEDULE_DELETE,
    "logging.sinks.delete": CanonicalAction.LOGGING_CONFIG_DISABLE,
}


def resolve_canonical_action(action: str, provider: CloudProvider | str | None = None) -> CanonicalAction:
    """
    Resolve a cloud-specific action string to a unified CanonicalAction enum.

    Args:
        action: Raw action string (e.g., 'RunInstances', 'Microsoft.Compute/virtualMachines/write').
        provider: Optional CloudProvider or string to narrow down lookup.

    Returns:
        CanonicalAction enum value.
    """
    if not action:
        return CanonicalAction.UNKNOWN_OR_CUSTOM

    # Direct match if action is already a CanonicalAction
    if action in CanonicalAction.__members__:
        return CanonicalAction(action)

    prov_str = str(provider).lower() if provider else ""

    if "aws" in prov_str and action in _AWS_ACTION_MAP:
        return _AWS_ACTION_MAP[action]
    if "azure" in prov_str and action in _AZURE_ACTION_MAP:
        return _AZURE_ACTION_MAP[action]
    if "gcp" in prov_str and action in _GCP_ACTION_MAP:
        return _GCP_ACTION_MAP[action]

    # Search all maps if provider is not explicitly supplied or was not found
    for action_map in (_AWS_ACTION_MAP, _AZURE_ACTION_MAP, _GCP_ACTION_MAP):
        if action in action_map:
            return action_map[action]

    # Heuristic fallback
    lower_action = action.lower()
    if any(k in lower_action for k in ("get", "list", "describe", "read")):
        return CanonicalAction.GENERIC_READ
    if any(k in lower_action for k in ("create", "put", "update", "delete", "write", "modify")):
        return CanonicalAction.GENERIC_WRITE

    return CanonicalAction.UNKNOWN_OR_CUSTOM
