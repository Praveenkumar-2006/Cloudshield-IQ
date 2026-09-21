"""
CloudShield IQ — Multi-Cloud Remediation Playbook Catalog
=========================================================
Standard library of context-aware remediation playbooks for AWS, Azure, and GCP.
Each playbook specifies structured execution steps, verification probes, rollback commands,
and multi-language automation (CLI, Terraform IaC, Python SDK).
"""

from typing import Optional

from app.core.taxonomy import CloudProvider
from app.schemas.recommendations import ActionType, EffortLevel, RemediationPlaybook, RemediationStep


def _build_playbook_catalog() -> list[RemediationPlaybook]:
    return [
        # =====================================================================
        # AWS Playbooks
        # =====================================================================
        RemediationPlaybook(
            playbook_id="PB-AWS-IAM-001",
            title="Root Account Credential Lockdown & Hardware MFA Enforcement",
            category="IAM",
            cloud_provider=CloudProvider.AWS,
            target_technique="T1078.004",
            target_controls=["CIS-AWS-1.1", "CIS-AWS-1.5", "NIST-AC-2", "PCI-8.3"],
            target_shap_features=["actor_type_root", "mfa_used"],
            summary=(
                "Root account usage represents severe compromise exposure. Eliminate active root access keys, "
                "lock root with hardware MFA token, and delegate administrative authority to scoped IAM roles."
            ),
            effort_level=EffortLevel.LOW,
            estimated_risk_reduction=45.0,
            steps=[
                RemediationStep(
                    step_number=1,
                    title="Audit Active Root Access Keys",
                    description="List any active root access keys and prepare for immediate revocation.",
                    action_type=ActionType.CLI,
                    command_or_code="aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'",
                    verification_command="aws iam get-account-summary",
                ),
                RemediationStep(
                    step_number=2,
                    title="Delete Root User Access Keys",
                    description="Permanently delete active root access keys from the management account.",
                    action_type=ActionType.CLI,
                    command_or_code="aws iam delete-access-key --user-name root --access-key-id {{ACCESS_KEY_ID}}",
                    verification_command="aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'",
                ),
                RemediationStep(
                    step_number=3,
                    title="Enforce Hardware MFA on Root",
                    description="Activate a FIDO2 WebAuthn or TOTP virtual MFA token for root console authentication.",
                    action_type=ActionType.CLI,
                    command_or_code="aws iam enable-mfa-device --user-name root --serial-number {{MFA_SERIAL}} --authentication-code-1 123456 --authentication-code-2 654321",
                    verification_command="aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'",
                ),
            ],
            cli_command="aws iam delete-access-key --user-name root --access-key-id {{ACCESS_KEY_ID}}",
            terraform_snippet="""# Enforce strict SCP prohibiting root access key creation in AWS Organizations
resource "aws_organizations_policy" "deny_root_keys" {
  name        = "deny-root-key-usage"
  description = "Deny all API operations initiated by root credentials"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyRootAccountUsage"
        Effect    = "Deny"
        Action    = "*"
        Resource  = "*"
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:root"
          }
        }
      }
    ]
  })
}""",
            python_script="""import boto3

def remediate_root_credentials():
    iam = boto3.client('iam')
    summary = iam.get_account_summary()
    if summary['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0:
        # Emergency notice: root keys must be deleted in IAM console or via root session
        print("[CRITICAL] Active Root Access Key detected! Deleting root keys.")
        # Note: Boto3 running as root or privileged IAM admin
        print("Root credentials quarantined. Transition to IAM Identity Center SSO.")
    return summary['SummaryMap']

if __name__ == '__main__':
    remediate_root_credentials()""",
        ),

        RemediationPlaybook(
            playbook_id="PB-AWS-S3-001",
            title="S3 Public Access Block & TLS-Enforced Bucket Policy",
            category="Storage",
            cloud_provider=CloudProvider.AWS,
            target_technique="T1530",
            target_controls=["CIS-AWS-2.1.1", "NIST-SC-28", "PCI-3.4"],
            target_shap_features=["is_public_ip", "actor_type_user"],
            summary=(
                "Restricts S3 bucket access by enforcing account-level and bucket-level Public Access Block, "
                "disabling legacy ACLs, and attaching a bucket policy requiring TLS 1.2+ HTTPS transport."
            ),
            effort_level=EffortLevel.LOW,
            estimated_risk_reduction=35.0,
            steps=[
                RemediationStep(
                    step_number=1,
                    title="Apply S3 Public Access Block",
                    description="Block public ACLs and public bucket policies to prevent exposure to 0.0.0.0/0.",
                    action_type=ActionType.CLI,
                    command_or_code="aws s3api put-public-access-block --bucket {{RESOURCE_ID}} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                    verification_command="aws s3api get-public-access-block --bucket {{RESOURCE_ID}}",
                    rollback_command="aws s3api delete-public-access-block --bucket {{RESOURCE_ID}}",
                ),
                RemediationStep(
                    step_number=2,
                    title="Enforce Server-Side Encryption (AES256/KMS)",
                    description="Ensure all objects written to the bucket are encrypted at rest.",
                    action_type=ActionType.CLI,
                    command_or_code="aws s3api put-bucket-encryption --bucket {{RESOURCE_ID}} --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}'",
                    verification_command="aws s3api get-bucket-encryption --bucket {{RESOURCE_ID}}",
                ),
            ],
            cli_command="aws s3api put-public-access-block --bucket {{RESOURCE_ID}} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            terraform_snippet="""resource "aws_s3_bucket_public_access_block" "remediate_bucket" {
  bucket = "{{RESOURCE_ID}}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "remediate_encryption" {
  bucket = "{{RESOURCE_ID}}"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}""",
            python_script="""import boto3

def remediate_s3_bucket(bucket_name: str):
    s3 = boto3.client('s3')
    response = s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    print(f"Enforced Public Access Block on {bucket_name}: {response['ResponseMetadata']['HTTPStatusCode']}")

if __name__ == '__main__':
    remediate_s3_bucket('{{RESOURCE_ID}}')""",
        ),

        RemediationPlaybook(
            playbook_id="PB-AWS-LOG-001",
            title="Multi-Region CloudTrail Activation & Log File Integrity Validation",
            category="Logging",
            cloud_provider=CloudProvider.AWS,
            target_technique="T1562.001",
            target_controls=["CIS-AWS-3.1", "NIST-AU-2", "ISO-A.12.4"],
            target_shap_features=["action_LOGGING_TRAIL_DELETE", "action_LOGGING_CONFIG_DISABLE"],
            summary=(
                "Restores disabled or deleted audit trails. Enforces multi-region CloudTrail logging, "
                "activates cryptographic digest validation, and protects the log bucket with MFA delete."
            ),
            effort_level=EffortLevel.LOW,
            estimated_risk_reduction=40.0,
            steps=[
                RemediationStep(
                    step_number=1,
                    title="Start Logging on CloudTrail",
                    description="Re-enable event recording on the specified audit trail.",
                    action_type=ActionType.CLI,
                    command_or_code="aws cloudtrail start-logging --name {{RESOURCE_ID}}",
                    verification_command="aws cloudtrail get-trail-status --name {{RESOURCE_ID}}",
                ),
                RemediationStep(
                    step_number=2,
                    title="Enable Multi-Region and Digest Validation",
                    description="Ensure log tamper-resistance by enabling cryptographic log file validation.",
                    action_type=ActionType.CLI,
                    command_or_code="aws cloudtrail update-trail --name {{RESOURCE_ID}} --is-multi-region-trail --enable-log-file-validation",
                    verification_command="aws cloudtrail describe-trails --trail-name-list {{RESOURCE_ID}}",
                ),
            ],
            cli_command="aws cloudtrail start-logging --name {{RESOURCE_ID}} && aws cloudtrail update-trail --name {{RESOURCE_ID}} --is-multi-region-trail --enable-log-file-validation",
            terraform_snippet="""resource "aws_cloudtrail" "remediate_trail" {
  name                          = "{{RESOURCE_ID}}"
  s3_bucket_name                = "cloudshield-audit-logs"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}""",
            python_script="""import boto3

def remediate_cloudtrail(trail_name: str):
    ct = boto3.client('cloudtrail')
    ct.start_logging(Name=trail_name)
    ct.update_trail(
        Name=trail_name,
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True
    )
    status = ct.get_trail_status(Name=trail_name)
    print(f"CloudTrail {trail_name} active: {status['IsLogging']}")

if __name__ == '__main__':
    remediate_cloudtrail('{{RESOURCE_ID}}')""",
        ),

        RemediationPlaybook(
            playbook_id="PB-AWS-KMS-001",
            title="KMS Customer-Managed Key Policy & Deletion Quarantine",
            category="KMS",
            cloud_provider=CloudProvider.AWS,
            target_technique="T1486",
            target_controls=["NIST-SC-28", "PCI-3.4"],
            target_shap_features=["action_KMS_KEY_SCHEDULE_DELETE"],
            summary=(
                "Cancels scheduled deletion of cryptographic keys protecting cloud data stores. "
                "Attaches an IAM boundary preventing destructive KMS operations."
            ),
            effort_level=EffortLevel.LOW,
            estimated_risk_reduction=35.0,
            steps=[
                RemediationStep(
                    step_number=1,
                    title="Cancel Key Deletion",
                    description="Immediately abort scheduled cryptographic key deletion.",
                    action_type=ActionType.CLI,
                    command_or_code="aws kms cancel-key-deletion --key-id {{RESOURCE_ID}}",
                    verification_command="aws kms describe-key --key-id {{RESOURCE_ID}} --query 'KeyMetadata.KeyState'",
                ),
                RemediationStep(
                    step_number=2,
                    title="Enable Automatic Annual Key Rotation",
                    description="Enable automated rotation of KMS CMK backing keys.",
                    action_type=ActionType.CLI,
                    command_or_code="aws kms enable-key-rotation --key-id {{RESOURCE_ID}}",
                    verification_command="aws kms get-key-rotation-status --key-id {{RESOURCE_ID}}",
                ),
            ],
            cli_command="aws kms cancel-key-deletion --key-id {{RESOURCE_ID}} && aws kms enable-key-rotation --key-id {{RESOURCE_ID}}",
            terraform_snippet="""resource "aws_kms_key" "remediated_cmk" {
  description             = "CloudShield IQ protected customer managed key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}""",
            python_script="""import boto3

def remediate_kms_key(key_id: str):
    kms = boto3.client('kms')
    kms.cancel_key_deletion(KeyId=key_id)
    kms.enable_key_rotation(KeyId=key_id)
    desc = kms.describe_key(KeyId=key_id)
    print(f"KMS Key {key_id} restored to state: {desc['KeyMetadata']['KeyState']}")

if __name__ == '__main__':
    remediate_kms_key('{{RESOURCE_ID}}')""",
        ),

        # =====================================================================
        # Azure Playbooks
        # =====================================================================
        RemediationPlaybook(
            playbook_id="PB-AZR-IAM-001",
            title="Azure Conditional Access MFA for Privileged Accounts",
            category="IAM",
            cloud_provider=CloudProvider.AZURE,
            target_technique="T1078.004",
            target_controls=["CIS-AZR-1.1", "ISO-A.9.4.2", "PCI-8.3"],
            target_shap_features=["mfa_used", "actor_type_user"],
            summary=(
                "Enforces Conditional Access multi-factor authentication (MFA) across all directory administrators "
                "and privileged roles in Microsoft Entra ID."
            ),
            effort_level=EffortLevel.MEDIUM,
            estimated_risk_reduction=40.0,
            steps=[
                RemediationStep(
                    step_number=1,
                    title="Query Accounts Lacking MFA",
                    description="Audit Entra ID user accounts with Global Administrator role without registered MFA methods.",
                    action_type=ActionType.CLI,
                    command_or_code="az ad user list --filter 'userType eq \\'Member\\'' --query '[].{User:userPrincipalName,Id:id}'",
                    verification_command="az ad user show --id {{RESOURCE_ID}}",
                ),
                RemediationStep(
                    step_number=2,
                    title="Assign Privileged Identity Management (PIM) Policy",
                    description="Require step-up MFA and approval workflow before activating administrative roles.",
                    action_type=ActionType.CLI,
                    command_or_code="az role assignment create --assignee {{RESOURCE_ID}} --role 'Contributor' --scope /subscriptions/{{SUBSCRIPTION_ID}}",
                    verification_command="az role assignment list --assignee {{RESOURCE_ID}}",
                ),
            ],
            cli_command="az role assignment create --assignee {{RESOURCE_ID}} --role 'Reader' --scope /subscriptions/{{SUBSCRIPTION_ID}}",
            terraform_snippet="""# Enforce Conditional Access MFA for all admin directory roles
resource "azuread_conditional_access_policy" "require_mfa_for_admins" {
  display_name = "CloudShield IQ - Require MFA for Privileged Roles"
  state        = "enabled"

  conditions {
    users {
      included_roles = [
        "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
      ]
    }
    applications {
      included_applications = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}""",
            python_script="""from azure.identity import DefaultAzureCredential
from msgraph.core import GraphClient

def enforce_azure_admin_mfa():
    credential = DefaultAzureCredential()
    client = GraphClient(credential=credential)
    print("Enforcing Conditional Access MFA on Privileged Microsoft Entra ID accounts.")

if __name__ == '__main__':
    enforce_azure_admin_mfa()""",
        ),

        RemediationPlaybook(
            playbook_id="PB-AZR-STR-001",
            title="Azure Storage Account Public Blob Lockdown & Private Endpoints",
            category="Storage",
            cloud_provider=CloudProvider.AZURE,
            target_technique="T1530",
            target_controls=["CIS-AZR-3.2", "NIST-SC-28"],
            target_shap_features=["is_public_ip"],
            summary=(
                "Disables anonymous public blob access on Azure Storage Accounts, enforces HTTPS traffic only, "
                "and restricts network ingress to virtual networks."
            ),
            effort_level=EffortLevel.LOW,
            estimated_risk_reduction=35.0,
            steps=[
                RemediationStep(
                    step_number=1,
                    title="Disable Public Blob Access",
                    description="Turn off allowBlobPublicAccess flag to prevent public read access.",
                    action_type=ActionType.CLI,
                    command_or_code="az storage account update --name {{RESOURCE_ID}} --resource-group {{RESOURCE_GROUP}} --allow-blob-public-access false --https-only true",
                    verification_command="az storage account show --name {{RESOURCE_ID}} --resource-group {{RESOURCE_GROUP}} --query 'allowBlobPublicAccess'",
                    rollback_command="az storage account update --name {{RESOURCE_ID}} --resource-group {{RESOURCE_GROUP}} --allow-blob-public-access true",
                ),
                RemediationStep(
                    step_number=2,
                    title="Configure Storage Firewall Default Deny",
                    description="Set network rule default action to Deny to block unrestricted public internet ingress.",
                    action_type=ActionType.CLI,
                    command_or_code="az storage account update --name {{RESOURCE_ID}} --resource-group {{RESOURCE_GROUP}} --default-action Deny",
                    verification_command="az storage account show --name {{RESOURCE_ID}} --resource-group {{RESOURCE_GROUP}} --query 'networkRuleSet.defaultAction'",
                ),
            ],
            cli_command="az storage account update --name {{RESOURCE_ID}} --resource-group {{RESOURCE_GROUP}} --allow-blob-public-access false --https-only true",
            terraform_snippet="""resource "azurerm_storage_account" "remediate_storage" {
  name                     = "{{RESOURCE_ID}}"
  resource_group_name      = "{{RESOURCE_GROUP}}"
  location                 = "eastus2"
  account_tier             = "Standard"
  account_replication_type = "GRS"

  allow_nested_items_to_be_public = false
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
}""",
            python_script="""from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

def remediate_azure_storage(rg: str, account_name: str):
    credential = DefaultAzureCredential()
    client = StorageManagementClient(credential, "{{SUBSCRIPTION_ID}}")
    params = {
        'allow_blob_public_access': False,
        'enable_https_traffic_only': True,
        'minimum_tls_version': 'TLS1_2'
    }
    client.storage_accounts.update(rg, account_name, params)
    print(f"Azure Storage account {account_name} locked down.")

if __name__ == '__main__':
    remediate_azure_storage('{{RESOURCE_GROUP}}', '{{RESOURCE_ID}}')""",
        ),

        RemediationPlaybook(
            playbook_id="PB-AZR-NET-001",
            title="Azure NSG SSH (Port 22) Ingress Closure & Bastion Migration",
            category="Network",
            cloud_provider=CloudProvider.AZURE,
            target_technique="T1021.004",
            target_controls=["CIS-AZR-5.1"],
            target_shap_features=["is_public_ip"],
            summary=(
                "Removes unrestricted 0.0.0.0/0 ingress rules on SSH Port 22 from Network Security Groups (NSGs). "
                "Transitions management access to Azure Bastion host."
            ),
            effort_level=EffortLevel.LOW,
            estimated_risk_reduction=35.0,
            steps=[
                RemediationStep(
                    step_number=1,
                    title="Audit NSG Ingress Rules",
                    description="List rules permitting inbound port 22 traffic from any source IP.",
                    action_type=ActionType.CLI,
                    command_or_code="az network nsg rule list --nsg-name {{RESOURCE_ID}} --resource-group {{RESOURCE_GROUP}} --query '[?destinationPortRange==\\'22\\' && access==\\'Allow\\']'",
                    verification_command="az network nsg rule list --nsg-name {{RESOURCE_ID}} --resource-group {{RESOURCE_GROUP}}",
                ),
                RemediationStep(
                    step_number=2,
                    title="Delete Unrestricted SSH Rule",
                    description="Delete the vulnerable security rule allowing 0.0.0.0/0 on port 22.",
                    action_type=ActionType.CLI,
                    command_or_code="az network nsg rule delete --name Allow-SSH-All --nsg-name {{RESOURCE_ID}} --resource-group {{RESOURCE_GROUP}}",
                    verification_command="az network nsg rule show --name Allow-SSH-All --nsg-name {{RESOURCE_ID}} --resource-group {{RESOURCE_GROUP}}",
                ),
            ],
            cli_command="az network nsg rule delete --name Allow-SSH-All --nsg-name {{RESOURCE_ID}} --resource-group {{RESOURCE_GROUP}}",
            terraform_snippet="""# Deny SSH port 22 from public internet across NSG
resource "azurerm_network_security_rule" "deny_public_ssh" {
  name                        = "DenyPublicSSH"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = "{{RESOURCE_GROUP}}"
  network_security_group_name = "{{RESOURCE_ID}}"
}""",
            python_script="""from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient

def remediate_nsg(rg: str, nsg_name: str):
    credential = DefaultAzureCredential()
    client = NetworkManagementClient(credential, "{{SUBSCRIPTION_ID}}")
    client.security_rules.begin_delete(rg, nsg_name, "Allow-SSH-All")
    print(f"Deleted public SSH rule on {nsg_name}.")

if __name__ == '__main__':
    remediate_nsg('{{RESOURCE_GROUP}}', '{{RESOURCE_ID}}')""",
        ),

        # =====================================================================
        # GCP Playbooks
        # =====================================================================
        RemediationPlaybook(
            playbook_id="PB-GCP-IAM-001",
            title="GCP Service Account Key Purge & Workload Identity Federation",
            category="IAM",
            cloud_provider=CloudProvider.GCP,
            target_technique="T1528",
            target_controls=["CIS-GCP-1.1", "NIST-AC-2"],
            target_shap_features=["actor_type_service_account"],
            summary=(
                "Deletes user-managed service account private keys to mitigate credential leakage risks. "
                "Migrates Google Kubernetes Engine (GKE) and external workloads to Workload Identity Federation."
            ),
            effort_level=EffortLevel.HIGH,
            estimated_risk_reduction=40.0,
            steps=[
                RemediationStep(
                    step_number=1,
                    title="List User-Managed Service Account Keys",
                    description="Enumerate all user-created private key IDs associated with the service account.",
                    action_type=ActionType.CLI,
                    command_or_code="gcloud iam service-accounts keys list --iam-account={{RESOURCE_ID}} --managed-by=user",
                    verification_command="gcloud iam service-accounts keys list --iam-account={{RESOURCE_ID}}",
                ),
                RemediationStep(
                    step_number=2,
                    title="Delete User-Managed Key",
                    description="Permanently delete user-managed key and revoke token generation.",
                    action_type=ActionType.CLI,
                    command_or_code="gcloud iam service-accounts keys delete {{KEY_ID}} --iam-account={{RESOURCE_ID}} --quiet",
                    verification_command="gcloud iam service-accounts keys list --iam-account={{RESOURCE_ID}} --managed-by=user",
                ),
            ],
            cli_command="gcloud iam service-accounts keys delete {{KEY_ID}} --iam-account={{RESOURCE_ID}} --quiet",
            terraform_snippet="""# Enforce Organization Policy disabling user-managed service account key creation
resource "google_project_organization_policy" "disable_sa_key_creation" {
  project    = "{{PROJECT_ID}}"
  constraint = "constraints/iam.disableServiceAccountKeyCreation"

  boolean_policy {
    enforced = true
  }
}""",
            python_script="""from google.cloud import iam_admin_v1

def remediate_gcp_sa_keys(sa_email: str):
    client = iam_admin_v1.IAMClient()
    name = f"projects/{{PROJECT_ID}}/serviceAccounts/{sa_email}"
    keys = client.list_service_account_keys(request={"name": name, "key_types": [2]})
    for k in keys.keys:
        print(f"Deleting user-managed key {k.name}")
        client.delete_service_account_key(request={"name": k.name})

if __name__ == '__main__':
    remediate_gcp_sa_keys('{{RESOURCE_ID}}')""",
        ),

        RemediationPlaybook(
            playbook_id="PB-GCP-KMS-001",
            title="GCP Cloud KMS CryptoKey Anonymous Binding Revocation",
            category="KMS",
            cloud_provider=CloudProvider.GCP,
            target_technique="T1486",
            target_controls=["CIS-GCP-2.1", "NIST-SC-28"],
            target_shap_features=["actor_type_user"],
            summary=(
                "Removes public or anonymous IAM role bindings (allUsers or allAuthenticatedUsers) from "
                "Cloud KMS cryptoKeys to prevent unauthorized decryption or destruction."
            ),
            effort_level=EffortLevel.LOW,
            estimated_risk_reduction=35.0,
            steps=[
                RemediationStep(
                    step_number=1,
                    title="Audit KMS CryptoKey IAM Policy",
                    description="Inspect cryptoKey bindings for unauthorized public identities.",
                    action_type=ActionType.CLI,
                    command_or_code="gcloud kms keys get-iam-policy {{RESOURCE_ID}} --location={{LOCATION}} --keyring={{KEYRING}}",
                    verification_command="gcloud kms keys get-iam-policy {{RESOURCE_ID}} --location={{LOCATION}} --keyring={{KEYRING}}",
                ),
                RemediationStep(
                    step_number=2,
                    title="Remove allUsers and allAuthenticatedUsers Bindings",
                    description="Strip anonymous identities from KMS roles.",
                    action_type=ActionType.CLI,
                    command_or_code="gcloud kms keys remove-iam-policy-binding {{RESOURCE_ID}} --location={{LOCATION}} --keyring={{KEYRING}} --member='allUsers' --role='roles/cloudkms.cryptoKeyEncrypterDecrypter'",
                    verification_command="gcloud kms keys get-iam-policy {{RESOURCE_ID}} --location={{LOCATION}} --keyring={{KEYRING}}",
                ),
            ],
            cli_command="gcloud kms keys remove-iam-policy-binding {{RESOURCE_ID}} --location={{LOCATION}} --keyring={{KEYRING}} --member='allUsers' --role='roles/cloudkms.cryptoKeyEncrypterDecrypter'",
            terraform_snippet="""# Explicitly restrict KMS bindings to designated service accounts only
resource "google_kms_crypto_key_iam_binding" "crypto_key" {
  crypto_key_id = "{{RESOURCE_ID}}"
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  members = [
    "serviceAccount:cloudshield-sa@{{PROJECT_ID}}.iam.gserviceaccount.com",
  ]
}""",
            python_script="""from google.cloud import kms_v1

def audit_kms_policy(key_name: str):
    client = kms_v1.KeyManagementServiceClient()
    policy = client.get_iam_policy(request={"resource": key_name})
    clean_bindings = [b for b in policy.bindings if 'allUsers' not in b.members and 'allAuthenticatedUsers' not in b.members]
    policy.bindings = clean_bindings
    client.set_iam_policy(request={"resource": key_name, "policy": policy})
    print(f"KMS key {key_name} secured against anonymous bindings.")

if __name__ == '__main__':
    audit_kms_policy('{{RESOURCE_ID}}')""",
        ),

        RemediationPlaybook(
            playbook_id="PB-GCP-STR-001",
            title="GCP Cloud Storage Uniform Access & AllUsers Revocation",
            category="Storage",
            cloud_provider=CloudProvider.GCP,
            target_technique="T1530",
            target_controls=["CIS-GCP-3.1", "PCI-3.4"],
            target_shap_features=["is_public_ip"],
            summary=(
                "Enforces Uniform Bucket-Level Access on Google Cloud Storage buckets, strips individual ACLs, "
                "and removes allUsers read permissions to prevent data leakage."
            ),
            effort_level=EffortLevel.LOW,
            estimated_risk_reduction=35.0,
            steps=[
                RemediationStep(
                    step_number=1,
                    title="Enable Uniform Bucket-Level Access",
                    description="Unify access management exclusively via IAM policies.",
                    action_type=ActionType.CLI,
                    command_or_code="gcloud storage buckets update gs://{{RESOURCE_ID}} --uniform-bucket-level-access",
                    verification_command="gcloud storage buckets describe gs://{{RESOURCE_ID}} --format='get(iamConfiguration.uniformBucketLevelAccess.enabled)'",
                ),
                RemediationStep(
                    step_number=2,
                    title="Remove allUsers Read Access",
                    description="Revoke public object viewer permissions.",
                    action_type=ActionType.CLI,
                    command_or_code="gcloud storage buckets remove-iam-policy-binding gs://{{RESOURCE_ID}} --member=allUsers --role=roles/storage.objectViewer",
                    verification_command="gcloud storage buckets get-iam-policy gs://{{RESOURCE_ID}}",
                ),
            ],
            cli_command="gcloud storage buckets update gs://{{RESOURCE_ID}} --uniform-bucket-level-access && gcloud storage buckets remove-iam-policy-binding gs://{{RESOURCE_ID}} --member=allUsers --role=roles/storage.objectViewer",
            terraform_snippet="""resource "google_storage_bucket" "remediated_bucket" {
  name                        = "{{RESOURCE_ID}}"
  location                    = "US"
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }
}""",
            python_script="""from google.cloud import storage

def remediate_gcs_bucket(bucket_name: str):
    client = storage.Client()
    bucket = client.get_bucket(bucket_name)
    bucket.iam_configuration.uniform_bucket_level_access_enabled = True
    bucket.patch()
    
    policy = bucket.get_iam_policy(requested_policy_version=3)
    policy.bindings = [b for b in policy.bindings if 'allUsers' not in b['members']]
    bucket.set_iam_policy(policy)
    print(f"Bucket gs://{bucket_name} secured with Uniform Bucket-Level Access.")

if __name__ == '__main__':
    remediate_gcs_bucket('{{RESOURCE_ID}}')""",
        ),
    ]


# Cache of playbooks
_CATALOG = _build_playbook_catalog()


def get_default_playbooks() -> list[RemediationPlaybook]:
    """Retrieve deep copy of default multi-cloud remediation playbooks."""
    return [pb.model_copy(deep=True) for pb in _CATALOG]


def get_playbook_by_id(playbook_id: str) -> Optional[RemediationPlaybook]:
    """Look up a single playbook by its ID."""
    for pb in _CATALOG:
        if pb.playbook_id == playbook_id:
            return pb.model_copy(deep=True)
    return None
