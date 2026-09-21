import { useState, useEffect, useMemo } from 'react';
import {
  AlertTriangle,
  RefreshCw,
  UploadCloud,
  Terminal,
  Activity,
  Copy,
  Check,
  X,
  Send,
  Menu,
  CheckCircle2,
  Download,
  Play,
  Pause,
  Search,
  Shield,
  ShieldAlert,
  Server,
  Layers,
  Sliders,
  Sparkles
} from 'lucide-react';

interface SecurityExplanation {
  finding_id: string;
  risk: string;
  what_happened: string;
  why_it_matters: string;
  evidence: string[];
  compliance_impact: string;
  recommended_action: string;
  grounding_score: number;
  is_llm_generated: boolean;
  generated_at: string;
  model_used?: string;
}

interface HealthData {
  status: 'ok' | 'degraded' | 'offline' | 'checking';
  service: string;
  version: string;
  latency?: number;
  timestamp?: string;
  error?: string;
}

interface Finding {
  id: string;
  title: string;
  cloud: 'AWS' | 'Azure' | 'GCP';
  resourceId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: 'IAM' | 'Storage' | 'Network' | 'Compute' | 'Encryption' | 'Logging' | 'Authorization' | 'Cryptography';
  riskScore: number;
  shapTopFeature: string;
  shapImpact: number;
  complianceViolation: string[];
  remediation: string;
  cliCommand: string;
  terraform: string;
  pythonSnippet?: string;
  attackVector?: string;
}

interface ComplianceControl {
  id: string;
  name: string;
  framework: 'CIS AWS 1.4' | 'CIS Azure 2.0' | 'CIS GCP 1.3' | 'NIST 800-53' | 'ISO 27001' | 'PCI-DSS 4.0';
  status: 'PASS' | 'FAIL' | 'PARTIAL';
  evaluatedResources: number;
  failedCount: number;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
}

interface SecOpsMessage {
  id: string;
  sender: 'operator' | 'system';
  text: string;
  code?: string;
  codeLang?: string;
  timestamp: string;
}

const mockFindings: Finding[] = [
  {
    id: 'FND-AWS-1049',
    title: 'IAM Root User Account Has Active Access Keys Without MFA Enforcement',
    cloud: 'AWS',
    resourceId: 'arn:aws:iam::123456789012:root',
    severity: 'CRITICAL',
    category: 'IAM',
    riskScore: 96.4,
    shapTopFeature: 'iam_root_access_key_active',
    shapImpact: 0.42,
    complianceViolation: ['CIS AWS 1.1', 'NIST AC-2(1)', 'ISO 27001 A.9.2.1'],
    remediation: 'Delete active root access keys immediately and enforce hardware token multi-factor authentication (MFA).',
    cliCommand: 'aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE',
    terraform: `resource "aws_iam_account_password_policy" "strict" {
  require_symbols        = true
  require_numbers        = true
  minimum_password_length = 16
  hard_expiry            = false
}`,
    attackVector: 'Unprotected root API credentials allow unrestricted full cloud account takeover, billing destruction, and resource tampering without MFA barriers.',
    pythonSnippet: `import boto3

iam = boto3.client('iam')
# Revoke root credentials and enforce MFA policies
iam.delete_access_key(UserName='root', AccessKeyId='AKIAIOSFODNN7EXAMPLE')
print("[SECOPS] Active root credentials deleted successfully.")`
  },
  {
    id: 'FND-AWS-2081',
    title: 'S3 Bucket with Sensitive Financial Artifacts Has Public Read/List ACLs Enabled',
    cloud: 'AWS',
    resourceId: 'arn:aws:s3:::cloudshield-prod-analytics-exports',
    severity: 'CRITICAL',
    category: 'Storage',
    riskScore: 94.8,
    shapTopFeature: 's3_public_read_access_granted',
    shapImpact: 0.38,
    complianceViolation: ['CIS AWS 2.1.1', 'PCI-DSS 3.4', 'NIST SC-28'],
    remediation: 'Enable S3 Public Access Block at account and bucket level and restrict bucket policy to IAM roles.',
    cliCommand: 'aws s3api put-public-access-block --bucket cloudshield-prod-analytics-exports --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
    terraform: `resource "aws_s3_bucket_public_access_block" "block_all" {
  bucket                  = aws_s3_bucket.analytics.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
    attackVector: 'Anonymous internet users can enumerate all bucket objects, exfiltrating financial reports and PII without authorization.',
    pythonSnippet: `import boto3

s3 = boto3.client('s3')
s3.put_public_access_block(
    Bucket='cloudshield-prod-analytics-exports',
    PublicAccessBlockConfiguration={
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True
    }
)
print("[SECOPS] S3 Public Access Block enforced.")`
  },
  {
    id: 'FND-AZR-3012',
    title: 'Security Group Ingress Allows Unrestricted SSH (Port 22) From 0.0.0.0/0',
    cloud: 'Azure',
    resourceId: '/subscriptions/sub-01/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-core',
    severity: 'HIGH',
    category: 'Network',
    riskScore: 88.2,
    shapTopFeature: 'ingress_port_22_open_to_any',
    shapImpact: 0.31,
    complianceViolation: ['CIS Azure 5.1', 'NIST AC-17', 'ISO 27001 A.13.1.1'],
    remediation: 'Remove public CIDR 0.0.0.0/0 ingress rule on port 22 and restrict administration to Azure Bastion or corporate VPN subnet.',
    cliCommand: 'az network nsg rule delete -g rg-prod --nsg-name nsg-core -n AllowSSHAny',
    terraform: `resource "azurerm_network_security_rule" "deny_ssh_pub" {
  name                        = "DenyInternetSSH"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-prod"
  network_security_group_name = "nsg-core"
}`,
    attackVector: 'Exposed SSH ports are susceptible to brute-force credential stuffing, zero-day daemon exploitation, and perimeter pivoting.',
    pythonSnippet: `from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient

client = NetworkManagementClient(DefaultAzureCredential(), 'sub-01')
client.security_rules.begin_delete('rg-prod', 'nsg-core', 'AllowSSHAny').wait()
print("[SECOPS] Inbound port 22 open rule revoked.")`
  },
  {
    id: 'FND-GCP-4099',
    title: 'Compute Engine Disk Volumes Not Encrypted with Customer Managed Keys (CMEK)',
    cloud: 'GCP',
    resourceId: 'projects/cloudshield-sec-gcp/zones/us-central1-a/disks/db-replica-vol01',
    severity: 'MEDIUM',
    category: 'Encryption',
    riskScore: 68.5,
    shapTopFeature: 'cmek_disk_encryption_absent',
    shapImpact: 0.19,
    complianceViolation: ['CIS GCP 4.1', 'ISO 27001 A.10.1.1'],
    remediation: 'Configure Google Cloud KMS key ring and associate customer-managed key with persistent disk volumes.',
    cliCommand: 'gcloud compute disks create db-replica-vol01 --kms-key projects/cloudshield-sec-gcp/locations/global/keyRings/kr/cryptoKeys/kms-disk',
    terraform: `resource "google_compute_disk" "encrypted_disk" {
  name = "db-replica-vol01"
  zone = "us-central1-a"
  kms_key_self_link = google_kms_crypto_key.key.id
}`,
    attackVector: 'Default Google-managed keys do not provide cryptographic separation of duties or user-controlled key rotation schedules.',
    pythonSnippet: `from google.cloud import kms_v1

client = kms_v1.KeyManagementServiceClient()
parent = client.key_ring_path('cloudshield-sec-gcp', 'global', 'kr')
key = client.create_crypto_key(
    parent=parent,
    crypto_key_id='kms-disk',
    crypto_key={'purpose': kms_v1.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT}
)
print(f"[SECOPS] CMEK key initialized: {key.name}")`
  },
  {
    id: 'FND-AWS-5034',
    title: 'IAM Policy Grants Wildcard Action ("*") on All CloudWatch Log Groups',
    cloud: 'AWS',
    resourceId: 'arn:aws:iam::123456789012:policy/DevLogWriter',
    severity: 'LOW',
    category: 'IAM',
    riskScore: 42.1,
    shapTopFeature: 'iam_wildcard_action_logs',
    shapImpact: 0.09,
    complianceViolation: ['CIS AWS 1.16', 'NIST AC-6'],
    remediation: 'Scope down IAM policy actions to logs:PutLogEvents and logs:CreateLogStream with specific log group ARN targets.',
    cliCommand: 'aws iam create-policy-version --policy-arn arn:aws:iam::123456789012:policy/DevLogWriter --policy-document file://scoped-policy.json --set-as-default',
    terraform: `data "aws_iam_policy_document" "scoped_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:log-group:/aws/lambda/*"]
  }
}`,
    attackVector: 'Broad wildcard permissions allow compromised compute workloads to delete or tamper with audit trail logs.',
    pythonSnippet: `import boto3, json

iam = boto3.client('iam')
policy_doc = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/*"}]
}
iam.create_policy_version(PolicyArn='arn:aws:iam::123456789012:policy/DevLogWriter', PolicyDocument=json.dumps(policy_doc), SetAsDefault=True)
print("[SECOPS] Wildcard policy scoped to minimum privilege.")`
  },
  {
    id: 'FND-AZR-3045',
    title: 'Storage Account Public Blob Container Access Enabled Allowing Anonymous Read',
    cloud: 'Azure',
    resourceId: '/subscriptions/sub-01/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/stdataanalytics',
    severity: 'CRITICAL',
    category: 'Storage',
    riskScore: 93.4,
    shapTopFeature: 'azure_storage_allow_blob_public_access',
    shapImpact: 0.36,
    complianceViolation: ['CIS Azure 3.5', 'NIST SC-28', 'PCI-DSS 3.4'],
    remediation: 'Disable AllowBlobPublicAccess on the storage account and configure private endpoint connections.',
    cliCommand: 'az storage account update --name stdataanalytics --resource-group rg-prod --allow-blob-public-access false',
    terraform: `resource "azurerm_storage_account" "secure_storage" {
  name                     = "stdataanalytics"
  resource_group_name      = "rg-prod"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"
  allow_nested_items_to_be_public = false
}`,
    attackVector: 'Anonymous internet users can probe blob storage endpoints directly to harvest intellectual property or database dumps.',
    pythonSnippet: `from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

client = StorageManagementClient(DefaultAzureCredential(), 'sub-01')
client.storage_accounts.update('rg-prod', 'stdataanalytics', {'allow_blob_public_access': False})
print("[SECOPS] Storage account blob public access revoked.")`
  },
  {
    id: 'FND-GCP-4011',
    title: 'Service Account User-Managed Key Created Without Mandatory Rotation Schedule',
    cloud: 'GCP',
    resourceId: 'projects/cloudshield-sec-gcp/serviceAccounts/data-exporter@cloudshield-sec-gcp.iam.gserviceaccount.com',
    severity: 'HIGH',
    category: 'IAM',
    riskScore: 86.7,
    shapTopFeature: 'gcp_iam_service_account_key_created',
    shapImpact: 0.28,
    complianceViolation: ['CIS GCP 1.4', 'ISO 27001 A.9.4.3'],
    remediation: 'Delete user-managed service account keys and transition workloads to Workload Identity Federation.',
    cliCommand: 'gcloud iam service-accounts keys delete KEY_ID --iam-account data-exporter@cloudshield-sec-gcp.iam.gserviceaccount.com',
    terraform: `resource "google_iam_workload_identity_pool" "pool" {
  workload_identity_pool_id = "prod-pool"
}`,
    attackVector: 'Unrotated service account private keys committed to repositories or build logs provide permanent backdoors into GCP projects.',
    pythonSnippet: `from google.cloud import iam_admin_v1

client = iam_admin_v1.IAMClient()
client.delete_service_account_key(name='projects/cloudshield-sec-gcp/serviceAccounts/data-exporter@cloudshield-sec-gcp.iam.gserviceaccount.com/keys/KEY_ID')
print("[SECOPS] User-managed service account key deleted.")`
  },
  {
    id: 'FND-AWS-1090',
    title: 'CloudTrail Multi-Region Audit Trail Disabled or Deletion Attempted',
    cloud: 'AWS',
    resourceId: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/security-audit-trail',
    severity: 'CRITICAL',
    category: 'Logging',
    riskScore: 98.5,
    shapTopFeature: 'cloudtrail_logging_disabled',
    shapImpact: 0.48,
    complianceViolation: ['CIS AWS 3.1', 'NIST AU-2', 'SOC2 CC7.2'],
    remediation: 'Re-enable CloudTrail immediately and attach an SCP forbidding DeleteTrail and StopLogging actions.',
    cliCommand: 'aws cloudtrail start-logging --name security-audit-trail',
    terraform: `resource "aws_cloudtrail" "core" {
  name                          = "security-audit-trail"
  s3_bucket_name                = "audit-logs-bucket"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
}`,
    attackVector: 'Threat actors disable audit logging as defense evasion prior to executing data theft and cryptomining deployment.',
    pythonSnippet: `import boto3

ct = boto3.client('cloudtrail')
ct.start_logging(Name='security-audit-trail')
print("[SECOPS] Multi-region CloudTrail audit logging re-enabled.")`
  }
];

const mockComplianceControls: ComplianceControl[] = [
  { id: 'CIS-AWS-1.1', name: 'Avoid the use of the root account and enforce MFA', framework: 'CIS AWS 1.4', status: 'FAIL', evaluatedResources: 1, failedCount: 1, severity: 'HIGH' },
  { id: 'CIS-AWS-2.1.1', name: 'Ensure S3 Bucket Policy blocks public read access', framework: 'CIS AWS 1.4', status: 'FAIL', evaluatedResources: 34, failedCount: 3, severity: 'HIGH' },
  { id: 'CIS-AWS-3.1', name: 'Ensure CloudTrail is enabled across all multi-region zones', framework: 'CIS AWS 1.4', status: 'PASS', evaluatedResources: 4, failedCount: 0, severity: 'HIGH' },
  { id: 'CIS-AZR-5.1', name: 'Ensure that SSH access is restricted from the internet', framework: 'CIS Azure 2.0', status: 'FAIL', evaluatedResources: 18, failedCount: 2, severity: 'HIGH' },
  { id: 'CIS-AZR-3.2', name: 'Ensure storage account default network access is set to Deny', framework: 'CIS Azure 2.0', status: 'PARTIAL', evaluatedResources: 22, failedCount: 4, severity: 'MEDIUM' },
  { id: 'NIST-AC-2', name: 'Account Management and Principle of Least Privilege', framework: 'NIST 800-53', status: 'FAIL', evaluatedResources: 86, failedCount: 14, severity: 'HIGH' },
  { id: 'NIST-SC-28', name: 'Protection of Information at Rest (Cryptographic Keys)', framework: 'NIST 800-53', status: 'PARTIAL', evaluatedResources: 64, failedCount: 8, severity: 'MEDIUM' },
  { id: 'ISO-A.9.4.2', name: 'Secure Log-on Procedures and Multi-Factor Authentication', framework: 'ISO 27001', status: 'FAIL', evaluatedResources: 92, failedCount: 11, severity: 'HIGH' },
  { id: 'PCI-3.4', name: 'Render primary account numbers (PAN) unreadable anywhere stored', framework: 'PCI-DSS 4.0', status: 'PASS', evaluatedResources: 12, failedCount: 0, severity: 'HIGH' }
];

const defaultGlobalShapAttributions = {
  model_version: 'supervised-xgboost-v1',
  base_value: 48.5,
  sample_count_analyzed: 20000,
  top_global_features: [
    { feature_name: 'actor_type_root', display_name: 'Root Cloud Account Usage', domain: 'IAM', mean_abs_shap: 4.12, relative_percentage: 34.5, description: 'Privileged root cloud account invoked without scoped delegation' },
    { feature_name: 'mfa_used', display_name: 'Missing Multi-Factor Auth', domain: 'Authentication', mean_abs_shap: 3.02, relative_percentage: 25.3, description: 'Multi-factor authentication status during session creation' },
    { feature_name: 'is_public_ip', display_name: 'Public Internet Ingress', domain: 'Network', mean_abs_shap: 2.15, relative_percentage: 18.0, description: 'Connection initiated from public non-RFC1918 IP address' },
    { feature_name: 'action_StopLogging', display_name: 'Audit Trail Interruption', domain: 'Logging', mean_abs_shap: 1.45, relative_percentage: 12.1, description: 'Deactivation of continuous cloud security event logging' },
    { feature_name: 'action_PutBucketAcl', display_name: 'Storage ACL Modification', domain: 'Storage', mean_abs_shap: 0.72, relative_percentage: 6.0, description: 'Modifying object or bucket access control list permissions' },
    { feature_name: 'action_ScheduleKeyDeletion', display_name: 'KMS Key Destruction', domain: 'Encryption', mean_abs_shap: 0.49, relative_percentage: 4.1, description: 'Cryptographic key scheduled for permanent deletion' }
  ],
  domain_distribution: { 'IAM': 38.2, 'Authentication': 26.5, 'Network': 19.1, 'Logging': 10.4, 'Storage': 5.8 }
};

export function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'compliance' | 'ml-engine' | 'ingestion' | 'architecture'>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [findings] = useState<Finding[]>(mockFindings);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(mockFindings[0]);
  const [selectedCloudFilter, setSelectedCloudFilter] = useState<'ALL' | 'AWS' | 'Azure' | 'GCP'>('ALL');
  const [selectedSeverityFilter, setSelectedSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Tactical Operations HUD & Stream states
  const [utcTime, setUtcTime] = useState(new Date().toUTCString().replace('GMT', 'UTC'));
  const [isLiveStreamActive, setIsLiveStreamActive] = useState(true);
  const [telemetryFilter, setTelemetryFilter] = useState<'ALL' | 'AWS' | 'AZURE' | 'GCP' | 'CRIT'>('ALL');

  // Tactical Toast Notifications
  const [toasts, setToasts] = useState<Array<{ id: string; message: string; type?: 'info' | 'success' | 'warn' }>>([]);
  const showToast = (message: string, type: 'info' | 'success' | 'warn' = 'info') => {
    const id = Date.now().toString() + Math.random().toString().slice(2, 5);
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 3500);
  };

  // Command Palette state (Ctrl+K)
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState('');

  // Finding Remediation & Lifecycle Triage states
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState<string>('ALL');
  const [findingStatuses, setFindingStatuses] = useState<Record<string, 'OPEN' | 'IN_PROGRESS' | 'RESOLVED'>>({
    'FND-AWS-1049': 'OPEN',
    'FND-AWS-2081': 'OPEN',
    'FND-AZR-3012': 'OPEN',
    'FND-GCP-4099': 'OPEN',
    'FND-AWS-5034': 'OPEN',
    'FND-AZR-3045': 'OPEN',
    'FND-GCP-4011': 'OPEN',
    'FND-AWS-1090': 'OPEN'
  });

  // Compliance Filter States
  const [complianceStatusFilter, setComplianceStatusFilter] = useState<'ALL' | 'PASS' | 'FAIL' | 'PARTIAL'>('ALL');
  const [complianceFrameworkFilter, setComplianceFrameworkFilter] = useState<string>('ALL');

  // SecOps Remediation Console state
  const [isConsoleOpen, setIsConsoleOpen] = useState(false);
  const [consoleInput, setConsoleInput] = useState('');
  const [isConsoleExecuting, setIsConsoleExecuting] = useState(false);
  const [consoleMessages, setConsoleMessages] = useState<SecOpsMessage[]>([
    {
      id: 'init',
      sender: 'system',
      text: 'SecOps Remediation Engine initialized. Continuous posture assessment, TreeSHAP quantitative risk attribution, and zero-trust Infrastructure-as-Code mitigation ready.',
      timestamp: 'Ready'
    }
  ]);

  // Simulation Sliders
  const [simPrivilege, setSimPrivilege] = useState(85);
  const [simExposure, setSimExposure] = useState(90);
  const [simRadius, setSimRadius] = useState(70);
  const [simEncryption, setSimEncryption] = useState(40);

  // Ingestion State (Testing states: idle, loading, complete, error)
  const [uploadStatus, setUploadStatus] = useState<'idle' | 'loading' | 'complete' | 'error'>('idle');
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);

  // Telemetry stream
  const [telemetryLogs, setTelemetryLogs] = useState<Array<{ id: string; time: string; cloud: string; action: string; status: 'WARN' | 'CRIT' | 'INFO' }>>([
    { id: 'TL-9912', time: '14:22:12', cloud: 'AWS', action: 'iam:CreateAccessKey (Root)', status: 'CRIT' },
    { id: 'TL-9913', time: '14:22:18', cloud: 'AZURE', action: 'nsg:InboundRuleModified (Port 22)', status: 'WARN' },
    { id: 'TL-9914', time: '14:22:25', cloud: 'GCP', action: 'kms:KeyRingAuditChecked', status: 'INFO' },
    { id: 'TL-9915', time: '14:22:31', cloud: 'AWS', action: 's3:PutBucketAcl (Public)', status: 'CRIT' },
    { id: 'TL-9916', time: '14:22:44', cloud: 'AWS', action: 'cloudtrail:LookupEvents', status: 'INFO' },
  ]);

  // Backend connection state
  const [backendHealth, setBackendHealth] = useState<HealthData>({
    status: 'checking',
    service: 'cloudshield-iq-api',
    version: '0.1.0'
  });
  const [isRefreshing, setIsRefreshing] = useState(false);

  const checkBackendHealth = async () => {
    setIsRefreshing(true);
    const start = performance.now();
    try {
      const response = await fetch('http://127.0.0.1:8001/api/v1/health', { method: 'GET', signal: AbortSignal.timeout(600) });
      const latency = Math.round(performance.now() - start);
      if (response.ok) {
        setBackendHealth({
          status: 'ok',
          service: 'cloudshield-iq-api',
          version: '0.1.0',
          latency,
          timestamp: new Date().toLocaleTimeString()
        });
      } else {
        setBackendHealth({
          status: 'degraded',
          service: 'cloudshield-iq-api',
          version: '0.1.0',
          latency,
          timestamp: new Date().toLocaleTimeString(),
          error: `HTTP ${response.status}`
        });
      }
    } catch {
      setBackendHealth({
        status: 'offline',
        service: 'cloudshield-iq-api',
        version: '0.1.0',
        timestamp: new Date().toLocaleTimeString(),
        error: 'Offline (port 8001)'
      });
    } finally {
      setIsRefreshing(false);
    }
  };

  const [modelInfo, setModelInfo] = useState<{
    model_version: string;
    algorithm: string;
    is_trained: boolean;
    trained_at?: string;
    training_records_count: number;
    feature_count: number;
    features: string[];
    contamination: number;
    n_estimators: number;
    status: string;
    metrics?: Record<string, any>;
  } | null>(null);

  const [mlInferenceResult, setMlInferenceResult] = useState<any>(null);
  const [isInferring, setIsInferring] = useState(false);

  const fetchModelInfo = async () => {
    try {
      const resp = await fetch('http://127.0.0.1:8001/api/v1/ml/model-info');
      if (resp.ok) {
        const data = await resp.json();
        setModelInfo(data);
      }
    } catch {
      // Offline fallback
    }
  };

  const [supervisedModelInfo, setSupervisedModelInfo] = useState<{
    model_version: string;
    algorithm: string;
    is_trained: boolean;
    created_at?: string;
    training_records_count: number;
    feature_count: number;
    classes: string[];
    status: string;
    metrics?: Record<string, any>;
  } | null>(null);

  const [supervisedRiskResult, setSupervisedRiskResult] = useState<any>(null);
  const [isSupervisedInferring, setIsSupervisedInferring] = useState(false);

  // Phase 7: TreeSHAP Explainability State
  const [globalShapAttributions, setGlobalShapAttributions] = useState<{
    model_version: string;
    base_value: number;
    sample_count_analyzed: number;
    top_global_features: Array<{
      feature_name: string;
      display_name: string;
      domain: string;
      mean_abs_shap: number;
      relative_percentage: number;
      description: string;
    }>;
    domain_distribution: Record<string, number>;
  } | null>(defaultGlobalShapAttributions);

  const [selectedEventExplanation, setSelectedEventExplanation] = useState<{
    event_id?: string;
    base_value: number;
    predicted_risk_score: number;
    top_risk_drivers: Array<{
      feature_name: string;
      display_name: string;
      domain: string;
      shap_value: number;
      feature_value: any;
      direction: string;
      description: string;
    }>;
    top_risk_mitigators: Array<{
      feature_name: string;
      display_name: string;
      domain: string;
      shap_value: number;
      feature_value: any;
      direction: string;
      description: string;
    }>;
    all_attributions: Record<string, number>;
  } | null>(null);

  const [isExplainingEvent, setIsExplainingEvent] = useState(false);

  // Grounded LLM Explanation Layer State
  const [selectedFindingExplanation, setSelectedFindingExplanation] = useState<SecurityExplanation | null>(null);
  const [isLoadingExplanation, setIsLoadingExplanation] = useState(false);

  const fetchExplanationForFinding = async (finding: Finding) => {
    setIsLoadingExplanation(true);
    try {
      const resp = await fetch(`http://127.0.0.1:8001/api/v1/findings/${finding.id}/explain`, {
        method: 'POST',
        signal: AbortSignal.timeout(2000),
      });
      if (resp.ok) {
        const data = await resp.json();
        setSelectedFindingExplanation(data);
        setIsLoadingExplanation(false);
        return;
      }
    } catch {
      // Graceful offline fallback
    }

    const score = finding.riskScore;
    const isAnom = score >= 85.0;
    const fallback: SecurityExplanation = {
      finding_id: finding.id,
      risk: finding.severity,
      what_happened: `CloudShield IQ detected a verified ${finding.severity} exposure on ${finding.cloud} resource '${finding.resourceId}': ${finding.title}.`,
      why_it_matters: `Calibrated risk score of ${score.toFixed(1)}/100 indicates critical exposure to unauthorized manipulation or data leakage. TreeSHAP attribution identifies '${finding.shapTopFeature}' (+${Math.round(finding.shapImpact * 100)}% risk weight) as dominant contributor.`,
      evidence: [
        `Identity activity lacked verified multi-factor authentication (MFA).`,
        `TreeSHAP identified primary risk contributor: '${finding.shapTopFeature}'.`,
        `Verified control failure flagged on target cloud provider ${finding.cloud}.`,
        isAnom ? `Isolation Forest ensemble classified behavior as anomalous outlier.` : `Deterministic policy evaluation failed against regulatory baseline.`
      ],
      compliance_impact: `Non-compliant with codified standards: ${finding.complianceViolation.join(', ')}. Deterministic compliance verification failed against active regulatory baselines.`,
      recommended_action: `${finding.remediation} Immediate CLI command: \`${finding.cliCommand}\`.`,
      grounding_score: 1.0,
      is_llm_generated: false,
      generated_at: new Date().toISOString(),
      model_used: 'deterministic-grounded-engine'
    };
    setSelectedFindingExplanation(fallback);
    setIsLoadingExplanation(false);
  };

  useEffect(() => {
    if (selectedFinding) {
      fetchExplanationForFinding(selectedFinding);
    }
  }, [selectedFinding?.id]);

  const fetchSupervisedModelInfo = async () => {
    if (backendHealth.status !== 'ok') return;
    try {
      const resp = await fetch('http://127.0.0.1:8001/api/v1/ml/risk-model-info', { signal: AbortSignal.timeout(600) });
      if (resp.ok) {
        const data = await resp.json();
        setSupervisedModelInfo(data);
      }
    } catch {
      // Offline fallback
    }
  };

  const fetchGlobalShapAttributions = async () => {
    if (backendHealth.status !== 'ok') return;
    try {
      const resp = await fetch('http://127.0.0.1:8001/api/v1/ml/explain/global?top_k=6', { signal: AbortSignal.timeout(600) });
      if (resp.ok) {
        const data = await resp.json();
        setGlobalShapAttributions(data);
        return;
      }
      throw new Error(`HTTP ${resp.status}`);
    } catch {
      setGlobalShapAttributions(defaultGlobalShapAttributions);
    }
  };

  const explainEventWithShap = async (eventPayload?: any) => {
    setIsExplainingEvent(true);
    const event = eventPayload || {
      event_id: 'evt-fnd-root-01',
      timestamp: new Date().toISOString(),
      cloud_provider: 'aws',
      resource_type: 'iam:Role',
      action: 'DeleteRole',
      actor_type: 'root',
      actor_name: 'root',
      source_ip: '198.51.100.24',
      mfa_used: false,
      outcome: 'Failure',
      session_duration_s: 0
    };

    const fallbackExplanation = {
      event_id: event.event_id || 'evt-fnd-root-01',
      base_value: 48.5,
      predicted_risk_score: 92.4,
      top_risk_drivers: [
        { feature_name: 'actor_type_root', display_name: 'Root Account Usage', domain: 'IAM', shap_value: 24.5, feature_value: 1.0, direction: 'risk_enhancer', description: 'Privileged root account used for destructive operations' },
        { feature_name: 'mfa_used', display_name: 'Missing MFA Verification', domain: 'Authentication', shap_value: 12.8, feature_value: 0.0, direction: 'risk_enhancer', description: 'Action executed without hardware or virtual MFA' },
        { feature_name: 'action_DeleteRole', display_name: 'IAM Role Deletion', domain: 'IAM', shap_value: 8.6, feature_value: 1.0, direction: 'risk_enhancer', description: 'Critical IAM role destruction detected' },
        { feature_name: 'is_public_ip', display_name: 'Untrusted Public Ingress', domain: 'Network', shap_value: 4.2, feature_value: 1.0, direction: 'risk_enhancer', description: 'Origin IP 198.51.100.24 outside corporate VPN perimeter' }
      ],
      top_risk_mitigators: [
        { feature_name: 'session_duration_s', display_name: 'Zero Session Duration', domain: 'Authentication', shap_value: -6.2, feature_value: 0.0, direction: 'risk_mitigator', description: 'Immediate termination prevented sustained privilege abuse' }
      ],
      all_attributions: {
        'actor_type_root': 24.5,
        'mfa_used': 12.8,
        'action_DeleteRole': 8.6,
        'is_public_ip': 4.2,
        'session_duration_s': -6.2
      }
    };

    if (backendHealth.status !== 'ok') {
      setSelectedEventExplanation(fallbackExplanation);
      setIsExplainingEvent(false);
      return;
    }

    try {
      const resp = await fetch('http://127.0.0.1:8001/api/v1/ml/explain/event?top_k=4', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event),
        signal: AbortSignal.timeout(600)
      });
      if (resp.ok) {
        const data = await resp.json();
        setSelectedEventExplanation(data);
        return;
      }
      throw new Error(`HTTP ${resp.status}`);
    } catch {
      setSelectedEventExplanation(fallbackExplanation);
    } finally {
      setIsExplainingEvent(false);
    }
  };

  const runLiveSupervisedScan = async () => {
    setIsSupervisedInferring(true);
    try {
      const sampleEvents = [
        {
          timestamp: new Date().toISOString(),
          cloud_provider: 'aws',
          resource_type: 'iam:Role',
          action: 'DeleteRole',
          actor_type: 'root',
          actor_name: 'root',
          source_ip: '198.51.100.24',
          mfa_used: false,
          outcome: 'Failure',
          session_duration_s: 0
        },
        {
          timestamp: new Date().toISOString(),
          cloud_provider: 'azure',
          resource_type: 'Microsoft.Storage/storageAccounts',
          action: 'PutBucketAcl',
          actor_type: 'user',
          actor_name: 'admin_bob',
          source_ip: '203.0.113.88',
          mfa_used: false,
          outcome: 'Success',
          session_duration_s: 360
        },
        {
          timestamp: new Date().toISOString(),
          cloud_provider: 'aws',
          resource_type: 'ec2:Instance',
          action: 'DescribeInstances',
          actor_type: 'user',
          actor_name: 'developer_alice',
          source_ip: '10.0.1.5',
          mfa_used: true,
          outcome: 'Success',
          session_duration_s: 1800
        }
      ];

      const resp = await fetch('http://127.0.0.1:8001/api/v1/ml/classify-risk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sampleEvents)
      });
      if (resp.ok) {
        const data = await resp.json();
        setSupervisedRiskResult(data);
        return;
      }
      throw new Error(`HTTP ${resp.status}`);
    } catch {
      // Standalone client fallback simulation
      setSupervisedRiskResult({
        total_events: 3,
        severity_counts: { critical: 1, high: 1, low: 1, medium: 0 },
        mean_risk_score: 62.4,
        predictions: [
          {
            event_id: 'evt-sup-101',
            predicted_severity: 'critical',
            confidence: 0.94,
            predicted_risk_score: 91.2,
            model_version: 'supervised-xgboost-v1',
            severity_probabilities: { low: 0.01, medium: 0.02, high: 0.03, critical: 0.94 }
          },
          {
            event_id: 'evt-sup-102',
            predicted_severity: 'high',
            confidence: 0.82,
            predicted_risk_score: 74.5,
            model_version: 'supervised-xgboost-v1',
            severity_probabilities: { low: 0.04, medium: 0.06, high: 0.82, critical: 0.08 }
          },
          {
            event_id: 'evt-sup-103',
            predicted_severity: 'low',
            confidence: 0.91,
            predicted_risk_score: 21.5,
            model_version: 'supervised-xgboost-v1',
            severity_probabilities: { low: 0.91, medium: 0.06, high: 0.02, critical: 0.01 }
          }
        ]
      });
    } finally {
      setIsSupervisedInferring(false);
    }
  };

  const runLiveMlInference = async () => {
    setIsInferring(true);
    try {
      const sampleEvents = [
        {
          timestamp: new Date().toISOString(),
          cloud_provider: 'aws',
          resource_type: 'iam:Role',
          action: 'DeleteRole',
          actor_type: 'root',
          actor_name: 'root',
          source_ip: '198.51.100.24',
          mfa_used: false,
          outcome: 'Failure',
          session_duration_s: 0
        },
        {
          timestamp: new Date().toISOString(),
          cloud_provider: 'aws',
          resource_type: 'ec2:Instance',
          action: 'DescribeInstances',
          actor_type: 'user',
          actor_name: 'developer_alice',
          source_ip: '10.0.1.5',
          mfa_used: true,
          outcome: 'Success',
          session_duration_s: 1800
        }
      ];

      const resp = await fetch('http://127.0.0.1:8001/api/v1/ml/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sampleEvents)
      });
      if (resp.ok) {
        const data = await resp.json();
        setMlInferenceResult(data);
        return;
      }
      throw new Error(`HTTP ${resp.status}`);
    } catch {
      // Standalone client fallback simulation
      setMlInferenceResult({
        total_events: 2,
        anomalies_detected: 1,
        anomaly_rate: 0.5,
        predictions: [
          {
            event_id: 'evt-iforest-1',
            is_anomaly: true,
            anomaly_score: 0.89,
            raw_score: -0.21,
            feature_impacts: { privilege_escalation: 0.44, off_hours_activity: 0.31 },
            evaluated_at: new Date().toISOString()
          },
          {
            event_id: 'evt-iforest-2',
            is_anomaly: false,
            anomaly_score: 0.14,
            raw_score: 0.18,
            feature_impacts: { routine_read: 0.05 },
            evaluated_at: new Date().toISOString()
          }
        ]
      });
    } finally {
      setIsInferring(false);
    }
  };

  useEffect(() => {
    checkBackendHealth();
    fetchModelInfo();
    fetchSupervisedModelInfo();
    fetchGlobalShapAttributions();
    const interval = setInterval(() => {
      checkBackendHealth();
      fetchModelInfo();
      fetchSupervisedModelInfo();
      fetchGlobalShapAttributions();
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  // Keyboard shortcut listener for Command Palette (Ctrl+K / ⌘K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsCommandPaletteOpen(prev => !prev);
      } else if (e.key === 'Escape') {
        setIsCommandPaletteOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Realtime UTC Chronometer Ticker (ticks every second)
  useEffect(() => {
    const timer = setInterval(() => {
      setUtcTime(new Date().toUTCString().replace('GMT', 'UTC'));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Telemetry ticker simulation (controlled by isLiveStreamActive)
  useEffect(() => {
    if (!isLiveStreamActive) return;
    const timer = setInterval(() => {
      const providers = ['AWS', 'AZURE', 'GCP'];
      const actions = [
        { action: 'iam:AssumeRole', status: 'INFO' as const },
        { action: 's3:GetBucketPolicy', status: 'INFO' as const },
        { action: 'securityGroup:RevokeIngress', status: 'INFO' as const },
        { action: 'kms:DecryptPayload', status: 'WARN' as const },
        { action: 'cloudtrail:StopLogging', status: 'CRIT' as const },
        { action: 'compute:CreateSnapshot', status: 'INFO' as const },
      ];
      const p = providers[Math.floor(Math.random() * providers.length)];
      const a = actions[Math.floor(Math.random() * actions.length)];
      const now = new Date().toLocaleTimeString();
      const randId = `TL-${Math.floor(1000 + Math.random() * 9000)}`;

      setTelemetryLogs(prev => [
        { id: randId, time: now, cloud: p, action: a.action, status: a.status },
        ...prev.slice(0, 7)
      ]);
    }, 4500);

    return () => clearInterval(timer);
  }, [isLiveStreamActive]);

  const copyToClipboard = (text: string, key: string, label: string = 'Copied to clipboard') => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast(label, 'success');
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleExportComplianceReport = () => {
    const reportData = {
      report_id: `COMP-AUDIT-${Date.now()}`,
      generated_at: new Date().toISOString(),
      overall_compliance_score_percent: 66.7,
      total_controls: mockComplianceControls.length,
      passing_controls: mockComplianceControls.filter(c => c.status === 'PASS').length,
      failing_controls: mockComplianceControls.filter(c => c.status === 'FAIL').length,
      partial_controls: mockComplianceControls.filter(c => c.status === 'PARTIAL').length,
      evaluated_frameworks: ['CIS AWS 1.4', 'CIS Azure 2.0', 'CIS GCP 1.3', 'NIST 800-53', 'ISO 27001', 'PCI-DSS 4.0'],
      controls: mockComplianceControls
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `compliance-audit-report-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Compliance Audit Report (JSON) downloaded', 'success');
  };

  const handleExecutePlaybook = (promptText?: string) => {
    const query = promptText || consoleInput;
    if (!query.trim()) return;

    const operatorMsg: SecOpsMessage = {
      id: Date.now().toString(),
      sender: 'operator',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setConsoleMessages(prev => [...prev, operatorMsg]);
    setConsoleInput('');
    setIsConsoleExecuting(true);
    setIsConsoleOpen(true);

    setTimeout(() => {
      let sysResponse = '';
      let snippet = '';

      if (query.toLowerCase().includes('root') || query.toLowerCase().includes('mfa') || selectedFinding?.id.includes('1049')) {
        sysResponse = 'Threat Analysis: Root IAM Credentials Detected. Blast radius is unrestricted. TreeSHAP weight +42% risk escalation from iam_root_access_key_active. Execute immediate key revocation:';
        snippet = 'aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE\naws iam create-virtual-mfa-device --virtual-mfa-device-name RootMFADevice';
      } else if (query.toLowerCase().includes('s3') || query.toLowerCase().includes('bucket') || selectedFinding?.id.includes('2081')) {
        sysResponse = 'Storage Exposure: Public read ACL allows unauthenticated object download. Violates CIS AWS 2.1.1 and PCI-DSS 3.4. Apply public access block:';
        snippet = 'resource "aws_s3_account_public_access_block" "block_global" {\n  block_public_acls   = true\n  block_public_policy = true\n  ignore_public_acls  = true\n  restrict_public_buckets = true\n}';
      } else {
        sysResponse = 'Posture Assessment: Evaluated 9 multi-cloud compliance benchmarks. Composite Risk Index: 74.2 / 100. Primary concentration: Unrestricted IAM root and Port 22 Ingress.';
        snippet = selectedFinding?.cliCommand || 'aws iam get-account-summary';
      }

      setConsoleMessages(prev => [
        ...prev,
        {
          id: (Date.now() + 1).toString(),
          sender: 'system',
          text: sysResponse,
          code: snippet,
          codeLang: snippet.includes('resource') ? 'terraform' : 'bash',
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
      setIsConsoleExecuting(false);
    }, 500);
  };

  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      const matchesCloud = selectedCloudFilter === 'ALL' || f.cloud === selectedCloudFilter;
      const matchesSeverity = selectedSeverityFilter === 'ALL' || f.severity === selectedSeverityFilter;
      const matchesCategory = selectedCategoryFilter === 'ALL' || f.category === selectedCategoryFilter;
      const matchesSearch = f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.resourceId.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.id.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesCloud && matchesSeverity && matchesCategory && matchesSearch;
    });
  }, [findings, selectedCloudFilter, selectedSeverityFilter, selectedCategoryFilter, searchQuery]);

  const filteredComplianceControls = useMemo(() => {
    return mockComplianceControls.filter(c => {
      const matchesStatus = complianceStatusFilter === 'ALL' || c.status === complianceStatusFilter;
      const matchesFramework = complianceFrameworkFilter === 'ALL' || c.framework === complianceFrameworkFilter;
      return matchesStatus && matchesFramework;
    });
  }, [complianceStatusFilter, complianceFrameworkFilter]);

  const filteredTelemetryLogs = useMemo(() => {
    return telemetryLogs.filter(log => {
      if (telemetryFilter === 'ALL') return true;
      if (telemetryFilter === 'CRIT') return log.status === 'CRIT';
      return log.cloud.toUpperCase() === telemetryFilter.toUpperCase();
    });
  }, [telemetryLogs, telemetryFilter]);

  const simulatedScore = Math.min(100, Math.round((simPrivilege * 0.35) + (simExposure * 0.35) + (simRadius * 0.2) + (simEncryption * 0.1)));

  const handleSimulatedFileUpload = (simulateFail = false) => {
    setUploadStatus('loading');
    setUploadedFileName('cloud-telemetry-dump-prod-01.json');
    setTimeout(() => {
      if (simulateFail) {
        setUploadStatus('error');
      } else {
        setUploadStatus('complete');
      }
    }, 1200);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* ═══════════════════════════════════
          NAVIGATION BAR
          ═══════════════════════════════════ */}
      <header className="nav-header">
        <div className="nav-wrapper">
          {/* Logo Left */}
          <a href="#" className="nav-logo-group" onClick={(e) => { e.preventDefault(); setActiveTab('overview'); }}>
            <span className="nav-logo-badge">CS</span>
            <span className="nav-logo-text">CloudShield IQ</span>
          </a>

          {/* Nav Links Center (Desktop) */}
          <nav className="nav-tabs-desktop" aria-label="Main Navigation">
            <button
              className={`nav-tab-btn ${activeTab === 'overview' ? 'is-active' : ''}`}
              onClick={() => setActiveTab('overview')}
            >
              Overview
            </button>
            <button
              className={`nav-tab-btn ${activeTab === 'findings' ? 'is-active' : ''}`}
              onClick={() => setActiveTab('findings')}
            >
              Findings ({findings.length})
            </button>
            <button
              className={`nav-tab-btn ${activeTab === 'compliance' ? 'is-active' : ''}`}
              onClick={() => setActiveTab('compliance')}
            >
              Compliance
            </button>
            <button
              className={`nav-tab-btn ${activeTab === 'ml-engine' ? 'is-active' : ''}`}
              onClick={() => setActiveTab('ml-engine')}
            >
              ML Engine
            </button>
            <button
              className={`nav-tab-btn ${activeTab === 'ingestion' ? 'is-active' : ''}`}
              onClick={() => setActiveTab('ingestion')}
            >
              Ingestion
            </button>
            <button
              className={`nav-tab-btn ${activeTab === 'architecture' ? 'is-active' : ''}`}
              onClick={() => setActiveTab('architecture')}
            >
              Architecture
            </button>
          </nav>

          {/* Controls & CTA Right */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              className="btn btn-secondary"
              onClick={checkBackendHealth}
              title="Refresh API telemetry"
              aria-label="Refresh Backend"
            >
              <RefreshCw size={16} className={isRefreshing ? 'spinner' : ''} />
              <span className="caption" style={{ color: backendHealth.status === 'ok' ? 'var(--status-pass)' : 'var(--text-secondary)' }}>
                {backendHealth.status === 'ok' ? 'API Online' : 'API Standalone'}
              </span>
            </button>

            <button
              className="btn btn-primary"
              onClick={() => setIsConsoleOpen(true)}
              aria-label="Open SecOps Console"
            >
              <Terminal size={15} />
              <span>SecOps Console</span>
            </button>

            {/* Mobile Hamburger Button */}
            <button
              className="hamburger-btn"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-label="Toggle mobile menu"
            >
              {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation Drawer */}
        <div className={`mobile-nav-drawer ${mobileMenuOpen ? 'is-open' : ''}`}>
          {(['overview', 'findings', 'compliance', 'ml-engine', 'ingestion', 'architecture'] as const).map(tab => (
            <button
              key={tab}
              className={`mobile-nav-item ${activeTab === tab ? 'is-active' : ''}`}
              onClick={() => {
                setActiveTab(tab);
                setMobileMenuOpen(false);
              }}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1).replace('-', ' ')}
            </button>
          ))}
        </div>
      </header>

      {/* ═══════════════════════════════════
          TACTICAL OPERATIONS HUD / TICKER
          ═══════════════════════════════════ */}
      <div className="hud-ticker">
        <div className="hud-ticker-inner">
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <span className="hud-item">
              <span className="hud-pulse-dot" />
              <span style={{ color: 'var(--accent)', fontWeight: 700 }}>LIVE POSTURE</span>
            </span>
            <span className="hud-item" style={{ color: 'var(--text-primary)' }}>
              UTC {utcTime}
            </span>
            <span className="hud-item">
              <span style={{ color: 'var(--text-secondary)' }}>Threat Level:</span>
              <span className="tag tag-critical" style={{ fontSize: '10px' }}>DEFCON 2 / ELEVATED</span>
            </span>
            <span className="hud-item">
              <span style={{ color: 'var(--text-secondary)' }}>Tenants:</span>
              <span className="tag" style={{ fontSize: '10px' }}>AWS us-east-1</span>
              <span className="tag" style={{ fontSize: '10px' }}>Azure eastus</span>
              <span className="tag" style={{ fontSize: '10px' }}>GCP us-central1</span>
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              className="hud-search-btn"
              onClick={() => setIsCommandPaletteOpen(true)}
              title="Search Findings, Controls & Models (Ctrl+K)"
            >
              <Search size={12} />
              <span>Quick Search</span>
              <kbd style={{ fontSize: '9px', background: 'var(--bg-primary)', padding: '1px 4px', borderRadius: '2px', border: '1px solid var(--border)' }}>⌘K</kbd>
            </button>
          </div>
        </div>
      </div>

      {/* ═══════════════════════════════════
          TOAST NOTIFICATION OVERLAY
          ═══════════════════════════════════ */}
      {toasts.length > 0 && (
        <div className="toast-container">
          {toasts.map(t => (
            <div key={t.id} className="toast-item">
              {t.type === 'success' ? (
                <CheckCircle2 size={16} style={{ color: 'var(--accent)' }} />
              ) : t.type === 'warn' ? (
                <AlertTriangle size={16} style={{ color: 'var(--status-warning)' }} />
              ) : (
                <Activity size={16} style={{ color: 'var(--text-secondary)' }} />
              )}
              <span>{t.message}</span>
            </div>
          ))}
        </div>
      )}

      {/* ═══════════════════════════════════
          COMMAND PALETTE MODAL (Ctrl+K)
          ═══════════════════════════════════ */}
      {isCommandPaletteOpen && (
        <div className="cmd-palette-backdrop" onClick={() => setIsCommandPaletteOpen(false)}>
          <div className="cmd-palette-box" onClick={e => e.stopPropagation()}>
            <input
              type="text"
              className="cmd-palette-input"
              placeholder="Type to search findings, compliance controls, or ML tools... (ESC to close)"
              value={paletteQuery}
              onChange={e => setPaletteQuery(e.target.value)}
              autoFocus
            />
            <div className="cmd-palette-results">
              <div className="caption" style={{ padding: '4px 8px', color: 'var(--text-muted)' }}>
                FINDINGS & INCIDENTS
              </div>
              {findings
                .filter(f => f.title.toLowerCase().includes(paletteQuery.toLowerCase()) || f.id.toLowerCase().includes(paletteQuery.toLowerCase()))
                .slice(0, 4)
                .map(f => (
                  <button
                    key={f.id}
                    className="cmd-palette-item"
                    onClick={() => {
                      setSelectedFinding(f);
                      setActiveTab('findings');
                      setIsCommandPaletteOpen(false);
                      showToast(`Navigated to ${f.id}`);
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600 }}>{f.id}: {f.title}</div>
                      <div className="caption">{f.cloud} • {f.category} • Risk Score {f.riskScore}</div>
                    </div>
                    <span className={`tag ${f.severity === 'CRITICAL' ? 'tag-critical' : 'tag-warning'}`}>
                      {f.severity}
                    </span>
                  </button>
                ))}

              <div className="caption" style={{ padding: '8px 8px 4px', color: 'var(--text-muted)' }}>
                SYSTEM CONTROLS & ENGINES
              </div>
              <button
                className="cmd-palette-item"
                onClick={() => {
                  setActiveTab('ml-engine');
                  setIsCommandPaletteOpen(false);
                }}
              >
                <div>
                  <div style={{ fontWeight: 600 }}>TreeSHAP Explainability & Waterfall Engine</div>
                  <div className="caption">Inspect mathematical local & global risk attributions</div>
                </div>
                <span className="tag tag-accent">PHASE 7</span>
              </button>
              <button
                className="cmd-palette-item"
                onClick={() => {
                  setActiveTab('compliance');
                  setIsCommandPaletteOpen(false);
                }}
              >
                <div>
                  <div style={{ fontWeight: 600 }}>Multi-Cloud Compliance Matrix</div>
                  <div className="caption">Audit CIS AWS 1.4, NIST 800-53, PCI-DSS 4.0 controls</div>
                </div>
                <span className="tag">6 FRAMEWORKS</span>
              </button>
              <button
                className="cmd-palette-item"
                onClick={() => {
                  setIsConsoleOpen(true);
                  setIsCommandPaletteOpen(false);
                }}
              >
                <div>
                  <div style={{ fontWeight: 600 }}>SecOps Interactive Remediation Console</div>
                  <div className="caption">Execute direct zero-trust playbooks</div>
                </div>
                <span className="tag">CLI</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════
          MAIN APPLICATION CONTENT
          ═══════════════════════════════════ */}
      <main className="app-container" style={{ flexGrow: 1, paddingBottom: '64px' }}>
        {/* HERO SECTION — Elevated Executive Banner on Overview; Sleek Context Strip on Deep Tabs */}
        {activeTab === 'overview' ? (
          <section style={{ paddingTop: '32px', paddingBottom: '28px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="badge-emerald"><Shield size={12} /> Version 0.1.0</span>
                <span className="caption text-emerald-400">Multi-Cloud Security & Compliance Suite</span>
              </div>
              <h1>CloudShield IQ</h1>
              <p style={{ maxWidth: '820px', fontSize: '15px', color: 'var(--text-secondary)' }}>
                Continuous multi-cloud posture evaluation, quantitative TreeSHAP risk attribution, and automated zero-trust remediation across AWS, Azure, and GCP.
              </p>
            </div>

            {/* Above the fold CTA bar */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', marginTop: '20px' }}>
              <button
                className="btn btn-primary"
                onClick={() => setActiveTab('findings')}
              >
                <ShieldAlert size={15} />
                <span>Audit Security Findings</span>
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => setActiveTab('compliance')}
              >
                <Layers size={15} />
                <span>View Compliance Matrix</span>
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => handleExecutePlaybook('Generate emergency IAM root remediation')}
              >
                <Terminal size={15} />
                <span>Generate Remediation Patch</span>
              </button>
            </div>
          </section>
        ) : (
          <div style={{ padding: '20px 0 16px 0', borderBottom: '1px solid var(--border-subtle)', marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h1 style={{ display: 'none' }}>CloudShield IQ</h1>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="badge-emerald" style={{ fontSize: '10px' }}>
                  <Shield size={11} /> CloudShield IQ
                </span>
                <span style={{ color: 'var(--text-muted)' }}>/</span>
                <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: '15px' }}>
                  {activeTab === 'findings' ? 'Security Findings Workspace' :
                   activeTab === 'compliance' ? 'Compliance Posture & Frameworks' :
                   activeTab === 'ml-engine' ? 'Machine Learning Risk Intelligence' :
                   activeTab === 'ingestion' ? 'Configuration & Telemetry Ingestion' : 'System Architecture Topology'}
                </span>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                className="btn btn-secondary"
                style={{ height: '32px', minHeight: '32px', padding: '0 10px', fontSize: '12px' }}
                onClick={() => setActiveTab('overview')}
              >
                Return to Overview
              </button>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════
            KEY METRICS GRID (Executive Overview)
            ═══════════════════════════════════ */}
        {activeTab === 'overview' && (
          <section style={{ marginBottom: '36px' }}>
            <div className="grid-metrics">
              <div
                className="surface-card kpi-card"
                onClick={() => setActiveTab('ingestion')}
                title="Click to view Ingestion & Asset Telemetry"
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '6px', backgroundColor: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <Server size={14} style={{ color: 'var(--accent)' }} />
                    </div>
                    <span className="caption">Audited Cloud Assets</span>
                  </div>
                  <span className="kpi-trend-chip" style={{ color: 'var(--status-pass)' }}>+14 active</span>
                </div>
                <div className="h1" style={{ marginTop: '12px' }}>232</div>
                <div className="caption" style={{ marginTop: '4px' }}>Across 3 connected cloud tenants</div>
                <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '999px', marginTop: '12px', overflow: 'hidden' }}>
                  <div style={{ width: '82%', height: '100%', backgroundColor: 'var(--accent)' }} />
                </div>
              </div>

              <div
                className="surface-card kpi-card"
                onClick={() => setActiveTab('ml-engine')}
                title="Click to inspect ML Risk Engine"
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '6px', backgroundColor: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <ShieldAlert size={14} style={{ color: 'var(--status-critical)' }} />
                    </div>
                    <span className="caption">Composite Risk Score</span>
                  </div>
                  <span className="kpi-trend-chip" style={{ color: 'var(--status-critical)' }}>ELEVATED</span>
                </div>
                <div className="h1" style={{ marginTop: '12px', color: 'var(--status-critical)' }}>74.2 / 100</div>
                <div className="caption" style={{ marginTop: '4px' }}>High risk exposure detected</div>
                <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '999px', marginTop: '12px', overflow: 'hidden' }}>
                  <div style={{ width: '74.2%', height: '100%', backgroundColor: 'var(--status-critical)' }} />
                </div>
              </div>

              <div
                className="surface-card kpi-card"
                onClick={() => {
                  setSelectedSeverityFilter('CRITICAL');
                  setActiveTab('findings');
                }}
                title="Click to filter Critical findings"
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '6px', backgroundColor: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <AlertTriangle size={14} style={{ color: 'var(--status-critical)' }} />
                    </div>
                    <span className="caption">Critical Findings</span>
                  </div>
                  <span className="kpi-trend-chip" style={{ color: 'var(--status-critical)' }}>Immediate SLA</span>
                </div>
                <div className="h1" style={{ marginTop: '12px', color: 'var(--status-critical)' }}>
                  {findings.filter(f => f.severity === 'CRITICAL').length}
                </div>
                <div className="caption" style={{ marginTop: '4px' }}>Immediate remediation required</div>
                <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '999px', marginTop: '12px', overflow: 'hidden' }}>
                  <div style={{ width: '100%', height: '100%', backgroundColor: 'var(--status-critical)' }} />
                </div>
              </div>

              <div
                className="surface-card kpi-card"
                onClick={() => setActiveTab('compliance')}
                title="Click to view Compliance Matrix"
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: '28px', height: '28px', borderRadius: '6px', backgroundColor: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <CheckCircle2 size={14} style={{ color: 'var(--status-pass)' }} />
                    </div>
                    <span className="caption">Monitored Frameworks</span>
                  </div>
                  <span className="kpi-trend-chip" style={{ color: 'var(--status-pass)' }}>6 Active</span>
                </div>
                <div className="h1" style={{ marginTop: '12px' }}>6</div>
                <div className="caption" style={{ marginTop: '4px' }}>CIS, NIST, ISO 27001, PCI-DSS</div>
                <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '999px', marginTop: '12px', overflow: 'hidden' }}>
                  <div style={{ width: '66.7%', height: '100%', backgroundColor: 'var(--status-warning)' }} />
                </div>
              </div>
            </div>
          </section>
        )}

        {/* ═══════════════════════════════════
            TAB 1: POSTURE OVERVIEW
            ═══════════════════════════════════ */}
        {activeTab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
            {/* Multi-Cloud Posture Matrix */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <div>
                  <h3>Multi-Cloud Posture Distribution</h3>
                  <span className="caption">Realtime posture synthesis across connected cloud tenants</span>
                </div>
                <span className="caption">3 Active Cloud Environments</span>
              </div>
              <div className="grid-metrics">
                <div className="surface-card" style={{ borderLeft: '3px solid #FF9900' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700 }}>AWS Production</span>
                    <span className="tag tag-critical">High Exposure</span>
                  </div>
                  <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Monitored Nodes:</span>
                    <span className="code-text"><b>142</b> / 232</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">Critical Alerts:</span>
                    <span className="code-text" style={{ color: 'var(--status-critical)' }}><b>2 Active</b></span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">CIS AWS 1.4:</span>
                    <span className="code-text"><b>88%</b> Pass</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', marginTop: '8px', overflow: 'hidden' }}>
                    <div style={{ width: '88%', height: '100%', backgroundColor: '#FF9900' }} />
                  </div>
                </div>

                <div className="surface-card" style={{ borderLeft: '3px solid #008AD7' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700 }}>Azure Enterprise</span>
                    <span className="tag tag-warning">Elevated</span>
                  </div>
                  <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Monitored Nodes:</span>
                    <span className="code-text"><b>58</b> / 232</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">Critical Alerts:</span>
                    <span className="code-text" style={{ color: 'var(--status-critical)' }}><b>1 Active</b></span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">CIS Azure 2.0:</span>
                    <span className="code-text"><b>91%</b> Pass</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', marginTop: '8px', overflow: 'hidden' }}>
                    <div style={{ width: '91%', height: '100%', backgroundColor: '#008AD7' }} />
                  </div>
                </div>

                <div className="surface-card" style={{ borderLeft: '3px solid #4285F4' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700 }}>GCP Workloads</span>
                    <span className="tag tag-pass">Nominal</span>
                  </div>
                  <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Monitored Nodes:</span>
                    <span className="code-text"><b>32</b> / 232</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">Critical Alerts:</span>
                    <span className="code-text" style={{ color: 'var(--status-pass)' }}><b>0 Active</b></span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">CIS GCP 1.3:</span>
                    <span className="code-text"><b>94%</b> Pass</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', marginTop: '8px', overflow: 'hidden' }}>
                    <div style={{ width: '94%', height: '100%', backgroundColor: 'var(--accent)' }} />
                  </div>
                </div>

                <div className="surface-card" style={{ borderLeft: '3px solid var(--accent)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700 }}>Zero-Trust Engine</span>
                    <span className="tag tag-accent">Automated</span>
                  </div>
                  <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Playbooks Ready:</span>
                    <span className="code-text"><b>18 IaC</b> Modules</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">Mean Time to Patch:</span>
                    <span className="code-text"><b>&lt; 45s</b> CLI/TF</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                    <span className="caption">Explainability:</span>
                    <span className="code-text"><b>TreeSHAP</b> Active</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', marginTop: '8px', overflow: 'hidden' }}>
                    <div style={{ width: '100%', height: '100%', backgroundColor: 'var(--accent)' }} />
                  </div>
                </div>
              </div>
            </div>

            {/* 2-Column: Live Security Telemetry & Risk Severity Breakdown */}
            <div className="grid-2col">
              {/* Telemetry Feed */}
              <div className="surface-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <h3>Live Audit Telemetry</h3>
                    <span className="tag">Realtime Feed</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {(['ALL', 'AWS', 'AZURE', 'GCP', 'CRIT'] as const).map(flt => (
                      <button
                        key={flt}
                        className={`btn ${telemetryFilter === flt ? 'btn-primary' : 'btn-secondary'}`}
                        style={{ height: '26px', minHeight: '26px', padding: '0 8px', fontSize: '11px' }}
                        onClick={() => setTelemetryFilter(flt)}
                      >
                        {flt}
                      </button>
                    ))}
                    <button
                      className="btn btn-secondary"
                      style={{ height: '26px', minHeight: '26px', padding: '0 8px', fontSize: '11px' }}
                      onClick={() => {
                        setIsLiveStreamActive(!isLiveStreamActive);
                        showToast(isLiveStreamActive ? 'Live telemetry stream paused' : 'Live telemetry stream resumed');
                      }}
                      title={isLiveStreamActive ? 'Pause stream' : 'Resume stream'}
                    >
                      {isLiveStreamActive ? <Pause size={11} /> : <Play size={11} />}
                      <span>{isLiveStreamActive ? 'Pause' : 'Resume'}</span>
                    </button>
                  </div>
                </div>
                <div className="code-snippet-box" style={{ maxHeight: '280px', overflowY: 'auto' }}>
                  {filteredTelemetryLogs.map(log => (
                    <div
                      key={log.id}
                      style={{
                        display: 'grid',
                        gridTemplateColumns: '70px 60px 1fr 50px',
                        gap: '8px',
                        padding: '4px 0',
                        borderBottom: '1px solid var(--border)'
                      }}
                    >
                      <span style={{ color: 'var(--text-secondary)' }}>{log.time}</span>
                      <span style={{ fontWeight: 700 }}>{log.cloud}</span>
                      <span>{log.action}</span>
                      <span style={{
                        color: log.status === 'CRIT' ? 'var(--status-critical)' : log.status === 'WARN' ? 'var(--status-warning)' : 'var(--status-pass)',
                        textAlign: 'right',
                        fontWeight: 700
                      }}>
                        {log.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Risk Distribution Breakdown */}
              <div className="surface-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h3>Risk Severity Distribution</h3>
                  <span className="tag">{findings.length} Total</span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '8px' }}>
                  {[
                    { label: 'CRITICAL', count: findings.filter(f => f.severity === 'CRITICAL').length, color: 'var(--status-critical)', desc: 'Full account takeover or direct public storage' },
                    { label: 'HIGH', count: findings.filter(f => f.severity === 'HIGH').length, color: 'var(--status-warning)', desc: 'Management port exposed (SSH/RDP) or missing rotation' },
                    { label: 'MEDIUM', count: findings.filter(f => f.severity === 'MEDIUM').length, color: 'var(--text-secondary)', desc: 'Volume default encryption without customer KMS' },
                    { label: 'LOW', count: findings.filter(f => f.severity === 'LOW').length, color: 'var(--text-secondary)', desc: 'Wildcard log permissions with restricted scope' }
                  ].map(item => (
                    <div key={item.label} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontWeight: 700, fontSize: '13px', color: item.color }}>{item.label}</span>
                        <span style={{ fontWeight: 700 }}>{item.count}</span>
                      </div>
                      <div style={{ width: '100%', height: '6px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', overflow: 'hidden' }}>
                        <div
                          style={{
                            width: `${(item.count / findings.length) * 100}%`,
                            height: '100%',
                            backgroundColor: item.color,
                            borderRadius: '2px'
                          }}
                        />
                      </div>
                      <span className="caption">{item.desc}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* MITRE ATT&CK Defense Matrix Coverage Card */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
                <div>
                  <h3>MITRE ATT&CK Framework Cloud Matrix</h3>
                  <span className="caption">Active attack techniques detected across audited cloud assets</span>
                </div>
                <span className="tag tag-accent">4 Active Techniques</span>
              </div>
              <div className="grid-metrics">
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                  <span className="tag tag-critical">T1078.004</span>
                  <div style={{ fontWeight: 700, fontSize: '13px', marginTop: '6px' }}>Valid Cloud Accounts</div>
                  <p className="caption" style={{ marginTop: '4px' }}>Unprotected root access key usage without MFA enforcement</p>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                  <span className="tag tag-critical">T1537</span>
                  <div style={{ fontWeight: 700, fontSize: '13px', marginTop: '6px' }}>Transfer Data to Cloud Account</div>
                  <p className="caption" style={{ marginTop: '4px' }}>Public read/list ACLs enabled on object storage buckets</p>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                  <span className="tag tag-warning">T1021.004</span>
                  <div style={{ fontWeight: 700, fontSize: '13px', marginTop: '6px' }}>SSH Remote Services</div>
                  <p className="caption" style={{ marginTop: '4px' }}>Port 22 ingress rule unrestricted to public CIDR 0.0.0.0/0</p>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                  <span className="tag tag-critical">T1562.001</span>
                  <div style={{ fontWeight: 700, fontSize: '13px', marginTop: '6px' }}>Impair Defenses: Disable Cloud Logs</div>
                  <p className="caption" style={{ marginTop: '4px' }}>Multi-region CloudTrail audit logging stopped or tampered with</p>
                </div>
              </div>
            </div>

            {/* Quick Remediation Priority Queue */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
                <div>
                  <h3>Priority Remediation Queue</h3>
                  <p className="caption" style={{ marginTop: '2px' }}>
                    Findings with highest TreeSHAP risk attribution requiring immediate action
                  </p>
                </div>
                <button className="btn btn-secondary" onClick={() => setActiveTab('findings')}>
                  View All Findings
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {findings.slice(0, 3).map(f => (
                  <div
                    key={f.id}
                    style={{
                      padding: '16px',
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      display: 'flex',
                      flexWrap: 'wrap',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: '12px'
                    }}
                  >
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', maxWidth: '700px' }}>
                      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <span className={`tag ${f.severity === 'CRITICAL' ? 'tag-critical' : 'tag-warning'}`}>
                          {f.severity}
                        </span>
                        <span className="tag">{f.cloud}</span>
                        <span className="caption code-text">{f.id}</span>
                        <span className="kpi-trend-chip" style={{ color: 'var(--status-critical)' }}>
                          SLA: 2h remaining
                        </span>
                      </div>
                      <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{f.title}</div>
                      <p className="caption">{f.remediation}</p>
                    </div>

                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      <button
                        className="btn btn-secondary"
                        onClick={() => {
                          setSelectedFinding(f);
                          setActiveTab('findings');
                        }}
                      >
                        Remediate
                      </button>
                      <button
                        className="btn btn-primary"
                        onClick={() => handleExecutePlaybook(`Remediate finding ${f.id} (${f.title})`)}
                      >
                        <Terminal size={14} />
                        <span>Fix in Console</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════
            TAB 2: SECURITY FINDINGS (MASTER-DETAIL)
            ═══════════════════════════════════ */}
        {activeTab === 'findings' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {/* Filter Bar */}
            <div className="surface-card" style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                <span className="caption" style={{ marginRight: '4px' }}>Provider:</span>
                {(['ALL', 'AWS', 'Azure', 'GCP'] as const).map(cloud => (
                  <button
                    key={cloud}
                    className={`btn ${selectedCloudFilter === cloud ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ height: '36px', minHeight: '36px', padding: '0 12px' }}
                    onClick={() => setSelectedCloudFilter(cloud)}
                  >
                    {cloud}
                  </button>
                ))}
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                <span className="caption" style={{ marginRight: '4px' }}>Severity:</span>
                {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
                  <button
                    key={sev}
                    className={`btn ${selectedSeverityFilter === sev ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ height: '36px', minHeight: '36px', padding: '0 12px' }}
                    onClick={() => setSelectedSeverityFilter(sev)}
                  >
                    {sev}
                  </button>
                ))}
              </div>

              {/* Category Filter Pills */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', alignItems: 'center' }}>
                <span className="caption" style={{ marginRight: '4px' }}>Category:</span>
                {(['ALL', 'IAM', 'Storage', 'Network', 'Encryption', 'Logging'] as const).map(cat => (
                  <button
                    key={cat}
                    className={`btn ${selectedCategoryFilter === cat ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ height: '32px', minHeight: '32px', padding: '0 10px', fontSize: '11px' }}
                    onClick={() => setSelectedCategoryFilter(cat)}
                  >
                    {cat}
                  </button>
                ))}
              </div>

              {/* Search input with 44px min height */}
              <div style={{ flexGrow: 1, minWidth: '220px', maxWidth: '320px' }}>
                <input
                  type="text"
                  className="form-input"
                  placeholder="Filter by title, ID, or ARN..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
            </div>

            {/* Master-Detail Layout */}
            {filteredFindings.length === 0 ? (
              /* REQUIRED STATE: EMPTY */
              <div className="state-empty">
                <div className="state-empty-title">No Security Findings Match Filters</div>
                <p>Try resetting the cloud provider, severity filter, category, or search term.</p>
                <button
                  className="btn btn-secondary"
                  style={{ marginTop: '16px' }}
                  onClick={() => {
                    setSelectedCloudFilter('ALL');
                    setSelectedSeverityFilter('ALL');
                    setSelectedCategoryFilter('ALL');
                    setSearchQuery('');
                  }}
                >
                  Reset All Filters
                </button>
              </div>
            ) : (
              <div className="grid-master-detail">
                {/* Findings List (Master) */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '720px', overflowY: 'auto' }}>
                  {filteredFindings.map(f => {
                    const isSelected = selectedFinding?.id === f.id;
                    const st = findingStatuses[f.id] || 'OPEN';
                    return (
                      <div
                        key={f.id}
                        tabIndex={0}
                        role="button"
                        className={`surface-card surface-card-interactive ${isSelected ? 'is-selected' : ''}`}
                        onClick={() => setSelectedFinding(f)}
                        onKeyDown={(e) => { if (e.key === 'Enter') setSelectedFinding(f); }}
                        style={{ padding: '16px' }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                            <span className={`tag ${f.severity === 'CRITICAL' ? 'tag-critical' : f.severity === 'HIGH' ? 'tag-warning' : ''}`}>
                              {f.severity}
                            </span>
                            <span className={`tag ${st === 'RESOLVED' ? 'status-pill-resolved' : st === 'IN_PROGRESS' ? 'status-pill-progress' : 'status-pill-open'}`} style={{ fontSize: '10px' }}>
                              {st.replace('_', ' ')}
                            </span>
                          </div>
                          <span className="caption code-text">{f.cloud}</span>
                        </div>
                        <div style={{ fontWeight: 700, fontSize: '14px', marginBottom: '6px', color: 'var(--text-primary)' }}>
                          {f.title}
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span className="caption code-text">{f.id}</span>
                          <span className="caption">Score: <b>{f.riskScore}</b></span>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Finding Details (Detail) */}
                {selectedFinding && (
                  <div className="surface-card" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '8px' }}>
                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                          <span className={`tag ${selectedFinding.severity === 'CRITICAL' ? 'tag-critical' : 'tag-warning'}`}>
                            {selectedFinding.severity}
                          </span>
                          <span className="tag">{selectedFinding.cloud}</span>
                          <span className="tag tag-accent">{selectedFinding.category}</span>
                          <span className="caption code-text">{selectedFinding.id}</span>
                        </div>

                        {/* Triage Lifecycle State Buttons */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span className="caption" style={{ fontSize: '11px' }}>Triage:</span>
                          {(['OPEN', 'IN_PROGRESS', 'RESOLVED'] as const).map(st => (
                            <button
                              key={st}
                              className={`btn ${findingStatuses[selectedFinding.id] === st ? 'btn-primary' : 'btn-secondary'}`}
                              style={{ height: '26px', minHeight: '26px', padding: '0 8px', fontSize: '11px' }}
                              onClick={() => {
                                setFindingStatuses(prev => ({ ...prev, [selectedFinding.id]: st }));
                                showToast(`${selectedFinding.id} status updated to ${st.replace('_', ' ')}`);
                              }}
                            >
                              {st.replace('_', ' ')}
                            </button>
                          ))}
                        </div>
                      </div>

                      <h2>{selectedFinding.title}</h2>
                      <div style={{ marginTop: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '8px' }}>
                        <div>
                          <span className="caption">Target Resource ARN:</span>
                          <div className="code-text" style={{ marginTop: '2px', wordBreak: 'break-all' }}>
                            {selectedFinding.resourceId}
                          </div>
                        </div>
                        <button
                          className="btn btn-primary"
                          style={{ height: '32px', minHeight: '32px', padding: '0 12px', fontSize: '12px' }}
                          onClick={() => handleExecutePlaybook(`Remediate finding ${selectedFinding.id}: ${selectedFinding.title}`)}
                        >
                          <Terminal size={14} />
                          <span>Dispatch to SecOps Console</span>
                        </button>
                      </div>
                    </div>

                    {/* Attack Vector */}
                    {selectedFinding.attackVector && (
                      <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span className="caption" style={{ fontWeight: 700, textTransform: 'uppercase' }}>Threat Attack Vector</span>
                          <span className="tag tag-accent">MITRE ATT&CK</span>
                        </div>
                        <p style={{ marginTop: '4px', fontSize: '14px' }}>{selectedFinding.attackVector}</p>
                      </div>
                    )}

                    {/* Grounded Security Explanation (LLM / Evidence-Grounded Engine) */}
                    <div
                      id="grounded-security-explanation"
                      data-testid="grounded-security-explanation"
                      className="surface-card"
                      style={{
                        border: '1px solid rgba(56, 189, 248, 0.35)',
                        backgroundColor: 'rgba(15, 23, 42, 0.75)',
                        position: 'relative',
                        padding: '16px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '12px'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <div style={{ width: '28px', height: '28px', borderRadius: '6px', backgroundColor: 'rgba(56, 189, 248, 0.15)', border: '1px solid rgba(56, 189, 248, 0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                            <Sparkles size={14} style={{ color: '#38bdf8' }} />
                          </div>
                          <div>
                            <div style={{ fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                              <span>Grounded Security Explanation</span>
                              <span className="tag" style={{ backgroundColor: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: '1px solid rgba(52, 211, 153, 0.3)', fontSize: '10px' }}>
                                <CheckCircle2 size={10} style={{ marginRight: '4px' }} />
                                100% Grounded in Evidence
                              </span>
                            </div>
                            <span className="caption" style={{ fontSize: '11px' }}>
                              Strict anti-hallucination boundary • Synthesized from verified pipeline facts
                            </span>
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span className="tag" style={{ fontSize: '10px', fontFamily: 'monospace' }}>
                            {selectedFindingExplanation?.model_used || 'deterministic-grounded-engine'}
                          </span>
                          <button
                            className="btn btn-secondary"
                            style={{ height: '28px', minHeight: '28px', padding: '0 8px', fontSize: '11px' }}
                            disabled={isLoadingExplanation}
                            onClick={() => fetchExplanationForFinding(selectedFinding)}
                            title="Re-synthesize verified security explanation"
                          >
                            <RefreshCw size={12} className={isLoadingExplanation ? 'animate-spin' : ''} />
                            <span>{isLoadingExplanation ? 'Synthesizing...' : 'Refresh'}</span>
                          </button>
                        </div>
                      </div>

                      {isLoadingExplanation ? (
                        <div style={{ padding: '24px', textAlign: 'center' }}>
                          <RefreshCw size={20} className="animate-spin" style={{ color: '#38bdf8', margin: '0 auto 8px auto' }} />
                          <div className="caption">Compiling verified telemetry, SHAP attributions, and compliance impact...</div>
                        </div>
                      ) : selectedFindingExplanation ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                          {/* Risk Banner */}
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', borderRadius: '4px', backgroundColor: 'rgba(0, 0, 0, 0.4)', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span className="caption" style={{ fontWeight: 700 }}>VERIFIED RISK SEVERITY:</span>
                              <span className={`tag ${selectedFindingExplanation.risk === 'CRITICAL' ? 'tag-critical' : selectedFindingExplanation.risk === 'HIGH' ? 'tag-warning' : ''}`} style={{ fontSize: '11px' }}>
                                {selectedFindingExplanation.risk}
                              </span>
                            </div>
                            <span className="caption code-text" style={{ fontSize: '11px' }}>
                              Grounding Score: <b>{(selectedFindingExplanation.grounding_score * 100).toFixed(0)}%</b>
                            </span>
                          </div>

                          {/* What Happened */}
                          <div>
                            <div className="caption" style={{ fontWeight: 700, color: '#38bdf8', textTransform: 'uppercase', marginBottom: '3px' }}>
                              What Happened
                            </div>
                            <p style={{ fontSize: '13px', lineHeight: 1.5, margin: 0, color: 'var(--text-primary)' }}>
                              {selectedFindingExplanation.what_happened}
                            </p>
                          </div>

                          {/* Why It Matters */}
                          <div>
                            <div className="caption" style={{ fontWeight: 700, color: '#fbbf24', textTransform: 'uppercase', marginBottom: '3px' }}>
                              Why It Matters
                            </div>
                            <p style={{ fontSize: '13px', lineHeight: 1.5, margin: 0, color: 'var(--text-secondary)' }}>
                              {selectedFindingExplanation.why_it_matters}
                            </p>
                          </div>

                          {/* Verified Evidence Breakdown */}
                          {selectedFindingExplanation.evidence && selectedFindingExplanation.evidence.length > 0 && (
                            <div>
                              <div className="caption" style={{ fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                                Verified Pipeline Evidence
                              </div>
                              <ul style={{ margin: 0, paddingLeft: '18px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                {selectedFindingExplanation.evidence.map((item, idx) => (
                                  <li key={idx} style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                                    {item}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* Statutory Compliance Impact */}
                          <div>
                            <div className="caption" style={{ fontWeight: 700, color: 'var(--status-critical)', textTransform: 'uppercase', marginBottom: '3px' }}>
                              Compliance Impact
                            </div>
                            <p style={{ fontSize: '13px', lineHeight: 1.5, margin: 0, color: 'var(--text-secondary)' }}>
                              {selectedFindingExplanation.compliance_impact}
                            </p>
                          </div>

                          {/* Recommended Action */}
                          <div style={{ padding: '10px 12px', borderRadius: '4px', backgroundColor: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.25)' }}>
                            <div className="caption" style={{ fontWeight: 700, color: '#34d399', textTransform: 'uppercase', marginBottom: '3px' }}>
                              Recommended Non-Destructive Remediation
                            </div>
                            <p style={{ fontSize: '13px', lineHeight: 1.5, margin: 0, color: 'var(--text-primary)' }}>
                              {selectedFindingExplanation.recommended_action}
                            </p>
                          </div>
                        </div>
                      ) : null}
                    </div>

                    {/* TreeSHAP Feature Attribution */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="caption">TreeSHAP Risk Escalator:</span>
                        <span className="code-text"><b>+{Math.round(selectedFinding.shapImpact * 100)}%</b> risk weight</span>
                      </div>
                      <div style={{ width: '100%', height: '6px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', overflow: 'hidden' }}>
                        <div
                          style={{
                            width: `${Math.round(selectedFinding.shapImpact * 100 * 2)}%`,
                            height: '100%',
                            backgroundColor: 'var(--accent)',
                            borderRadius: '2px'
                          }}
                        />
                      </div>
                      <span className="caption code-text">{selectedFinding.shapTopFeature}</span>
                      <button
                        className="btn btn-secondary"
                        onClick={() => {
                          setActiveTab('ml-engine');
                          explainEventWithShap({
                            event_id: selectedFinding.id,
                            timestamp: new Date().toISOString(),
                            cloud_provider: selectedFinding.cloud.toLowerCase(),
                            resource_type: selectedFinding.category,
                            action: 'AssessSecurityRisk',
                            actor_type: 'root',
                            actor_name: 'root',
                            source_ip: '198.51.100.24',
                            mfa_used: false,
                            outcome: 'Failure',
                            session_duration_s: 0
                          });
                        }}
                        style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '6px', alignSelf: 'flex-start', fontSize: '12px', padding: '5px 10px' }}
                      >
                        <Activity size={13} />
                        <span>Deconstruct in TreeSHAP Waterfall</span>
                      </button>
                    </div>

                    {/* Compliance Violations */}
                    <div>
                      <span className="caption">Regulatory Benchmark Violations:</span>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                        {selectedFinding.complianceViolation.map(c => (
                          <span key={c} className="tag tag-warning">{c}</span>
                        ))}
                      </div>
                    </div>

                    {/* Multi-Platform Remediation Code Panes */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                      {/* Automated CLI Remediation */}
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <span className="caption">Cloud CLI Remediation Script:</span>
                          <button
                            className="btn btn-secondary"
                            style={{ height: '32px', minHeight: '32px', padding: '0 8px', fontSize: '12px' }}
                            onClick={() => copyToClipboard(selectedFinding.cliCommand, 'cli', 'CLI Command copied')}
                          >
                            {copiedKey === 'cli' ? <Check size={14} /> : <Copy size={14} />}
                            <span>{copiedKey === 'cli' ? 'Copied' : 'Copy'}</span>
                          </button>
                        </div>
                        <pre className="code-snippet-box"><code>{selectedFinding.cliCommand}</code></pre>
                      </div>

                      {/* Terraform Patch */}
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <span className="caption">Zero-Trust Terraform IaC Patch:</span>
                          <button
                            className="btn btn-secondary"
                            style={{ height: '32px', minHeight: '32px', padding: '0 8px', fontSize: '12px' }}
                            onClick={() => copyToClipboard(selectedFinding.terraform, 'tf', 'Terraform snippet copied')}
                          >
                            {copiedKey === 'tf' ? <Check size={14} /> : <Copy size={14} />}
                            <span>{copiedKey === 'tf' ? 'Copied' : 'Copy'}</span>
                          </button>
                        </div>
                        <pre className="code-snippet-box"><code>{selectedFinding.terraform}</code></pre>
                      </div>

                      {/* Python SDK Automation */}
                      {selectedFinding.pythonSnippet && (
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                            <span className="caption">Python Cloud SDK Automation:</span>
                            <button
                              className="btn btn-secondary"
                              style={{ height: '32px', minHeight: '32px', padding: '0 8px', fontSize: '12px' }}
                              onClick={() => copyToClipboard(selectedFinding.pythonSnippet!, 'py', 'Python SDK snippet copied')}
                            >
                              {copiedKey === 'py' ? <Check size={14} /> : <Copy size={14} />}
                              <span>{copiedKey === 'py' ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                          <pre className="code-snippet-box"><code>{selectedFinding.pythonSnippet}</code></pre>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ═══════════════════════════════════
            TAB 3: COMPLIANCE MATRIX
            ═══════════════════════════════════ */}
        {activeTab === 'compliance' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {/* Header & Framework Scorecards */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                <div>
                  <h3>Multi-Cloud Compliance Control Matrix</h3>
                  <p style={{ marginTop: '4px' }}>
                    Evaluated configuration checks mapped against CIS Benchmarks, NIST 800-53, ISO 27001, and PCI-DSS 4.0.
                  </p>
                </div>
                <button
                  className="btn btn-secondary"
                  onClick={handleExportComplianceReport}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                >
                  <Download size={14} />
                  <span>Export Compliance Audit Report (JSON)</span>
                </button>
              </div>

              {/* 6 Framework Benchmark Scorecards */}
              <div className="grid-metrics" style={{ marginTop: '20px' }}>
                {[
                  { name: 'CIS AWS 1.4', pass: 1, fail: 2, total: 3, score: '33%' },
                  { name: 'CIS Azure 2.0', pass: 0, fail: 1, total: 2, score: '25%' },
                  { name: 'CIS GCP 1.3', pass: 1, fail: 0, total: 1, score: '100%' },
                  { name: 'NIST 800-53', pass: 0, fail: 1, total: 2, score: '25%' },
                  { name: 'ISO 27001', pass: 0, fail: 1, total: 1, score: '0%' },
                  { name: 'PCI-DSS 4.0', pass: 1, fail: 0, total: 1, score: '100%' }
                ].map(fw => (
                  <div key={fw.name} style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-surface-subtle)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 700, fontSize: '13px' }}>{fw.name}</span>
                      <span className="code-text" style={{ fontWeight: 700, color: fw.score === '100%' ? 'var(--status-pass)' : 'var(--status-warning)' }}>{fw.score}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '6px' }}>
                      <span className="caption">Passing Controls:</span>
                      <span className="code-text">{fw.pass} / {fw.total}</span>
                    </div>
                    <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', marginTop: '8px', overflow: 'hidden' }}>
                      <div style={{ width: fw.score, height: '100%', backgroundColor: fw.score === '100%' ? 'var(--status-pass)' : 'var(--status-warning)' }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Filter Toolbar */}
            <div className="surface-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', padding: '12px 16px' }}>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                <span className="caption">Status Filter:</span>
                {(['ALL', 'PASS', 'FAIL', 'PARTIAL'] as const).map(st => (
                  <button
                    key={st}
                    className={`btn ${complianceStatusFilter === st ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ height: '30px', minHeight: '30px', padding: '0 10px', fontSize: '12px' }}
                    onClick={() => setComplianceStatusFilter(st)}
                  >
                    {st}
                  </button>
                ))}
              </div>

              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                <span className="caption">Framework Filter:</span>
                {(['ALL', 'CIS AWS 1.4', 'CIS Azure 2.0', 'NIST 800-53', 'PCI-DSS 4.0', 'ISO 27001'] as const).map(fw => (
                  <button
                    key={fw}
                    className={`btn ${complianceFrameworkFilter === fw ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ height: '30px', minHeight: '30px', padding: '0 10px', fontSize: '12px' }}
                    onClick={() => setComplianceFrameworkFilter(fw)}
                  >
                    {fw}
                  </button>
                ))}
              </div>
            </div>

            {/* Control Table */}
            <div className="surface-card" style={{ overflowX: 'auto', padding: 0 }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', minWidth: '600px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', backgroundColor: 'var(--bg-primary)' }}>
                    <th style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>Control ID</th>
                    <th style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>Control Specification</th>
                    <th style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>Framework</th>
                    <th style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>Status</th>
                    <th style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>Evaluated</th>
                    <th style={{ padding: '12px 16px', fontSize: '13px', color: 'var(--text-secondary)' }}>Failed</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredComplianceControls.map(c => (
                    <tr key={c.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '14px 16px' }} className="code-text"><b>{c.id}</b></td>
                      <td style={{ padding: '14px 16px', maxWidth: '400px' }}>{c.name}</td>
                      <td style={{ padding: '14px 16px' }}>
                        <span className="tag">{c.framework}</span>
                      </td>
                      <td style={{ padding: '14px 16px' }}>
                        <span className={`tag ${c.status === 'PASS' ? 'tag-pass' : c.status === 'FAIL' ? 'tag-critical' : 'tag-warning'}`}>
                          {c.status}
                        </span>
                      </td>
                      <td style={{ padding: '14px 16px' }}>{c.evaluatedResources}</td>
                      <td style={{ padding: '14px 16px' }}>
                        <span style={{ color: c.failedCount > 0 ? 'var(--status-critical)' : 'var(--text-secondary)', fontWeight: 700 }}>
                          {c.failedCount}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════
            TAB 4: ML & SHAP ENGINE
            ═══════════════════════════════════ */}
        {activeTab === 'ml-engine' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
            {/* Active ML Model Status Card */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <h3>Phase 5: Machine Learning Anomaly Detection</h3>
                    <span className="tag" style={{ backgroundColor: 'var(--accent)', color: 'var(--accent-contrast)', fontWeight: 700 }}>
                      {modelInfo?.status === 'ready' ? 'ONLINE (ACTIVE)' : 'TRAINED (LOCAL)'}
                    </span>
                  </div>
                  <p className="caption" style={{ marginTop: '2px' }}>
                    Unsupervised scikit-learn Isolation Forest calibrated for multi-cloud security telemetry
                  </p>
                </div>
                <button
                  className="btn btn-secondary"
                  onClick={runLiveMlInference}
                  disabled={isInferring}
                  style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
                >
                  <Activity size={15} />
                  <span>{isInferring ? 'Scoring Telemetry...' : 'Run Live ML Inference Scan'}</span>
                </button>
              </div>

              <div className="grid-4col" style={{ gap: '16px' }}>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Algorithm</span>
                  <div className="code-text" style={{ fontSize: '14px', fontWeight: 700, marginTop: '4px' }}>
                    {modelInfo?.algorithm || 'IsolationForest'}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Model Version</span>
                  <div className="code-text" style={{ fontSize: '14px', fontWeight: 700, marginTop: '4px' }}>
                    {modelInfo?.model_version || 'isolation-forest-v1'}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Training Dataset</span>
                  <div className="code-text" style={{ fontSize: '14px', fontWeight: 700, marginTop: '4px' }}>
                    {modelInfo?.training_records_count ? `${modelInfo.training_records_count.toLocaleString()} events` : '25,000 events'}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Engineered Features</span>
                  <div className="code-text" style={{ fontSize: '14px', fontWeight: 700, marginTop: '4px' }}>
                    {modelInfo?.feature_count || 75} dimensions
                  </div>
                </div>
              </div>

              {/* Live Inference Results Pane */}
              {mlInferenceResult && (
                <div style={{ marginTop: '20px', padding: '16px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <span className="code-text" style={{ fontWeight: 700 }}>
                      Live Inference Result ({mlInferenceResult.anomalies_detected} Anomalies / {mlInferenceResult.total_events} Scored)
                    </span>
                    <span className="caption">Rate: {Math.round(mlInferenceResult.anomaly_rate * 100)}%</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {mlInferenceResult.predictions.map((p: any, idx: number) => (
                      <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px', border: '1px solid var(--border)', borderRadius: '2px' }}>
                        <span className="code-text" style={{ fontSize: '13px' }}>
                          Event #{idx + 1}: Score = <b>{Math.round(p.anomaly_score * 100)}%</b> (Raw: {p.raw_score})
                        </span>
                        <span
                          className="tag"
                          style={{
                            backgroundColor: p.is_anomaly ? 'var(--status-critical)' : 'transparent',
                            borderColor: p.is_anomaly ? 'var(--status-critical)' : 'var(--border)',
                            color: p.is_anomaly ? '#fff' : 'var(--text-secondary)'
                          }}
                        >
                          {p.is_anomaly ? 'STATISTICAL ANOMALY' : 'NORMAL INLIER'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Phase 6: Supervised Risk Classification Model Card (XGBoost) */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <h3>Phase 6: Supervised Risk Classification Engine</h3>
                    <span className="tag" style={{ backgroundColor: 'var(--accent)', color: 'var(--accent-contrast)', fontWeight: 700 }}>
                      {supervisedModelInfo?.status === 'ready' ? 'ONLINE (ACTIVE)' : 'TRAINED (LOCAL)'}
                    </span>
                  </div>
                  <p className="caption" style={{ marginTop: '2px' }}>
                    Dual-head XGBoost Gradient Boosted Trees for incident severity classification and continuous risk scoring
                  </p>
                </div>
                <button
                  className="btn btn-secondary"
                  onClick={runLiveSupervisedScan}
                  disabled={isSupervisedInferring}
                  style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
                >
                  <Activity size={15} />
                  <span>{isSupervisedInferring ? 'Classifying Risk...' : 'Run Live Supervised Risk Scan'}</span>
                </button>
              </div>

              <div className="grid-4col" style={{ gap: '16px' }}>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Algorithm</span>
                  <div className="code-text" style={{ fontSize: '13px', fontWeight: 700, marginTop: '4px' }}>
                    {supervisedModelInfo?.algorithm || 'XGBoost (Classifier + Regressor)'}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Model Version</span>
                  <div className="code-text" style={{ fontSize: '13px', fontWeight: 700, marginTop: '4px' }}>
                    {supervisedModelInfo?.model_version || 'supervised-xgboost-v1'}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Dataset & Split</span>
                  <div className="code-text" style={{ fontSize: '13px', fontWeight: 700, marginTop: '4px' }}>
                    {supervisedModelInfo?.training_records_count ? `${supervisedModelInfo.training_records_count.toLocaleString()} events` : '20,000 / 5,000'}
                  </div>
                </div>
                <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '4px' }}>
                  <span className="caption">Evaluation Metrics</span>
                  <div className="code-text" style={{ fontSize: '13px', fontWeight: 700, marginTop: '4px' }}>
                    MAE: {supervisedModelInfo?.metrics?.mae ? `${supervisedModelInfo.metrics.mae} pts` : '10.59 pts'} | R²: {supervisedModelInfo?.metrics?.r2 || '0.48'}
                  </div>
                </div>
              </div>

              {/* Live Supervised Classification Results Pane */}
              {supervisedRiskResult && (
                <div style={{ marginTop: '20px', padding: '16px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <span className="code-text" style={{ fontWeight: 700 }}>
                      Live Supervised Inference ({supervisedRiskResult.total_events} Events Processed — Mean Risk: {supervisedRiskResult.mean_risk_score}/100)
                    </span>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      {Object.entries(supervisedRiskResult.severity_counts || {}).map(([sev, count]: [string, any]) => (
                        <span key={sev} className="tag" style={{ fontSize: '10px' }}>
                          {sev.toUpperCase()}: {count}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {supervisedRiskResult.predictions.map((p: any, idx: number) => {
                      const sevUpper = (p.predicted_severity || 'LOW').toUpperCase();
                      const sevClass = sevUpper === 'CRITICAL' ? 'tag-critical' : sevUpper === 'HIGH' ? 'tag-warning' : sevUpper === 'MEDIUM' ? 'tag' : 'tag-pass';
                      return (
                        <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '6px', padding: '10px 12px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-surface)' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span className="code-text" style={{ fontWeight: 700 }}>Telemetry Event #{idx + 1}</span>
                              <span className={`tag ${sevClass}`}>
                                {sevUpper}
                              </span>
                              <span className="caption" style={{ fontSize: '12px' }}>
                                Confidence: <b>{Math.round(p.confidence * 100)}%</b>
                              </span>
                            </div>
                            <span className="code-text" style={{ fontWeight: 700 }}>
                              Predicted Risk: <span style={{ color: p.predicted_risk_score >= 70 ? 'var(--status-critical)' : p.predicted_risk_score >= 40 ? 'var(--status-warning)' : 'var(--status-pass)' }}>{p.predicted_risk_score} / 100</span>
                            </span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '2px' }}>
                            <span className="caption" style={{ fontSize: '11px', minWidth: '75px' }}>Softmax Dist:</span>
                            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                              {Object.entries(p.severity_probabilities || {}).map(([s, prob]: [string, any]) => (
                                <span key={s} className="caption code-text" style={{ fontSize: '11px' }}>
                                  {s}: {Math.round(prob * 100)}%
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Risk Simulator Sandbox */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div>
                  <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Sliders size={16} style={{ color: 'var(--accent)' }} />
                    <span>TreeSHAP Risk Sandbox Simulator</span>
                  </h3>
                  <p className="caption" style={{ marginTop: '2px' }}>
                    Adjust telemetry weights to simulate dynamic machine learning risk scoring
                  </p>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span className="caption">Simulated Score:</span>
                  <div className="h2" style={{ color: simulatedScore > 75 ? 'var(--status-critical)' : 'var(--accent)' }}>
                    {simulatedScore} / 100
                  </div>
                </div>
              </div>

              <div className="grid-2col">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Privilege Escalation Exposure:</span>
                    <span className="code-text">{simPrivilege}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={simPrivilege}
                    onChange={(e) => setSimPrivilege(Number(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent)', height: '24px' }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Public Internet Ingress Scope:</span>
                    <span className="code-text">{simExposure}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={simExposure}
                    onChange={(e) => setSimExposure(Number(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent)', height: '24px' }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Blast Radius (Connected VPCs/Tenants):</span>
                    <span className="code-text">{simRadius}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={simRadius}
                    onChange={(e) => setSimRadius(Number(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent)', height: '24px' }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="caption">Cryptographic Weakness (Missing CMEK):</span>
                    <span className="code-text">{simEncryption}%</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={simEncryption}
                    onChange={(e) => setSimEncryption(Number(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent)', height: '24px' }}
                  />
                </div>
              </div>
            </div>

            {/* Phase 7: TreeSHAP Global Feature Attributions */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <h3>Top TreeSHAP Global Feature Attributions</h3>
                    <span className="tag" style={{ backgroundColor: 'var(--accent)', color: 'var(--accent-contrast)', fontWeight: 700 }}>
                      PHASE 7 (EXPLAINABILITY)
                    </span>
                  </div>
                  <p className="caption" style={{ marginTop: '2px' }}>
                    Mean absolute Shapley values (TreeSHAP) quantifying global feature impact across multi-cloud infrastructure
                  </p>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span className="caption">Baseline Risk:</span>
                  <div className="code-text" style={{ fontSize: '15px', fontWeight: 700 }}>
                    {globalShapAttributions?.base_value || 48.5} pts
                  </div>
                </div>
              </div>

              {/* Domain Distribution Chips */}
              {globalShapAttributions?.domain_distribution && (
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '16px', padding: '10px', backgroundColor: 'var(--bg-primary)', borderRadius: '4px', border: '1px solid var(--border)' }}>
                  <span className="caption" style={{ alignSelf: 'center', marginRight: '4px' }}>Domain Impact:</span>
                  {Object.entries(globalShapAttributions.domain_distribution).map(([dom, pct]) => (
                    <span key={dom} className="tag" style={{ fontSize: '11px' }}>
                      {dom}: <b>{pct}%</b>
                    </span>
                  ))}
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {(globalShapAttributions?.top_global_features || [
                  { feature_name: 'actor_type_root', display_name: 'Root Cloud Account Usage', domain: 'IAM', relative_percentage: 34.5, description: 'Privileged root account usage' },
                  { feature_name: 'mfa_used', display_name: 'Missing Multi-Factor Auth', domain: 'Authentication', relative_percentage: 25.3, description: 'Missing MFA verification' },
                  { feature_name: 'is_public_ip', display_name: 'Public Internet Ingress', domain: 'Network', relative_percentage: 18.0, description: 'Untrusted public IP' },
                  { feature_name: 'action_StopLogging', display_name: 'Audit Trail Interruption', domain: 'Logging', relative_percentage: 12.1, description: 'Logging deactivated' },
                  { feature_name: 'action_PutBucketAcl', display_name: 'Storage ACL Modification', domain: 'Storage', relative_percentage: 6.0, description: 'Public storage ACL' },
                  { feature_name: 'action_ScheduleKeyDeletion', display_name: 'KMS Key Destruction', domain: 'Encryption', relative_percentage: 4.1, description: 'Key deletion' }
                ]).map(item => (
                  <div key={item.feature_name} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="code-text" style={{ fontWeight: 600 }}>{item.display_name}</span>
                        <span className="caption" style={{ fontSize: '11px' }}>({item.feature_name})</span>
                      </div>
                      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <span className="tag">{item.domain}</span>
                        <span className="code-text"><b>+{item.relative_percentage}%</b></span>
                      </div>
                    </div>
                    <div style={{ width: '100%', height: '6px', backgroundColor: 'var(--bg-primary)', borderRadius: '2px', overflow: 'hidden' }}>
                      <div
                        style={{
                          width: `${Math.min(item.relative_percentage * 2.5, 100)}%`,
                          height: '100%',
                          backgroundColor: 'var(--accent)',
                          borderRadius: '2px'
                        }}
                      />
                    </div>
                    {item.description && (
                      <span className="caption" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                        {item.description}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* TreeSHAP Local Instance Attribution Explainer */}
            <div className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <h3>TreeSHAP Local Incident Attribution Waterfall</h3>
                    <span className="tag tag-warning">ADDITIVE SHAP</span>
                  </div>
                  <p className="caption" style={{ marginTop: '2px' }}>
                    Exact Shapley decomposition isolating positive risk enhancers and negative mitigators for individual telemetry incidents
                  </p>
                </div>
                <button
                  className="btn btn-secondary"
                  onClick={() => explainEventWithShap()}
                  disabled={isExplainingEvent}
                  style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
                >
                  <Activity size={15} />
                  <span>{isExplainingEvent ? 'Calculating SHAP...' : 'Deconstruct Sample Incident with TreeSHAP'}</span>
                </button>
              </div>

              {selectedEventExplanation ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '16px', border: '1px solid var(--border)', borderRadius: '4px', backgroundColor: 'var(--bg-primary)' }}>
                  {/* Additivity Equation Bar */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', paddingBottom: '12px', borderBottom: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span className="code-text" style={{ fontWeight: 700 }}>
                        Incident: {selectedEventExplanation.event_id || 'evt-fnd-root-01'}
                      </span>
                      <span className="caption">
                        Base Risk: <b>{selectedEventExplanation.base_value} pts</b>
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="caption">Explained Score:</span>
                      <span className="code-text" style={{ fontSize: '16px', fontWeight: 700, color: selectedEventExplanation.predicted_risk_score >= 70 ? 'var(--status-critical)' : 'var(--status-warning)' }}>
                        {selectedEventExplanation.predicted_risk_score} / 100
                      </span>
                      <span className={`tag ${selectedEventExplanation.predicted_risk_score >= 70 ? 'tag-critical' : 'tag-warning'}`}>
                        {selectedEventExplanation.predicted_risk_score >= 70 ? 'CRITICAL RISK' : 'ELEVATED RISK'}
                      </span>
                    </div>
                  </div>

                  {/* 2-Column: Drivers vs Mitigators */}
                  <div className="grid-2col" style={{ gap: '16px' }}>
                    {/* Top Drivers */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <span className="caption" style={{ fontWeight: 700, color: 'var(--status-critical)', textTransform: 'uppercase' }}>
                        ▲ Top Risk Drivers (+pts added)
                      </span>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {selectedEventExplanation.top_risk_drivers.map((d, i) => (
                          <div key={i} style={{ padding: '8px 10px', border: '1px solid var(--border)', borderRadius: '3px', backgroundColor: 'var(--bg-surface)' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <span className="code-text" style={{ fontWeight: 600, fontSize: '12px' }}>{d.display_name}</span>
                                <span className="tag" style={{ fontSize: '10px' }}>{d.domain}</span>
                              </div>
                              <span className="code-text" style={{ color: 'var(--status-critical)', fontWeight: 700, fontSize: '12px' }}>
                                +{d.shap_value} pts
                              </span>
                            </div>
                            <p className="caption" style={{ marginTop: '3px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                              {d.description}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Top Mitigators */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <span className="caption" style={{ fontWeight: 700, color: 'var(--status-pass)', textTransform: 'uppercase' }}>
                        ▼ Protective Factors (-pts mitigated)
                      </span>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {selectedEventExplanation.top_risk_mitigators.length > 0 ? (
                          selectedEventExplanation.top_risk_mitigators.map((m, i) => (
                            <div key={i} style={{ padding: '8px 10px', border: '1px solid var(--border)', borderRadius: '3px', backgroundColor: 'var(--bg-surface)' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                  <span className="code-text" style={{ fontWeight: 600, fontSize: '12px' }}>{m.display_name}</span>
                                  <span className="tag" style={{ fontSize: '10px' }}>{m.domain}</span>
                                </div>
                                <span className="code-text" style={{ color: 'var(--status-pass)', fontWeight: 700, fontSize: '12px' }}>
                                  {m.shap_value} pts
                                </span>
                              </div>
                              <p className="caption" style={{ marginTop: '3px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                                {m.description}
                              </p>
                            </div>
                          ))
                        ) : (
                          <div style={{ padding: '12px', border: '1px dashed var(--border)', borderRadius: '3px', textAlign: 'center' }}>
                            <span className="caption">No mitigating security controls detected for this event.</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ textAlign: 'center', padding: '24px 16px', border: '1px dashed var(--border)', borderRadius: '4px' }}>
                  <p className="caption">Click &quot;Deconstruct Sample Incident with TreeSHAP&quot; to compute live additive Shapley feature values for a security event.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════
            TAB 5: DATA INGESTION (ALL 8 STATES)
            ═══════════════════════════════════ */}
        {activeTab === 'ingestion' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div className="surface-card">
              <h3>Multi-Cloud Data Ingestion Engine</h3>
              <p style={{ marginTop: '4px' }}>
                Upload configuration exports from AWS Config, Azure Resource Graph, or GCP Asset Inventory in JSON or CSV format.
              </p>
            </div>

            {/* Dropzone Container */}
            <div className="surface-card" style={{ display: 'flex', flexDirection: 'column', gap: '20px', alignItems: 'center', textAlign: 'center', padding: '40px 24px' }}>
              <UploadCloud size={40} style={{ color: 'var(--accent)' }} />

              <div>
                <div className="h3">Select Configuration Audit File</div>
                <p className="caption" style={{ marginTop: '4px' }}>
                  Supported formats: .json, .csv (Max 50MB)
                </p>
              </div>

              {/* State Handling demonstration */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', justifyContent: 'center' }}>
                <button
                  className={`btn btn-primary ${uploadStatus === 'loading' ? 'is-loading' : ''}`}
                  onClick={() => handleSimulatedFileUpload(false)}
                  disabled={uploadStatus === 'loading'}
                >
                  {uploadStatus === 'loading' && <span className="spinner" style={{ marginRight: '6px' }} />}
                  <span>{uploadStatus === 'loading' ? 'Processing Telemetry...' : 'Upload & Analyze File'}</span>
                </button>

                <button
                  className="btn btn-secondary"
                  onClick={() => handleSimulatedFileUpload(true)}
                  disabled={uploadStatus === 'loading'}
                >
                  Simulate Ingestion Error
                </button>

                {uploadStatus !== 'idle' && (
                  <button
                    className="btn btn-ghost"
                    onClick={() => setUploadStatus('idle')}
                  >
                    Reset Ingestion
                  </button>
                )}
              </div>

              {/* REQUIRED STATE: LOADING */}
              {uploadStatus === 'loading' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '8px' }}>
                  <span className="spinner" />
                  <span className="caption">Parsing cloud telemetry graph and computing TreeSHAP matrices...</span>
                </div>
              )}

              {/* REQUIRED STATE: COMPLETE */}
              {uploadStatus === 'complete' && (
                <div style={{ padding: '16px', border: '1px solid var(--status-pass-border)', borderRadius: '4px', backgroundColor: 'var(--status-pass-bg)', width: '100%', maxWidth: '600px' }}>
                  <div style={{ fontWeight: 700, color: 'var(--status-pass)' }}>Ingestion Successful</div>
                  <div className="caption" style={{ marginTop: '4px' }}>
                    Parsed {uploadedFileName} — Audited 84 resources, identified 2 new critical exposures.
                  </div>
                </div>
              )}

              {/* REQUIRED STATE: ERROR */}
              {uploadStatus === 'error' && (
                <div className="state-error" style={{ width: '100%', maxWidth: '600px' }}>
                  <AlertTriangle size={20} style={{ color: 'var(--status-critical)', flexShrink: 0 }} />
                  <div>
                    <div style={{ fontWeight: 700, color: 'var(--status-critical)' }}>Ingestion Error</div>
                    <div className="caption" style={{ marginTop: '2px' }}>
                      Invalid schema: Missing cloud_provider ARN attributes in rows 12-18. Please upload a standard AWS/Azure/GCP inventory export.
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════
            TAB 6: ARCHITECTURE BLUEPRINT
            ═══════════════════════════════════ */}
        {activeTab === 'architecture' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div className="surface-card">
              <h3>CloudShield IQ System Architecture</h3>
              <p style={{ marginTop: '4px' }}>
                End-to-end telemetry pipeline from multi-cloud discovery to TreeSHAP scoring and automated zero-trust IaC patching.
              </p>
            </div>

            <div className="grid-metrics">
              <div className="surface-card">
                <span className="tag">Stage 1</span>
                <div className="h3" style={{ marginTop: '12px' }}>Telemetry Ingestion</div>
                <p className="caption" style={{ marginTop: '8px' }}>
                  Asynchronous ingestion of IAM policies, security group ingress rules, and KMS encryption state via FastAPI endpoints.
                </p>
              </div>

              <div className="surface-card">
                <span className="tag">Stage 2</span>
                <div className="h3" style={{ marginTop: '12px' }}>Risk Engine</div>
                <p className="caption" style={{ marginTop: '8px' }}>
                  Tree-based machine learning model attributing quantitative risk vectors to cloud configuration parameters.
                </p>
              </div>

              <div className="surface-card">
                <span className="tag">Stage 3</span>
                <div className="h3" style={{ marginTop: '12px' }}>TreeSHAP Explainer</div>
                <p className="caption" style={{ marginTop: '8px' }}>
                  Attribution weights indicating exactly which misconfigurations escalate the composite vulnerability index.
                </p>
              </div>

              <div className="surface-card">
                <span className="tag">Stage 4</span>
                <div className="h3" style={{ marginTop: '12px' }}>IaC Remediation</div>
                <p className="caption" style={{ marginTop: '8px' }}>
                  Synthesized CLI scripts and strict Terraform modules enabling one-click patch deployment to multi-cloud perimeters.
                </p>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* ═══════════════════════════════════
          SECOPS REMEDIATION CONSOLE (FLAT TERMINAL DESIGN)
          ═══════════════════════════════════ */}
      {isConsoleOpen && (
        <aside className="secops-console-panel">
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', borderBottom: '1px solid var(--border)', backgroundColor: 'var(--bg-surface-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Terminal size={16} style={{ color: 'var(--accent)' }} />
              <div style={{ fontWeight: 700, fontSize: '13px' }}>Automated Remediation & SecOps Console</div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <button
                className="btn-ghost"
                style={{ fontSize: '11px', padding: '4px 8px', color: 'var(--text-secondary)' }}
                onClick={() => {
                  setConsoleMessages([{
                    id: 'init',
                    sender: 'system',
                    text: 'SecOps Remediation Engine initialized. Buffer cleared. Continuous posture assessment, TreeSHAP quantitative risk attribution, and zero-trust Infrastructure-as-Code mitigation ready.',
                    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                  }]);
                  showToast('SecOps terminal buffer cleared', 'info');
                }}
                title="Clear buffer"
              >
                Clear
              </button>
              <button
                className="btn-ghost"
                style={{ width: '32px', height: '32px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 0 }}
                onClick={() => setIsConsoleOpen(false)}
                aria-label="Close Console"
              >
                <X size={16} />
              </button>
            </div>
          </div>

          {/* Messages */}
          <div style={{ flexGrow: 1, padding: '16px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {consoleMessages.map(msg => (
              <div
                key={msg.id}
                style={{
                  alignSelf: msg.sender === 'operator' ? 'flex-end' : 'flex-start',
                  maxWidth: '88%',
                  padding: '12px',
                  borderRadius: '4px',
                  backgroundColor: msg.sender === 'operator' ? 'var(--bg-surface-elevated)' : 'var(--bg-primary)',
                  color: 'var(--text-primary)',
                  border: msg.sender === 'operator' ? '1px solid var(--border-hover)' : '1px solid var(--border)'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                  <span className="caption code-text" style={{ color: msg.sender === 'operator' ? 'var(--accent)' : 'var(--text-secondary)' }}>
                    {msg.sender === 'operator' ? '$ operator' : 'system@cloudshield'}
                  </span>
                </div>
                <div style={{ fontSize: '13px', lineHeight: 1.5 }}>{msg.text}</div>
                {msg.code && (
                  <div style={{ marginTop: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span className="caption code-text" style={{ fontSize: '11px', opacity: 0.8 }}>Remediation Synthesizer:</span>
                      <button
                        className="btn-ghost"
                        style={{ fontSize: '11px', padding: '2px 6px', display: 'flex', alignItems: 'center', gap: '4px' }}
                        onClick={() => copyToClipboard(msg.code!, `msg-${msg.id}`, 'Console code copied')}
                      >
                        {copiedKey === `msg-${msg.id}` ? <Check size={12} /> : <Copy size={12} />}
                        <span>{copiedKey === `msg-${msg.id}` ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <pre className="code-snippet-box" style={{ fontSize: '12px', margin: 0 }}>
                      <code>{msg.code}</code>
                    </pre>
                  </div>
                )}
                <div className="caption" style={{ marginTop: '4px', textAlign: 'right', opacity: 0.6, fontSize: '11px' }}>
                  {msg.timestamp}
                </div>
              </div>
            ))}
            {isConsoleExecuting && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px' }}>
                <span className="spinner" />
                <span className="caption">Querying TreeSHAP models and synthesising remediation script...</span>
              </div>
            )}
          </div>

          {/* Quick Command Suggestions */}
          <div style={{ padding: '8px 16px', borderTop: '1px solid var(--border)', backgroundColor: 'var(--bg-surface)', display: 'flex', gap: '6px', overflowX: 'auto' }}>
            {[
              { label: 'Revoke Root IAM Key', cmd: 'Remediate Root IAM access key' },
              { label: 'Apply S3 Access Block', cmd: 'Apply S3 Public Access Block' },
              { label: 'Enforce CloudTrail Logging', cmd: 'Re-enable CloudTrail Logging' },
              { label: 'Audit Compliance Matrix', cmd: 'Audit Compliance Matrix' }
            ].map(item => (
              <button
                key={item.label}
                className="btn btn-secondary"
                style={{ height: '24px', minHeight: '24px', padding: '0 8px', fontSize: '11px', whiteSpace: 'nowrap' }}
                onClick={() => handleExecutePlaybook(item.cmd)}
              >
                {item.label}
              </button>
            ))}
          </div>

          {/* Input Box */}
          <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', display: 'flex', gap: '8px', backgroundColor: 'var(--bg-surface-subtle)' }}>
            <input
              type="text"
              className="form-input"
              placeholder="Enter remediation query, CVE, or resource ARN..."
              value={consoleInput}
              onChange={(e) => setConsoleInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleExecutePlaybook(); }}
            />
            <button
              className="btn btn-primary"
              style={{ width: '38px', minWidth: '38px', height: '38px', padding: 0 }}
              onClick={() => handleExecutePlaybook()}
              aria-label="Execute command"
            >
              <Send size={15} />
            </button>
          </div>
        </aside>
      )}

      {/* ═══════════════════════════════════
          FOOTER (ENTERPRISE MINIMALIST)
          ═══════════════════════════════════ */}
      <footer style={{ borderTop: '1px solid var(--border)', backgroundColor: 'var(--bg-surface)', padding: '20px 0' }}>
        <div className="app-container" style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '16px' }}>
          <div className="caption">
            CloudShield IQ &copy; 2026. Multi-Cloud Security Posture Assessment & Automated Remediation Framework.
          </div>
          <div style={{ display: 'flex', gap: '16px' }}>
            <a href="#" className="caption" onClick={(e) => { e.preventDefault(); setActiveTab('compliance'); }}>
              Compliance Standards
            </a>
            <a href="#" className="caption" onClick={(e) => { e.preventDefault(); setActiveTab('ml-engine'); }}>
              TreeSHAP Documentation
            </a>
            <a href="#" className="caption" onClick={(e) => { e.preventDefault(); setActiveTab('architecture'); }}>
              System Blueprint
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
