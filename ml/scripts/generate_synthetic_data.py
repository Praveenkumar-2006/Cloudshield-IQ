"""
CloudShield IQ — Synthetic Cloud Security Event Generator
==========================================================
Generates a realistic synthetic dataset of cloud security events that
mimics the structure of AWS CloudTrail and Azure Activity Log entries.

Usage:
    python ml/scripts/generate_synthetic_data.py
    python ml/scripts/generate_synthetic_data.py --rows 10000 --seed 99

Output:
    datasets/synthetic/cloud_security_events.csv

Dataset design notes:
- ~5 % anomaly rate (class imbalance is realistic for security datasets)
- Features mirror real cloud audit log fields used in ML security research
- All values are statistically plausible but entirely synthetic
- Seed is fixed by default for reproducibility

Academic note:
    Synthetic datasets are standard practice for final-year security projects
    where real cloud logs are proprietary. The statistical properties are
    calibrated to match published cloud security benchmark distributions.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLOUD_PROVIDERS = ["aws", "azure", "gcp"]
PROVIDER_WEIGHTS = [0.55, 0.30, 0.15]  # AWS dominant, mirrors real market share

RESOURCE_TYPES: dict[str, list[str]] = {
    "aws": [
        "ec2:Instance",
        "s3:Bucket",
        "iam:Role",
        "iam:User",
        "rds:Instance",
        "lambda:Function",
        "vpc:SecurityGroup",
        "kms:Key",
        "cloudtrail:Trail",
        "elb:LoadBalancer",
    ],
    "azure": [
        "Microsoft.Compute/virtualMachines",
        "Microsoft.Storage/storageAccounts",
        "Microsoft.KeyVault/vaults",
        "Microsoft.Network/networkSecurityGroups",
        "Microsoft.Sql/servers",
        "Microsoft.Web/sites",
        "Microsoft.Authorization/roleAssignments",
    ],
    "gcp": [
        "compute.instances",
        "storage.buckets",
        "iam.serviceAccounts",
        "cloudsql.instances",
        "cloudrun.services",
        "container.clusters",
    ],
}

ACTIONS: dict[str, list[tuple[str, float]]] = {
    # (action, relative_weight) — higher weight = more frequent
    "aws": [
        ("DescribeInstances", 0.18),
        ("RunInstances", 0.10),
        ("TerminateInstances", 0.05),
        ("CreateBucket", 0.08),
        ("DeleteBucket", 0.03),
        ("PutBucketPublicAccessBlock", 0.06),
        ("CreateRole", 0.07),
        ("DeleteRole", 0.03),
        ("AttachRolePolicy", 0.09),
        ("CreateUser", 0.07),
        ("DeleteUser", 0.03),
        ("CreateKeyPair", 0.04),
        ("AuthorizeSecurityGroupIngress", 0.05),  # anomaly-prone
        ("ModifyInstanceAttribute", 0.04),
        ("PutPublicAccessBlock", 0.04),
        ("DisableCloudtrailLogging", 0.02),        # anomaly-prone
        ("GetSecretValue", 0.02),
    ],
    "azure": [
        ("Microsoft.Compute/virtualMachines/write", 0.15),
        ("Microsoft.Compute/virtualMachines/delete", 0.05),
        ("Microsoft.Storage/storageAccounts/write", 0.12),
        ("Microsoft.KeyVault/vaults/secrets/read", 0.10),
        ("Microsoft.Authorization/roleAssignments/write", 0.08),
        ("Microsoft.Network/networkSecurityGroups/write", 0.10),
        ("Microsoft.Sql/servers/write", 0.07),
        ("Microsoft.Web/sites/write", 0.08),
        ("Microsoft.Authorization/policyAssignments/write", 0.05),
        ("Microsoft.KeyVault/vaults/delete", 0.03),
        ("Microsoft.Authorization/roleDefinitions/write", 0.04),
        ("Microsoft.Compute/disks/write", 0.06),
        ("Microsoft.Resources/deployments/write", 0.07),
    ],
    "gcp": [
        ("compute.instances.insert", 0.15),
        ("compute.instances.delete", 0.07),
        ("storage.buckets.create", 0.10),
        ("storage.buckets.setIamPolicy", 0.08),
        ("iam.serviceAccounts.create", 0.10),
        ("iam.serviceAccounts.keys.create", 0.08),
        ("cloudsql.instances.create", 0.08),
        ("container.clusters.create", 0.07),
        ("compute.firewalls.insert", 0.08),
        ("logging.sinks.delete", 0.04),            # anomaly-prone
        ("iam.serviceAccounts.actAs", 0.05),
        ("storage.buckets.delete", 0.05),
        ("resourcemanager.projects.setIamPolicy", 0.05),
    ],
}

# Actions that strongly correlate with anomalies (weighted toward anomaly class)
HIGH_RISK_ACTIONS = {
    "AuthorizeSecurityGroupIngress",
    "DisableCloudtrailLogging",
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.KeyVault/vaults/delete",
    "storage.buckets.setIamPolicy",
    "logging.sinks.delete",
    "iam.serviceAccounts.keys.create",
    "resourcemanager.projects.setIamPolicy",
    "DeleteRole",
    "PutPublicAccessBlock",
}

ACTOR_TYPES = ["user", "service_account", "assumed_role", "root", "api_key"]
ACTOR_WEIGHTS = [0.45, 0.30, 0.15, 0.03, 0.07]

REGIONS: dict[str, list[str]] = {
    "aws": ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "us-east-2", "eu-central-1"],
    "azure": ["eastus", "westeurope", "southeastasia", "westus2", "northeurope"],
    "gcp": ["us-central1", "europe-west1", "asia-east1", "us-east1", "australia-southeast1"],
}

SEVERITIES = ["low", "medium", "high", "critical"]

# Typical office IP subnets + some unusual ranges for anomalies
NORMAL_IP_PREFIXES = [
    "10.0.", "10.1.", "172.16.", "172.17.", "192.168.1.", "192.168.0."
]
ANOMALOUS_IP_PREFIXES = [
    "45.33.", "185.220.", "91.108.", "198.51.", "203.0.", "103.21."
]

OUTCOME_TYPES = ["Success", "Failure", "Denied"]
OUTCOME_WEIGHTS = [0.80, 0.12, 0.08]


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

def _weighted_choice(rng: np.random.Generator, items: list, weights: list) -> str:
    weights_arr = np.array(weights, dtype=float)
    weights_arr /= weights_arr.sum()
    idx = rng.choice(len(items), p=weights_arr)
    return items[idx]


def _generate_ip(rng: np.random.Generator, is_anomaly: bool) -> str:
    if is_anomaly and rng.random() < 0.55:
        prefix = ANOMALOUS_IP_PREFIXES[rng.integers(0, len(ANOMALOUS_IP_PREFIXES))]
    else:
        prefix = NORMAL_IP_PREFIXES[rng.integers(0, len(NORMAL_IP_PREFIXES))]
    return f"{prefix}{rng.integers(1, 255)}.{rng.integers(1, 255)}"


def _generate_risk_score(
    rng: np.random.Generator,
    is_anomaly: bool,
    severity: str,
    action: str,
    actor_type: str,
    outcome: str,
) -> float:
    """
    Deterministic but realistic risk score with some controlled noise.
    Range: 0–100 (float, 2 d.p.)
    """
    base = 15.0 if not is_anomaly else 60.0

    # Severity contribution
    sev_bonus = {"low": 0, "medium": 10, "high": 25, "critical": 40}[severity]

    # High-risk action
    action_bonus = 20 if any(hr in action for hr in HIGH_RISK_ACTIONS) else 0

    # Root / assumed_role actor is higher risk
    actor_bonus = 15 if actor_type in ("root", "assumed_role") else 0

    # Denied outcomes are suspicious
    outcome_bonus = 10 if outcome == "Denied" else 0

    noise = rng.normal(0, 5)
    score = base + sev_bonus + action_bonus + actor_bonus + outcome_bonus + noise
    return float(np.clip(round(score, 2), 0.0, 100.0))


def _choose_action(rng: np.random.Generator, provider: str, is_anomaly: bool) -> str:
    action_list = ACTIONS[provider]
    actions = [a for a, _ in action_list]
    weights = [w for _, w in action_list]

    # Boost anomalous actions when generating anomaly rows
    if is_anomaly:
        weights = [
            w * 5.0 if any(hr in a for hr in HIGH_RISK_ACTIONS) else w
            for a, w in zip(actions, weights)
        ]

    weights_arr = np.array(weights, dtype=float)
    weights_arr /= weights_arr.sum()
    idx = rng.choice(len(actions), p=weights_arr)
    return actions[idx]


def _choose_severity(rng: np.random.Generator, is_anomaly: bool) -> str:
    if is_anomaly:
        weights = [0.05, 0.20, 0.45, 0.30]
    else:
        weights = [0.55, 0.30, 0.12, 0.03]
    return _weighted_choice(rng, SEVERITIES, weights)


def generate_dataset(n_rows: int, seed: int, anomaly_rate: float = 0.05) -> pd.DataFrame:
    """
    Generate a synthetic cloud security event dataset.

    Parameters
    ----------
    n_rows : int
        Total number of events to generate.
    seed : int
        Random seed for reproducibility.
    anomaly_rate : float
        Fraction of rows that are anomalous (default 5%).

    Returns
    -------
    pd.DataFrame
        The generated dataset with all columns described in the module docstring.
    """
    rng = np.random.default_rng(seed)
    py_rng = random.Random(seed)

    n_anomalies = int(n_rows * anomaly_rate)
    anomaly_flags = np.array([True] * n_anomalies + [False] * (n_rows - n_anomalies))
    rng.shuffle(anomaly_flags)

    # Base timestamps: spread over 90 days ending "today"
    # We use integer offsets to keep numpy-only
    end_ts = pd.Timestamp("2025-06-30 23:59:59")
    start_ts = end_ts - pd.Timedelta(days=90)
    start_epoch = int(start_ts.timestamp())
    end_epoch = int(end_ts.timestamp())

    timestamp_epochs = rng.integers(start_epoch, end_epoch, size=n_rows)
    timestamps = pd.to_datetime(timestamp_epochs, unit="s", utc=True).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    rows = []
    for i in range(n_rows):
        is_anomaly = bool(anomaly_flags[i])

        provider = _weighted_choice(rng, CLOUD_PROVIDERS, PROVIDER_WEIGHTS)
        resource_type = rng.choice(RESOURCE_TYPES[provider])
        action = _choose_action(rng, provider, is_anomaly)
        actor_type = _weighted_choice(rng, ACTOR_TYPES, ACTOR_WEIGHTS)
        region = rng.choice(REGIONS[provider])
        severity = _choose_severity(rng, is_anomaly)
        outcome = _weighted_choice(rng, OUTCOME_TYPES, OUTCOME_WEIGHTS)
        source_ip = _generate_ip(rng, is_anomaly)
        mfa_used = bool(rng.choice([True, False], p=[0.70, 0.30]))

        # Anomalies are less likely to have MFA
        if is_anomaly:
            mfa_used = bool(rng.choice([True, False], p=[0.25, 0.75]))

        risk_score = _generate_risk_score(
            rng, is_anomaly, severity, action, actor_type, outcome
        )

        # User / principal name
        if actor_type == "root":
            actor_name = "root"
        elif actor_type == "service_account":
            svc_idx = rng.integers(1, 30)
            actor_name = f"svc-account-{svc_idx:03d}"
        elif actor_type == "assumed_role":
            role_idx = rng.integers(1, 20)
            actor_name = f"assumed-role/deploy-role-{role_idx:03d}"
        else:
            user_idx = rng.integers(1, 150)
            actor_name = f"user-{user_idx:04d}"

        # Session duration (seconds) — None for non-session actions
        has_session = actor_type in ("user", "assumed_role")
        if has_session:
            session_duration_s = int(rng.integers(60, 28800))
        else:
            session_duration_s = None

        rows.append(
            {
                "event_id": f"evt-{i:07d}",
                "timestamp": timestamps[i],
                "cloud_provider": provider,
                "resource_type": resource_type,
                "action": action,
                "actor_type": actor_type,
                "actor_name": actor_name,
                "source_ip": source_ip,
                "region": region,
                "mfa_used": mfa_used,
                "outcome": outcome,
                "severity": severity,
                "risk_score": risk_score,
                "session_duration_s": session_duration_s,
                "anomaly_label": int(is_anomaly),
            }
        )

    df = pd.DataFrame(rows)

    # Sort by timestamp for chronological order
    df = df.sort_values("timestamp").reset_index(drop=True)
    # Regenerate sequential event IDs after sort
    df["event_id"] = [f"evt-{i:07d}" for i in range(len(df))]

    return df


# ---------------------------------------------------------------------------
# Provider-Specific Synthetic Log Generators
# ---------------------------------------------------------------------------

def generate_cloudtrail_logs(n_records: int = 500, seed: int = 42) -> dict[str, list[dict]]:
    """
    Generate synthetic AWS CloudTrail format audit log entries.
    Includes normal administration, reconnaissance, and suspicious activity.
    """
    rng = np.random.default_rng(seed)
    actions = [
        ("DescribeInstances", "ec2.amazonaws.com", "AWS::EC2::Instance", False),
        ("RunInstances", "ec2.amazonaws.com", "AWS::EC2::Instance", False),
        ("TerminateInstances", "ec2.amazonaws.com", "AWS::EC2::Instance", True),
        ("GetObject", "s3.amazonaws.com", "AWS::S3::Object", False),
        ("PutBucketPolicy", "s3.amazonaws.com", "AWS::S3::Bucket", True),
        ("CreateBucket", "s3.amazonaws.com", "AWS::S3::Bucket", False),
        ("DeleteBucket", "s3.amazonaws.com", "AWS::S3::Bucket", True),
        ("DeleteTrail", "cloudtrail.amazonaws.com", "AWS::CloudTrail::Trail", True),
        ("StopLogging", "cloudtrail.amazonaws.com", "AWS::CloudTrail::Trail", True),
        ("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", "AWS::EC2::SecurityGroup", True),
        ("AttachRolePolicy", "iam.amazonaws.com", "AWS::IAM::Role", True),
        ("CreateAccessKey", "iam.amazonaws.com", "AWS::IAM::AccessKey", True),
        ("DisableKey", "kms.amazonaws.com", "AWS::KMS::Key", True),
        ("ScheduleKeyDeletion", "kms.amazonaws.com", "AWS::KMS::Key", True),
        ("ConsoleLogin", "signin.amazonaws.com", "AWS::IAM::User", False),
    ]

    base_time = pd.Timestamp("2026-09-01 00:00:00")
    records = []

    for i in range(n_records):
        action_tuple = actions[rng.integers(0, len(actions))]
        action_name, event_source, res_type, is_risky = action_tuple

        is_anomaly = bool(rng.random() < 0.12 or is_risky and rng.random() < 0.4)
        ts = (base_time + pd.Timedelta(minutes=int(i * 12 + rng.integers(0, 5)))).strftime("%Y-%m-%dT%H:%M:%SZ")

        if is_anomaly and rng.random() < 0.35:
            user_type = "Root"
            user_name = "root"
            mfa = "false"
        elif rng.random() < 0.3:
            user_type = "AssumedRole"
            user_name = f"role-session-{rng.integers(1, 20):03d}"
            mfa = "true" if rng.random() < 0.8 else "false"
        else:
            user_type = "IAMUser"
            user_name = f"dev-user-{rng.integers(1, 40):03d}"
            mfa = "false" if is_anomaly else "true"

        src_ip = _generate_ip(rng, is_anomaly)
        region = rng.choice(REGIONS["aws"])
        error_code = "AccessDenied" if (is_anomaly and rng.random() < 0.3) else None

        records.append({
            "eventVersion": "1.08",
            "userIdentity": {
                "type": user_type,
                "principalId": f"AID{rng.integers(100000, 999999)}EXAMPLE",
                "arn": f"arn:aws:iam::123456789012:{user_type.lower()}/{user_name}",
                "accountId": "123456789012",
                "userName": user_name,
                "mfaAuthenticated": mfa,
            },
            "eventTime": ts,
            "eventSource": event_source,
            "eventName": action_name,
            "awsRegion": region,
            "sourceIPAddress": src_ip,
            "userAgent": "aws-cli/2.15.0" if rng.random() < 0.6 else "console.amazonaws.com",
            "errorCode": error_code,
            "requestParameters": {
                "resourceName": f"cloudshield-asset-{rng.integers(1, 50):03d}",
                "riskLevel": "elevated" if is_anomaly else "normal"
            },
            "resources": [{
                "ARN": f"arn:aws:{event_source.split('.')[0]}:{region}:123456789012:{res_type.split('::')[-1].lower()}/asset-{i:04d}",
                "type": res_type,
            }],
            "eventID": f"trail-{i:06d}",
            "readOnly": action_name.startswith("Describe") or action_name.startswith("Get"),
        })

    return {"Records": records}


def generate_azure_activity_logs(n_records: int = 500, seed: int = 42) -> list[dict]:
    """
    Generate synthetic Azure Activity Log entries.
    Includes compute, storage, keyvault, network security, and RBAC events.
    """
    rng = np.random.default_rng(seed)
    operations = [
        ("Microsoft.Compute/virtualMachines/write", "virtualMachines", False),
        ("Microsoft.Compute/virtualMachines/delete", "virtualMachines", True),
        ("Microsoft.Storage/storageAccounts/write", "storageAccounts", False),
        ("Microsoft.Storage/storageAccounts/blobServices/containers/write", "containers", True),
        ("Microsoft.KeyVault/vaults/secrets/read", "vaults", False),
        ("Microsoft.KeyVault/vaults/delete", "vaults", True),
        ("Microsoft.Network/networkSecurityGroups/securityRules/write", "securityRules", True),
        ("Microsoft.Authorization/roleAssignments/write", "roleAssignments", True),
        ("Microsoft.Sql/servers/firewallRules/write", "firewallRules", True),
        ("Microsoft.Resources/deployments/write", "deployments", False),
    ]

    base_time = pd.Timestamp("2026-09-01 00:00:00")
    events = []

    for i in range(n_records):
        op_name, res_sub, is_risky = operations[rng.integers(0, len(operations))]
        is_anomaly = bool(rng.random() < 0.12 or is_risky and rng.random() < 0.4)
        ts = (base_time + pd.Timedelta(minutes=int(i * 12 + rng.integers(0, 5)))).strftime("%Y-%m-%dT%H:%M:%SZ")

        caller = f"user_{rng.integers(1, 30):03d}@contoso.com" if not is_anomaly else "external_principal_attacker@badnet.org"
        mfa = "mfa" if not is_anomaly and rng.random() < 0.85 else "pwd"
        status_val = "Denied" if (is_anomaly and rng.random() < 0.25) else "Succeeded"
        src_ip = _generate_ip(rng, is_anomaly)
        region = rng.choice(REGIONS["azure"])

        events.append({
            "correlationId": f"azr-corr-{i:06d}",
            "eventTimestamp": ts,
            "submissionTimestamp": ts,
            "operationName": {
                "value": op_name,
                "localizedValue": op_name.split("/")[-1],
            },
            "status": {
                "value": status_val,
                "localizedValue": status_val,
            },
            "caller": caller,
            "claims": {
                "amr": mfa,
                "authMethod": "SSO" if mfa == "mfa" else "Password",
            },
            "resourceId": f"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-cloudshield-prod/providers/{op_name.rsplit('/', 1)[0]}/{res_sub}-{i:04d}",
            "resourceType": {
                "value": op_name.rsplit("/", 1)[0],
            },
            "resourceLocation": region,
            "httpRequest": {
                "clientIpAddress": src_ip,
                "method": "POST" if "write" in op_name else "GET",
            },
            "properties": {
                "statusCode": "200" if status_val == "Succeeded" else "403",
                "riskFlag": is_anomaly,
            },
        })

    return events


def generate_gcp_audit_logs(n_records: int = 500, seed: int = 42) -> list[dict]:
    """
    Generate synthetic Google Cloud Platform (GCP) Cloud Audit Log entries.
    Includes Compute Engine, Cloud Storage, IAM, and BigQuery.
    """
    rng = np.random.default_rng(seed)
    methods = [
        ("compute.instances.insert", "gce_instance", False),
        ("compute.instances.delete", "gce_instance", True),
        ("compute.firewalls.insert", "gce_firewall", True),
        ("storage.buckets.create", "gcs_bucket", False),
        ("storage.buckets.setIamPolicy", "gcs_bucket", True),
        ("storage.buckets.delete", "gcs_bucket", True),
        ("iam.serviceAccounts.create", "iam_service_account", False),
        ("iam.serviceAccounts.keys.create", "iam_service_account", True),
        ("iam.serviceAccounts.actAs", "iam_service_account", True),
        ("logging.sinks.delete", "logging_sink", True),
        ("resourcemanager.projects.setIamPolicy", "project", True),
    ]

    base_time = pd.Timestamp("2026-09-01 00:00:00")
    events = []

    for i in range(n_records):
        method_name, res_type, is_risky = methods[rng.integers(0, len(methods))]
        is_anomaly = bool(rng.random() < 0.12 or is_risky and rng.random() < 0.4)
        ts = (base_time + pd.Timedelta(minutes=int(i * 12 + rng.integers(0, 5)))).strftime("%Y-%m-%dT%H:%M:%SZ")

        if is_anomaly:
            principal = "unknown_attacker@malicious.com"
            status_code = 7 if rng.random() < 0.3 else 0  # 7 = PERMISSION_DENIED
        elif rng.random() < 0.5:
            principal = f"automation-svc@{rng.integers(100, 999)}.iam.gserviceaccount.com"
            status_code = 0
        else:
            principal = f"engineer_{rng.integers(1, 30):03d}@enterprise.com"
            status_code = 0

        src_ip = _generate_ip(rng, is_anomaly)
        region = rng.choice(REGIONS["gcp"])

        events.append({
            "insertId": f"gcp-log-{i:06d}",
            "timestamp": ts,
            "severity": "CRITICAL" if is_anomaly else "INFO",
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": f"{method_name.split('.')[0]}.googleapis.com",
                "methodName": method_name,
                "resourceName": f"projects/cloudshield-iq-prod/zones/{region}/assets/{res_type}-{i:04d}",
                "authenticationInfo": {
                    "principalEmail": principal,
                },
                "requestMetadata": {
                    "callerIp": src_ip,
                },
                "status": {
                    "code": status_code,
                    "message": "Permission denied" if status_code == 7 else "OK",
                },
                "request": {
                    "anomalyDetected": is_anomaly,
                },
            },
            "resource": {
                "type": res_type,
                "labels": {
                    "zone": region,
                    "project_id": "cloudshield-iq-prod",
                },
            },
        })

    return events


def generate_attack_scenario_logs(seed: int = 42) -> list[dict]:
    """
    Generate a 100-event chronological multi-stage APT attack scenario mapped
    to MITRE ATT&CK Cloud Matrix tactics.
    """
    rng = np.random.default_rng(seed)
    base_time = pd.Timestamp("2026-09-02 02:00:00")

    stages = [
        # Stage 1: Reconnaissance
        ("Reconnaissance", "aws", "DescribeInstances", "AWS::EC2::Instance", "user", "attacker_recon", "198.51.100.15", False, "Success", "low", 25.0),
        ("Reconnaissance", "aws", "DescribeSecurityGroups", "AWS::EC2::SecurityGroup", "user", "attacker_recon", "198.51.100.15", False, "Success", "low", 30.0),
        ("Reconnaissance", "azure", "Microsoft.Resources/subscriptions/read", "Microsoft.Resources/subscriptions", "user", "recon_user@tor.exit", "185.220.101.5", False, "Success", "low", 32.0),
        
        # Stage 2: Credential Access & Initial Access
        ("Initial Access", "aws", "ConsoleLogin", "AWS::IAM::User", "user", "stolen_dev_credentials", "198.51.100.15", False, "Failure", "high", 72.0),
        ("Initial Access", "aws", "ConsoleLogin", "AWS::IAM::User", "root", "root", "198.51.100.15", False, "Success", "critical", 95.0),
        ("Initial Access", "azure", "Microsoft.KeyVault/vaults/secrets/read", "Microsoft.KeyVault/vaults", "user", "stolen_token", "185.220.101.5", False, "Success", "critical", 90.0),
        
        # Stage 3: Defense Evasion
        ("Defense Evasion", "aws", "StopLogging", "AWS::CloudTrail::Trail", "root", "root", "198.51.100.15", False, "Success", "critical", 98.0),
        ("Defense Evasion", "aws", "DeleteTrail", "AWS::CloudTrail::Trail", "root", "root", "198.51.100.15", False, "Success", "critical", 99.0),
        ("Defense Evasion", "gcp", "logging.sinks.delete", "logging_sink", "service_account", "compromised-sa@gserviceaccount.com", "198.51.100.15", False, "Success", "critical", 96.0),
        
        # Stage 4: Persistence & Privilege Escalation
        ("Privilege Escalation", "aws", "AttachRolePolicy", "AWS::IAM::Role", "root", "root", "198.51.100.15", False, "Success", "critical", 95.0),
        ("Privilege Escalation", "aws", "CreateAccessKey", "AWS::IAM::User", "root", "root", "198.51.100.15", False, "Success", "critical", 94.0),
        ("Privilege Escalation", "azure", "Microsoft.Authorization/roleAssignments/write", "Microsoft.Authorization/roleAssignments", "user", "attacker_admin", "185.220.101.5", False, "Success", "critical", 95.0),
        ("Privilege Escalation", "gcp", "iam.serviceAccounts.keys.create", "iam_service_account", "user", "malicious_user@external.com", "198.51.100.15", False, "Success", "critical", 94.0),
        
        # Stage 5: Lateral Movement & Infrastructure Tampering
        ("Lateral Movement", "aws", "AuthorizeSecurityGroupIngress", "AWS::EC2::SecurityGroup", "root", "root", "198.51.100.15", False, "Success", "critical", 92.0),
        ("Lateral Movement", "azure", "Microsoft.Network/networkSecurityGroups/securityRules/write", "Microsoft.Network/networkSecurityGroups", "user", "attacker_admin", "185.220.101.5", False, "Success", "high", 88.0),
        ("Lateral Movement", "gcp", "compute.firewalls.insert", "gce_firewall", "user", "malicious_user@external.com", "198.51.100.15", False, "Success", "high", 89.0),
        
        # Stage 6: Exfiltration
        ("Exfiltration", "aws", "GetObject", "AWS::S3::Object", "root", "root", "198.51.100.15", False, "Success", "high", 85.0),
        ("Exfiltration", "aws", "PutBucketPolicy", "AWS::S3::Bucket", "root", "root", "198.51.100.15", False, "Success", "critical", 96.0),
        ("Exfiltration", "azure", "Microsoft.Storage/storageAccounts/blobServices/containers/write", "Microsoft.Storage/storageAccounts", "user", "attacker_admin", "185.220.101.5", False, "Success", "critical", 93.0),
        ("Exfiltration", "gcp", "storage.buckets.setIamPolicy", "gcs_bucket", "user", "malicious_user@external.com", "198.51.100.15", False, "Success", "critical", 97.0),
        
        # Stage 7: Impact / Key Disruption
        ("Impact", "aws", "DisableKey", "AWS::KMS::Key", "root", "root", "198.51.100.15", False, "Success", "critical", 98.0),
        ("Impact", "aws", "ScheduleKeyDeletion", "AWS::KMS::Key", "root", "root", "198.51.100.15", False, "Success", "critical", 99.0),
    ]

    events = []
    # Repeat sequence with variations to reach 100 events
    for i in range(100):
        stage, provider, action, res_type, actor_type, actor, ip, mfa, outcome, severity, risk = stages[i % len(stages)]
        ts = (base_time + pd.Timedelta(minutes=i * 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events.append({
            "event_id": f"atk-{i:05d}",
            "timestamp": ts,
            "cloud_provider": provider,
            "resource_type": res_type,
            "resource_id": f"arn:{provider}:security-asset/target-{i % 15:02d}",
            "action": action,
            "actor_type": actor_type,
            "actor_name": actor,
            "source_ip": ip,
            "region": "us-east-1" if provider == "aws" else ("eastus" if provider == "azure" else "us-central1"),
            "mfa_used": mfa,
            "outcome": outcome,
            "severity": severity,
            "risk_score": float(np.clip(risk + rng.normal(0, 2), 0.0, 100.0)),
            "attack_stage": stage,
            "anomaly_label": 1,
        })

    return events


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate synthetic cloud security events dataset for CloudShield IQ."
    )
    parser.add_argument(
        "--rows",
        type=int,
        default=25000,
        help="Number of events to generate for primary benchmark CSV (default: 25000)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--anomaly-rate",
        type=float,
        default=0.05,
        help="Fraction of anomalous events (default: 0.05 = 5%%)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output CSV path. Defaults to datasets/synthetic/cloud_security_events.csv",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        default=True,
        help="Also generate CloudTrail, Azure Activity, GCP Audit, and Attack Scenario datasets (default: True)",
    )
    return parser.parse_args()


def main() -> None:
    import json
    args = _parse_args()

    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent.parent  # cloudshield-iq/
    synthetic_dir = project_root / "datasets" / "synthetic"
    synthetic_dir.mkdir(parents=True, exist_ok=True)

    if args.output is None:
        output_path = synthetic_dir / "cloud_security_events.csv"
    else:
        output_path = args.output.resolve()

    print(f"Generating {args.rows:,} synthetic cloud security events (seed={args.seed}, "
          f"anomaly_rate={args.anomaly_rate:.1%})...")

    df = generate_dataset(
        n_rows=args.rows,
        seed=args.seed,
        anomaly_rate=args.anomaly_rate,
    )
    df.to_csv(output_path, index=False)

    n_anomalies = df["anomaly_label"].sum()
    print(f"\n[1/5] Main CSV Dataset saved to: {output_path}")
    print(f"      Shape            : {df.shape[0]:,} rows x {df.shape[1]} columns")
    print(f"      Anomaly count    : {n_anomalies:,} ({n_anomalies / len(df):.1%})")
    print(f"      Cloud providers  : {df['cloud_provider'].value_counts().to_dict()}")

    if args.all:
        # 2. AWS CloudTrail synthetic JSON
        ct_data = generate_cloudtrail_logs(n_records=500, seed=args.seed)
        ct_path = synthetic_dir / "aws_cloudtrail_events.json"
        with open(ct_path, "w", encoding="utf-8") as f:
            json.dump(ct_data, f, indent=2)
        print(f"\n[2/5] AWS CloudTrail JSON saved to: {ct_path} (500 events)")

        # 3. Azure Activity Log synthetic JSON
        az_data = generate_azure_activity_logs(n_records=500, seed=args.seed)
        az_path = synthetic_dir / "azure_activity_events.json"
        with open(az_path, "w", encoding="utf-8") as f:
            json.dump(az_data, f, indent=2)
        print(f"\n[3/5] Azure Activity Log JSON saved to: {az_path} (500 events)")

        # 4. GCP Audit Log synthetic JSON
        gcp_data = generate_gcp_audit_logs(n_records=500, seed=args.seed)
        gcp_path = synthetic_dir / "gcp_audit_events.json"
        with open(gcp_path, "w", encoding="utf-8") as f:
            json.dump(gcp_data, f, indent=2)
        print(f"\n[4/5] GCP Cloud Audit Log JSON saved to: {gcp_path} (500 events)")

        # 5. Multi-Stage Attack Scenario JSON
        atk_data = generate_attack_scenario_logs(seed=args.seed)
        atk_path = synthetic_dir / "multi_stage_attack_scenario.json"
        with open(atk_path, "w", encoding="utf-8") as f:
            json.dump(atk_data, f, indent=2)
        print(f"\n[5/5] Multi-Stage Attack Scenario saved to: {atk_path} (100 events)")

    print("\nAll synthetic datasets successfully generated!")


if __name__ == "__main__":
    main()
