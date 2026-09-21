# Dataset Profile — cloud_security_events

**Profiled at:** 2026-09-02T19:08:03Z  
**Shape:** 25,000 rows × 15 columns  
**Memory:** 16.639 MB  
**Total nulls:** 10,070 (2.69%)  
**Duplicate rows:** 0  

---

## Column Summary

| Column | Kind | Dtype | Nulls | Nulls % | Unique |
|---|---|---|---|---|---|
| `event_id` | categorical | str | 0 | 0.0% | 25000 |
| `timestamp` | timestamp | str | 0 | 0.0% | 24949 |
| `cloud_provider` | categorical | str | 0 | 0.0% | 3 |
| `resource_type` | categorical | str | 0 | 0.0% | 23 |
| `action` | categorical | str | 0 | 0.0% | 43 |
| `actor_type` | categorical | str | 0 | 0.0% | 5 |
| `actor_name` | categorical | str | 0 | 0.0% | 198 |
| `source_ip` | categorical | str | 0 | 0.0% | 24238 |
| `region` | categorical | str | 0 | 0.0% | 16 |
| `mfa_used` | numeric | bool | 0 | 0.0% | 2 |
| `outcome` | categorical | str | 0 | 0.0% | 3 |
| `severity` | categorical | str | 0 | 0.0% | 4 |
| `risk_score` | numeric | float64 | 0 | 0.0% | 6422 |
| `session_duration_s` | numeric | float64 | 10070 | 40.28% | 11622 |
| `anomaly_label` | numeric | int64 | 0 | 0.0% | 2 |

---

## Per-Column Details

### `event_id`

- **Kind:** categorical
- **Dtype:** `str`
- **Null count:** 0 (0.0%)
- **Unique values:** 25000

**Top values:**

| Value | Count | % |
|---|---|---|
| `evt-0000000` | 1 | 0.0% |
| `evt-0000001` | 1 | 0.0% |
| `evt-0000002` | 1 | 0.0% |
| `evt-0000003` | 1 | 0.0% |
| `evt-0000004` | 1 | 0.0% |
| `evt-0000005` | 1 | 0.0% |
| `evt-0000006` | 1 | 0.0% |
| `evt-0000007` | 1 | 0.0% |
| `evt-0000008` | 1 | 0.0% |
| `evt-0000009` | 1 | 0.0% |
| `evt-0000010` | 1 | 0.0% |
| `evt-0000011` | 1 | 0.0% |
| `evt-0000012` | 1 | 0.0% |
| `evt-0000013` | 1 | 0.0% |
| `evt-0000014` | 1 | 0.0% |

### `timestamp`

- **Kind:** timestamp
- **Dtype:** `str`
- **Null count:** 0 (0.0%)
- **Unique values:** 24949

**Timestamp statistics:**

| Stat | Value |
|---|---|
| Min | 2025-04-02 00:00:22+00:00 |
| Max | 2025-06-30 23:57:42+00:00 |
| Range (days) | 89 |

### `cloud_provider`

- **Kind:** categorical
- **Dtype:** `str`
- **Null count:** 0 (0.0%)
- **Unique values:** 3

**Top values:**

| Value | Count | % |
|---|---|---|
| `aws` | 13726 | 54.9% |
| `azure` | 7502 | 30.01% |
| `gcp` | 3772 | 15.09% |

### `resource_type`

- **Kind:** categorical
- **Dtype:** `str`
- **Null count:** 0 (0.0%)
- **Unique values:** 23

**Top values:**

| Value | Count | % |
|---|---|---|
| `rds:Instance` | 1413 | 5.65% |
| `elb:LoadBalancer` | 1403 | 5.61% |
| `s3:Bucket` | 1396 | 5.58% |
| `cloudtrail:Trail` | 1390 | 5.56% |
| `kms:Key` | 1385 | 5.54% |
| `lambda:Function` | 1378 | 5.51% |
| `iam:Role` | 1361 | 5.44% |
| `ec2:Instance` | 1351 | 5.4% |
| `iam:User` | 1330 | 5.32% |
| `vpc:SecurityGroup` | 1319 | 5.28% |
| `Microsoft.Sql/servers` | 1100 | 4.4% |
| `Microsoft.Web/sites` | 1092 | 4.37% |
| `Microsoft.KeyVault/vaults` | 1076 | 4.3% |
| `Microsoft.Authorization/roleAssignments` | 1075 | 4.3% |
| `Microsoft.Compute/virtualMachines` | 1072 | 4.29% |

### `action`

- **Kind:** categorical
- **Dtype:** `str`
- **Null count:** 0 (0.0%)
- **Unique values:** 43

**Top values:**

| Value | Count | % |
|---|---|---|
| `DescribeInstances` | 2424 | 9.7% |
| `RunInstances` | 1372 | 5.49% |
| `AttachRolePolicy` | 1159 | 4.64% |
| `CreateBucket` | 1121 | 4.48% |
| `Microsoft.Compute/virtualMachines/write` | 1106 | 4.42% |
| `CreateRole` | 946 | 3.78% |
| `CreateUser` | 941 | 3.76% |
| `Microsoft.Storage/storageAccounts/write` | 935 | 3.74% |
| `PutBucketPublicAccessBlock` | 813 | 3.25% |
| `AuthorizeSecurityGroupIngress` | 758 | 3.03% |
| `Microsoft.Network/networkSecurityGroups/write` | 717 | 2.87% |
| `Microsoft.KeyVault/vaults/secrets/read` | 694 | 2.78% |
| `TerminateInstances` | 682 | 2.73% |
| `Microsoft.Authorization/roleAssignments/write` | 641 | 2.56% |
| `PutPublicAccessBlock` | 607 | 2.43% |

### `actor_type`

- **Kind:** categorical
- **Dtype:** `str`
- **Null count:** 0 (0.0%)
- **Unique values:** 5

**Top values:**

| Value | Count | % |
|---|---|---|
| `user` | 11231 | 44.92% |
| `service_account` | 7564 | 30.26% |
| `assumed_role` | 3699 | 14.8% |
| `api_key` | 1738 | 6.95% |
| `root` | 768 | 3.07% |

### `actor_name`

- **Kind:** categorical
- **Dtype:** `str`
- **Null count:** 0 (0.0%)
- **Unique values:** 198

**Top values:**

| Value | Count | % |
|---|---|---|
| `root` | 768 | 3.07% |
| `svc-account-020` | 292 | 1.17% |
| `svc-account-007` | 279 | 1.12% |
| `svc-account-029` | 277 | 1.11% |
| `svc-account-014` | 277 | 1.11% |
| `svc-account-004` | 275 | 1.1% |
| `svc-account-015` | 273 | 1.09% |
| `svc-account-026` | 270 | 1.08% |
| `svc-account-013` | 269 | 1.08% |
| `svc-account-002` | 269 | 1.08% |
| `svc-account-023` | 267 | 1.07% |
| `svc-account-021` | 266 | 1.06% |
| `svc-account-011` | 266 | 1.06% |
| `svc-account-003` | 266 | 1.06% |
| `svc-account-006` | 262 | 1.05% |

### `source_ip`

- **Kind:** categorical
- **Dtype:** `str`
- **Null count:** 0 (0.0%)
- **Unique values:** 24238

**Top values:**

| Value | Count | % |
|---|---|---|
| `172.17.38.109` | 3 | 0.01% |
| `10.1.220.58` | 3 | 0.01% |
| `10.1.203.131` | 3 | 0.01% |
| `10.0.254.225` | 3 | 0.01% |
| `172.17.174.15` | 3 | 0.01% |
| `10.0.178.109` | 3 | 0.01% |
| `192.168.0.33.80` | 3 | 0.01% |
| `172.17.208.254` | 3 | 0.01% |
| `10.0.171.52` | 3 | 0.01% |
| `192.168.0.114.181` | 3 | 0.01% |
| `192.168.1.224.151` | 3 | 0.01% |
| `10.1.78.23` | 3 | 0.01% |
| `10.1.98.135` | 3 | 0.01% |
| `172.16.59.24` | 3 | 0.01% |
| `10.0.106.115` | 3 | 0.01% |

### `region`

- **Kind:** categorical
- **Dtype:** `str`
- **Null count:** 0 (0.0%)
- **Unique values:** 16

**Top values:**

| Value | Count | % |
|---|---|---|
| `eu-west-1` | 2314 | 9.26% |
| `eu-central-1` | 2313 | 9.25% |
| `ap-southeast-1` | 2312 | 9.25% |
| `us-east-1` | 2268 | 9.07% |
| `us-east-2` | 2265 | 9.06% |
| `us-west-2` | 2254 | 9.02% |
| `westus2` | 1537 | 6.15% |
| `southeastasia` | 1525 | 6.1% |
| `westeurope` | 1512 | 6.05% |
| `eastus` | 1495 | 5.98% |
| `northeurope` | 1433 | 5.73% |
| `europe-west1` | 784 | 3.14% |
| `us-central1` | 779 | 3.12% |
| `us-east1` | 747 | 2.99% |
| `australia-southeast1` | 740 | 2.96% |

### `mfa_used`

- **Kind:** numeric
- **Dtype:** `bool`
- **Null count:** 0 (0.0%)
- **Unique values:** 2

**Numeric statistics:**

| Stat | Value |
|---|---|
| Min | nan |
| Max | nan |
| Mean | nan |
| Median | nan |
| Std Dev | nan |
| 25th pct | nan |
| 75th pct | nan |

**Top values:**

| Value | Count | % |
|---|---|---|
| `True` | 16898 | 67.59% |
| `False` | 8102 | 32.41% |

### `outcome`

- **Kind:** categorical
- **Dtype:** `str`
- **Null count:** 0 (0.0%)
- **Unique values:** 3

**Top values:**

| Value | Count | % |
|---|---|---|
| `Success` | 20006 | 80.02% |
| `Failure` | 3002 | 12.01% |
| `Denied` | 1992 | 7.97% |

### `severity`

- **Kind:** categorical
- **Dtype:** `str`
- **Null count:** 0 (0.0%)
- **Unique values:** 4

**Top values:**

| Value | Count | % |
|---|---|---|
| `low` | 13057 | 52.23% |
| `medium` | 7445 | 29.78% |
| `high` | 3406 | 13.62% |
| `critical` | 1092 | 4.37% |

### `risk_score`

- **Kind:** numeric
- **Dtype:** `float64`
- **Null count:** 0 (0.0%)
- **Unique values:** 6422

**Numeric statistics:**

| Stat | Value |
|---|---|
| Min | 0.0 |
| Max | 100.0 |
| Mean | 31.7601 |
| Median | 27.055 |
| Std Dev | 20.0621 |
| 25th pct | 17.5575 |
| 75th pct | 39.88 |

### `session_duration_s`

- **Kind:** numeric
- **Dtype:** `float64`
- **Null count:** 10070 (40.28%)
- **Unique values:** 11622

**Numeric statistics:**

| Stat | Value |
|---|---|
| Min | 60.0 |
| Max | 28798.0 |
| Mean | 14364.0873 |
| Median | 14387.5 |
| Std Dev | 8242.0881 |
| 25th pct | 7163.25 |
| 75th pct | 21396.0 |

### `anomaly_label`

- **Kind:** numeric
- **Dtype:** `int64`
- **Null count:** 0 (0.0%)
- **Unique values:** 2

**Numeric statistics:**

| Stat | Value |
|---|---|
| Min | 0.0 |
| Max | 1.0 |
| Mean | 0.05 |
| Median | 0.0 |
| Std Dev | 0.2179 |
| 25th pct | 0.0 |
| 75th pct | 0.0 |

**Top values:**

| Value | Count | % |
|---|---|---|
| `0` | 23750 | 95.0% |
| `1` | 1250 | 5.0% |

---

## Class Balance

### `anomaly_label`

| Class | Count | % |
|---|---|---|
| `0` | 23750 | 95.0% |
| `1` | 1250 | 5.0% |

> [!WARNING]
> Significant class imbalance detected in `anomaly_label`. Minority class < 10%. Consider SMOTE, cost-sensitive learning, or stratified sampling for ML training.
