# Phase 2 — Profiling Results

**Dataset:** `cloud_security_events` (synthetic)  
**Profiled:** 2026-08-31T11:10:47Z  
**Script:** `ml/scripts/profile_dataset.py`  
**Profile files:** `datasets/profiles/cloud_security_events_profile.json` / `.md`

---

## Dataset Overview

| Property | Value |
|---|---|
| Rows | 8,000 |
| Columns | 15 |
| Memory | 5.324 MB |
| Total nulls | 3,233 (2.69%) |
| Duplicate rows | 0 |
| Date range | 2025-04-02 to 2025-06-30 (89 days) |

---

## Column Inventory

| Column | Kind | Dtype | Nulls | Unique | Notes |
|---|---|---|---|---|---|
| `event_id` | categorical | str | 0 | 8,000 | UUID-style sequential ID |
| `timestamp` | timestamp | str | 0 | 7,997 | UTC ISO 8601 |
| `cloud_provider` | categorical | str | 0 | 3 | aws / azure / gcp |
| `resource_type` | categorical | str | 0 | 23 | Provider-specific resource names |
| `action` | categorical | str | 0 | 43 | Provider-specific API actions |
| `actor_type` | categorical | str | 0 | 5 | user / service_account / assumed_role / api_key / root |
| `actor_name` | categorical | str | 0 | 198 | Pseudonymised principal names |
| `source_ip` | categorical | str | 0 | 7,932 | Nearly unique per event |
| `region` | categorical | str | 0 | 16 | Cloud region codes |
| `mfa_used` | boolean | bool | 0 | 2 | True / False |
| `outcome` | categorical | str | 0 | 3 | Success / Failure / Denied |
| `severity` | categorical | str | 0 | 4 | low / medium / high / critical |
| `risk_score` | numeric | float64 | 0 | 4,135 | 0–100 continuous score |
| `session_duration_s` | numeric | float64 | **3,233 (40.4%)** | 4,378 | Null for non-session actors |
| `anomaly_label` | numeric | int64 | 0 | 2 | 0=normal / 1=anomaly |

---

## Distribution Analysis

### Cloud Provider

| Provider | Count | % |
|---|---|---|
| aws | 4,449 | 55.6% |
| azure | 2,395 | 29.9% |
| gcp | 1,156 | 14.5% |

Reflects real-world cloud market share (AWS dominant). Consistent with intended weights in the generator.

---

### Severity

| Severity | Count | % |
|---|---|---|
| low | 4,237 | 53.0% |
| medium | 2,329 | 29.1% |
| high | 1,097 | 13.7% |
| critical | 337 | 4.2% |

Realistic long-tail distribution — most events are low severity with a small fraction being critical.

---

### Outcome

| Outcome | Count | % |
|---|---|---|
| Success | 6,415 | 80.2% |
| Failure | 947 | 11.8% |
| Denied | 638 | 8.0% |

Standard cloud audit log profile: the majority of API calls succeed.
Denied events (8%) are higher than typical production environments (~2–4%) but useful for training.

---

### Actor Type

| Actor Type | Count | % |
|---|---|---|
| user | 3,583 | 44.8% |
| service_account | 2,434 | 30.4% |
| assumed_role | 1,184 | 14.8% |
| api_key | 546 | 6.8% |
| root | 253 | 3.2% |

`root` access at 3.2% is intentionally elevated vs production (typically <1%) to provide
sufficient positive examples for the anomaly model.

---

### Risk Score (Numeric)

| Stat | Value |
|---|---|
| Min | 0.0 |
| Max | 100.0 |
| Mean | 31.67 |
| Median | 26.83 |
| Std Dev | 20.09 |
| 25th percentile | 17.36 |
| 75th percentile | 39.84 |

Right-skewed distribution — most events have low risk scores, with a tail of high-risk events.
This is expected: the anomaly class (5%) drives the high-score tail.

---

### Session Duration (Numeric, Sparse)

| Stat | Value |
|---|---|
| Min | 60 s |
| Max | 28,798 s (~8 hrs) |
| Mean | 14,157 s (~3.9 hrs) |
| Median | 13,973 s (~3.9 hrs) |
| Std Dev | 8,312 s |
| Null count | **3,233 (40.4%)** |

The 40.4% null rate is by design — service accounts and API key actors do not have sessions.
Any ML model using this feature must handle sparsity (imputation or a nullability indicator feature).

---

## Class Balance

> [!WARNING]
> **Significant class imbalance detected in `anomaly_label`.**
> Minority class (anomaly=1) represents only **5.0%** of records.

| Class | Count | % |
|---|---|---|
| 0 (normal) | 7,600 | 95.0% |
| 1 (anomaly) | 400 | 5.0% |

**Implications for ML (Phase 5–6):**

1. **Do NOT use accuracy as a primary metric.** A classifier predicting all-normal achieves 95%
   accuracy. Use Precision, Recall, F1 (minority class), AUC-ROC, and AUC-PR instead.

2. **Stratified train/test split** — ensure anomaly class is represented proportionally in
   both training and test sets. Use `stratify=y` in `train_test_split`.

3. **Consider class weighting** — XGBoost's `scale_pos_weight` parameter can compensate for
   class imbalance without oversampling.

4. **SMOTE as alternative** — Synthetic Minority Oversampling Technique (SMOTE) can be
   applied to the training set only (never to test set) if weighting is insufficient.

5. **Evaluate on F2 score** in addition to F1 — for anomaly detection, recall (catching
   real anomalies) is more important than precision (avoiding false alarms). F2 gives
   recall double the weight of precision.

---

## Data Quality Assessment

| Check | Result | Status |
|---|---|---|
| Duplicate rows | 0 | ✅ Pass |
| Null values in critical fields | 0 nulls in event_id, timestamp, provider, action, label | ✅ Pass |
| Null values in optional fields | 40.4% null in session_duration_s (by design) | ✅ Acceptable |
| Timestamp parseable | All 8,000 timestamps parse to UTC | ✅ Pass |
| Label column present | anomaly_label (0/1) | ✅ Pass |
| Risk score in bounds | Min=0.0, Max=100.0 | ✅ Pass |
| Categorical cardinality | No unexpected high-cardinality categoricals | ✅ Pass |
| Source IP uniqueness | 7,932/8,000 unique (99.2%) | ✅ Expected |

**Overall quality: Good** — synthetic dataset is clean, well-formed, and ready for Phase 3 schema design and Phase 4 rule-based engine development.

---

## Recommendations for Phase 3 (Common Schema)

Based on the profiling results, the following design decisions are recommended for the
common data schema:

1. **`session_duration_s` should be `Optional[int]`** — nullable field with a boolean
   companion feature `has_session` for ML use.

2. **`risk_score` should NOT be an input schema field** — it is an ML output, not a raw
   log field. Store in a separate `assessment` table.

3. **`anomaly_label` is for training only** — remove from production schema; replace with
   `anomaly_score: float` as the model output.

4. **Add `event_source` field** — distinguish CloudTrail from Azure Activity Log from GCP
   Cloud Audit Logs at the raw event level.

5. **`action` needs a canonical mapping** — create a lookup table mapping provider-specific
   action names to canonical CloudShield IQ action categories (e.g., `IAM_WRITE`,
   `STORAGE_POLICY_CHANGE`, `LOGGING_DISABLE`).

6. **Index on `(cloud_provider, timestamp)`** — primary query pattern for the dashboard
   will be time-range queries per provider.
