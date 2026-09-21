# ADR-001: ML Strategy — Anomaly Detection vs. Risk Classification

**Date:** 2026-08-30 (Ratified: 2026-09-05)
**Status:** Accepted — Option 3 (Hybrid Architecture Ratified)
**Deciders:** Project team

---

## Context

CloudShield IQ requires an ML layer to detect anomalous or risky security behaviour in cloud environments. Two ML tasks are relevant:

- **Task A (Anomaly Detection):** Identify observations that deviate from learned normal behaviour. Unsupervised. Does not require labels.
- **Task B (Risk Classification):** Classify observations into risk categories (Low/Medium/High/Critical). Supervised. Requires reliable labels.

---

## Decision Drivers

1. Label availability in candidate datasets
2. Dataset size and dimensionality
3. Model interpretability for SHAP compatibility
4. Academic defensibility
5. Implementation complexity within project timeline

---

## Options Considered

### Option 1: Anomaly Detection Only (Isolation Forest)
- **Pros:** No labels required; well-suited to security log data; interpretable via SHAP; handles high-dimensional sparse data; fast training
- **Cons:** Anomaly score ≠ security risk score; requires separate risk scoring methodology; harder to evaluate without ground-truth labels

### Option 2: Risk Classification Only (XGBoost)
- **Pros:** Direct risk label output; clear evaluation metrics (F1, ROC-AUC); strong SHAP support
- **Cons:** Requires reliable labelled data; labels in public datasets may be unreliable, synthetic, or misaligned with cloud security risk; risk of training on fabricated labels

### Option 3: Hybrid (Anomaly Detection + Risk Classification)
- **Pros:** Covers both scenarios; anomaly score can be used as a feature in the classifier
- **Cons:** Increased complexity; requires labelled data for the classification component; may introduce redundancy if labels are unavailable

---

## Decision

**Ratified: Option 3 (Hybrid Architecture — Unsupervised Anomaly Detection + Supervised Risk Classification + Deterministic Heuristics).**

### Evolution & Rationale:
1. **Phase 0 (Provisional)**: Option 1 was initially selected tentatively to protect academic integrity while investigating public intrusion detection datasets (KDD Cup 99, NSL-KDD, UNSW-NB15).
2. **Phase 2 (Dataset Profiling Resolution)**: Public datasets were found either obsolete (KDD) or unrepresentative of cloud control-plane telemetry. A calibrated synthetic multi-cloud dataset (8,000 baseline records, seed 42, 5% contamination rate) was constructed and profiled (`datasets/profiles/cloud_security_events_profile.md`).
3. **Phase 5 & 6 (Implementation)**: Option 3 was formally adopted:
   - **Unsupervised Track (Phase 5)**: `IsolationForest` (150 estimators, 5% contamination, ROC-AUC: 0.7723) detects zero-day statistical anomalies without needing ground-truth labels.
   - **Supervised Track (Phase 6)**: Dual-head model consisting of an `XGBRegressor` predicting continuous risk scores $[0.0, 100.0]$ and a `HistGradientBoostingClassifier` predicting discrete severity classes (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   - **Explainability Track (Phase 7)**: Exact additive `TreeSHAP` decomposes XGBoost risk scores into 5 interpretable security domains.
   - **Deterministic Guardrails (Phase 4)**: Heuristic rules enforce non-negotiable compliance and statutory security invariants.

---

## Consequences

- **Composite Scoring Synergy**: Risk scoring does not rely solely on anomaly scores or solely on supervised predictions. Instead, it is computed via a bounded composite formula:
  $$R(e) = \min\left(100.0, \quad 0.40 \times W_{\text{rule}}(e) + 0.35 \times R_{\text{xgb}}(e) + 0.25 \times (P_{\text{anomaly}}(e) \times 100)\right)$$
- **Explainability Compliance**: SHAP attribution operates directly on the tree structure of the XGBoost regressor, guaranteeing mathematically proven local additivity without heuristic approximations.
- **Robustness Against Zero-Day Threats**: Even if a novel attack bypasses deterministic rules, the unsupervised Isolation Forest identifies high-dimensional behavioral outliers and elevates the composite risk score.

---

## Status History

- **2026-08-30**: Proposed (Provisional Option 1 selected pending dataset discovery).
- **2026-09-02**: Re-evaluated following Phase 2 synthetic dataset profiling.
- **2026-09-05**: **Accepted & Ratified** — Option 3 (Hybrid Engine) implemented across Phases 5, 6, and 7.

