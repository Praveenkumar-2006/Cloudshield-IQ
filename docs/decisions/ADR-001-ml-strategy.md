# ADR-001: ML Strategy — Anomaly Detection vs. Risk Classification

**Date:** 2026-08-30
**Status:** Proposed (pending dataset validation)
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

**Tentative: Option 1 (Anomaly Detection with Isolation Forest) as primary track.**

Rationale:
- Label availability in public cloud security datasets is not yet confirmed.
- Fabricating labels to justify supervised learning would undermine academic integrity.
- Isolation Forest is well-matched to: detecting rare events (security anomalies), high-dimensional feature spaces, and the unsupervised nature of the problem when ground-truth labels are absent.
- If a reliably labelled dataset is found during Phase 2 (Dataset Discovery), Option 3 will be re-evaluated.

**This decision is provisional and subject to revision after dataset profiling.**

---

## Consequences

- Risk scoring methodology must be designed separately and documented explicitly. Anomaly score alone is not a risk score.
- Model evaluation will rely on: false-positive rate analysis, qualitative scenario testing, and — if a labelled test set can be obtained — precision/recall/F1.
- If supervised classification is added later, it must be implemented and evaluated as a separate, clearly labelled component, not as a replacement for the anomaly detector.

---

## Open Questions

1. Does any candidate dataset contain reliable security-relevant labels?
2. Can a synthetic labelled dataset be constructed with sufficient rigour for academic validation?
3. What is the false-positive tolerance for this system?

These questions will be answered in Phase 2 (Dataset Discovery and Profiling).
