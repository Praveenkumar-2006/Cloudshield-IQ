"""
CloudShield IQ — Supervised Risk Model Training CLI
===================================================
Trains and evaluates the dual-head XGBoost classifier and regressor
against multi-cloud security telemetry benchmark datasets.
Serializes production model artifacts and comprehensive performance metrics.

Usage:
    python ml/scripts/train_supervised_model.py
    python ml/scripts/train_supervised_model.py --dataset datasets/synthetic/cloud_security_events.csv
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    mean_absolute_error,
    mean_squared_error,
    precision_score,
    r2_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight

# Ensure backend package is in python path
repo_root = Path(__file__).resolve().parent.parent.parent
backend_dir = repo_root / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.ml.models.risk_classifier import (
    INDEX_TO_SEVERITY,
    SEVERITY_ORDER,
    SEVERITY_TO_INDEX,
    SupervisedRiskClassifier,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train CloudShield IQ Supervised Risk Model")
    parser.add_argument(
        "--dataset",
        type=str,
        default=str(repo_root / "datasets" / "synthetic" / "cloud_security_events.csv"),
        help="Path to input telemetry CSV dataset",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(backend_dir / "ml" / "models"),
        help="Directory where model artifacts will be saved",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=120,
        help="Number of gradient boosted trees (default: 120)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        help="Maximum tree depth (default: 5)",
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=0.08,
        help="Learning rate (default: 0.08)",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--balanced-weights",
        action="store_true",
        default=False,
        help="Apply balanced inverse-frequency sample weights (default: False)",
    )
    return parser.parse_args()


def train_and_evaluate() -> None:
    args = parse_args()
    dataset_path = Path(args.dataset)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("================================================================")
    print("   CloudShield IQ — Phase 6: Supervised Risk Model Training     ")
    print("================================================================")
    print(f"[*] Dataset:          {dataset_path}")
    print(f"[*] Output Dir:       {output_dir}")
    print(f"[*] Trees:            {args.n_estimators}")
    print(f"[*] Max Depth:        {args.max_depth}")
    print(f"[*] Learning Rate:    {args.learning_rate}")
    print(f"[*] Balanced Weights: {args.balanced_weights}")
    print("----------------------------------------------------------------")

    if not dataset_path.exists():
        print(f"[ERROR] Dataset file not found: {dataset_path}")
        sys.exit(1)

    print("[*] Loading telemetry dataset...")
    df = pd.read_csv(dataset_path)
    print(f"[OK] Loaded {len(df):,} events with columns: {list(df.columns)}")

    if "severity" not in df.columns or "risk_score" not in df.columns:
        print("[ERROR] Dataset must contain 'severity' and 'risk_score' target columns.")
        sys.exit(1)

    # Normalize severity column
    df["severity_clean"] = df["severity"].astype(str).str.lower()
    valid_mask = df["severity_clean"].isin(SEVERITY_ORDER)
    df = df[valid_mask].copy()

    print(f"[*] Target Distribution (Severity):")
    for s in SEVERITY_ORDER:
        count = (df["severity_clean"] == s).sum()
        pct = (count / len(df)) * 100
        print(f"    - {s.upper():<10}: {count:>6,} ({pct:.1f}%)")

    print("[*] Performing 80/20 stratified train/test split...")
    train_df, test_df = train_test_split(
        df,
        test_size=0.20,
        random_state=args.random_state,
        stratify=df["severity_clean"],
    )
    print(f"[OK] Training events: {len(train_df):,} | Test events: {len(test_df):,}")

    sample_weights = (
        compute_sample_weight("balanced", train_df["severity_clean"])
        if args.balanced_weights
        else None
    )

    print("\n[*] Initializing SupervisedRiskClassifier (XGBoost)...")
    model = SupervisedRiskClassifier(
        model_version="supervised-xgboost-v1",
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        random_state=args.random_state,
    )

    t0 = time.perf_counter()
    model.fit(
        X_raw=train_df,
        y_severity=train_df["severity_clean"].tolist(),
        y_risk_score=train_df["risk_score"].tolist(),
        sample_weight=sample_weights,
    )
    train_time = time.perf_counter() - t0
    print(f"[OK] Model training completed in {train_time:.2f}s")
    print(f"[*] Total engineered features: {model.metadata.feature_count}")

    print("\n[*] Evaluating on held-out test split (5,000 events)...")
    eval_t0 = time.perf_counter()
    test_preds = model.predict_batch(test_df)
    eval_time = time.perf_counter() - eval_t0

    # Extract test targets and predictions
    y_test_true_str = test_df["severity_clean"].tolist()
    y_test_true_idx = [SEVERITY_TO_INDEX[s] for s in y_test_true_str]
    y_test_pred_str = [p.predicted_severity for p in test_preds]
    y_test_pred_idx = [SEVERITY_TO_INDEX[s] for s in y_test_pred_str]

    y_test_true_score = test_df["risk_score"].to_numpy(dtype=float)
    y_test_pred_score = np.array([p.predicted_risk_score for p in test_preds], dtype=float)

    # Classification Metrics
    acc = accuracy_score(y_test_true_idx, y_test_pred_idx)
    macro_f1 = f1_score(y_test_true_idx, y_test_pred_idx, average="macro")
    weighted_f1 = f1_score(y_test_true_idx, y_test_pred_idx, average="weighted")

    # Probabilities for ROC-AUC
    proba_matrix = np.array([
        [p.severity_probabilities[s] for s in SEVERITY_ORDER]
        for p in test_preds
    ])
    try:
        roc_auc_ovr = roc_auc_score(
            y_test_true_idx,
            proba_matrix,
            multi_class="ovr",
            average="weighted",
        )
    except Exception:
        roc_auc_ovr = 0.0

    cm = confusion_matrix(y_test_true_idx, y_test_pred_idx, labels=list(range(4)))
    cls_report = classification_report(
        y_test_true_idx,
        y_test_pred_idx,
        target_names=[s.upper() for s in SEVERITY_ORDER],
        digits=4,
        output_dict=True,
    )

    # Regression Metrics
    mae = mean_absolute_error(y_test_true_score, y_test_pred_score)
    rmse = np.sqrt(mean_squared_error(y_test_true_score, y_test_pred_score))
    r2 = r2_score(y_test_true_score, y_test_pred_score)

    print("\n================================================================")
    print("                     EVALUATION RESULTS                         ")
    print("================================================================")
    print(f"Classification Metrics (Incident Severity):")
    print(f"  - Accuracy:         {acc * 100:.2f}%")
    print(f"  - Macro F1-Score:   {macro_f1:.4f}")
    print(f"  - Weighted F1-Score:{weighted_f1:.4f}")
    print(f"  - ROC-AUC (OvR):    {roc_auc_ovr:.4f}")
    print("\nPer-Class Breakdown:")
    for s in SEVERITY_ORDER:
        s_upper = s.upper()
        metrics = cls_report.get(s_upper, {})
        p = metrics.get("precision", 0.0)
        r = metrics.get("recall", 0.0)
        f = metrics.get("f1-score", 0.0)
        sup = metrics.get("support", 0)
        print(f"  - {s_upper:<10} (N={sup:>4}): Precision={p:.4f}, Recall={r:.4f}, F1={f:.4f}")

    print(f"\nRegression Metrics (Continuous Risk Score [0-100]):")
    print(f"  - Mean Absolute Error (MAE): {mae:.2f} points")
    print(f"  - Root Mean Squared Error:   {rmse:.2f} points")
    print(f"  - R² Coefficient of Determ.: {r2:.4f}")
    print(f"  - Batch Inference Latency:   {eval_time * 1000:.1f}ms for {len(test_df):,} events ({eval_time / len(test_df) * 1000:.3f}ms/event)")
    print("----------------------------------------------------------------")

    # Serialize evaluation metrics in model metadata
    model.metadata.metrics = {
        "accuracy": round(float(acc), 4),
        "macro_f1": round(float(macro_f1), 4),
        "weighted_f1": round(float(weighted_f1), 4),
        "roc_auc_ovr": round(float(roc_auc_ovr), 4),
        "mae": round(float(mae), 4),
        "rmse": round(float(rmse), 4),
        "r2": round(float(r2), 4),
        "training_time_s": round(float(train_time), 3),
        "evaluation_time_s": round(float(eval_time), 3),
        "confusion_matrix": cm.tolist(),
        "per_class": {
            s: {
                "precision": round(float(cls_report[s.upper()]["precision"]), 4),
                "recall": round(float(cls_report[s.upper()]["recall"]), 4),
                "f1_score": round(float(cls_report[s.upper()]["f1-score"]), 4),
                "support": int(cls_report[s.upper()]["support"]),
            }
            for s in SEVERITY_ORDER
            if s.upper() in cls_report
        },
    }

    model_file = output_dir / "supervised_risk_v1.joblib"
    metadata_file = output_dir / "supervised_risk_v1.json"

    print(f"[*] Saving model artifacts...")
    model.save(model_file, metadata_file)
    print(f"[OK] Saved model to:    {model_file} ({model_file.stat().st_size / 1024:.1f} KB)")
    print(f"[OK] Saved metadata to: {metadata_file}")
    print("================================================================")
    print("            Phase 6 Training Complete Successfully!             ")
    print("================================================================")


if __name__ == "__main__":
    train_and_evaluate()
