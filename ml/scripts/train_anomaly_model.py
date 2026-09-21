"""
CloudShield IQ — ML Anomaly Model Training CLI
==============================================
Trains and evaluates the Isolation Forest anomaly detector against multi-cloud
security telemetry datasets and serializes model artifacts for production serving.

Usage:
    python ml/scripts/train_anomaly_model.py
    python ml/scripts/train_anomaly_model.py --dataset datasets/synthetic/cloud_security_events.csv --contamination 0.05
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
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

# Ensure backend package is in python path
repo_root = Path(__file__).resolve().parent.parent.parent
backend_dir = repo_root / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.ml.models.anomaly_detector import IsolationForestAnomalyDetector


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train CloudShield IQ Anomaly Detector")
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
        "--contamination",
        type=float,
        default=0.05,
        help="Expected anomaly contamination fraction (default: 0.05)",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=150,
        help="Number of isolation trees (default: 150)",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    return parser.parse_args()


def train_and_evaluate() -> None:
    args = parse_args()
    dataset_path = Path(args.dataset)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("================================================================")
    print("      CloudShield IQ — ML Anomaly Detection Training CLI       ")
    print("================================================================")
    print(f"[*] Dataset:       {dataset_path}")
    print(f"[*] Output Dir:    {output_dir}")
    print(f"[*] Contamination: {args.contamination}")
    print(f"[*] Trees:         {args.n_estimators}")
    print("----------------------------------------------------------------")

    if not dataset_path.exists():
        print(f"[ERROR] Dataset file not found: {dataset_path}")
        sys.exit(1)

    print("[*] Loading telemetry dataset...")
    df = pd.read_csv(dataset_path)
    print(f"[OK] Loaded {len(df):,} events with columns: {list(df.columns)}")

    has_ground_truth = "anomaly_label" in df.columns
    if has_ground_truth:
        pos_count = int(df["anomaly_label"].sum())
        print(f"[*] Ground-truth anomaly label detected: {pos_count} anomalies ({pos_count / len(df) * 100:.2f}%)")

    # Initialize model
    detector = IsolationForestAnomalyDetector(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=args.random_state,
        model_version="isolation-forest-v1",
    )

    # Train
    print("[*] Fitting feature extractor and Isolation Forest trees...")
    t0 = time.perf_counter()
    detector.fit(df)
    train_time = round(time.perf_counter() - t0, 3)
    print(f"[OK] Training completed in {train_time}s across {len(detector.extractor.feature_names_)} engineered features.")

    # Save artifact
    model_save_path = output_dir / "isolation_forest_v1.joblib"
    detector.save(model_save_path)
    print(f"[OK] Model artifact saved to: {model_save_path}")

    # Evaluate if labels available
    if has_ground_truth:
        print("\n[*] Evaluating detection performance against benchmark labels...")
        y_true = df["anomaly_label"].to_numpy().astype(int)
        preds = detector.predict_events(df)

        y_pred = np.array([1 if p.is_anomaly else 0 for p in preds])
        scores = np.array([p.anomaly_score for p in preds])

        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        roc = roc_auc_score(y_true, scores)
        cm = confusion_matrix(y_true, y_pred)

        print("\n================ Classification Metrics ================")
        print(f"  Precision: {prec:.4f}")
        print(f"  Recall:    {rec:.4f}")
        print(f"  F1 Score:  {f1:.4f}")
        print(f"  ROC-AUC:   {roc:.4f}")
        print("\nConfusion Matrix:")
        print(f"  TN: {cm[0, 0]:<6} | FP: {cm[0, 1]:<6}")
        print(f"  FN: {cm[1, 0]:<6} | TP: {cm[1, 1]:<6}")
        print("========================================================\n")

        # Save metrics to report
        report_data = {
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "train_time_seconds": train_time,
            "dataset_rows": len(df),
            "feature_count": len(detector.extractor.feature_names_),
            "features": detector.extractor.feature_names_,
            "metrics": {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "roc_auc": round(roc, 4),
                "confusion_matrix": {
                    "tn": int(cm[0, 0]),
                    "fp": int(cm[0, 1]),
                    "fn": int(cm[1, 0]),
                    "tp": int(cm[1, 1]),
                },
            },
        }

        eval_path = output_dir / "evaluation_report.json"
        with open(eval_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"[OK] Evaluation report saved to: {eval_path}")

    print("[SUCCESS] Phase 5 Model Training and Evaluation Complete!")


if __name__ == "__main__":
    train_and_evaluate()
