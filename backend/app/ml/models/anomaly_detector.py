"""
CloudShield IQ — Machine Learning Anomaly Detector
===================================================
Unsupervised anomaly detection model using scikit-learn Isolation Forest
for multi-cloud telemetry risk evaluation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Optional, Sequence, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.core.logging import get_logger
from app.ml.features.pipeline import SecurityFeatureExtractor
from app.schemas.events import CloudSecurityEvent

logger = get_logger(__name__)


@dataclass
class AnomalyPrediction:
    """Standardized output for an anomaly detection inference."""
    is_anomaly: bool
    anomaly_score: float  # Bounded continuous probability [0.0, 1.0]
    raw_score: float      # Raw IsolationForest decision_function output
    feature_impacts: dict[str, float]
    evaluated_at: str


class IsolationForestAnomalyDetector:
    """
    End-to-end anomaly detector combining domain feature extraction
    with scikit-learn's Isolation Forest algorithm.
    """

    DEFAULT_MODEL_VERSION = "isolation-forest-v1"

    def __init__(
        self,
        n_estimators: int = 150,
        contamination: float = 0.05,
        max_samples: Union[int, float, str] = "auto",
        random_state: int = 42,
        model_version: str = DEFAULT_MODEL_VERSION,
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.max_samples = max_samples
        self.random_state = random_state
        self.model_version = model_version

        self.extractor = SecurityFeatureExtractor()
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_samples=self.max_samples,
            random_state=self.random_state,
            n_jobs=-1,
        )

        self.is_trained: bool = False
        self.training_records_count: int = 0
        self.trained_at: Optional[str] = None
        self.feature_means_: Optional[np.ndarray] = None
        self.score_min_: float = -0.3
        self.score_max_: float = 0.2

    def fit(
        self,
        X: Union[pd.DataFrame, Sequence[CloudSecurityEvent], Sequence[dict[str, Any]]],
    ) -> IsolationForestAnomalyDetector:
        """
        Train the feature extractor and Isolation Forest on telemetry events.
        """
        logger.info(
            "Training Isolation Forest anomaly detector",
            n_estimators=self.n_estimators,
            contamination=self.contamination,
        )

        matrix = self.extractor.fit_transform(X)
        if matrix.shape[0] == 0:
            raise ValueError("Cannot train IsolationForest on empty dataset.")

        self.model.fit(matrix)
        self.is_trained = True
        self.training_records_count = matrix.shape[0]
        self.trained_at = datetime.now(timezone.utc).isoformat()
        self.feature_means_ = np.mean(matrix, axis=0)

        # Calibrate score range on training set
        raw_scores = self.model.decision_function(matrix)
        self.score_min_ = float(np.percentile(raw_scores, 1))
        self.score_max_ = float(np.percentile(raw_scores, 99))

        logger.info(
            "Isolation Forest training completed",
            samples=self.training_records_count,
            features_dim=matrix.shape[1],
            score_range=f"[{self.score_min_:.4f}, {self.score_max_:.4f}]",
        )
        return self

    def _calibrate_anomaly_score(self, raw_score: float) -> float:
        """
        Convert scikit-learn decision_function output (negative for anomalies)
        into a smooth, normalized [0.0, 1.0] anomaly probability where 1.0 = highly anomalous.
        """
        # Threshold at 0.0 separates anomalies (< 0) from normal (> 0)
        # Using a sigmoid-like mapping centered around decision boundary (0.0)
        # k factor controls steepness of the transition
        k = 12.0
        # sigmoid of -k * score: when score < 0, probability > 0.5
        prob = 1.0 / (1.0 + np.exp(k * raw_score))
        return float(np.clip(round(prob, 4), 0.0, 1.0))

    def _compute_feature_impacts(self, sample_features: np.ndarray) -> dict[str, float]:
        """
        Compute heuristic feature attribution based on deviation from training mean.
        Precursor for TreeSHAP integration in Phase 7.
        """
        if self.feature_means_ is None or len(self.extractor.feature_names_) == 0:
            return {}

        diffs = np.abs(sample_features - self.feature_means_)
        top_indices = np.argsort(diffs)[::-1][:5]
        impacts: dict[str, float] = {}
        for idx in top_indices:
            feat_name = self.extractor.feature_names_[idx]
            impacts[feat_name] = float(round(diffs[idx], 4))
        return impacts

    def predict_matrix(self, matrix: np.ndarray) -> list[AnomalyPrediction]:
        """Run batch inference directly on preprocessed numerical matrix."""
        if not self.is_trained:
            # Fallback if model not yet fitted
            now_str = datetime.now(timezone.utc).isoformat()
            return [
                AnomalyPrediction(
                    is_anomaly=False,
                    anomaly_score=0.1,
                    raw_score=0.1,
                    feature_impacts={},
                    evaluated_at=now_str,
                )
                for _ in range(matrix.shape[0])
            ]

        raw_preds = self.model.predict(matrix)            # -1 for anomaly, 1 for inlier
        raw_scores = self.model.decision_function(matrix)  # lower = more anomalous
        now_str = datetime.now(timezone.utc).isoformat()

        results: list[AnomalyPrediction] = []
        for i in range(matrix.shape[0]):
            raw_s = float(raw_scores[i])
            is_anom = bool(raw_preds[i] == -1)
            anom_score = self._calibrate_anomaly_score(raw_s)

            # Heuristic feature impacts
            impacts = self._compute_feature_impacts(matrix[i])

            results.append(
                AnomalyPrediction(
                    is_anomaly=is_anom,
                    anomaly_score=anom_score,
                    raw_score=round(raw_s, 4),
                    feature_impacts=impacts,
                    evaluated_at=now_str,
                )
            )
        return results

    def predict_events(
        self, events: Sequence[Union[CloudSecurityEvent, dict[str, Any]]]
    ) -> list[AnomalyPrediction]:
        if events is None or len(events) == 0:
            return []
        matrix = self.extractor.transform(events)
        return self.predict_matrix(matrix)

    def predict_event(self, event: Union[CloudSecurityEvent, dict[str, Any]]) -> AnomalyPrediction:
        """Predict anomaly posture for a single security telemetry event."""
        preds = self.predict_events([event])
        return preds[0]

    def save(self, filepath: Union[str, Path]) -> None:
        """Serialize detector pipeline and metadata to disk."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "model": self.model,
            "extractor": self.extractor,
            "params": {
                "n_estimators": self.n_estimators,
                "contamination": self.contamination,
                "max_samples": self.max_samples,
                "random_state": self.random_state,
                "model_version": self.model_version,
            },
            "stats": {
                "is_trained": self.is_trained,
                "training_records_count": self.training_records_count,
                "trained_at": self.trained_at,
                "feature_means_": self.feature_means_,
                "feature_names_": self.extractor.feature_names_,
                "score_min_": self.score_min_,
                "score_max_": self.score_max_,
            },
        }
        joblib.dump(payload, path)

        # Save metadata JSON alongside joblib file
        meta_path = path.with_suffix(".json")
        meta_payload = {
            "model_version": self.model_version,
            "algorithm": "IsolationForest",
            "is_trained": self.is_trained,
            "trained_at": self.trained_at,
            "training_records_count": self.training_records_count,
            "feature_count": len(self.extractor.feature_names_),
            "features": self.extractor.feature_names_,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_payload, f, indent=2)

        logger.info("Anomaly detector model artifacts saved", path=str(path))

    @classmethod
    def load(cls, filepath: Union[str, Path]) -> IsolationForestAnomalyDetector:
        """Load detector pipeline and metadata from disk."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found at {path}")

        payload = joblib.load(path)
        params = payload.get("params", {})
        detector = cls(
            n_estimators=params.get("n_estimators", 150),
            contamination=params.get("contamination", 0.05),
            max_samples=params.get("max_samples", "auto"),
            random_state=params.get("random_state", 42),
            model_version=params.get("model_version", cls.DEFAULT_MODEL_VERSION),
        )
        detector.model = payload["model"]
        detector.extractor = payload["extractor"]

        stats = payload.get("stats", {})
        detector.is_trained = stats.get("is_trained", True)
        detector.training_records_count = stats.get("training_records_count", 0)
        detector.trained_at = stats.get("trained_at")
        detector.feature_means_ = stats.get("feature_means_")
        detector.score_min_ = stats.get("score_min_", -0.3)
        detector.score_max_ = stats.get("score_max_", 0.2)

        logger.info(
            "Anomaly detector loaded successfully",
            model_version=detector.model_version,
            training_records=detector.training_records_count,
        )
        return detector
