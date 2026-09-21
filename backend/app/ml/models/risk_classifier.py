"""
CloudShield IQ — Supervised Risk Classifier & Regressor (XGBoost)
=================================================================
Dual-head gradient boosted decision tree model predicting multi-class
security incident severity (low, medium, high, critical) and continuous
risk scores (0.0 - 100.0) from multi-cloud telemetry.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Optional, Sequence, Union

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from app.ml.features.pipeline import SecurityFeatureExtractor
from app.schemas.events import CloudSecurityEvent

logger = logging.getLogger("cloudshield.ml.risk_classifier")

SEVERITY_ORDER: list[str] = ["low", "medium", "high", "critical"]
SEVERITY_TO_INDEX: dict[str, int] = {s: i for i, s in enumerate(SEVERITY_ORDER)}
INDEX_TO_SEVERITY: dict[int, str] = {i: s for i, s in enumerate(SEVERITY_ORDER)}


@dataclass(frozen=True)
class SupervisedRiskPrediction:
    """Prediction result for a single telemetry event."""

    predicted_severity: str
    severity_probabilities: dict[str, float]
    predicted_risk_score: float
    confidence: float
    model_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SupervisedRiskMetadata:
    """Metadata describing the trained model artifact."""

    model_version: str = "supervised-xgboost-v1"
    algorithm: str = "XGBoost (Classifier + Regressor)"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    training_records_count: int = 0
    feature_count: int = 0
    feature_names: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=lambda: list(SEVERITY_ORDER))
    metrics: dict[str, Any] = field(default_factory=dict)
    hyperparameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SupervisedRiskClassifier:
    """
    Supervised Machine Learning Risk Engine powered by XGBoost.
    Predicts categorical incident severity and continuous posture risk index.
    """

    DEFAULT_VERSION = "supervised-xgboost-v1"

    def __init__(
        self,
        model_version: str = DEFAULT_VERSION,
        n_estimators: int = 120,
        max_depth: int = 5,
        learning_rate: float = 0.08,
        random_state: int = 42,
        subsample: float = 0.85,
        colsample_bytree: float = 0.85,
    ) -> None:
        self.model_version = model_version
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.random_state = random_state
        self.subsample = subsample
        self.colsample_bytree = colsample_bytree

        self.feature_extractor = SecurityFeatureExtractor()

        self.classifier = xgb.XGBClassifier(
            objective="multi:softprob",
            num_class=len(SEVERITY_ORDER),
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            random_state=self.random_state,
            subsample=self.subsample,
            colsample_bytree=self.colsample_bytree,
            eval_metric="mlogloss",
        )

        self.regressor = xgb.XGBRegressor(
            objective="reg:squarederror",
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            random_state=self.random_state,
            subsample=self.subsample,
            colsample_bytree=self.colsample_bytree,
            eval_metric="rmse",
        )

        self.metadata = SupervisedRiskMetadata(
            model_version=self.model_version,
            hyperparameters={
                "n_estimators": n_estimators,
                "max_depth": max_depth,
                "learning_rate": learning_rate,
                "subsample": subsample,
                "colsample_bytree": colsample_bytree,
                "random_state": random_state,
            },
        )
        self.is_trained: bool = False

    def fit(
        self,
        X_raw: Union[pd.DataFrame, Sequence[CloudSecurityEvent]],
        y_severity: Sequence[Union[str, int]],
        y_risk_score: Sequence[float],
        sample_weight: Optional[Sequence[float]] = None,
        metrics: Optional[dict[str, Any]] = None,
    ) -> SupervisedRiskClassifier:
        """Fit the feature extractor and both gradient-boosted models."""
        logger.info(
            "Fitting SecurityFeatureExtractor on %d training records...",
            len(y_severity),
        )
        X_mat = self.feature_extractor.fit_transform(X_raw)

        # Normalize severity targets to integer indices [0..3]
        if isinstance(y_severity[0], str):
            y_cls = np.array(
                [SEVERITY_TO_INDEX.get(s.lower(), 0) for s in y_severity],
                dtype=np.int64,
            )
        else:
            y_cls = np.array(y_severity, dtype=np.int64)

        y_reg = np.clip(np.array(y_risk_score, dtype=np.float64), 0.0, 100.0)

        weight_arr = np.array(sample_weight) if sample_weight is not None else None

        logger.info("Training XGBClassifier (multi:softprob)...")
        self.classifier.fit(X_mat, y_cls, sample_weight=weight_arr)

        logger.info("Training XGBRegressor (reg:squarederror)...")
        self.regressor.fit(X_mat, y_reg, sample_weight=weight_arr)

        self.is_trained = True
        self.metadata.training_records_count = len(y_severity)
        self.metadata.feature_count = X_mat.shape[1]
        self.metadata.feature_names = list(self.feature_extractor.feature_names_)
        if metrics:
            self.metadata.metrics = metrics

        logger.info(
            "SupervisedRiskClassifier training complete. Features: %d",
            self.metadata.feature_count,
        )
        return self

    def predict_matrix(
        self, X_mat: np.ndarray
    ) -> list[SupervisedRiskPrediction]:
        """Predict severity and risk scores directly from a preprocessed numerical matrix."""
        if not self.is_trained:
            raise RuntimeError("SupervisedRiskClassifier must be fitted before predict().")

        if X_mat.shape[0] == 0:
            return []

        proba_matrix = self.classifier.predict_proba(X_mat)
        predicted_indices = np.argmax(proba_matrix, axis=1)
        risk_scores = np.clip(self.regressor.predict(X_mat), 0.0, 100.0)

        predictions: list[SupervisedRiskPrediction] = []
        for i in range(X_mat.shape[0]):
            probs = {
                s: float(proba_matrix[i, idx])
                for s, idx in SEVERITY_TO_INDEX.items()
            }
            pred_idx = int(predicted_indices[i])
            pred_sev = INDEX_TO_SEVERITY[pred_idx]
            conf = float(proba_matrix[i, pred_idx])
            pred_score = round(float(risk_scores[i]), 2)

            predictions.append(
                SupervisedRiskPrediction(
                    predicted_severity=pred_sev,
                    severity_probabilities=probs,
                    predicted_risk_score=pred_score,
                    confidence=round(conf, 4),
                    model_version=self.model_version,
                )
            )

        return predictions

    def predict_batch(
        self, events: Union[pd.DataFrame, Sequence[CloudSecurityEvent], Sequence[dict[str, Any]]]
    ) -> list[SupervisedRiskPrediction]:
        """Transform events and return predictions for the batch."""
        if not self.is_trained:
            raise RuntimeError("SupervisedRiskClassifier is not trained.")

        X_mat = self.feature_extractor.transform(events)
        return self.predict_matrix(X_mat)

    def predict_event(
        self, event: Union[CloudSecurityEvent, dict[str, Any]]
    ) -> SupervisedRiskPrediction:
        """Predict risk profile for a single cloud security telemetry event."""
        preds = self.predict_batch([event])
        if not preds:
            raise ValueError("Failed to produce prediction for event.")
        return preds[0]

    def save(
        self,
        model_path: Union[str, Path],
        metadata_path: Optional[Union[str, Path]] = None,
    ) -> None:
        """Serialize model weights and metadata to disk."""
        model_path = Path(model_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "model_version": self.model_version,
            "classifier": self.classifier,
            "regressor": self.regressor,
            "feature_extractor": self.feature_extractor,
            "metadata": self.metadata.to_dict(),
            "is_trained": self.is_trained,
        }
        joblib.dump(payload, model_path, compress=3)
        logger.info("Saved SupervisedRiskClassifier to %s", model_path)

        if metadata_path is None:
            metadata_path = model_path.with_suffix(".json")
        else:
            metadata_path = Path(metadata_path)

        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(self.metadata.to_dict(), f, indent=2)
        logger.info("Saved model metadata to %s", metadata_path)

    @classmethod
    def load(cls, model_path: Union[str, Path]) -> SupervisedRiskClassifier:
        """Load trained classifier and regressor from disk."""
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        payload = joblib.load(model_path)
        instance = cls(model_version=payload.get("model_version", cls.DEFAULT_VERSION))
        instance.classifier = payload["classifier"]
        instance.regressor = payload["regressor"]
        instance.feature_extractor = payload["feature_extractor"]
        instance.is_trained = payload.get("is_trained", True)

        raw_meta = payload.get("metadata", {})
        instance.metadata = SupervisedRiskMetadata(
            model_version=raw_meta.get("model_version", instance.model_version),
            algorithm=raw_meta.get("algorithm", "XGBoost"),
            created_at=raw_meta.get("created_at", datetime.now(timezone.utc).isoformat()),
            training_records_count=raw_meta.get("training_records_count", 0),
            feature_count=raw_meta.get("feature_count", 0),
            feature_names=raw_meta.get("feature_names", []),
            classes=raw_meta.get("classes", list(SEVERITY_ORDER)),
            metrics=raw_meta.get("metrics", {}),
            hyperparameters=raw_meta.get("hyperparameters", {}),
        )

        logger.info(
            "Loaded SupervisedRiskClassifier v=%s (features=%d)",
            instance.model_version,
            instance.metadata.feature_count,
        )
        return instance
