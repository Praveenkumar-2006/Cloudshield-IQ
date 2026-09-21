"""
CloudShield IQ — Risk Assessment Service
========================================
Service layer coordinating deterministic risk heuristics and ML anomaly detection.
"""

from __future__ import annotations

from collections.abc import Sequence
import json
from pathlib import Path
import time
from typing import Any

import pandas as pd

from app.core.config import get_settings
from app.core.logging import get_logger
from app.ml.models.anomaly_detector import (
    AnomalyPrediction,
    IsolationForestAnomalyDetector,
)
from app.ml.explainability.tree_shap import (
    GlobalAttributionSummary,
    LocalExplanation,
    TreeSHAPExplainer,
)
from app.ml.models.risk_classifier import (
    SupervisedRiskClassifier,
    SupervisedRiskPrediction,
)
from app.ml.rules.engine import RuleAssessmentResult, RuleBasedRiskEngine
from app.schemas.events import CloudSecurityEvent

logger = get_logger(__name__)


class RiskAssessmentService:
    """
    High-level service interface for evaluating multi-cloud security risks
    using deterministic heuristics, scikit-learn Isolation Forest ML models,
    and supervised XGBoost severity classifiers.
    """

    def __init__(
        self,
        rule_engine: RuleBasedRiskEngine | None = None,
        anomaly_detector: IsolationForestAnomalyDetector | None = None,
        supervised_classifier: SupervisedRiskClassifier | None = None,
        use_hybrid_scoring: bool = False,
    ):
        settings = get_settings()
        self.model_dir: Path = settings.MODEL_DIR
        self.model_path: Path = self.model_dir / "isolation_forest_v1.joblib"
        self.supervised_model_path: Path = self.model_dir / "supervised_risk_v1.joblib"

        # Load or initialize anomaly detector
        if anomaly_detector is not None:
            self.anomaly_detector = anomaly_detector
        else:
            self.anomaly_detector = self._load_or_train_anomaly_detector()

        # Load or initialize supervised XGBoost classifier
        if supervised_classifier is not None:
            self.supervised_classifier = supervised_classifier
        else:
            self.supervised_classifier = self._load_or_train_supervised_classifier()

        # Initialize rule engine with anomaly detector
        self.rule_engine = rule_engine or RuleBasedRiskEngine(
            anomaly_detector=self.anomaly_detector,
            use_hybrid_scoring=use_hybrid_scoring,
        )

        # Initialize TreeSHAP explainability engine
        self.explainer = TreeSHAPExplainer(self.supervised_classifier)

    def _load_or_train_supervised_classifier(self) -> SupervisedRiskClassifier:
        """Load trained XGBoost risk classifier from disk, or initialize baseline."""
        if self.supervised_model_path.exists():
            try:
                classifier = SupervisedRiskClassifier.load(self.supervised_model_path)
                logger.info(
                    "Loaded pre-trained Supervised Risk Classifier",
                    path=str(self.supervised_model_path),
                    version=classifier.model_version,
                )
                return classifier
            except Exception as exc:
                logger.warning(
                    "Failed loading supervised model file, creating new instance",
                    error=str(exc),
                )

        base_dir = Path(__file__).resolve().parent.parent.parent.parent.parent
        csv_path = base_dir / "datasets" / "synthetic" / "cloud_security_events.csv"
        classifier = SupervisedRiskClassifier(model_version="supervised-xgboost-v1")

        if csv_path.exists():
            try:
                logger.info(
                    "Training initial supervised risk model from dataset",
                    path=str(csv_path),
                )
                df = pd.read_csv(csv_path)
                if "severity" in df.columns and "risk_score" in df.columns:
                    classifier.fit(
                        X_raw=df,
                        y_severity=df["severity"].tolist(),
                        y_risk_score=df["risk_score"].tolist(),
                    )
                    classifier.save(self.supervised_model_path)
                    logger.info("Initial supervised model trained and serialized successfully")
            except Exception as exc:
                logger.warning("Failed to auto-train supervised model", error=str(exc))
        else:
            logger.info("No benchmark dataset found; supervised classifier uninitialized.")

        return classifier

    def _load_or_train_anomaly_detector(self) -> IsolationForestAnomalyDetector:
        """Load trained model from disk, or train baseline if dataset exists."""
        if self.model_path.exists():
            try:
                detector = IsolationForestAnomalyDetector.load(self.model_path)
                logger.info(
                    "Loaded pre-trained Isolation Forest anomaly detector",
                    path=str(self.model_path),
                    version=detector.model_version,
                )
                return detector
            except Exception as exc:
                logger.warning("Failed loading model file, creating new instance", error=str(exc))

        # Check for benchmark dataset to train on
        base_dir = Path(__file__).resolve().parent.parent.parent.parent.parent
        csv_path = base_dir / "datasets" / "synthetic" / "cloud_security_events.csv"
        detector = IsolationForestAnomalyDetector(model_version="isolation-forest-v1")

        if csv_path.exists():
            try:
                logger.info(
                    "Training initial Isolation Forest model from dataset",
                    path=str(csv_path),
                )
                df = pd.read_csv(csv_path)
                detector.fit(df)
                detector.save(self.model_path)
                logger.info("Initial model trained and serialized successfully")
            except Exception as exc:
                logger.warning("Failed to auto-train initial model", error=str(exc))
        else:
            logger.info("No benchmark dataset found; anomaly detector uninitialized.")

        return detector

    def assess_event(self, event: CloudSecurityEvent) -> RuleAssessmentResult:
        """Assess risk for a single canonical security event."""
        result = self.rule_engine.evaluate_event(event)
        logger.info(
            "Event assessed",
            event_id=event.event_id,
            risk_score=result.assessment.risk_score,
            severity=result.assessment.severity.value,
            anomaly_score=result.assessment.anomaly_score,
            is_anomaly=result.assessment.is_anomaly,
            finding_count=len(result.findings),
        )
        return result

    def assess_batch(self, events: list[CloudSecurityEvent]) -> list[RuleAssessmentResult]:
        """Assess risk for a batch of canonical security events."""
        return self.rule_engine.evaluate_batch(events)

    def detect_anomalies(self, events: list[CloudSecurityEvent]) -> list[AnomalyPrediction]:
        """Directly run ML anomaly inference on a batch of events."""
        return self.anomaly_detector.predict_events(events)

    def get_model_info(self) -> dict[str, Any]:
        """Retrieve active ML model metadata and operational statistics."""
        meta_file = self.model_path.with_suffix(".json")
        saved_meta: dict[str, Any] = {}
        if meta_file.exists():
            try:
                with open(meta_file, encoding="utf-8") as f:
                    saved_meta = json.load(f)
            except (OSError, json.JSONDecodeError):
                pass

        return {
            "model_version": self.anomaly_detector.model_version,
            "algorithm": "IsolationForest",
            "is_trained": self.anomaly_detector.is_trained,
            "trained_at": self.anomaly_detector.trained_at or saved_meta.get("trained_at"),
            "training_records_count": (
                self.anomaly_detector.training_records_count
                or saved_meta.get("training_records_count", 0)
            ),
            "feature_count": len(self.anomaly_detector.extractor.feature_names_),
            "features": self.anomaly_detector.extractor.feature_names_,
            "contamination": self.anomaly_detector.contamination,
            "n_estimators": self.anomaly_detector.n_estimators,
            "status": "ready" if self.anomaly_detector.is_trained else "uninitialized",
            "metrics": saved_meta.get("metrics", {}),
        }

    def retrain_anomaly_model(
        self,
        contamination: float = 0.05,
        n_estimators: int = 150,
        dataset_path: str | None = None,
    ) -> dict[str, Any]:
        """Retrain the Isolation Forest model on demand."""
        target_path: Path
        if dataset_path:
            target_path = Path(dataset_path)
        else:
            base_dir = Path(__file__).resolve().parent.parent.parent.parent.parent
            target_path = base_dir / "datasets" / "synthetic" / "cloud_security_events.csv"

        if not target_path.exists():
            raise FileNotFoundError(f"Telemetry dataset not found at {target_path}")

        t0 = time.perf_counter()
        df = pd.read_csv(target_path)
        self.anomaly_detector.contamination = contamination
        self.anomaly_detector.n_estimators = n_estimators
        self.anomaly_detector.fit(df)
        self.anomaly_detector.save(self.model_path)
        duration = round(time.perf_counter() - t0, 3)

        # Update engine reference
        self.rule_engine.anomaly_detector = self.anomaly_detector

        info = self.get_model_info()
        info["training_duration_seconds"] = duration
        return info

    def classify_risk(
        self,
        events: pd.DataFrame | Sequence[Any],
    ) -> list[SupervisedRiskPrediction]:
        """Classify incident severity and continuous risk score for telemetry events."""
        return self.supervised_classifier.predict_batch(events)

    def get_supervised_model_info(self) -> dict[str, Any]:
        """Retrieve active supervised XGBoost model metadata and metrics."""
        meta_file = self.supervised_model_path.with_suffix(".json")
        saved_meta: dict[str, Any] = {}
        if meta_file.exists():
            try:
                with open(meta_file, encoding="utf-8") as f:
                    saved_meta = json.load(f)
            except (OSError, json.JSONDecodeError):
                pass

        meta = self.supervised_classifier.metadata
        return {
            "model_version": meta.model_version,
            "algorithm": meta.algorithm,
            "is_trained": self.supervised_classifier.is_trained,
            "created_at": meta.created_at or saved_meta.get("created_at"),
            "training_records_count": (
                meta.training_records_count or saved_meta.get("training_records_count", 0)
            ),
            "feature_count": meta.feature_count or len(meta.feature_names),
            "features": meta.feature_names or saved_meta.get("feature_names", []),
            "classes": (
                meta.classes or saved_meta.get("classes", ["low", "medium", "high", "critical"])
            ),
            "status": "ready" if self.supervised_classifier.is_trained else "uninitialized",
            "metrics": meta.metrics or saved_meta.get("metrics", {}),
            "hyperparameters": meta.hyperparameters or saved_meta.get("hyperparameters", {}),
        }

    def retrain_supervised_model(
        self,
        dataset_path: str | None = None,
        n_estimators: int = 120,
        max_depth: int = 5,
        learning_rate: float = 0.08,
    ) -> dict[str, Any]:
        """Retrain the supervised XGBoost model on demand."""
        target_path: Path
        if dataset_path:
            target_path = Path(dataset_path)
        else:
            base_dir = Path(__file__).resolve().parent.parent.parent.parent.parent
            target_path = base_dir / "datasets" / "synthetic" / "cloud_security_events.csv"

        if not target_path.exists():
            raise FileNotFoundError(f"Telemetry dataset not found at {target_path}")

        t0 = time.perf_counter()
        df = pd.read_csv(target_path)
        if "severity" not in df.columns or "risk_score" not in df.columns:
            raise ValueError("Dataset missing 'severity' or 'risk_score' columns")

        self.supervised_classifier.n_estimators = n_estimators
        self.supervised_classifier.max_depth = max_depth
        self.supervised_classifier.learning_rate = learning_rate

        self.supervised_classifier.fit(
            X_raw=df,
            y_severity=df["severity"].tolist(),
            y_risk_score=df["risk_score"].tolist(),
        )
        self.supervised_classifier.save(self.supervised_model_path)
        self.explainer = TreeSHAPExplainer(self.supervised_classifier)
        duration = round(time.perf_counter() - t0, 3)

        info = self.get_supervised_model_info()
        info["training_duration_seconds"] = duration
        return info

    def explain_security_event(
        self,
        event: dict[str, Any] | CloudSecurityEvent,
        top_k: int = 5,
    ) -> LocalExplanation:
        """Calculate local TreeSHAP attribution breakdown for a single security event."""
        return self.explainer.explain_event(event, top_k=top_k)

    def explain_events_batch(
        self,
        events: Sequence[dict[str, Any] | CloudSecurityEvent],
        top_k: int = 5,
    ) -> list[LocalExplanation]:
        """Calculate local TreeSHAP attribution breakdowns for multiple events."""
        return self.explainer.explain_batch(events, top_k=top_k)

    def get_global_shap_attributions(
        self,
        background_data: Any = None,
        top_k: int = 8,
    ) -> GlobalAttributionSummary:
        """Calculate global TreeSHAP feature importance rankings."""
        return self.explainer.get_global_attributions(background_data=background_data, top_k=top_k)


_service_instance: RiskAssessmentService | None = None


def get_risk_assessment_service() -> RiskAssessmentService:
    """Singleton getter for RiskAssessmentService."""
    global _service_instance
    if _service_instance is None:
        _service_instance = RiskAssessmentService()
    return _service_instance
