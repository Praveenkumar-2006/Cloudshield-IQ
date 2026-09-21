"""
Unit tests for SupervisedRiskClassifier (Phase 6: Supervised Risk Classification)
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest

from app.ml.models.risk_classifier import (
    SEVERITY_ORDER,
    SupervisedRiskClassifier,
    SupervisedRiskPrediction,
)


@pytest.fixture
def sample_events() -> list[dict[str, Any]]:
    return [
        {
            "event_id": f"evt-{i:03d}",
            "timestamp": "2026-09-05T12:00:00Z",
            "cloud_provider": "aws" if i % 2 == 0 else "azure",
            "resource_type": "iam:Role" if i % 2 == 0 else "compute:Disk",
            "action": "DeleteRole" if i % 2 == 0 else "AttachVolume",
            "actor_type": "root" if i % 4 == 0 else "user",
            "actor_name": "root" if i % 4 == 0 else f"user_{i}",
            "source_ip": "198.51.100.1" if i % 3 == 0 else "10.0.0.1",
            "mfa_used": bool(i % 2 != 0),
            "outcome": "Failure" if i % 3 == 0 else "Success",
            "session_duration_s": float(i * 100),
        }
        for i in range(40)
    ]


@pytest.fixture
def trained_classifier(sample_events: list[dict[str, Any]]) -> SupervisedRiskClassifier:
    clf = SupervisedRiskClassifier(
        model_version="test-risk-v1",
        n_estimators=15,
        max_depth=3,
        learning_rate=0.1,
        random_state=42,
    )
    y_sev = [SEVERITY_ORDER[i % len(SEVERITY_ORDER)] for i in range(len(sample_events))]
    y_risk = [float((i * 7) % 100) for i in range(len(sample_events))]

    clf.fit(X_raw=sample_events, y_severity=y_sev, y_risk_score=y_risk)
    return clf


def test_classifier_fit_and_properties(trained_classifier: SupervisedRiskClassifier):
    assert trained_classifier.is_trained is True
    assert trained_classifier.metadata.training_records_count == 40
    assert trained_classifier.metadata.feature_count > 0
    assert len(trained_classifier.metadata.feature_names) > 0
    assert "XGBoost" in trained_classifier.metadata.algorithm


def test_classifier_prediction_event(
    trained_classifier: SupervisedRiskClassifier,
    sample_events: list[dict[str, Any]],
):
    pred = trained_classifier.predict_event(sample_events[0])
    assert isinstance(pred, SupervisedRiskPrediction)
    assert pred.predicted_severity in SEVERITY_ORDER
    assert 0.0 <= pred.predicted_risk_score <= 100.0
    assert 0.0 <= pred.confidence <= 1.0

    prob_sum = sum(pred.severity_probabilities.values())
    assert abs(prob_sum - 1.0) < 1e-4
    for s in SEVERITY_ORDER:
        assert s in pred.severity_probabilities


def test_classifier_prediction_batch(
    trained_classifier: SupervisedRiskClassifier,
    sample_events: list[dict[str, Any]],
):
    preds = trained_classifier.predict_batch(sample_events[:5])
    assert len(preds) == 5
    for p in preds:
        assert p.predicted_severity in SEVERITY_ORDER
        assert 0.0 <= p.predicted_risk_score <= 100.0


def test_classifier_save_and_load(
    trained_classifier: SupervisedRiskClassifier,
    sample_events: list[dict[str, Any]],
):
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = Path(tmpdir) / "test_model.joblib"
        trained_classifier.save(model_path)

        assert model_path.exists()
        assert model_path.with_suffix(".json").exists()

        loaded = SupervisedRiskClassifier.load(model_path)
        assert loaded.is_trained is True
        assert loaded.model_version == trained_classifier.model_version

        pred_orig = trained_classifier.predict_event(sample_events[0])
        pred_loaded = loaded.predict_event(sample_events[0])

        assert pred_orig.predicted_severity == pred_loaded.predicted_severity
        assert abs(pred_orig.predicted_risk_score - pred_loaded.predicted_risk_score) < 1e-2


def test_unfitted_prediction_error(sample_events: list[dict[str, Any]]):
    unfitted = SupervisedRiskClassifier()
    with pytest.raises(RuntimeError):
        unfitted.predict_event(sample_events[0])
