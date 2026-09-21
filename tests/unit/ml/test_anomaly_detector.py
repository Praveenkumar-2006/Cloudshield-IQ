"""
Unit Tests — Isolation Forest Anomaly Detector
==============================================
"""

import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.ml.models.anomaly_detector import AnomalyPrediction, IsolationForestAnomalyDetector
from app.schemas.events import CloudSecurityEvent, CloudSecurityEventCreate


def _generate_synthetic_events(count: int = 50) -> list[dict]:
    events = []
    for i in range(count):
        events.append({
            "timestamp": "2026-09-05T12:00:00Z",
            "cloud_provider": "aws",
            "resource_type": "ec2:Instance",
            "action": "DescribeInstances",
            "actor_type": "user",
            "actor_name": f"user_{i % 5}",
            "source_ip": "10.0.0.1",
            "mfa_used": True,
            "outcome": "Success",
            "session_duration_s": 1200,
        })
    # Add an outlier
    events.append({
        "timestamp": "2026-09-05T03:15:00Z",
        "cloud_provider": "gcp",
        "resource_type": "iam:Role",
        "action": "DeleteRole",
        "actor_type": "root",
        "actor_name": "root",
        "source_ip": "203.0.113.195",
        "mfa_used": False,
        "outcome": "Failure",
        "session_duration_s": 0,
    })
    return events


class TestIsolationForestAnomalyDetector:
    """Test suite for Isolation Forest detector."""

    def test_fit_and_predict(self):
        detector = IsolationForestAnomalyDetector(
            n_estimators=30,
            contamination=0.1,
            random_state=42,
        )
        events = _generate_synthetic_events(60)
        detector.fit(events)

        assert detector.is_trained is True
        assert detector.training_records_count == 61
        assert detector.trained_at is not None

        # Predict batch
        preds = detector.predict_events(events)
        assert len(preds) == 61
        assert all(isinstance(p, AnomalyPrediction) for p in preds)
        assert all(0.0 <= p.anomaly_score <= 1.0 for p in preds)

        # Single event prediction
        single_pred = detector.predict_event(events[0])
        assert isinstance(single_pred, AnomalyPrediction)
        assert single_pred.anomaly_score >= 0.0

    def test_save_and_load_roundtrip(self):
        detector = IsolationForestAnomalyDetector(n_estimators=25, contamination=0.08)
        events = _generate_synthetic_events(30)
        detector.fit(events)

        with tempfile.TemporaryDirectory() as tmpdir:
            model_file = Path(tmpdir) / "test_detector.joblib"
            detector.save(model_file)

            assert model_file.exists()
            assert model_file.with_suffix(".json").exists()

            loaded = IsolationForestAnomalyDetector.load(model_file)
            assert loaded.is_trained is True
            assert loaded.n_estimators == 25
            assert loaded.contamination == 0.08
            assert loaded.training_records_count == detector.training_records_count

            # Verify predictions match
            p1 = detector.predict_event(events[0])
            p2 = loaded.predict_event(events[0])
            assert p1.is_anomaly == p2.is_anomaly
            assert p1.anomaly_score == p2.anomaly_score

    def test_unfitted_model_graceful_fallback(self):
        detector = IsolationForestAnomalyDetector()
        events = _generate_synthetic_events(5)
        # Predicting before fitting should not crash
        matrix = np.zeros((2, 5))
        preds = detector.predict_matrix(matrix)
        assert len(preds) == 2
        assert preds[0].is_anomaly is False
