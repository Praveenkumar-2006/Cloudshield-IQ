"""
Unit Tests — Hybrid Risk Engine & ML Integration
=================================================
"""

from datetime import datetime, timezone
import pytest

from app.core.taxonomy import ActorType, CloudProvider, OutcomeType, SeverityLevel
from app.ml.models.anomaly_detector import IsolationForestAnomalyDetector
from app.ml.rules.catalog import RootActivityRule
from app.ml.rules.engine import RuleBasedRiskEngine
from app.schemas.events import CloudSecurityEvent, CloudSecurityEventCreate
from app.services.ml.risk_engine import RiskAssessmentService


def _create_event(**overrides) -> CloudSecurityEvent:
    base = {
        "timestamp": datetime.now(timezone.utc),
        "cloud_provider": CloudProvider.AWS,
        "event_source": "aws_cloudtrail",
        "resource_type": "AWS::S3::Bucket",
        "resource_id": "arn:aws:s3:::test-bucket",
        "raw_action": "GetObject",
        "actor_type": ActorType.USER,
        "actor_name": "developer",
        "source_ip": "10.0.0.1",
        "region": "us-east-1",
        "mfa_used": True,
        "outcome": OutcomeType.SUCCESS,
        "session_duration_s": 1800,
    }
    base.update(overrides)
    return CloudSecurityEvent.from_create(CloudSecurityEventCreate(**base))


class TestHybridRiskEngine:
    """Test suite for hybrid deterministic + ML anomaly risk assessment."""

    def test_hybrid_scoring_with_trained_detector(self):
        # Prepare trained detector
        detector = IsolationForestAnomalyDetector(n_estimators=20, contamination=0.1)
        training_events = [
            {"timestamp": "2026-09-05T12:00:00Z", "cloud_provider": "aws", "resource_type": "s3:Bucket", "action": "GetObject", "actor_type": "user", "actor_name": "alice", "source_ip": "10.0.0.1", "mfa_used": True, "outcome": "Success", "session_duration_s": 1000}
            for _ in range(40)
        ]
        detector.fit(training_events)

        engine = RuleBasedRiskEngine(
            anomaly_detector=detector,
            use_hybrid_scoring=True,
        )

        # Benign event
        benign_event = _create_event(raw_action="GetObject", mfa_used=True)
        res_benign = engine.evaluate_event(benign_event)
        assert res_benign.assessment.model_version == detector.model_version
        assert 0.0 <= res_benign.assessment.anomaly_score <= 1.0

        # High risk root event triggering rule
        root_event = _create_event(actor_type=ActorType.ROOT, raw_action="DeleteTrail", mfa_used=False)
        res_root = engine.evaluate_event(root_event)
        assert res_root.assessment.risk_score > 50.0
        assert len(res_root.findings) >= 1

    def test_risk_assessment_service_lifecycle(self):
        service = RiskAssessmentService(use_hybrid_scoring=True)
        assert service.anomaly_detector is not None

        info = service.get_model_info()
        assert "model_version" in info
        assert "algorithm" in info
        assert info["algorithm"] == "IsolationForest"

        event = _create_event()
        result = service.assess_event(event)
        assert result.assessment is not None
        assert result.assessment.risk_score >= 0.0
