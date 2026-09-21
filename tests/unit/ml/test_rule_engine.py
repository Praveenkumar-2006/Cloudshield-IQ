"""
Unit Tests — Deterministic Baseline Risk Engine & Rule Catalog
==============================================================
"""

from datetime import datetime, timezone
import pytest

from app.core.taxonomy import (
    ActorType,
    CanonicalAction,
    CloudProvider,
    OutcomeType,
    SeverityLevel,
)
from app.ml.rules.catalog import (
    DeniedPrivilegedActionRule,
    KmsDestructionRule,
    LoggingTamperingRule,
    NetworkSecurityTamperingRule,
    PrivilegeEscalationNoMfaRule,
    PublicStorageExposureRule,
    RootActivityRule,
    get_default_rules,
)
from app.ml.rules.engine import RuleBasedRiskEngine
from app.schemas.events import CloudSecurityEvent, CloudSecurityEventCreate
from app.services.ml.risk_engine import RiskAssessmentService


def _create_test_event(**overrides) -> CloudSecurityEvent:
    """Helper to generate a valid canonical CloudSecurityEvent for testing."""
    payload = {
        "timestamp": datetime.now(timezone.utc),
        "cloud_provider": CloudProvider.AWS,
        "event_source": "aws_cloudtrail",
        "resource_type": "AWS::S3::Bucket",
        "resource_id": "arn:aws:s3:::my-secure-bucket",
        "raw_action": "GetObject",
        "actor_type": ActorType.USER,
        "actor_name": "developer_alice",
        "source_ip": "192.168.1.50",
        "region": "us-east-1",
        "mfa_used": True,
        "outcome": OutcomeType.SUCCESS,
        "session_duration_s": 1800,
    }
    payload.update(overrides)
    create_obj = CloudSecurityEventCreate(**payload)
    return CloudSecurityEvent.from_create(create_obj)


class TestIndividualRules:
    """Test suite for individual deterministic security rules."""

    def test_root_activity_rule_positive(self):
        rule = RootActivityRule()
        event = _create_test_event(actor_type=ActorType.ROOT, actor_name="root")
        match = rule.evaluate(event)
        assert match is not None
        assert match.rule_id == "RULE-IAM-001"
        assert match.penalty == 40.0
        assert "Root account usage" in match.remediation_guidance

    def test_root_activity_rule_negative(self):
        rule = RootActivityRule()
        event = _create_test_event(actor_type=ActorType.USER)
        assert rule.evaluate(event) is None

    def test_privilege_escalation_no_mfa_positive(self):
        rule = PrivilegeEscalationNoMfaRule()
        event = _create_test_event(
            raw_action="AttachUserPolicy",
            mfa_used=False,
        )
        match = rule.evaluate(event)
        assert match is not None
        assert match.rule_id == "RULE-IAM-002"
        assert match.penalty == 35.0

    def test_privilege_escalation_with_mfa_negative(self):
        rule = PrivilegeEscalationNoMfaRule()
        event = _create_test_event(
            raw_action="AttachUserPolicy",
            mfa_used=True,
        )
        assert rule.evaluate(event) is None

    def test_logging_tampering_rule(self):
        rule = LoggingTamperingRule()
        event = _create_test_event(raw_action="DeleteTrail")
        match = rule.evaluate(event)
        assert match is not None
        assert match.rule_id == "RULE-LOG-001"
        assert match.penalty == 50.0

    def test_kms_destruction_rule(self):
        rule = KmsDestructionRule()
        event = _create_test_event(raw_action="DisableKey")
        match = rule.evaluate(event)
        assert match is not None
        assert match.rule_id == "RULE-KMS-001"
        assert match.penalty == 45.0

    def test_public_storage_exposure_rule(self):
        rule = PublicStorageExposureRule()
        event = _create_test_event(raw_action="PutBucketPolicy")
        match = rule.evaluate(event)
        assert match is not None
        assert match.rule_id == "RULE-STR-001"
        assert match.penalty == 30.0

    def test_network_security_tampering_rule(self):
        rule = NetworkSecurityTamperingRule()
        event = _create_test_event(raw_action="AuthorizeSecurityGroupIngress")
        match = rule.evaluate(event)
        assert match is not None
        assert match.rule_id == "RULE-NET-001"
        assert match.penalty == 25.0

    def test_denied_privileged_action_rule(self):
        rule = DeniedPrivilegedActionRule()
        denied_event = _create_test_event(
            raw_action="PutBucketPolicy",
            outcome=OutcomeType.DENIED,
        )
        match = rule.evaluate(denied_event)
        assert match is not None
        assert match.rule_id == "RULE-ACT-001"
        assert match.penalty == 20.0

        # Success should not trigger this rule
        success_event = _create_test_event(
            raw_action="PutBucketPolicy",
            outcome=OutcomeType.SUCCESS,
        )
        assert rule.evaluate(success_event) is None


class TestRuleBasedRiskEngine:
    """Test suite for RuleBasedRiskEngine orchestration and scoring."""

    def test_benign_event_evaluation(self):
        engine = RuleBasedRiskEngine()
        event = _create_test_event(raw_action="GetObject", mfa_used=True)
        res = engine.evaluate_event(event)

        assert res.assessment.risk_score == 0.0
        assert res.assessment.severity == SeverityLevel.LOW
        assert res.assessment.is_anomaly is False
        assert len(res.findings) == 0
        assert len(res.matches) == 0

    def test_single_rule_evaluation(self):
        engine = RuleBasedRiskEngine()
        event = _create_test_event(actor_type=ActorType.ROOT, raw_action="GetObject")
        res = engine.evaluate_event(event)

        assert res.assessment.risk_score == 40.0
        assert res.assessment.severity == SeverityLevel.MEDIUM
        assert res.assessment.top_feature == "RULE-IAM-001"
        assert len(res.findings) == 1
        assert res.findings[0].category == "IAM"

    def test_multiple_rule_combination(self):
        engine = RuleBasedRiskEngine()
        # Root user + Logging deletion without MFA
        event = _create_test_event(
            actor_type=ActorType.ROOT,
            raw_action="DeleteTrail",
            mfa_used=False,
        )
        res = engine.evaluate_event(event)

        # 40.0 (Root) + 50.0 (DeleteTrail) = 90.0
        assert res.assessment.risk_score == 90.0
        assert res.assessment.severity == SeverityLevel.CRITICAL
        assert res.assessment.is_anomaly is True
        assert len(res.findings) == 2

    def test_score_saturation_cap(self):
        engine = RuleBasedRiskEngine()
        # Root user (40) + DeleteTrail (50) + DisableKey (45) => 135 -> capped to 100.0
        event = _create_test_event(
            actor_type=ActorType.ROOT,
            raw_action="DeleteTrail",
            mfa_used=False,
        )
        # Register a duplicate high penalty rule for testing max cap
        class ExtraPenaltyRule(RootActivityRule):
            rule_id = "EXTRA-001"
            base_penalty = 50.0

        engine.register_rule(ExtraPenaltyRule())
        res = engine.evaluate_event(event)
        assert res.assessment.risk_score == 100.0
        assert res.assessment.severity == SeverityLevel.CRITICAL

    def test_severity_threshold_mapping(self):
        assert RuleBasedRiskEngine.map_score_to_severity(0.0) == SeverityLevel.LOW
        assert RuleBasedRiskEngine.map_score_to_severity(29.9) == SeverityLevel.LOW
        assert RuleBasedRiskEngine.map_score_to_severity(30.0) == SeverityLevel.MEDIUM
        assert RuleBasedRiskEngine.map_score_to_severity(59.9) == SeverityLevel.MEDIUM
        assert RuleBasedRiskEngine.map_score_to_severity(60.0) == SeverityLevel.HIGH
        assert RuleBasedRiskEngine.map_score_to_severity(84.9) == SeverityLevel.HIGH
        assert RuleBasedRiskEngine.map_score_to_severity(85.0) == SeverityLevel.CRITICAL
        assert RuleBasedRiskEngine.map_score_to_severity(100.0) == SeverityLevel.CRITICAL

    def test_batch_evaluation(self):
        engine = RuleBasedRiskEngine()
        events = [
            _create_test_event(raw_action="GetObject"),
            _create_test_event(actor_type=ActorType.ROOT),
            _create_test_event(raw_action="DeleteTrail"),
        ]
        results = engine.evaluate_batch(events)
        assert len(results) == 3
        assert results[0].assessment.risk_score == 0.0
        assert results[1].assessment.risk_score == 40.0
        assert results[2].assessment.risk_score == 50.0


class TestRiskAssessmentService:
    """Test high-level service orchestration."""

    def test_service_single_and_batch(self):
        service = RiskAssessmentService()
        event = _create_test_event(actor_type=ActorType.ROOT)
        result = service.assess_event(event)
        assert result.assessment.risk_score == 40.0

        batch_res = service.assess_batch([event, event])
        assert len(batch_res) == 2
