"""
CloudShield IQ — Remediation Prioritizer Tests
==============================================
Unit tests for calculating remediation priority scores, sorting order,
effort inversion, and quick-win tagging.
"""

import pytest

from app.core.taxonomy import SeverityLevel
from app.recommendations.prioritizer import RemediationPrioritizer
from app.schemas.recommendations import EffortLevel


class TestRemediationPrioritizer:
    """Tests the mathematical prioritization and quick win logic."""

    def test_calculate_priority_critical_vs_low(self):
        score_crit = RemediationPrioritizer.calculate_priority_score(
            risk_score=95.0,
            severity=SeverityLevel.CRITICAL,
            compliance_violation_count=3,
            effort_level=EffortLevel.LOW,
        )
        score_low = RemediationPrioritizer.calculate_priority_score(
            risk_score=20.0,
            severity=SeverityLevel.LOW,
            compliance_violation_count=0,
            effort_level=EffortLevel.HIGH,
        )
        assert score_crit > score_low
        assert 0.0 <= score_crit <= 100.0
        assert 0.0 <= score_low <= 100.0

    def test_effort_inversion_gives_boost_to_low_effort(self):
        # Two identical risks, but one is LOW effort (quick fix) and other is HIGH effort
        score_quick = RemediationPrioritizer.calculate_priority_score(
            risk_score=60.0,
            severity=SeverityLevel.HIGH,
            compliance_violation_count=1,
            effort_level=EffortLevel.LOW,
        )
        score_heavy = RemediationPrioritizer.calculate_priority_score(
            risk_score=60.0,
            severity=SeverityLevel.HIGH,
            compliance_violation_count=1,
            effort_level=EffortLevel.HIGH,
        )
        assert score_quick > score_heavy

    def test_compliance_violation_boost(self):
        score_with_violations = RemediationPrioritizer.calculate_priority_score(
            risk_score=50.0,
            severity=SeverityLevel.MEDIUM,
            compliance_violation_count=4,
            effort_level=EffortLevel.MEDIUM,
        )
        score_without = RemediationPrioritizer.calculate_priority_score(
            risk_score=50.0,
            severity=SeverityLevel.MEDIUM,
            compliance_violation_count=0,
            effort_level=EffortLevel.MEDIUM,
        )
        assert score_with_violations > score_without

    def test_score_bounding(self):
        # Test extreme upper and lower inputs
        max_score = RemediationPrioritizer.calculate_priority_score(
            risk_score=150.0,  # exceeds 100
            severity=SeverityLevel.CRITICAL,
            compliance_violation_count=10,
            effort_level=EffortLevel.LOW,
        )
        assert max_score <= 100.0

        min_score = RemediationPrioritizer.calculate_priority_score(
            risk_score=-50.0,  # sub-zero
            severity=SeverityLevel.LOW,
            compliance_violation_count=0,
            effort_level=EffortLevel.HIGH,
        )
        assert min_score >= 0.0

    def test_is_quick_win(self):
        assert RemediationPrioritizer.is_quick_win(EffortLevel.LOW, 30.0) is True
        assert RemediationPrioritizer.is_quick_win(EffortLevel.LOW, 10.0) is False
        assert RemediationPrioritizer.is_quick_win(EffortLevel.MEDIUM, 40.0) is False
        assert RemediationPrioritizer.is_quick_win(EffortLevel.HIGH, 50.0) is False
