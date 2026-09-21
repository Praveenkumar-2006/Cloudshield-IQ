"""
CloudShield IQ — Remediation Prioritizer
========================================
Intelligent priority queue calculator for security findings and remediation playbooks.
Balances risk reduction, compliance severity, and implementation effort to identify
high-ROI "quick wins" and sequence urgent mitigations.
"""

from typing import Optional

from app.core.taxonomy import SeverityLevel
from app.schemas.assessments import SecurityFinding, SecurityFindingBase
from app.schemas.recommendations import EffortLevel, RemediationPlaybook


class RemediationPrioritizer:
    """
    Ranks security findings and corresponding remediation countermeasures
    by operational urgency and return-on-investment (ROI).
    """

    # Weights sum to 1.0
    WEIGHT_RISK_SCORE = 0.45
    WEIGHT_SEVERITY = 0.25
    WEIGHT_COMPLIANCE = 0.15
    WEIGHT_EFFORT = 0.15

    SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 100.0,
        SeverityLevel.HIGH: 75.0,
        SeverityLevel.MEDIUM: 45.0,
        SeverityLevel.LOW: 20.0,
    }

    EFFORT_INVERSION = {
        EffortLevel.LOW: 100.0,      # Quickest to execute -> highest priority boost
        EffortLevel.MEDIUM: 50.0,
        EffortLevel.HIGH: 20.0,
    }

    @classmethod
    def calculate_priority_score(
        cls,
        risk_score: float,
        severity: SeverityLevel,
        compliance_violation_count: int = 0,
        effort_level: EffortLevel = EffortLevel.LOW,
    ) -> float:
        """
        Calculate a continuous priority score in [0.0, 100.0].

        Formula:
            Priority = (0.45 * risk_score) +
                       (0.25 * severity_weight) +
                       (0.15 * compliance_score) +
                       (0.15 * effort_score)
        """
        clamped_risk = max(0.0, min(100.0, float(risk_score)))
        sev_weight = cls.SEVERITY_WEIGHTS.get(severity, 45.0)
        comp_score = min(100.0, compliance_violation_count * 25.0)
        effort_score = cls.EFFORT_INVERSION.get(effort_level, 50.0)

        raw_score = (
            (cls.WEIGHT_RISK_SCORE * clamped_risk)
            + (cls.WEIGHT_SEVERITY * sev_weight)
            + (cls.WEIGHT_COMPLIANCE * comp_score)
            + (cls.WEIGHT_EFFORT * effort_score)
        )

        return round(max(0.0, min(100.0, raw_score)), 2)

    @classmethod
    def is_quick_win(
        cls,
        effort_level: EffortLevel,
        estimated_risk_reduction: float,
    ) -> bool:
        """
        Determine whether a remediation qualifies as an immediate quick win
        (low effort + >= 25.0 points of risk reduction).
        """
        return effort_level == EffortLevel.LOW and estimated_risk_reduction >= 25.0
