"""
CloudShield IQ — Deterministic Risk Rules Package
=================================================
Exports base classes, rule catalogs, and the risk engine.
"""

from app.ml.rules.base import BaseRiskRule, RuleMatch
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
from app.ml.rules.engine import RuleAssessmentResult, RuleBasedRiskEngine

__all__ = [
    "BaseRiskRule",
    "RuleMatch",
    "RootActivityRule",
    "PrivilegeEscalationNoMfaRule",
    "LoggingTamperingRule",
    "KmsDestructionRule",
    "PublicStorageExposureRule",
    "NetworkSecurityTamperingRule",
    "DeniedPrivilegedActionRule",
    "get_default_rules",
    "RuleBasedRiskEngine",
    "RuleAssessmentResult",
]
