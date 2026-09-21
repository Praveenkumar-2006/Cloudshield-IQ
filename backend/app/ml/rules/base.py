"""
CloudShield IQ — Risk Rule Base Interface
=========================================
Base classes, data models, and protocols for deterministic security heuristics.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from app.core.taxonomy import SeverityLevel
from app.schemas.events import CloudSecurityEvent


@dataclass
class RuleMatch:
    """
    Result returned when a risk rule evaluates positive on a security event.
    """

    rule_id: str
    title: str
    category: str
    penalty: float
    description: str
    mitre_technique: Optional[str] = None
    compliance_violations: list[str] = field(default_factory=list)
    remediation_guidance: str = ""
    cli_remediation_command: Optional[str] = None
    terraform_remediation_snippet: Optional[str] = None
    context: dict[str, str] = field(default_factory=dict)


class BaseRiskRule(ABC):
    """
    Abstract Base Class for all deterministic security risk assessment rules.
    """

    rule_id: str
    title: str
    description: str
    category: str  # IAM, Storage, Network, Logging, Cryptography, etc.
    base_penalty: float  # Weight score penalty (0.0 to 100.0)
    mitre_technique: Optional[str] = None
    compliance_violations: list[str] = []
    remediation_guidance: str = ""
    cli_remediation_command: Optional[str] = None
    terraform_remediation_snippet: Optional[str] = None

    @abstractmethod
    def evaluate(self, event: CloudSecurityEvent) -> Optional[RuleMatch]:
        """
        Evaluate a single canonical cloud security event.

        Args:
            event: Canonical CloudSecurityEvent object.

        Returns:
            RuleMatch if the event triggers the rule, else None.
        """
        pass
