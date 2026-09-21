"""
CloudShield IQ — Base Compliance Control
=========================================
Abstract base class for all deterministic multi-cloud compliance rules and benchmarks.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional
import uuid

from app.core.taxonomy import CloudProvider, SeverityLevel
from app.schemas.compliance import (
    ComplianceControlResult,
    ComplianceFramework,
    ComplianceStatus,
)
from app.schemas.events import CloudSecurityEvent


class BaseComplianceControl(ABC):
    """
    Abstract Base Class representing a specific compliance benchmark requirement.

    Compliance controls evaluate telemetry and resource configurations deterministically
    against established cybersecurity standards (CIS, NIST, ISO, PCI-DSS).
    """

    control_id: str
    control_name: str
    framework: ComplianceFramework
    cloud_provider: CloudProvider
    severity: SeverityLevel
    description: str
    remediation_guidance: str = ""
    cli_command: Optional[str] = None
    terraform_snippet: Optional[str] = None

    @abstractmethod
    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
    ) -> ComplianceControlResult:
        """
        Deterministically evaluate compliance for a batch of events or resources.

        Args:
            events: Normalized CloudSecurityEvent telemetry instances.
            resources: Optional cloud resource inventory configuration dictionaries.

        Returns:
            ComplianceControlResult detailing PASS, FAIL, or PARTIAL status.
        """
        pass

    def create_result(
        self,
        status: ComplianceStatus,
        evaluated_resources: int,
        failed_resources: int,
        failed_resource_ids: Optional[list[str]] = None,
    ) -> ComplianceControlResult:
        """
        Helper method to construct a standard ComplianceControlResult.
        """
        sanitized_ids = [str(r) for r in failed_resource_ids if r is not None and str(r).strip()] if failed_resource_ids else []
        return ComplianceControlResult(
            result_id=str(uuid.uuid4()),
            control_id=self.control_id,
            control_name=self.control_name,
            framework=self.framework,
            cloud_provider=self.cloud_provider,
            status=status,
            severity=self.severity,
            evaluated_resources=evaluated_resources,
            failed_resources=failed_resources,
            failed_resource_ids=sanitized_ids,
            evaluated_at=datetime.now(timezone.utc),
        )
