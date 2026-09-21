"""
CloudShield IQ — Deterministic Compliance Engine
=================================================
Evaluates multi-cloud security telemetry and asset configurations against
cybersecurity benchmarks and computes quantitative compliance posture summaries.
"""

from datetime import datetime, timezone
from typing import Any, Optional

from app.compliance.controls.base import BaseComplianceControl
from app.compliance.controls.catalog import (
    CisAwsCloudTrailEnabledControl,
    CisAwsMfaConsoleControl,
    CisAwsRootAccountControl,
    CisAwsS3PublicReadControl,
    CisAzureMfaPrivilegedControl,
    CisAzureSshRestrictedControl,
    CisAzureStorageNetworkAccessControl,
    CisGcpCorporateCredentialsControl,
    CisGcpKmsKeyAccessControl,
    CisGcpStorageUniformAccessControl,
    IsoA942SecureLogonControl,
    IsoA124AuditLoggingControl,
    NistAc2AccountManagementControl,
    NistAu2EventLoggingControl,
    NistSc28ProtectionAtRestControl,
    PciDss34CardholderDataProtectionControl,
    PciDss83MultiFactorAuthControl,
)
from app.core.taxonomy import CloudProvider
from app.schemas.compliance import (
    ComplianceControlResult,
    ComplianceFramework,
    ComplianceStatus,
    ComplianceSummary,
)
from app.schemas.events import CloudSecurityEvent


class ComplianceEngine:
    """
    Coordinator engine for multi-cloud compliance posture evaluation.
    """

    def __init__(self, controls: Optional[list[BaseComplianceControl]] = None) -> None:
        self._controls: dict[str, BaseComplianceControl] = {}

        # Register default standard catalog if not provided
        initial_controls = controls or [
            CisAwsRootAccountControl(),
            CisAwsMfaConsoleControl(),
            CisAwsS3PublicReadControl(),
            CisAwsCloudTrailEnabledControl(),
            CisAzureMfaPrivilegedControl(),
            CisAzureStorageNetworkAccessControl(),
            CisAzureSshRestrictedControl(),
            CisGcpCorporateCredentialsControl(),
            CisGcpKmsKeyAccessControl(),
            CisGcpStorageUniformAccessControl(),
            NistAc2AccountManagementControl(),
            NistAu2EventLoggingControl(),
            NistSc28ProtectionAtRestControl(),
            IsoA942SecureLogonControl(),
            IsoA124AuditLoggingControl(),
            PciDss34CardholderDataProtectionControl(),
            PciDss83MultiFactorAuthControl(),
        ]
        for ctrl in initial_controls:
            self.register_control(ctrl)

    def register_control(self, control: BaseComplianceControl) -> None:
        """Register a compliance control into the active catalog."""
        self._controls[control.control_id] = control

    def get_control(self, control_id: str) -> Optional[BaseComplianceControl]:
        """Retrieve a specific registered control by its ID."""
        return self._controls.get(control_id)

    def list_controls(
        self,
        framework: Optional[ComplianceFramework] = None,
        cloud_provider: Optional[CloudProvider] = None,
    ) -> list[BaseComplianceControl]:
        """
        List registered controls, with optional filtering by framework and/or provider.
        """
        controls = list(self._controls.values())
        if framework:
            controls = [c for c in controls if c.framework == framework]
        if cloud_provider:
            controls = [c for c in controls if c.cloud_provider == cloud_provider]
        return controls

    def list_frameworks(self) -> list[dict[str, Any]]:
        """
        Return structured metadata for all supported compliance benchmarks.
        """
        frameworks_meta = []
        for fw in ComplianceFramework:
            fw_controls = [c for c in self._controls.values() if c.framework == fw]
            frameworks_meta.append({
                "framework_name": fw.value,
                "framework_id": fw.name,
                "total_controls": len(fw_controls),
                "supported_providers": list({c.cloud_provider.value for c in fw_controls}),
                "control_ids": [c.control_id for c in fw_controls],
            })
        return frameworks_meta

    def evaluate(
        self,
        events: list[CloudSecurityEvent],
        resources: Optional[list[dict[str, Any]]] = None,
        framework: Optional[ComplianceFramework] = None,
        cloud_provider: Optional[CloudProvider] = None,
    ) -> list[ComplianceControlResult]:
        """
        Execute deterministic evaluation across registered controls.

        Args:
            events: Normalized telemetry security events.
            resources: Optional cloud asset configuration dictionaries.
            framework: Optional filter to evaluate a single framework.
            cloud_provider: Optional filter to evaluate a single cloud provider.

        Returns:
            List of ComplianceControlResult evaluation records.
        """
        active_controls = self.list_controls(framework=framework, cloud_provider=cloud_provider)
        results: list[ComplianceControlResult] = []

        for ctrl in active_controls:
            result = ctrl.evaluate(events=events, resources=resources)
            results.append(result)

        return results

    def calculate_summary(
        self,
        results: list[ComplianceControlResult],
    ) -> ComplianceSummary:
        """
        Calculate an aggregated compliance posture summary with framework breakdowns.

        Args:
            results: List of control evaluation results.

        Returns:
            ComplianceSummary containing overall pass rate, counts, and per-framework scores.
        """
        total = len(results)
        if total == 0:
            return ComplianceSummary(
                overall_pass_rate=100.0,
                total_controls=0,
                passed_controls=0,
                failed_controls=0,
                partial_controls=0,
                framework_scores={},
                evaluated_at=datetime.now(timezone.utc),
            )

        passed = sum(1 for r in results if r.status == ComplianceStatus.PASS)
        failed = sum(1 for r in results if r.status == ComplianceStatus.FAIL)
        partial = sum(1 for r in results if r.status == ComplianceStatus.PARTIAL)

        # Calculate overall pass rate: PASS gives 1.0, PARTIAL gives 0.5 weight
        weighted_score = (passed * 1.0 + partial * 0.5) / total * 100.0
        overall_pass_rate = round(weighted_score, 1)

        # Per-framework scores
        framework_scores: dict[str, float] = {}
        for fw in ComplianceFramework:
            fw_results = [r for r in results if r.framework == fw]
            if fw_results:
                fw_passed = sum(1 for r in fw_results if r.status == ComplianceStatus.PASS)
                fw_partial = sum(1 for r in fw_results if r.status == ComplianceStatus.PARTIAL)
                fw_score = round((fw_passed * 1.0 + fw_partial * 0.5) / len(fw_results) * 100.0, 1)
                framework_scores[fw.value] = fw_score

        return ComplianceSummary(
            overall_pass_rate=overall_pass_rate,
            total_controls=total,
            passed_controls=passed,
            failed_controls=failed,
            partial_controls=partial,
            framework_scores=framework_scores,
            evaluated_at=datetime.now(timezone.utc),
        )

    def export_audit_report(
        self,
        results: list[ComplianceControlResult],
    ) -> dict[str, Any]:
        """
        Synthesize a formal compliance audit report artifact.

        Args:
            results: List of control evaluation outcomes.

        Returns:
            JSON-serializable audit report dictionary with summary and control details.
        """
        summary = self.calculate_summary(results)
        return {
            "report_title": "CloudShield IQ Multi-Cloud Compliance Audit Report",
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "overall_pass_rate_percent": summary.overall_pass_rate,
                "total_controls_evaluated": summary.total_controls,
                "passed_controls": summary.passed_controls,
                "failed_controls": summary.failed_controls,
                "partial_controls": summary.partial_controls,
                "framework_scores": summary.framework_scores,
            },
            "control_evaluations": [r.model_dump(mode="json") for r in results],
        }


# Singleton factory helper
_default_engine: Optional[ComplianceEngine] = None


def get_compliance_engine() -> ComplianceEngine:
    """Return the application-wide singleton ComplianceEngine instance."""
    global _default_engine
    if _default_engine is None:
        _default_engine = ComplianceEngine()
    return _default_engine
