"""
Unit Tests — Compliance Engine & Coordinator
=============================================
Tests control registration, multi-framework evaluation, pass rate calculation,
and formal audit report generation.
"""

from datetime import datetime, timezone

from app.compliance import ComplianceEngine, get_compliance_engine
from app.core.taxonomy import ActorType, CanonicalAction, CloudProvider, OutcomeType
from app.schemas.compliance import ComplianceFramework
from app.schemas.events import CloudSecurityEvent


def make_test_event(
    provider: CloudProvider = CloudProvider.AWS,
    actor_type: ActorType = ActorType.USER,
    mfa_used: bool = True,
    action: CanonicalAction = CanonicalAction.COMPUTE_INSTANCE_LAUNCH,
) -> CloudSecurityEvent:
    return CloudSecurityEvent(
        event_id="evt-engine-test-1",
        timestamp=datetime.now(timezone.utc),
        cloud_provider=provider,
        resource_type="compute:Instance",
        resource_id="res-101",
        canonical_action=action,
        raw_action="RunInstances",
        actor_type=actor_type,
        actor_name="test_operator",
        source_ip="192.168.1.10",
        mfa_used=mfa_used,
        outcome=OutcomeType.SUCCESS,
        session_duration_s=1800,
        has_session=True,
        metadata_payload={},
    )


class TestComplianceEngine:
    def test_engine_initialization(self):
        engine = ComplianceEngine()
        controls = engine.list_controls()
        assert len(controls) >= 15

    def test_singleton_get_compliance_engine(self):
        e1 = get_compliance_engine()
        e2 = get_compliance_engine()
        assert e1 is e2

    def test_list_frameworks(self):
        engine = ComplianceEngine()
        fws = engine.list_frameworks()
        assert len(fws) == len(ComplianceFramework)
        names = [f["framework_name"] for f in fws]
        assert "CIS AWS 1.4" in names
        assert "NIST 800-53" in names
        assert "PCI-DSS 4.0" in names

    def test_filter_controls(self):
        engine = ComplianceEngine()
        aws_controls = engine.list_controls(cloud_provider=CloudProvider.AWS)
        assert len(aws_controls) > 0
        assert all(c.cloud_provider == CloudProvider.AWS for c in aws_controls)

        cis_controls = engine.list_controls(framework=ComplianceFramework.CIS_AWS_1_4)
        assert len(cis_controls) == 4

    def test_evaluate_clean_events(self):
        engine = ComplianceEngine()
        clean_event = make_test_event(mfa_used=True, actor_type=ActorType.USER)
        results = engine.evaluate(events=[clean_event])
        assert len(results) >= 15

        summary = engine.calculate_summary(results)
        assert summary.total_controls == len(results)
        assert summary.overall_pass_rate >= 80.0
        assert summary.passed_controls > 0

    def test_evaluate_framework_filtered(self):
        engine = ComplianceEngine()
        clean_event = make_test_event()
        results = engine.evaluate(events=[clean_event], framework=ComplianceFramework.CIS_AWS_1_4)
        assert len(results) == 4
        assert all(r.framework == ComplianceFramework.CIS_AWS_1_4 for r in results)

    def test_calculate_summary_empty(self):
        engine = ComplianceEngine()
        summary = engine.calculate_summary([])
        assert summary.total_controls == 0
        assert summary.overall_pass_rate == 100.0

    def test_export_audit_report(self):
        engine = ComplianceEngine()
        clean_event = make_test_event()
        results = engine.evaluate(events=[clean_event])
        report = engine.export_audit_report(results)

        assert "report_title" in report
        assert "generated_at" in report
        assert "summary" in report
        assert "control_evaluations" in report
        assert report["summary"]["total_controls_evaluated"] == len(results)
        assert len(report["control_evaluations"]) == len(results)
