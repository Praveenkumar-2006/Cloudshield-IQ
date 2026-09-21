"""
CloudShield IQ — Recommendation Engine Tests
============================================
Unit tests for the RecommendationEngine coordinator:
- Custom playbook registration and filtering
- Playbook matching (SHAP drivers, compliance violations, category)
- Parameter customization into automation templates
- Batch prioritization of findings
- Remediation impact simulation
- Global stats generation
"""

from datetime import datetime, timezone
import pytest

from app.core.taxonomy import ActorType, CanonicalAction, CloudProvider, OutcomeType, SeverityLevel
from app.recommendations import RecommendationEngine, get_recommendation_engine
from app.schemas.assessments import SecurityFinding
from app.schemas.events import CloudSecurityEvent
from app.schemas.recommendations import (
    EffortLevel,
    RecommendationRequest,
    RemediationPlaybook,
    RemediationSimulationRequest,
)


class TestRecommendationEngine:
    """Tests the RecommendationEngine implementation."""

    @pytest.fixture
    def engine(self) -> RecommendationEngine:
        return RecommendationEngine()

    @pytest.fixture
    def sample_finding(self) -> SecurityFinding:
        return SecurityFinding(
            finding_id="FND-AWS-ROOT-001",
            title="Root Account Activity Detected",
            cloud_provider=CloudProvider.AWS,
            resource_id="arn:aws:iam::123456789012:root",
            category="IAM",
            severity=SeverityLevel.CRITICAL,
            risk_score=92.0,
            shap_top_feature="actor_type_root",
            shap_impact=35.2,
            compliance_violations=["CIS-AWS-1.1", "NIST-AC-2"],
            remediation_guidance="Revoke root access keys immediately.",
        )

    def test_engine_initialization_and_singleton(self):
        eng = get_recommendation_engine()
        assert eng is not None
        assert len(eng.playbooks) >= 10

    def test_list_playbooks_with_filters(self, engine: RecommendationEngine):
        aws_playbooks = engine.list_playbooks(cloud_provider=CloudProvider.AWS)
        assert len(aws_playbooks) >= 4
        assert all(p.cloud_provider == CloudProvider.AWS for p in aws_playbooks)

        iam_playbooks = engine.list_playbooks(category="IAM")
        assert len(iam_playbooks) >= 3
        assert all(p.category == "IAM" for p in iam_playbooks)

        low_effort = engine.list_playbooks(effort_level=EffortLevel.LOW)
        assert len(low_effort) >= 5
        assert all(p.effort_level == EffortLevel.LOW for p in low_effort)

    def test_match_playbook_by_shap_driver(self, engine: RecommendationEngine):
        pb = engine.match_playbook(
            cloud_provider=CloudProvider.AWS,
            shap_drivers=["actor_type_root"],
        )
        assert pb.playbook_id == "PB-AWS-IAM-001"

    def test_match_playbook_by_compliance_violation(self, engine: RecommendationEngine):
        pb = engine.match_playbook(
            cloud_provider=CloudProvider.AZURE,
            compliance_violations=["CIS-AZR-3.2"],
        )
        assert pb.playbook_id == "PB-AZR-STR-001"

    def test_match_playbook_by_category_fallback(self, engine: RecommendationEngine):
        pb = engine.match_playbook(
            cloud_provider=CloudProvider.GCP,
            category="Storage",
        )
        assert pb.playbook_id == "PB-GCP-STR-001"

    def test_generate_recommendation_for_finding(
        self,
        engine: RecommendationEngine,
        sample_finding: SecurityFinding,
    ):
        req = RecommendationRequest(
            finding_id=sample_finding.finding_id,
            finding=sample_finding,
        )
        rec = engine.generate_recommendation(req)

        assert rec.finding_id == sample_finding.finding_id
        assert rec.cloud_provider == CloudProvider.AWS
        assert rec.target_resource == sample_finding.resource_id
        assert rec.priority_score > 70.0
        assert rec.original_risk_score == 92.0
        assert rec.projected_risk_score < 92.0
        assert rec.risk_reduction_points > 0
        assert rec.is_quick_win is True
        # Verify parameter injection in code snippets
        assert "arn:aws:iam::123456789012:root" in rec.playbook.terraform_snippet or "root" in rec.playbook.cli_command

    def test_generate_recommendation_for_event(self, engine: RecommendationEngine):
        event = CloudSecurityEvent(
            event_id="EVT-001",
            cloud_provider=CloudProvider.AWS,
            account_id="999888777666",
            region="us-west-2",
            raw_action="ConsoleLogin",
            canonical_action=CanonicalAction.IAM_ROLE_ASSUME,
            actor_name="root",
            actor_type=ActorType.ROOT,
            resource_id="arn:aws:iam::999888777666:root",
            resource_type="AWS::IAM::User",
            source_ip="203.0.113.1",
            timestamp=datetime.now(timezone.utc),
            outcome=OutcomeType.SUCCESS,
            has_mfa=False,
            has_session=True,
            metadata_payload={},
        )
        req = RecommendationRequest(event=event)
        rec = engine.generate_recommendation(req)

        assert rec.cloud_provider == CloudProvider.AWS
        assert rec.priority_score >= 80.0
        assert rec.original_risk_score == 90.0
        assert "actor_type_root" in rec.mitigated_shap_features

    def test_prioritize_findings(
        self,
        engine: RecommendationEngine,
        sample_finding: SecurityFinding,
    ):
        low_finding = SecurityFinding(
            finding_id="FND-GCP-LOW-002",
            title="Non-compliant Label",
            cloud_provider=CloudProvider.GCP,
            resource_id="projects/p1/buckets/b1",
            category="Storage",
            severity=SeverityLevel.LOW,
            risk_score=15.0,
            compliance_violations=[],
            remediation_guidance="Add missing tag.",
        )
        batch_resp = engine.prioritize_findings([low_finding, sample_finding])

        assert batch_resp.total_findings == 2
        assert batch_resp.recommendations[0].finding_id == sample_finding.finding_id
        assert batch_resp.recommendations[0].priority_rank == 1
        assert batch_resp.recommendations[1].finding_id == low_finding.finding_id
        assert batch_resp.recommendations[1].priority_rank == 2
        assert batch_resp.total_potential_risk_reduction > 0

    def test_simulate_remediation(
        self,
        engine: RecommendationEngine,
        sample_finding: SecurityFinding,
    ):
        req = RemediationSimulationRequest(
            finding_ids_to_remediate=[sample_finding.finding_id],
            current_findings=[sample_finding],
        )
        sim = engine.simulate_remediation(req)

        assert sim.findings_remediated_count == 1
        assert sim.original_average_risk == 92.0
        assert sim.projected_average_risk < sim.original_average_risk
        assert sim.overall_risk_reduction_pct > 0.0
        assert sim.remaining_critical_count == 0

    def test_get_stats(self, engine: RecommendationEngine):
        stats = engine.get_stats()
        assert stats.total_playbooks >= 10
        assert "aws" in stats.playbooks_by_provider
        assert "azure" in stats.playbooks_by_provider
        assert "gcp" in stats.playbooks_by_provider
        assert stats.average_risk_reduction_points > 0.0
        assert len(stats.covered_compliance_controls) > 0
        assert len(stats.mitigated_shap_features) > 0
