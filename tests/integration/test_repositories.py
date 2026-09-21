"""
Integration & Unit Tests — Async Database Repositories
======================================================
Tests verifying CRUD queries, filters, and schema converters across all Phase 11 repositories:
- BaseRepository
- EventRepository
- FindingRepository
- AssessmentRepository
- ComplianceRepository
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
import pytest

from app.core.taxonomy import (
    ActorType,
    CanonicalAction,
    CloudProvider,
    OutcomeType,
    SeverityLevel,
)
from app.models.assessments import (
    ComplianceResultModel,
    RiskAssessmentModel,
    SecurityFindingModel,
)
from app.models.events import SecurityEventModel
from app.repositories.assessments import AssessmentRepository
from app.repositories.base import BaseRepository
from app.repositories.compliance import ComplianceRepository
from app.repositories.events import EventRepository
from app.repositories.findings import FindingRepository
from app.schemas.assessments import RiskAssessment, SecurityFinding
from app.schemas.compliance import (
    ComplianceControlResult,
    ComplianceFramework,
    ComplianceStatus,
)
from app.schemas.events import CloudSecurityEvent


def make_mock_session() -> AsyncMock:
    """Create an AsyncSession mock with sync .add/.add_all and async execute/flush."""
    session = AsyncMock()
    session.add = MagicMock()
    session.add_all = MagicMock()
    return session


class TestBaseRepository:
    """Tests for the generic async BaseRepository."""

    @pytest.mark.asyncio
    async def test_create(self):
        mock_session = make_mock_session()
        repo = BaseRepository[SecurityEventModel](SecurityEventModel, mock_session)
        model = SecurityEventModel(event_id="ev-base-1")

        created = await repo.create(model)
        mock_session.add.assert_called_once_with(model)
        mock_session.flush.assert_awaited_once()
        assert created.event_id == "ev-base-1"

    @pytest.mark.asyncio
    async def test_get_by_id(self):
        mock_session = make_mock_session()
        expected = SecurityEventModel(event_id="ev-base-found")
        mock_session.get.return_value = expected

        repo = BaseRepository[SecurityEventModel](SecurityEventModel, mock_session)
        found = await repo.get_by_id("ev-base-found")

        mock_session.get.assert_awaited_once_with(SecurityEventModel, "ev-base-found")
        assert found == expected

    @pytest.mark.asyncio
    async def test_list(self):
        mock_session = make_mock_session()
        mock_result = MagicMock()
        expected = [SecurityEventModel(event_id="ev-1"), SecurityEventModel(event_id="ev-2")]
        mock_result.scalars.return_value.all.return_value = expected
        mock_session.execute.return_value = mock_result

        repo = BaseRepository[SecurityEventModel](SecurityEventModel, mock_session)
        items = await repo.list(offset=0, limit=10)

        assert len(items) == 2
        assert items[0].event_id == "ev-1"

    @pytest.mark.asyncio
    async def test_delete(self):
        mock_session = make_mock_session()
        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_session.execute.return_value = mock_result

        repo = BaseRepository[SecurityEventModel](SecurityEventModel, mock_session)
        deleted = await repo.delete("ev-del")

        mock_session.execute.assert_awaited_once()
        mock_session.flush.assert_awaited_once()
        assert deleted is True


class TestEventRepository:
    """Tests for EventRepository converting schemas and querying events."""

    @pytest.mark.asyncio
    async def test_create_from_schema(self):
        mock_session = make_mock_session()
        repo = EventRepository(mock_session)

        event = CloudSecurityEvent(
            event_id="ev-schema-1",
            timestamp=datetime.now(timezone.utc),
            cloud_provider=CloudProvider.AWS,
            event_source="aws.s3",
            resource_type="AWS::S3::Bucket",
            resource_id="arn:aws:s3:::test-bucket",
            raw_action="PutBucketAcl",
            canonical_action=CanonicalAction.STORAGE_ACL_MODIFY,
            actor_type=ActorType.USER,
            actor_name="alice",
            has_session=True,
            outcome=OutcomeType.SUCCESS,
        )

        created = await repo.create_from_schema(event)
        mock_session.add.assert_called_once()
        assert created.event_id == "ev-schema-1"
        assert created.cloud_provider == "aws"
        assert created.raw_action == "PutBucketAcl"

    @pytest.mark.asyncio
    async def test_create_batch_from_schemas(self):
        mock_session = make_mock_session()
        repo = EventRepository(mock_session)

        events = [
            CloudSecurityEvent(
                event_id=f"ev-batch-{i}",
                timestamp=datetime.now(timezone.utc),
                cloud_provider=CloudProvider.AWS,
                event_source="aws.iam",
                resource_type="AWS::IAM::User",
                resource_id=f"arn:aws:iam::user/user-{i}",
                raw_action="CreateUser",
                canonical_action=CanonicalAction.IAM_USER_CREATE,
                actor_type=ActorType.USER,
                actor_name="admin",
                has_session=False,
                outcome=OutcomeType.SUCCESS,
            )
            for i in range(3)
        ]

        count = await repo.create_batch_from_schemas(events)
        assert count == 3
        mock_session.add_all.assert_called_once()
        mock_session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_create_batch_empty(self):
        mock_session = make_mock_session()
        repo = EventRepository(mock_session)
        assert await repo.create_batch_from_schemas([]) == 0

    @pytest.mark.asyncio
    async def test_list_events_with_filters(self):
        mock_session = make_mock_session()
        count_result = MagicMock()
        count_result.scalar.return_value = 1
        items_result = MagicMock()
        items_result.scalars.return_value.all.return_value = [
            SecurityEventModel(event_id="ev-filtered-1", cloud_provider="aws")
        ]
        mock_session.execute.side_effect = [count_result, items_result]

        repo = EventRepository(mock_session)
        items, total = await repo.list_events(
            cloud_provider="aws",
            actor_type="user",
            outcome="Success",
            offset=0,
            limit=50,
        )

        assert total == 1
        assert len(items) == 1
        assert items[0].event_id == "ev-filtered-1"


class TestFindingRepository:
    """Tests for FindingRepository and triage state updates."""

    @pytest.mark.asyncio
    async def test_create_finding_from_schema(self):
        mock_session = make_mock_session()
        repo = FindingRepository(mock_session)

        finding = SecurityFinding(
            finding_id="FND-TEST-001",
            title="Root User API Keys In Use",
            cloud_provider=CloudProvider.AWS,
            resource_id="arn:aws:iam::root",
            category="IAM",
            severity=SeverityLevel.CRITICAL,
            risk_score=94.5,
            shap_top_feature="iam_root_access_key",
            shap_impact=0.45,
            compliance_violations=["CIS AWS 1.1"],
            remediation_guidance="Revoke root user keys immediately.",
        )

        created = await repo.create_finding(finding)
        mock_session.add.assert_called_once()
        assert created.finding_id == "FND-TEST-001"
        assert created.severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_update_status_to_resolved(self):
        mock_session = make_mock_session()
        existing = SecurityFindingModel(
            finding_id="FND-UPDATE-1",
            status="OPEN",
            severity="HIGH",
        )
        mock_session.get.return_value = existing

        repo = FindingRepository(mock_session)
        updated = await repo.update_status("FND-UPDATE-1", "RESOLVED")

        assert updated is not None
        assert updated.status == "RESOLVED"
        assert updated.resolved_at is not None
        mock_session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_status_not_found(self):
        mock_session = make_mock_session()
        mock_session.get.return_value = None

        repo = FindingRepository(mock_session)
        updated = await repo.update_status("FND-NONEXISTENT", "RESOLVED")
        assert updated is None

    @pytest.mark.asyncio
    async def test_get_severity_summary(self):
        mock_session = make_mock_session()
        mock_result = MagicMock()
        mock_result.all.return_value = [("CRITICAL", 3), ("HIGH", 7), ("MEDIUM", 12)]
        mock_session.execute.return_value = mock_result

        repo = FindingRepository(mock_session)
        summary = await repo.get_severity_summary()

        assert summary["CRITICAL"] == 3
        assert summary["HIGH"] == 7
        assert summary["MEDIUM"] == 12
        assert summary["LOW"] == 0


class TestAssessmentRepository:
    """Tests for AssessmentRepository."""

    @pytest.mark.asyncio
    async def test_save_assessment(self):
        mock_session = make_mock_session()
        repo = AssessmentRepository(mock_session)

        assessment = RiskAssessment(
            event_id="ev-ass-1",
            risk_score=88.5,
            anomaly_score=0.82,
            severity=SeverityLevel.HIGH,
            is_anomaly=True,
            cloud_provider=CloudProvider.AWS,
        )

        created = await repo.save_assessment(assessment)
        mock_session.add.assert_called_once()
        assert created.event_id == "ev-ass-1"
        assert created.risk_score == 88.5
        assert created.is_anomaly is True

    @pytest.mark.asyncio
    async def test_list_assessments(self):
        mock_session = make_mock_session()
        count_res = MagicMock()
        count_res.scalar.return_value = 2
        items_res = MagicMock()
        items_res.scalars.return_value.all.return_value = [
            RiskAssessmentModel(assessment_id="a-1", cloud_provider="aws"),
            RiskAssessmentModel(assessment_id="a-2", cloud_provider="aws"),
        ]
        mock_session.execute.side_effect = [count_res, items_res]

        repo = AssessmentRepository(mock_session)
        items, total = await repo.list_assessments(cloud_provider="AWS", is_anomaly=True)
        assert total == 2
        assert len(items) == 2

    @pytest.mark.asyncio
    async def test_get_risk_score_summary(self):
        mock_session = make_mock_session()
        avg_res = MagicMock()
        avg_res.first.return_value = (72.5, 96.0, 150)
        anomaly_res = MagicMock()
        anomaly_res.scalar.return_value = 14
        mock_session.execute.side_effect = [avg_res, anomaly_res]

        repo = AssessmentRepository(mock_session)
        summary = await repo.get_risk_score_summary()

        assert summary["average_risk_score"] == 72.5
        assert summary["max_risk_score"] == 96.0
        assert summary["total_assessed"] == 150
        assert summary["anomalies_detected"] == 14


class TestComplianceRepository:
    """Tests for ComplianceRepository saving control evaluations and summaries."""

    @pytest.mark.asyncio
    async def test_save_control_evaluation(self):
        mock_session = make_mock_session()
        repo = ComplianceRepository(mock_session)

        ctrl = ComplianceControlResult(
            control_id="CIS-AWS-1.1",
            control_name="Avoid the use of the root account",
            framework=ComplianceFramework.CIS_AWS_1_4,
            status=ComplianceStatus.FAIL,
            cloud_provider=CloudProvider.AWS,
            severity=SeverityLevel.CRITICAL,
        )

        saved = await repo.save_control_evaluation(ctrl, event_id="ev-cis-1")
        mock_session.add.assert_called_once()
        assert saved.control_id == "CIS-AWS-1.1"
        assert saved.framework == "CIS AWS 1.4"
        assert saved.status == "FAIL"

    @pytest.mark.asyncio
    async def test_list_results(self):
        mock_session = make_mock_session()
        count_res = MagicMock()
        count_res.scalar.return_value = 1
        items_res = MagicMock()
        items_res.scalars.return_value.all.return_value = [
            ComplianceResultModel(result_id="res-1", framework="CIS AWS 1.4")
        ]
        mock_session.execute.side_effect = [count_res, items_res]

        repo = ComplianceRepository(mock_session)
        items, total = await repo.list_results(framework="CIS AWS 1.4", status="FAIL")
        assert total == 1
        assert len(items) == 1

    @pytest.mark.asyncio
    async def test_get_framework_summary(self):
        mock_session = make_mock_session()
        group_res = MagicMock()
        group_res.all.return_value = [
            ("CIS AWS 1.4", "PASS", 8),
            ("CIS AWS 1.4", "FAIL", 2),
        ]
        mock_session.execute.return_value = group_res

        repo = ComplianceRepository(mock_session)
        summaries = await repo.get_framework_summary()

        assert len(summaries) == 1
        assert summaries[0]["framework"] == "CIS AWS 1.4"
        assert summaries[0]["passing_controls"] == 8
        assert summaries[0]["total_controls"] == 10
        assert summaries[0]["pass_rate_percent"] == 80.0
