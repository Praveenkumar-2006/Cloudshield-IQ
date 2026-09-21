"""
CloudShield IQ — Risk Assessment Repository
===========================================
Data access layer for ML anomaly predictions, continuous risk scores, and TreeSHAP weights.
"""

from datetime import datetime, timezone
from typing import Any, Optional, Sequence
import uuid
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.assessments import RiskAssessmentModel
from app.repositories.base import BaseRepository
from app.schemas.assessments import RiskAssessment


class AssessmentRepository(BaseRepository[RiskAssessmentModel]):
    """Repository managing machine learning risk assessment and explainability records."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(RiskAssessmentModel, session)

    async def save_assessment(self, assessment: RiskAssessment) -> RiskAssessmentModel:
        """Convert a RiskAssessment schema into a persistent ORM model and save it."""
        model = RiskAssessmentModel(
            assessment_id=getattr(assessment, "assessment_id", None) or str(uuid.uuid4()),
            event_id=assessment.event_id,
            resource_id=getattr(assessment, "resource_id", None),
            cloud_provider=assessment.cloud_provider.value if hasattr(assessment.cloud_provider, "value") else str(assessment.cloud_provider),
            risk_score=assessment.risk_score,
            anomaly_score=assessment.anomaly_score,
            is_anomaly=assessment.is_anomaly,
            severity=assessment.severity.value if hasattr(assessment.severity, "value") else str(assessment.severity),
            shap_values=getattr(assessment, "shap_values", {}),
            top_feature=getattr(assessment, "top_feature", None),
            top_feature_impact=getattr(assessment, "top_feature_impact", None),
            model_version=getattr(assessment, "model_version", "v0.1.0"),
            evaluated_at=datetime.now(timezone.utc),
        )
        return await self.create(model)

    async def get_by_event_id(self, event_id: str) -> Optional[RiskAssessmentModel]:
        """Fetch the risk assessment corresponding to a specific security event."""
        stmt = select(RiskAssessmentModel).where(RiskAssessmentModel.event_id == event_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_assessments(
        self,
        cloud_provider: Optional[str] = None,
        is_anomaly: Optional[bool] = None,
        severity: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[RiskAssessmentModel], int]:
        """Query ML risk assessments with anomaly and provider filters."""
        stmt = select(RiskAssessmentModel)
        count_stmt = select(func.count()).select_from(RiskAssessmentModel)

        if cloud_provider and cloud_provider.upper() != "ALL":
            stmt = stmt.where(RiskAssessmentModel.cloud_provider == cloud_provider.lower())
            count_stmt = count_stmt.where(RiskAssessmentModel.cloud_provider == cloud_provider.lower())

        if is_anomaly is not None:
            stmt = stmt.where(RiskAssessmentModel.is_anomaly == is_anomaly)
            count_stmt = count_stmt.where(RiskAssessmentModel.is_anomaly == is_anomaly)

        if severity and severity.upper() != "ALL":
            stmt = stmt.where(RiskAssessmentModel.severity == severity.upper())
            count_stmt = count_stmt.where(RiskAssessmentModel.severity == severity.upper())

        total_res = await self.session.execute(count_stmt)
        total = total_res.scalar() or 0

        stmt = stmt.order_by(RiskAssessmentModel.evaluated_at.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all(), total

    async def get_risk_score_summary(self) -> dict[str, Any]:
        """Calculate composite and average risk metrics across all assessed assets."""
        stmt = select(
            func.avg(RiskAssessmentModel.risk_score),
            func.max(RiskAssessmentModel.risk_score),
            func.count(RiskAssessmentModel.assessment_id),
        )
        res = await self.session.execute(stmt)
        avg_score, max_score, total = res.first() or (0.0, 0.0, 0)

        anomaly_count_stmt = select(func.count()).where(RiskAssessmentModel.is_anomaly == True)
        anomaly_res = await self.session.execute(anomaly_count_stmt)
        anomalies = anomaly_res.scalar() or 0

        return {
            "average_risk_score": round(float(avg_score or 0.0), 1),
            "max_risk_score": round(float(max_score or 0.0), 1),
            "total_assessed": total or 0,
            "anomalies_detected": anomalies,
        }
