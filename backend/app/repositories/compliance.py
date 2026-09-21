"""
CloudShield IQ — Compliance Result Repository
=============================================
Data access layer for deterministic compliance control checks and audit evaluation histories.
"""

from datetime import datetime, timezone
from typing import Any, Optional, Sequence
import uuid
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.assessments import ComplianceResultModel
from app.repositories.base import BaseRepository
from app.schemas.compliance import ComplianceControlResult


class ComplianceRepository(BaseRepository[ComplianceResultModel]):
    """Repository managing compliance benchmark outcomes and pass rates."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(ComplianceResultModel, session)

    async def save_control_evaluation(
        self,
        result: ComplianceControlResult,
        event_id: Optional[str] = None,
    ) -> ComplianceResultModel:
        """Convert a ComplianceControlResult into an ORM model and persist it."""
        model = ComplianceResultModel(
            result_id=str(uuid.uuid4()),
            control_id=result.control_id,
            control_name=getattr(result, "control_name", None) or getattr(result, "title", "Compliance Control"),
            framework=result.framework.value if hasattr(result.framework, "value") else str(result.framework),
            cloud_provider=result.cloud_provider.value if hasattr(result.cloud_provider, "value") else str(result.cloud_provider),
            status=result.status.value if hasattr(result.status, "value") else str(result.status),
            severity=result.severity.value if hasattr(result.severity, "value") else str(result.severity),
            evaluated_resources=getattr(result, "evaluated_resources", 1),
            failed_resources=getattr(result, "failed_resources", 1 if (hasattr(result.status, "value") and result.status.value == "FAIL") or str(result.status) == "FAIL" else 0),
            failed_resource_ids=getattr(result, "failed_resource_ids", []),
            evaluated_at=datetime.now(timezone.utc),
        )
        return await self.create(model)

    async def list_results(
        self,
        framework: Optional[str] = None,
        cloud_provider: Optional[str] = None,
        status: Optional[str] = None,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[Sequence[ComplianceResultModel], int]:
        """Query compliance control evaluation results."""
        stmt = select(ComplianceResultModel)
        count_stmt = select(func.count()).select_from(ComplianceResultModel)

        if framework and framework.upper() != "ALL":
            stmt = stmt.where(ComplianceResultModel.framework == framework)
            count_stmt = count_stmt.where(ComplianceResultModel.framework == framework)

        if cloud_provider and cloud_provider.upper() != "ALL":
            stmt = stmt.where(ComplianceResultModel.cloud_provider == cloud_provider.lower())
            count_stmt = count_stmt.where(ComplianceResultModel.cloud_provider == cloud_provider.lower())

        if status and status.upper() != "ALL":
            stmt = stmt.where(ComplianceResultModel.status == status.upper())
            count_stmt = count_stmt.where(ComplianceResultModel.status == status.upper())

        total_res = await self.session.execute(count_stmt)
        total = total_res.scalar() or 0

        stmt = stmt.order_by(ComplianceResultModel.evaluated_at.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all(), total

    async def get_framework_summary(self) -> list[dict[str, Any]]:
        """Calculate pass rates and evaluated controls for each compliance framework."""
        stmt = (
            select(
                ComplianceResultModel.framework,
                ComplianceResultModel.status,
                func.count(ComplianceResultModel.result_id),
            )
            .group_by(ComplianceResultModel.framework, ComplianceResultModel.status)
        )
        res = await self.session.execute(stmt)

        framework_data: dict[str, dict[str, int]] = {}
        for fw, st, count in res.all():
            if fw not in framework_data:
                framework_data[fw] = {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "TOTAL": 0}
            framework_data[fw][st] = framework_data[fw].get(st, 0) + count
            framework_data[fw]["TOTAL"] += count

        summaries = []
        for fw, counts in framework_data.items():
            total = counts["TOTAL"]
            pass_rate = round((counts["PASS"] / total) * 100, 1) if total > 0 else 0.0
            summaries.append({
                "framework": fw,
                "passing_controls": counts["PASS"],
                "total_controls": total,
                "pass_rate_percent": pass_rate,
                "failing_controls": counts["FAIL"],
                "partial_controls": counts["PARTIAL"],
            })

        return summaries
