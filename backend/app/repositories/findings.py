"""
CloudShield IQ — Security Finding Repository
============================================
Data access layer for actionable security findings and lifecycle triage management.
"""

from datetime import datetime, timezone
from typing import Any, Optional, Sequence
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.assessments import SecurityFindingModel
from app.repositories.base import BaseRepository
from app.schemas.assessments import SecurityFinding


class FindingRepository(BaseRepository[SecurityFindingModel]):
    """Repository managing actionable security findings and remediation records."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SecurityFindingModel, session)

    async def create_finding(
        self,
        finding: SecurityFinding,
    ) -> SecurityFindingModel:
        """Convert a validated SecurityFinding schema into a persistent ORM model and save it."""
        model = SecurityFindingModel(
            finding_id=finding.finding_id,
            title=finding.title,
            cloud_provider=finding.cloud_provider.value if hasattr(finding.cloud_provider, "value") else str(finding.cloud_provider),
            resource_id=finding.resource_id,
            category=finding.category,
            severity=finding.severity.value.upper() if hasattr(finding.severity, "value") else str(finding.severity).upper(),
            risk_score=finding.risk_score,
            shap_top_feature=finding.shap_top_feature,
            shap_impact=finding.shap_impact,
            compliance_violations=finding.compliance_violations,
            remediation_guidance=finding.remediation_guidance,
            cli_remediation_command=finding.cli_remediation_command,
            terraform_remediation_snippet=finding.terraform_remediation_snippet,
            status="OPEN",
            detected_at=datetime.now(timezone.utc),
        )
        return await self.create(model)

    async def list_findings(
        self,
        cloud_provider: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        search_query: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[SecurityFindingModel], int]:
        """Query findings with multi-cloud filters, severity, and search matching."""
        stmt = select(SecurityFindingModel)
        count_stmt = select(func.count()).select_from(SecurityFindingModel)

        if cloud_provider and cloud_provider.upper() != "ALL":
            stmt = stmt.where(SecurityFindingModel.cloud_provider.ilike(cloud_provider))
            count_stmt = count_stmt.where(SecurityFindingModel.cloud_provider.ilike(cloud_provider))

        if severity and severity.upper() != "ALL":
            stmt = stmt.where(SecurityFindingModel.severity == severity.upper())
            count_stmt = count_stmt.where(SecurityFindingModel.severity == severity.upper())

        if category and category.upper() != "ALL":
            stmt = stmt.where(SecurityFindingModel.category == category)
            count_stmt = count_stmt.where(SecurityFindingModel.category == category)

        if status and status.upper() != "ALL":
            stmt = stmt.where(SecurityFindingModel.status == status.upper())
            count_stmt = count_stmt.where(SecurityFindingModel.status == status.upper())

        if search_query:
            term = f"%{search_query}%"
            search_filter = or_(
                SecurityFindingModel.title.ilike(term),
                SecurityFindingModel.finding_id.ilike(term),
                SecurityFindingModel.resource_id.ilike(term),
            )
            stmt = stmt.where(search_filter)
            count_stmt = count_stmt.where(search_filter)

        total_res = await self.session.execute(count_stmt)
        total = total_res.scalar() or 0

        # Primary ordering: Risk score descending, then detection date
        stmt = (
            stmt.order_by(SecurityFindingModel.risk_score.desc(), SecurityFindingModel.detected_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all(), total

    async def update_status(self, finding_id: str, new_status: str) -> Optional[SecurityFindingModel]:
        """Update finding triage lifecycle status (OPEN, IN_PROGRESS, RESOLVED)."""
        finding = await self.get_by_id(finding_id)
        if not finding:
            return None

        status_norm = new_status.upper()
        finding.status = status_norm
        if status_norm == "RESOLVED":
            finding.resolved_at = datetime.now(timezone.utc)
        else:
            finding.resolved_at = None

        await self.session.flush()
        return finding

    async def get_severity_summary(self) -> dict[str, int]:
        """Aggregate finding counts by severity for executive KPI dashboard."""
        stmt = (
            select(SecurityFindingModel.severity, func.count())
            .where(SecurityFindingModel.status != "RESOLVED")
            .group_by(SecurityFindingModel.severity)
        )
        res = await self.session.execute(stmt)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for sev, count in res.all():
            if sev in counts:
                counts[sev] = count
        return counts
