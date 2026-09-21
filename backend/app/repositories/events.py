"""
CloudShield IQ — Security Event Repository
==========================================
Data access layer for ingesting and querying multi-cloud security telemetry events.
"""

from datetime import datetime, timezone
from typing import Any, Optional, Sequence
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.events import SecurityEventModel
from app.repositories.base import BaseRepository
from app.schemas.events import CloudSecurityEvent


class EventRepository(BaseRepository[SecurityEventModel]):
    """Repository managing normalized security event telemetry records."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(SecurityEventModel, session)

    async def create_from_schema(self, event: CloudSecurityEvent) -> SecurityEventModel:
        """Convert a validated Pydantic event into a persistent ORM model and save it."""
        model = SecurityEventModel(
            event_id=event.event_id,
            timestamp=event.timestamp,
            cloud_provider=event.cloud_provider.value if hasattr(event.cloud_provider, "value") else str(event.cloud_provider),
            event_source=event.event_source,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            raw_action=event.raw_action,
            canonical_action=event.canonical_action.value if hasattr(event.canonical_action, "value") else str(event.canonical_action),
            actor_type=event.actor_type.value if hasattr(event.actor_type, "value") else str(event.actor_type),
            actor_name=event.actor_name,
            source_ip=str(event.source_ip) if event.source_ip else None,
            region=event.region,
            mfa_used=event.mfa_used,
            outcome=event.outcome.value if hasattr(event.outcome, "value") else str(event.outcome),
            session_duration_s=event.session_duration_s,
            has_session=event.has_session,
            metadata_payload=event.metadata_payload,
            created_at=datetime.now(timezone.utc),
        )
        return await self.create(model)

    async def create_batch_from_schemas(self, events: list[CloudSecurityEvent]) -> int:
        """Bulk convert and persist a batch of normalized security events."""
        if not events:
            return 0
        now = datetime.now(timezone.utc)
        models = [
            SecurityEventModel(
                event_id=e.event_id,
                timestamp=e.timestamp,
                cloud_provider=e.cloud_provider.value if hasattr(e.cloud_provider, "value") else str(e.cloud_provider),
                event_source=e.event_source,
                resource_type=e.resource_type,
                resource_id=e.resource_id,
                raw_action=e.raw_action,
                canonical_action=e.canonical_action.value if hasattr(e.canonical_action, "value") else str(e.canonical_action),
                actor_type=e.actor_type.value if hasattr(e.actor_type, "value") else str(e.actor_type),
                actor_name=e.actor_name,
                source_ip=str(e.source_ip) if e.source_ip else None,
                region=e.region,
                mfa_used=e.mfa_used,
                outcome=e.outcome.value if hasattr(e.outcome, "value") else str(e.outcome),
                session_duration_s=e.session_duration_s,
                has_session=e.has_session,
                metadata_payload=e.metadata_payload,
                created_at=now,
            )
            for e in events
        ]
        return await self.create_batch(models)

    async def query_events(
        self,
        cloud_provider: Optional[str] = None,
        resource_type: Optional[str] = None,
        actor_type: Optional[str] = None,
        canonical_action: Optional[str] = None,
        outcome: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[Sequence[SecurityEventModel], int]:
        """Query security events with filters and return items with total match count."""
        stmt = select(SecurityEventModel)
        count_stmt = select(func.count()).select_from(SecurityEventModel)

        if cloud_provider and cloud_provider.upper() != "ALL":
            stmt = stmt.where(SecurityEventModel.cloud_provider == cloud_provider.lower())
            count_stmt = count_stmt.where(SecurityEventModel.cloud_provider == cloud_provider.lower())

        if resource_type:
            stmt = stmt.where(SecurityEventModel.resource_type == resource_type)
            count_stmt = count_stmt.where(SecurityEventModel.resource_type == resource_type)

        if actor_type:
            stmt = stmt.where(SecurityEventModel.actor_type == actor_type.lower())
            count_stmt = count_stmt.where(SecurityEventModel.actor_type == actor_type.lower())

        if canonical_action:
            stmt = stmt.where(SecurityEventModel.canonical_action == canonical_action)
            count_stmt = count_stmt.where(SecurityEventModel.canonical_action == canonical_action)

        if outcome:
            stmt = stmt.where(SecurityEventModel.outcome.ilike(outcome))
            count_stmt = count_stmt.where(SecurityEventModel.outcome.ilike(outcome))

        if start_time:
            stmt = stmt.where(SecurityEventModel.timestamp >= start_time)
            count_stmt = count_stmt.where(SecurityEventModel.timestamp >= start_time)

        if end_time:
            stmt = stmt.where(SecurityEventModel.timestamp <= end_time)
            count_stmt = count_stmt.where(SecurityEventModel.timestamp <= end_time)

        total_count_res = await self.session.execute(count_stmt)
        total = total_count_res.scalar() or 0

        stmt = stmt.order_by(SecurityEventModel.timestamp.desc()).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all(), total

    async def get_telemetry_stats(self) -> dict[str, Any]:
        """Aggregate telemetry statistics for dashboard HUD."""
        total = await self.count()

        # Count by cloud provider
        provider_stmt = (
            select(SecurityEventModel.cloud_provider, func.count())
            .group_by(SecurityEventModel.cloud_provider)
        )
        provider_res = await self.session.execute(provider_stmt)
        by_provider = {row[0]: row[1] for row in provider_res.all()}

        return {
            "total_events": total,
            "by_provider": by_provider,
        }

    # Alias for API consistency
    list_events = query_events
