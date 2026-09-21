"""
CloudShield IQ — Asynchronous Base Repository
=============================================
Generic data-access repository providing asynchronous CRUD abstractions for SQLAlchemy 2.0 ORM models.
"""

from typing import Any, Generic, Optional, Sequence, Type, TypeVar
from sqlalchemy import select, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """Generic async base repository encapsulating common database interactions."""

    def __init__(self, model: Type[ModelType], session: AsyncSession) -> None:
        self.model = model
        self.session = session

    async def get_by_id(self, primary_key: Any) -> Optional[ModelType]:
        """Fetch a single record by its primary key."""
        return await self.session.get(self.model, primary_key)

    async def list(self, offset: int = 0, limit: int = 100) -> Sequence[ModelType]:
        """List records with pagination."""
        stmt = select(self.model).offset(offset).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count(self) -> int:
        """Count total records in table."""
        stmt = select(func.count()).select_from(self.model)
        result = await self.session.execute(stmt)
        return result.scalar() or 0

    async def create(self, instance: ModelType) -> ModelType:
        """Add and commit a single record."""
        self.session.add(instance)
        await self.session.flush()
        return instance

    async def create_batch(self, instances: list[ModelType]) -> int:
        """Bulk insert multiple records."""
        if not instances:
            return 0
        self.session.add_all(instances)
        await self.session.flush()
        return len(instances)

    async def delete(self, primary_key: Any) -> bool:
        """Delete a record by primary key."""
        stmt = delete(self.model).where(self.model.__table__.primary_key.columns[0] == primary_key)
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0
