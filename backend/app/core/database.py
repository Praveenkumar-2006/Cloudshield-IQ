"""
CloudShield IQ — Database Connection
======================================
Async SQLAlchemy engine and session factory.

Design decisions:
- Async I/O (asyncpg) to match FastAPI's async model
- Connection pooling with explicit size limits
- Sessions are request-scoped: one session per HTTP request,
  committed on success, rolled back on any exception
- The engine URL is read from settings, never hard-coded
"""

import time
from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Circuit breaker state for offline development & graceful fallback
_last_db_failure_time: float = 0.0
DB_RETRY_INTERVAL_SECONDS: float = 15.0


def is_db_available() -> bool:
    """Return True if the database has not recently failed a connection check."""
    return (time.time() - _last_db_failure_time) > DB_RETRY_INTERVAL_SECONDS


def mark_db_unavailable() -> None:
    """Mark the database as temporarily unavailable to prevent connection stalls."""
    global _last_db_failure_time
    _last_db_failure_time = time.time()


def reset_db_availability() -> None:
    """Reset database availability state upon successful connection."""
    global _last_db_failure_time
    _last_db_failure_time = 0.0


class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy ORM models.

    All models inherit from this. Alembic migrations are generated
    from models that inherit Base, so every model must be imported
    in alembic/env.py for autogenerate to work.
    """


def _create_engine() -> any:
    """
    Build the async SQLAlchemy engine.

    Called once at module import. Configuration is read from
    Settings, which reads from environment variables.
    """
    settings = get_settings()
    db_url = settings.DATABASE_URL.get_secret_value()

    engine = create_async_engine(
        db_url,
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=settings.DATABASE_MAX_OVERFLOW,
        # Echo SQL only in development — never in production
        echo=settings.DEBUG and settings.APP_ENV == "development",
        # Health check before each connection is handed to the app
        pool_pre_ping=True,
    )
    return engine


engine = _create_engine()

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    # expire_on_commit=False so we can still access model attributes
    # after a commit without issuing a new SELECT
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides a request-scoped async DB session.

    Usage:
        @router.get("/example")
        async def example(db: AsyncSession = Depends(get_db_session)):
            ...

    The session is automatically committed on success and rolled back
    on any exception. Always closed after the request.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# Type alias for cleaner dependency injection in route handlers
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
