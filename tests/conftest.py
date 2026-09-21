"""
CloudShield IQ — Shared Test Fixtures
=======================================
Fixtures available to all tests in the test suite.

Environment:
Tests run with APP_ENV=development and a test database.
The test database URL must be set in the CI environment or
in a local .env.test file (never committed to Git).

Fixtures:
- app_client:   Sync TestClient for endpoint tests
- async_client: Async httpx client for async endpoint tests
- db_session:   Isolated database session (rolled back after each test)
- settings:     Application settings (development config)
"""

import os

import pytest
from fastapi.testclient import TestClient

# Ensure test environment is set before any app imports
# This prevents production settings from being loaded
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "test-secret-key-minimum-32-characters-long!!")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-key-minimum-32-characters-long!!!")
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://cloudshield:testpassword@localhost:5432/cloudshield_test",
)


@pytest.fixture(scope="session")
def app_client():
    """
    Session-scoped sync TestClient.

    Reused across all tests in a session for performance.
    Use this for read-only endpoint tests that don't mutate state.
    """
    from app.main import app
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture(scope="function")
def settings():
    """Return the application settings for the current test environment."""
    from app.core.config import get_settings
    return get_settings()
