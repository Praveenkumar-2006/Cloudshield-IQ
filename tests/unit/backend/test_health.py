"""
Unit tests for health endpoints.

These tests verify:
1. The liveness endpoint always returns 200
2. The response schema matches HealthStatus
3. No sensitive information leaks in health responses

The database readiness test is in tests/integration/ because
it requires a live database connection.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

# TestClient wraps the ASGI app for synchronous testing
# Use AsyncClient from httpx for async tests
client = TestClient(app, raise_server_exceptions=True)


class TestLiveness:
    def test_liveness_returns_200(self) -> None:
        response = client.get("/health")
        assert response.status_code == 200

    def test_liveness_returns_ok_status(self) -> None:
        response = client.get("/health")
        data = response.json()
        assert data["status"] == "ok"

    def test_liveness_returns_service_name(self) -> None:
        response = client.get("/health")
        data = response.json()
        assert data["service"] == "cloudshield-iq"

    def test_liveness_no_sensitive_fields(self) -> None:
        """Health response must not expose credentials or internal config."""
        response = client.get("/health")
        raw = response.text.lower()
        sensitive_terms = ["password", "secret", "key", "token", "credential"]
        for term in sensitive_terms:
            assert term not in raw, f"Sensitive term '{term}' found in health response"


class TestApiV1Liveness:
    def test_api_liveness_returns_200(self) -> None:
        response = client.get("/api/v1/health/live")
        assert response.status_code == 200

    def test_api_liveness_has_version(self) -> None:
        response = client.get("/api/v1/health/live")
        data = response.json()
        assert "version" in data
        assert data["version"] == "0.1.0"
