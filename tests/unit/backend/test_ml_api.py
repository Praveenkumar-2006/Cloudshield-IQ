"""
Unit Tests — ML API Endpoints
=============================
"""

import pytest
from starlette.testclient import TestClient

from app.main import create_application


@pytest.fixture
def client() -> TestClient:
    app = create_application()
    return TestClient(app)


class TestMLApiEndpoints:
    """Test suite for /api/v1/ml endpoints."""

    def test_get_model_info(self, client: TestClient):
        response = client.get("/api/v1/ml/model-info")
        assert response.status_code == 200
        data = response.json()
        assert "model_version" in data
        assert "algorithm" in data
        assert data["algorithm"] == "IsolationForest"
        assert "is_trained" in data
        assert "features" in data
        assert "contamination" in data

    def test_detect_anomalies_endpoint(self, client: TestClient):
        sample_batch = [
            {
                "timestamp": "2026-09-05T12:00:00Z",
                "cloud_provider": "aws",
                "resource_type": "AWS::S3::Bucket",
                "action": "GetObject",
                "actor_type": "user",
                "actor_name": "analyst",
                "source_ip": "10.0.0.1",
                "mfa_used": True,
                "outcome": "Success",
                "session_duration_s": 1200,
            },
            {
                "timestamp": "2026-09-05T02:00:00Z",
                "cloud_provider": "azure",
                "resource_type": "Microsoft.KeyVault/vaults",
                "action": "DeleteRole",
                "actor_type": "root",
                "actor_name": "root",
                "source_ip": "198.51.100.4",
                "mfa_used": False,
                "outcome": "Failure",
                "session_duration_s": 0,
            },
        ]

        response = client.post("/api/v1/ml/detect", json=sample_batch)
        assert response.status_code == 200
        data = response.json()
        assert data["total_events"] == 2
        assert "anomalies_detected" in data
        assert "predictions" in data
        assert len(data["predictions"]) == 2
        assert 0.0 <= data["predictions"][0]["anomaly_score"] <= 1.0

    def test_detect_anomalies_empty_payload(self, client: TestClient):
        response = client.post("/api/v1/ml/detect", json=[])
        assert response.status_code == 400
