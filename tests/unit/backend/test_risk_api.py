"""
Unit Tests — Supervised Risk API Endpoints (Phase 6: Supervised Risk Classification)
===================================================================================
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from app.main import create_application


@pytest.fixture
def client() -> TestClient:
    app = create_application()
    return TestClient(app)


class TestSupervisedRiskApiEndpoints:
    """Test suite for /api/v1/ml/risk-model-info and /api/v1/ml/classify-risk."""

    def test_get_risk_model_info(self, client: TestClient):
        response = client.get("/api/v1/ml/risk-model-info")
        assert response.status_code == 200
        data = response.json()
        assert "model_version" in data
        assert "algorithm" in data
        assert "XGBoost" in data["algorithm"]
        assert "is_trained" in data
        assert "classes" in data
        assert "features" in data
        assert len(data["classes"]) == 4

    def test_classify_risk_endpoint(self, client: TestClient):
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

        response = client.post("/api/v1/ml/classify-risk", json=sample_batch)
        assert response.status_code == 200
        data = response.json()
        assert data["total_events"] == 2
        assert "severity_counts" in data
        assert "mean_risk_score" in data
        assert len(data["predictions"]) == 2

        pred1 = data["predictions"][0]
        assert pred1["predicted_severity"] in ["low", "medium", "high", "critical"]
        assert 0.0 <= pred1["predicted_risk_score"] <= 100.0
        assert 0.0 <= pred1["confidence"] <= 1.0
        assert "severity_probabilities" in pred1
        assert len(pred1["severity_probabilities"]) == 4

    def test_classify_risk_empty_payload(self, client: TestClient):
        response = client.post("/api/v1/ml/classify-risk", json=[])
        assert response.status_code == 400
        assert "Payload must contain at least one telemetry event" in response.json()["detail"]
