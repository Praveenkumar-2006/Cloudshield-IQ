"""
Unit Tests — TreeSHAP Explainability API Endpoints (Phase 7: TreeSHAP)
======================================================================
"""

from __future__ import annotations

from typing import Any
import pytest
from starlette.testclient import TestClient

from app.main import create_application


@pytest.fixture
def client() -> TestClient:
    app = create_application()
    return TestClient(app)


class TestExplainabilityApiEndpoints:
    """Test suite for /api/v1/ml/explain endpoints."""

    def test_get_global_shap_attributions(self, client: TestClient):
        response = client.get("/api/v1/ml/explain/global?top_k=5")
        assert response.status_code == 200
        data = response.json()

        assert "model_version" in data
        assert "base_value" in data
        assert "top_global_features" in data
        assert "domain_distribution" in data
        assert len(data["top_global_features"]) <= 5

        # Check structure of top features
        top_feat = data["top_global_features"][0]
        assert "feature_name" in top_feat
        assert "display_name" in top_feat
        assert "domain" in top_feat
        assert "relative_percentage" in top_feat

    def test_explain_single_event_endpoint(self, client: TestClient):
        sample_event = {
            "event_id": "evt-explain-api-01",
            "timestamp": "2026-09-05T12:00:00Z",
            "cloud_provider": "aws",
            "resource_type": "iam:Role",
            "action": "DeleteRole",
            "actor_type": "root",
            "actor_name": "root",
            "source_ip": "198.51.100.24",
            "mfa_used": False,
            "outcome": "Failure",
            "session_duration_s": 0,
        }

        response = client.post("/api/v1/ml/explain/event?top_k=4", json=sample_event)
        assert response.status_code == 200
        data = response.json()

        assert data["event_id"] == "evt-explain-api-01"
        assert "base_value" in data
        assert "predicted_risk_score" in data
        assert "top_risk_drivers" in data
        assert "top_risk_mitigators" in data
        assert "all_attributions" in data

        # Check that top_risk_drivers has valid structure
        if data["top_risk_drivers"]:
            driver = data["top_risk_drivers"][0]
            assert "feature_name" in driver
            assert "shap_value" in driver
            assert driver["shap_value"] > 0
            assert driver["direction"] == "risk_enhancer"

    def test_explain_batch_events_endpoint(self, client: TestClient):
        sample_batch = [
            {
                "event_id": "evt-batch-01",
                "timestamp": "2026-09-05T12:00:00Z",
                "cloud_provider": "azure",
                "resource_type": "Microsoft.KeyVault/vaults",
                "action": "ScheduleKeyDeletion",
                "actor_type": "user",
                "actor_name": "developer",
                "source_ip": "10.0.0.5",
                "mfa_used": True,
                "outcome": "Success",
                "session_duration_s": 1200,
            },
            {
                "event_id": "evt-batch-02",
                "timestamp": "2026-09-05T12:30:00Z",
                "cloud_provider": "gcp",
                "resource_type": "storage.googleapis.com/Bucket",
                "action": "PutBucketAcl",
                "actor_type": "root",
                "actor_name": "root",
                "source_ip": "203.0.113.5",
                "mfa_used": False,
                "outcome": "Failure",
                "session_duration_s": 0,
            },
        ]

        response = client.post("/api/v1/ml/explain/batch", json=sample_batch)
        assert response.status_code == 200
        data = response.json()

        assert data["total_events"] == 2
        assert len(data["explanations"]) == 2
        assert data["explanations"][0]["event_id"] == "evt-batch-01"
        assert data["explanations"][1]["event_id"] == "evt-batch-02"

    def test_explain_empty_payload_validation(self, client: TestClient):
        response = client.post("/api/v1/ml/explain/event", json={})
        assert response.status_code == 400

        batch_response = client.post("/api/v1/ml/explain/batch", json=[])
        assert batch_response.status_code == 400
