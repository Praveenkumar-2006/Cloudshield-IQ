"""
Unit Tests — Security Findings API Endpoints
============================================
Tests verifying listing, filtering, detail fetching, and status updates on /api/v1/findings.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import create_application


@pytest.fixture
def client():
    app = create_application()
    return TestClient(app)


class TestFindingsAPIEndpoints:
    """Test findings query and triage update routes."""

    def test_list_findings_default(self, client):
        response = client.get("/api/v1/findings")
        assert response.status_code == 200
        data = response.json()
        assert "findings" in data
        assert "total" in data
        assert data["total"] >= 1
        assert len(data["findings"]) >= 1

    def test_list_findings_filter_by_cloud(self, client):
        response = client.get("/api/v1/findings?cloud=AWS")
        assert response.status_code == 200
        data = response.json()
        for f in data["findings"]:
            assert f["cloud_provider"].upper() == "AWS"

    def test_list_findings_filter_by_severity(self, client):
        response = client.get("/api/v1/findings?severity=CRITICAL")
        assert response.status_code == 200
        data = response.json()
        for f in data["findings"]:
            assert f["severity"].upper() == "CRITICAL"

    def test_get_finding_by_id_success(self, client):
        response = client.get("/api/v1/findings/FND-AWS-1049")
        assert response.status_code == 200
        data = response.json()
        assert data["finding_id"] == "FND-AWS-1049"
        assert "title" in data
        assert "remediation_guidance" in data

    def test_get_finding_by_id_not_found(self, client):
        response = client.get("/api/v1/findings/FND-NON-EXISTENT-XYZ")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_update_finding_status_success(self, client):
        payload = {"status": "RESOLVED"}
        response = client.patch("/api/v1/findings/FND-AWS-1049/status", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["finding_id"] == "FND-AWS-1049"
        assert data["status"] == "RESOLVED"

    def test_update_finding_status_invalid(self, client):
        payload = {"status": "NOT_A_VALID_STATUS"}
        response = client.patch("/api/v1/findings/FND-AWS-1049/status", json=payload)
        assert response.status_code == 422
