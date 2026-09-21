"""
Unit Tests — Recommendations REST API Endpoints
================================================
Tests FastAPI endpoints under /api/v1/recommendations/ for playbooks,
custom recommendations generation, batch prioritization, posture simulations, and metrics.
"""

from datetime import datetime, timezone
from fastapi.testclient import TestClient
import pytest

from app.main import app

client = TestClient(app, raise_server_exceptions=True)


class TestRecommendationsApi:
    """Validates /api/v1/recommendations REST endpoints."""

    def test_list_playbooks(self):
        resp = client.get("/api/v1/recommendations/playbooks")
        assert resp.status_code == 200
        playbooks = resp.json()
        assert isinstance(playbooks, list)
        assert len(playbooks) >= 10
        ids = [p["playbook_id"] for p in playbooks]
        assert "PB-AWS-IAM-001" in ids
        assert "PB-AZR-STR-001" in ids
        assert "PB-GCP-STR-001" in ids

    def test_list_playbooks_with_filter(self):
        resp = client.get("/api/v1/recommendations/playbooks", params={"provider": "AWS"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 4
        assert all(p["cloud_provider"] == "aws" for p in data)

    def test_get_single_playbook(self):
        resp = client.get("/api/v1/recommendations/playbooks/PB-AWS-IAM-001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["playbook_id"] == "PB-AWS-IAM-001"
        assert "Root Account" in data["title"]
        assert len(data["steps"]) >= 2
        assert "aws iam" in data["cli_command"]
        assert "resource" in data["terraform_snippet"]

    def test_get_single_playbook_not_found(self):
        resp = client.get("/api/v1/recommendations/playbooks/NON-EXISTENT-ID")
        assert resp.status_code == 404

    def test_generate_recommendation(self):
        payload = {
            "finding_id": "FND-001",
            "finding": {
                "title": "Public S3 Bucket Exposed",
                "cloud_provider": "AWS",
                "resource_id": "arn:aws:s3:::cloudshield-public-assets",
                "category": "Storage",
                "severity": "CRITICAL",
                "risk_score": 88.0,
                "shap_top_feature": "is_public_ip",
                "compliance_violations": ["CIS-AWS-2.1.1", "NIST-SC-28"],
                "remediation_guidance": "Enable Public Access Block on bucket.",
            },
            "shap_drivers": ["is_public_ip"],
            "target_resource_override": "cloudshield-public-assets",
        }
        resp = client.post("/api/v1/recommendations/generate", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["finding_id"] == "FND-001"
        assert data["cloud_provider"] == "aws"
        assert data["target_resource"] == "cloudshield-public-assets"
        assert data["original_risk_score"] == 88.0
        assert data["projected_risk_score"] < 88.0
        assert data["priority_score"] > 60.0
        assert "cloudshield-public-assets" in data["playbook"]["cli_command"]

    def test_batch_prioritize_findings(self):
        payload = {
            "findings": [
                {
                    "finding_id": "FND-001",
                    "title": "Root Access Keys Active",
                    "cloud_provider": "AWS",
                    "resource_id": "arn:aws:iam::111122223333:root",
                    "category": "IAM",
                    "severity": "CRITICAL",
                    "risk_score": 95.0,
                    "shap_top_feature": "actor_type_root",
                    "compliance_violations": ["CIS-AWS-1.1"],
                    "remediation_guidance": "Delete keys.",
                },
                {
                    "finding_id": "FND-002",
                    "title": "Missing Bucket Tag",
                    "cloud_provider": "AWS",
                    "resource_id": "arn:aws:s3:::my-test-bucket",
                    "category": "Storage",
                    "severity": "LOW",
                    "risk_score": 18.0,
                    "compliance_violations": [],
                    "remediation_guidance": "Apply tags.",
                },
            ]
        }
        resp = client.post("/api/v1/recommendations/prioritize", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_findings"] == 2
        assert len(data["recommendations"]) == 2
        assert data["recommendations"][0]["finding_id"] == "FND-001"
        assert data["recommendations"][0]["priority_rank"] == 1
        assert data["recommendations"][1]["finding_id"] == "FND-002"
        assert data["recommendations"][1]["priority_rank"] == 2

    def test_simulate_remediation(self):
        payload = {
            "finding_ids_to_remediate": ["FND-001"],
            "current_findings": [
                {
                    "finding_id": "FND-001",
                    "title": "Root Access Keys Active",
                    "cloud_provider": "AWS",
                    "resource_id": "arn:aws:iam::111122223333:root",
                    "category": "IAM",
                    "severity": "CRITICAL",
                    "risk_score": 95.0,
                    "compliance_violations": ["CIS-AWS-1.1"],
                    "remediation_guidance": "Delete keys.",
                }
            ],
        }
        resp = client.post("/api/v1/recommendations/simulate", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["findings_remediated_count"] == 1
        assert data["original_average_risk"] == 95.0
        assert data["projected_average_risk"] < 95.0
        assert data["overall_risk_reduction_pct"] > 0
        assert "Simulation successfully" in data["simulation_summary"] or "Simulated remediation" in data["simulation_summary"]

    def test_recommendation_stats(self):
        resp = client.get("/api/v1/recommendations/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_playbooks"] >= 10
        assert "aws" in data["playbooks_by_provider"]
        assert "azure" in data["playbooks_by_provider"]
        assert "gcp" in data["playbooks_by_provider"]
        assert data["average_risk_reduction_points"] > 0
        assert len(data["covered_compliance_controls"]) >= 5
