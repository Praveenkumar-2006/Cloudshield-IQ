"""
Unit Tests — Compliance REST API Endpoints
===========================================
Tests FastAPI endpoints under /api/v1/compliance/ for frameworks, controls catalog,
telemetry evaluation, summary metrics, and audit report generation.
"""

from datetime import datetime, timezone
from fastapi.testclient import TestClient
import pytest

from app.main import app

client = TestClient(app, raise_server_exceptions=True)


class TestComplianceApi:
    def test_list_frameworks(self):
        resp = client.get("/api/v1/compliance/frameworks")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 6
        fw_names = [item["framework_name"] for item in data]
        assert "CIS AWS 1.4" in fw_names
        assert "CIS Azure 2.0" in fw_names
        assert "CIS GCP 1.3" in fw_names
        assert "NIST 800-53" in fw_names
        assert "ISO 27001" in fw_names
        assert "PCI-DSS 4.0" in fw_names

    def test_list_controls_catalog(self):
        resp = client.get("/api/v1/compliance/controls")
        assert resp.status_code == 200
        controls = resp.json()
        assert isinstance(controls, list)
        assert len(controls) >= 15
        ctrl_ids = [c["control_id"] for c in controls]
        assert "CIS-AWS-1.1" in ctrl_ids
        assert "CIS-AWS-2.1.1" in ctrl_ids
        assert "NIST-AC-2" in ctrl_ids

    def test_filter_controls_by_framework(self):
        resp = client.get("/api/v1/compliance/controls", params={"framework": "CIS AWS 1.4"})
        assert resp.status_code == 200
        controls = resp.json()
        assert len(controls) == 4
        assert all(c["framework"] == "CIS AWS 1.4" for c in controls)

    def test_get_compliance_summary(self):
        resp = client.get("/api/v1/compliance/summary")
        assert resp.status_code == 200
        summary = resp.json()
        assert "overall_pass_rate" in summary
        assert "total_controls" in summary
        assert "passed_controls" in summary
        assert "framework_scores" in summary
        assert summary["total_controls"] >= 15

    def test_get_compliance_summary_filtered(self):
        resp = client.get("/api/v1/compliance/summary", params={"framework": "NIST 800-53"})
        assert resp.status_code == 200
        summary = resp.json()
        assert summary["total_controls"] == 3

    def test_evaluate_compliance_endpoint(self):
        sample_events = [
            {
                "event_id": "evt-api-eval-1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "cloud_provider": "aws",
                "resource_type": "iam:User",
                "resource_id": "arn:aws:iam::123456789012:user/admin",
                "canonical_action": "IAM_USER_CREATE",
                "raw_action": "CreateUser",
                "actor_type": "root",
                "actor_name": "root",
                "source_ip": "198.51.100.24",
                "mfa_used": False,
                "outcome": "Success",
                "session_duration_s": 300,
                "additional_context": {}
            }
        ]
        resp = client.post("/api/v1/compliance/evaluate", json=sample_events)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_controls" in data
        assert "results" in data
        assert "summary" in data
        # Root usage should cause CIS-AWS-1.1 to FAIL
        root_result = next((r for r in data["results"] if r["control_id"] == "CIS-AWS-1.1"), None)
        assert root_result is not None
        assert root_result["status"] == "FAIL"

    def test_generate_audit_report(self):
        resp = client.get("/api/v1/compliance/report")
        assert resp.status_code == 200
        report = resp.json()
        assert "report_title" in report
        assert "summary" in report
        assert "control_evaluations" in report
        assert isinstance(report["control_evaluations"], list)
