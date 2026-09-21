"""
Unit Tests — Data Ingestion Pipeline & API Endpoints
====================================================
"""

import json
from fastapi.testclient import TestClient
import pytest

from app.core.taxonomy import ActorType, CloudProvider, OutcomeType
from app.main import create_application
from app.services.ingestion import IngestionPipeline, IngestionStore
from app.services.normalizer import TelemetryNormalizer


@pytest.fixture
def client():
    app = create_application()
    return TestClient(app)


class TestNormalizerExtensions:
    """Test multi-cloud format parsing and normalization."""

    def test_normalize_azure_activity_log(self):
        record = {
            "correlationId": "azr-test-100",
            "eventTimestamp": "2026-09-01T10:00:00Z",
            "operationName": "Microsoft.Storage/storageAccounts/write",
            "caller": "devops_user@company.com",
            "resourceId": "/subscriptions/sub-1/resourceGroups/rg-sec/providers/Microsoft.Storage/storageAccounts/blobstore",
            "status": "Succeeded",
            "claims": {"amr": "mfa"},
        }
        event = TelemetryNormalizer.normalize_azure_activity_log(record)
        assert event.cloud_provider == CloudProvider.AZURE
        assert event.event_source == "AzureActivityLog"
        assert event.actor_name == "devops_user@company.com"
        assert event.mfa_used is True
        assert event.outcome == OutcomeType.SUCCESS

    def test_normalize_gcp_audit_log(self):
        record = {
            "insertId": "gcp-insert-200",
            "timestamp": "2026-09-01T10:05:00Z",
            "protoPayload": {
                "methodName": "compute.instances.insert",
                "authenticationInfo": {"principalEmail": "admin@cloud.iam.gserviceaccount.com"},
                "status": {"code": 0},
                "resourceName": "projects/proj-1/zones/us-central1-a/instances/worker-vm",
            },
            "resource": {"type": "gce_instance"},
        }
        event = TelemetryNormalizer.normalize_gcp_audit_log(record)
        assert event.cloud_provider == CloudProvider.GCP
        assert event.actor_type == ActorType.SERVICE_ACCOUNT
        assert event.raw_action == "compute.instances.insert"
        assert event.outcome == OutcomeType.SUCCESS

    def test_auto_detection_routing(self):
        aws_rec = {"eventName": "CreateUser", "userIdentity": {"type": "Root"}}
        azure_rec = {"operationName": "Microsoft.Compute/virtualMachines/write", "caller": "user@ms.com"}
        gcp_rec = {"protoPayload": {"methodName": "storage.buckets.create"}}

        assert TelemetryNormalizer.normalize_record(aws_rec).cloud_provider == CloudProvider.AWS
        assert TelemetryNormalizer.normalize_record(azure_rec).cloud_provider == CloudProvider.AZURE
        assert TelemetryNormalizer.normalize_record(gcp_rec).cloud_provider == CloudProvider.GCP


class TestIngestionPipeline:
    """Test pipeline byte parsing and metric calculation."""

    def test_parse_csv_bytes(self):
        csv_data = (
            "timestamp,cloud_provider,resource_type,action,actor_type,actor_name,mfa_used,outcome\n"
            "2026-09-01T12:00:00Z,aws,AWS::S3::Bucket,PutBucketPolicy,root,root,false,Success\n"
            "2026-09-01T12:05:00Z,azure,VirtualMachine,Microsoft.Compute/virtualMachines/write,user,alice,true,Success\n"
        ).encode("utf-8")

        pipeline = IngestionPipeline()
        res = pipeline.parse_csv_bytes(csv_data, filename="test.csv")

        assert res.status == "SUCCESS"
        assert res.total_parsed == 2
        assert res.successful_events == 2
        assert res.failed_events == 0
        assert res.risk_summary["findings_count"] >= 1  # Root user rule triggered

    def test_parse_cloudtrail_json_bytes(self):
        cloudtrail_data = json.dumps({
            "Records": [
                {
                    "eventID": "rec-1",
                    "eventTime": "2026-09-01T12:00:00Z",
                    "eventName": "DeleteTrail",
                    "userIdentity": {"type": "Root", "userName": "root"},
                }
            ]
        }).encode("utf-8")

        pipeline = IngestionPipeline()
        res = pipeline.parse_json_bytes(cloudtrail_data, filename="cloudtrail.json")

        assert res.successful_events == 1
        assert res.risk_summary["high_critical_count"] == 1


class TestIngestionAPIEndpoints:
    """Test FastAPI ingestion endpoints."""

    def test_upload_csv_endpoint(self, client):
        csv_content = (
            "timestamp,cloud_provider,resource_type,action,actor_type,actor_name,mfa_used,outcome\n"
            "2026-09-01T12:00:00Z,aws,AWS::S3::Bucket,GetObject,user,dev_user,true,Success\n"
        )
        response = client.post(
            "/api/v1/ingestion/upload",
            files={"file": ("test_logs.csv", csv_content, "text/csv")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["successful_events"] == 1
        assert data["filename"] == "test_logs.csv"

    def test_upload_invalid_extension(self, client):
        response = client.post(
            "/api/v1/ingestion/upload",
            files={"file": ("malicious.exe", b"binary", "application/octet-stream")},
        )
        assert response.status_code == 400

    def test_ingest_json_events_batch(self, client):
        payload = [
            {
                "timestamp": "2026-09-01T12:00:00Z",
                "cloud_provider": "aws",
                "resource_type": "AWS::IAM::Policy",
                "action": "AttachRolePolicy",
                "actor_type": "user",
                "actor_name": "attacker",
                "mfa_used": False,
                "outcome": "Success",
            }
        ]
        response = client.post("/api/v1/ingestion/events", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["successful_events"] == 1
        assert data["risk_summary"]["findings_count"] >= 1

    def test_load_sample_dataset_endpoint(self, client):
        response = client.post("/api/v1/ingestion/sample/cloudtrail")
        assert response.status_code == 200
        data = response.json()
        assert data["successful_events"] >= 1

    def test_get_stats_and_list_events(self, client):
        # Trigger an ingestion
        client.post("/api/v1/ingestion/sample/azure")

        # Check stats
        stats_resp = client.get("/api/v1/ingestion/stats")
        assert stats_resp.status_code == 200
        stats = stats_resp.json()
        assert stats["total_events_ingested"] >= 1

        # Check list events
        events_resp = client.get("/api/v1/ingestion/events?limit=10")
        assert events_resp.status_code == 200
        events_data = events_resp.json()
        assert len(events_data["events"]) >= 1

        # Check list findings
        findings_resp = client.get("/api/v1/ingestion/findings?limit=10")
        assert findings_resp.status_code == 200
        findings_data = findings_resp.json()
        assert "findings" in findings_data

    def test_end_to_end_upload_and_findings_retrieval(self, client):
        """Verify uploaded dataset results propagate to /api/v1/findings and /compliance/summary."""
        csv_content = (
            "timestamp,cloud_provider,resource_type,action,actor_type,actor_name,mfa_used,outcome\n"
            "2026-09-01T12:00:00Z,aws,AWS::IAM::Root,ConsoleLogin,root,root,false,Success\n"
            "2026-09-01T12:05:00Z,aws,AWS::S3::Bucket,PutBucketPolicy,root,root,false,Success\n"
        )
        upload_resp = client.post(
            "/api/v1/ingestion/upload",
            files={"file": ("incident_stream.csv", csv_content, "text/csv")},
        )
        assert upload_resp.status_code == 200
        result = upload_resp.json()
        assert result["successful_events"] == 2
        assert result["risk_summary"]["findings_count"] >= 1

        # Check findings API reflects uploaded data
        findings_resp = client.get("/api/v1/findings")
        assert findings_resp.status_code == 200
        findings_data = findings_resp.json()
        assert findings_data["total"] >= 1
        assert findings_data.get("data_source") in ("database", "ingested_memory")

        # Check compliance summary evaluated uploaded events
        comp_resp = client.get("/api/v1/compliance/summary")
        assert comp_resp.status_code == 200
        comp_data = comp_resp.json()
        assert "overall_pass_rate" in comp_data
        assert "framework_scores" in comp_data

    def test_upload_cloudtrail_json_endpoint(self, client):
        payload = json.dumps({
            "Records": [
                {
                    "eventID": "ct-upload-01",
                    "eventTime": "2026-09-01T12:00:00Z",
                    "eventName": "ConsoleLogin",
                    "userIdentity": {"type": "Root", "userName": "root"},
                    "responseElements": {"ConsoleLogin": "Success"},
                }
            ]
        })
        resp = client.post(
            "/api/v1/ingestion/upload",
            files={"file": ("cloudtrail.json", payload, "application/json")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["successful_events"] == 1
        assert data["risk_summary"]["findings_count"] >= 1

    def test_upload_azure_json_endpoint(self, client):
        payload = json.dumps([
            {
                "correlationId": "az-upload-01",
                "eventTimestamp": "2026-09-01T12:00:00Z",
                "operationName": "Microsoft.Storage/storageAccounts/write",
                "caller": "dev@azure.com",
                "resourceId": "/subscriptions/s1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/store1",
                "status": "Succeeded",
            }
        ])
        resp = client.post(
            "/api/v1/ingestion/upload",
            files={"file": ("azure_logs.json", payload, "application/json")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["successful_events"] == 1

    def test_upload_gcp_json_endpoint(self, client):
        payload = json.dumps([
            {
                "insertId": "gcp-upload-01",
                "timestamp": "2026-09-01T12:00:00Z",
                "protoPayload": {
                    "methodName": "storage.buckets.create",
                    "authenticationInfo": {"principalEmail": "admin@gcp.com"},
                    "resourceName": "projects/p1/buckets/b1",
                },
            }
        ])
        resp = client.post(
            "/api/v1/ingestion/upload",
            files={"file": ("gcp_logs.json", payload, "application/json")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["successful_events"] == 1

    def test_upload_malformed_json_endpoint(self, client):
        resp = client.post(
            "/api/v1/ingestion/upload",
            files={"file": ("bad.json", b"{broken json", "application/json")},
        )
        assert resp.status_code == 400
        assert "Failed to parse" in resp.json()["detail"]

    def test_upload_large_file_rejection(self, client, monkeypatch):
        from app.core.config import get_settings
        monkeypatch.setattr(get_settings(), "MAX_UPLOAD_SIZE_MB", 0.0001)  # ~100 bytes
        resp = client.post(
            "/api/v1/ingestion/upload",
            files={"file": ("large.json", b"x" * 1000, "application/json")},
        )
        assert resp.status_code == 413

    def test_treeshap_with_uploaded_event(self, client):
        # Ingest an event
        payload = json.dumps([
            {
                "event_id": "evt-shap-real-01",
                "timestamp": "2026-09-01T12:00:00Z",
                "cloud_provider": "aws",
                "resource_type": "AWS::IAM::Root",
                "action": "ConsoleLogin",
                "actor_type": "root",
                "actor_name": "root",
                "mfa_used": False,
                "outcome": "Success",
            }
        ])
        client.post(
            "/api/v1/ingestion/upload",
            files={"file": ("treeshap_test.json", payload, "application/json")},
        )

        # Get the actual event
        events_resp = client.get("/api/v1/ingestion/events?limit=5")
        events = events_resp.json()["events"]
        assert len(events) >= 1
        target_event = events[0]

        # Call TreeSHAP with real event
        explain_resp = client.post("/api/v1/ml/explain/event", json=target_event)
        assert explain_resp.status_code == 200
        explain_data = explain_resp.json()
        assert explain_data["event_id"] == target_event["event_id"]
        assert "predicted_risk_score" in explain_data
        assert "top_risk_drivers" in explain_data

    def test_finding_status_persistence(self, client):
        # Ingest event that creates finding
        csv_content = (
            "timestamp,cloud_provider,resource_type,action,actor_type,actor_name,mfa_used,outcome\n"
            "2026-09-01T12:00:00Z,aws,AWS::IAM::Root,ConsoleLogin,root,root,false,Success\n"
        )
        client.post(
            "/api/v1/ingestion/upload",
            files={"file": ("status_test.csv", csv_content, "text/csv")},
        )
        findings_resp = client.get("/api/v1/findings")
        findings = findings_resp.json()["findings"]
        assert len(findings) >= 1
        fid = findings[0]["finding_id"]

        # Update status
        patch_resp = client.patch(f"/api/v1/findings/{fid}/status", json={"status": "IN_PROGRESS"})
        assert patch_resp.status_code == 200
        assert patch_resp.json()["status"] == "IN_PROGRESS"

        # Verify status persists
        get_resp = client.get(f"/api/v1/findings/{fid}")
        assert get_resp.status_code == 200
        assert get_resp.json()["status"] == "IN_PROGRESS"

