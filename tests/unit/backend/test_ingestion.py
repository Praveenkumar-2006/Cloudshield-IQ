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
