"""
Unit Tests — Security Feature Extractor & Pipeline
===================================================
"""

from datetime import datetime, timezone
import numpy as np
import pandas as pd
import pytest

from app.core.taxonomy import ActorType, CloudProvider, OutcomeType
from app.ml.features.pipeline import SecurityFeatureExtractor, _is_private_ip, _parse_timestamp
from app.schemas.events import CloudSecurityEvent, CloudSecurityEventCreate


def _sample_event(**overrides) -> CloudSecurityEvent:
    base = {
        "timestamp": datetime.now(timezone.utc),
        "cloud_provider": CloudProvider.AWS,
        "event_source": "aws_cloudtrail",
        "resource_type": "AWS::S3::Bucket",
        "resource_id": "arn:aws:s3:::test-bucket",
        "raw_action": "GetObject",
        "actor_type": ActorType.USER,
        "actor_name": "alice",
        "source_ip": "10.0.1.25",
        "region": "us-east-1",
        "mfa_used": True,
        "outcome": OutcomeType.SUCCESS,
        "session_duration_s": 3600,
    }
    base.update(overrides)
    return CloudSecurityEvent.from_create(CloudSecurityEventCreate(**base))


class TestSecurityFeatureExtractor:
    """Test suite for domain telemetry feature extractor."""

    def test_ip_classification(self):
        assert _is_private_ip("192.168.1.1") is True
        assert _is_private_ip("10.50.12.3") is True
        assert _is_private_ip("172.16.0.5") is True
        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("103.21.40.45") is False
        assert _is_private_ip("invalid-ip") is False
        assert _is_private_ip(None) is True

    def test_timestamp_parser(self):
        dt = _parse_timestamp("2026-09-05T12:00:00Z")
        assert dt.hour == 12
        assert dt.tzinfo is not None

        dt_obj = datetime(2026, 9, 5, 8, 30, tzinfo=timezone.utc)
        assert _parse_timestamp(dt_obj).hour == 8

    def test_extractor_fit_transform_events(self):
        events = [
            _sample_event(actor_type=ActorType.USER, raw_action="DescribeInstances"),
            _sample_event(actor_type=ActorType.ROOT, raw_action="DeleteTrail", mfa_used=False),
            _sample_event(actor_type=ActorType.SERVICE_ACCOUNT, raw_action="PutObject"),
        ]

        extractor = SecurityFeatureExtractor(max_categories=10)
        matrix = extractor.fit_transform(events)

        assert isinstance(matrix, np.ndarray)
        assert matrix.shape[0] == 3
        assert matrix.shape[1] > 10
        assert len(extractor.feature_names_) == matrix.shape[1]
        assert "is_root_principal" in extractor.feature_names_
        assert "mfa_absent" in extractor.feature_names_

        # Verify second event is flagged as root
        root_idx = extractor.feature_names_.index("is_root_principal")
        assert matrix[1, root_idx] == 1.0
        assert matrix[0, root_idx] == 0.0

    def test_extractor_transform_dataframe(self):
        df = pd.DataFrame([
            {
                "timestamp": "2026-09-05T02:00:00Z",
                "cloud_provider": "aws",
                "resource_type": "s3:Bucket",
                "action": "PutBucketAcl",
                "actor_type": "user",
                "actor_name": "bob",
                "source_ip": "1.2.3.4",
                "mfa_used": False,
                "outcome": "Failure",
                "session_duration_s": 0,
            }
        ])

        extractor = SecurityFeatureExtractor(max_categories=5)
        extractor.fit(df)
        matrix = extractor.transform(df)

        assert matrix.shape[0] == 1
        denied_idx = extractor.feature_names_.index("is_denied_or_failure")
        assert matrix[0, denied_idx] == 1.0

        pub_idx = extractor.feature_names_.index("is_public_ip")
        assert matrix[0, pub_idx] == 1.0

    def test_empty_input_handling(self):
        extractor = SecurityFeatureExtractor()
        extractor.fit([])
        matrix = extractor.transform([])
        assert matrix.shape == (0, 0)
