"""
Unit tests for TreeSHAPExplainer (Phase 7: SHAP Explainability & Risk Attribution)
==================================================================================
Validates mathematical additivity, local waterfall attribution, and global importance.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pytest

from app.ml.explainability.tree_shap import (
    FeatureImpact,
    GlobalAttributionSummary,
    LocalExplanation,
    TreeSHAPExplainer,
)
from app.ml.models.risk_classifier import (
    SEVERITY_ORDER,
    SupervisedRiskClassifier,
)


@pytest.fixture
def sample_events() -> list[dict[str, Any]]:
    """Sample diverse telemetry events across AWS, Azure, and GCP."""
    return [
        {
            "event_id": f"evt-{i:03d}",
            "timestamp": "2026-09-05T12:00:00Z",
            "cloud_provider": "aws" if i % 3 == 0 else ("azure" if i % 3 == 1 else "gcp"),
            "resource_type": "iam:Role" if i % 2 == 0 else "storage:Bucket",
            "action": "DeleteRole" if i % 2 == 0 else "PutBucketAcl",
            "actor_type": "root" if i % 4 == 0 else "user",
            "actor_name": "root" if i % 4 == 0 else f"analyst_{i}",
            "source_ip": "198.51.100.1" if i % 3 == 0 else "10.0.0.1",
            "mfa_used": bool(i % 2 != 0),
            "outcome": "Failure" if i % 3 == 0 else "Success",
            "session_duration_s": float(i * 120),
        }
        for i in range(50)
    ]


@pytest.fixture
def trained_classifier(sample_events: list[dict[str, Any]]) -> SupervisedRiskClassifier:
    """Trains a compact SupervisedRiskClassifier instance for TreeSHAP testing."""
    clf = SupervisedRiskClassifier(
        model_version="test-shap-v1",
        n_estimators=15,
        max_depth=3,
        learning_rate=0.1,
        random_state=42,
    )
    y_sev = [SEVERITY_ORDER[i % len(SEVERITY_ORDER)] for i in range(len(sample_events))]
    y_risk = [float((i * 9) % 100) for i in range(len(sample_events))]

    clf.fit(X_raw=sample_events, y_severity=y_sev, y_risk_score=y_risk)
    return clf


@pytest.fixture
def explainer(trained_classifier: SupervisedRiskClassifier) -> TreeSHAPExplainer:
    return TreeSHAPExplainer(trained_classifier)


class TestTreeSHAPExplainer:
    """Test suite for TreeSHAP explainer engine."""

    def test_explainer_initialization(self, explainer: TreeSHAPExplainer):
        assert explainer.is_ready is True
        assert isinstance(explainer.base_value, float)
        assert 0.0 <= explainer.base_value <= 100.0

    def test_explain_single_event_additivity(
        self,
        explainer: TreeSHAPExplainer,
        sample_events: list[dict[str, Any]],
    ):
        """
        Verify the fundamental mathematical additivity of TreeSHAP:
            predicted_risk = base_value + sum(all_shap_values)
        """
        event = sample_events[0]
        explanation = explainer.explain_event(event, top_k=5)

        assert isinstance(explanation, LocalExplanation)
        assert explanation.event_id == "evt-000"
        assert 0.0 <= explanation.predicted_risk_score <= 100.0

        # Sum of all SHAP values + base value must equal predicted score
        shap_sum = sum(explanation.all_attributions.values())
        reconstructed_score = np.clip(explanation.base_value + shap_sum, 0.0, 100.0)

        assert np.isclose(reconstructed_score, explanation.predicted_risk_score, atol=0.2)

    def test_drivers_and_mitigators_structure(
        self,
        explainer: TreeSHAPExplainer,
        sample_events: list[dict[str, Any]],
    ):
        # Pick a critical root event
        high_risk_event = {
            "event_id": "evt-critical-test",
            "timestamp": "2026-09-05T02:00:00Z",
            "cloud_provider": "aws",
            "resource_type": "iam:Role",
            "action": "DeleteRole",
            "actor_type": "root",
            "actor_name": "root",
            "source_ip": "198.51.100.99",
            "mfa_used": False,
            "outcome": "Failure",
            "session_duration_s": 0.0,
        }

        explanation = explainer.explain_event(high_risk_event, top_k=5)

        # Drivers must have positive shap_values
        for driver in explanation.top_risk_drivers:
            assert isinstance(driver, FeatureImpact)
            assert driver.shap_value > 0
            assert driver.direction == "risk_enhancer"
            assert driver.domain in ("IAM", "Authentication", "Network", "Storage", "Logging", "Encryption", "Compute", "Cloud Platform")
            assert len(driver.display_name) > 0

        # Mitigators must have negative shap_values
        for mitigator in explanation.top_risk_mitigators:
            assert isinstance(mitigator, FeatureImpact)
            assert mitigator.shap_value < 0
            assert mitigator.direction == "risk_mitigator"

    def test_explain_batch(
        self,
        explainer: TreeSHAPExplainer,
        sample_events: list[dict[str, Any]],
    ):
        batch = sample_events[:5]
        explanations = explainer.explain_batch(batch, top_k=3)

        assert len(explanations) == 5
        for exp in explanations:
            assert isinstance(exp, LocalExplanation)
            assert len(exp.top_risk_drivers) <= 3
            assert len(exp.top_risk_mitigators) <= 3

    def test_get_global_attributions(
        self,
        explainer: TreeSHAPExplainer,
        sample_events: list[dict[str, Any]],
    ):
        global_summary = explainer.get_global_attributions(background_data=sample_events, top_k=6)

        assert isinstance(global_summary, GlobalAttributionSummary)
        assert global_summary.model_version == "test-shap-v1"
        assert len(global_summary.top_global_features) <= 6

        # Relative percentages should sum approximately to 100% across all features
        percentages = [f.relative_percentage for f in global_summary.top_global_features]
        assert all(p >= 0.0 for p in percentages)
        # Top features are sorted descending by importance
        assert percentages == sorted(percentages, reverse=True)

        # Domain distribution should exist
        assert len(global_summary.domain_distribution) > 0

    def test_uninitialized_explainer_fallback(self):
        """Unfitted explainer returns safe synthetic baseline rather than crashing."""
        unfitted_explainer = TreeSHAPExplainer(classifier=None)
        assert unfitted_explainer.is_ready is False

        fallback_summary = unfitted_explainer.get_global_attributions()
        assert len(fallback_summary.top_global_features) > 0
        assert "IAM" in fallback_summary.domain_distribution
