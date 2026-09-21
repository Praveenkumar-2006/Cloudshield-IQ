"""
CloudShield IQ — Recommendation Package
=======================================
Context-aware multi-cloud remediation playbooks, prioritized recommendations,
and posture improvement simulations.
"""

from typing import Optional

from app.recommendations.catalog import (
    get_default_playbooks,
    get_playbook_by_id,
)
from app.recommendations.engine import RecommendationEngine
from app.recommendations.prioritizer import RemediationPrioritizer

_RECOMMENDATION_ENGINE_INSTANCE: Optional[RecommendationEngine] = None


def get_recommendation_engine() -> RecommendationEngine:
    """Return singleton RecommendationEngine instance."""
    global _RECOMMENDATION_ENGINE_INSTANCE
    if _RECOMMENDATION_ENGINE_INSTANCE is None:
        _RECOMMENDATION_ENGINE_INSTANCE = RecommendationEngine()
    return _RECOMMENDATION_ENGINE_INSTANCE


__all__ = [
    "RecommendationEngine",
    "RemediationPrioritizer",
    "get_recommendation_engine",
    "get_default_playbooks",
    "get_playbook_by_id",
]
