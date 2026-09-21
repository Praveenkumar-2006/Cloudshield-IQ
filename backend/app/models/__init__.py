"""
CloudShield IQ — Database Model Registry
========================================
Exports all SQLAlchemy ORM models so that Alembic and application startup can detect table definitions.
"""

from app.models.assessments import (
    ComplianceResultModel,
    RiskAssessmentModel,
    SecurityFindingModel,
)
from app.models.events import SecurityEventModel

__all__ = [
    "SecurityEventModel",
    "RiskAssessmentModel",
    "SecurityFindingModel",
    "ComplianceResultModel",
]
