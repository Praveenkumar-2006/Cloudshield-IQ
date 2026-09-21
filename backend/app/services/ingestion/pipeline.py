"""
CloudShield IQ — Data Ingestion & Telemetry Pipeline
====================================================
High-performance streaming & batch ingestion engine for multi-cloud security logs.
Parses CSV and JSON telemetry, performs schema validation, normalizes events, and executes
instant risk evaluation and findings generation.
"""

import csv
from datetime import datetime, timezone
import io
import json
import time
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.core.logging import get_logger
from app.core.taxonomy import CloudProvider, SeverityLevel
from app.ml.rules.engine import RuleAssessmentResult, RuleBasedRiskEngine
from app.schemas.assessments import RiskAssessment, SecurityFinding
from app.schemas.events import CloudSecurityEvent
from app.services.normalizer import TelemetryNormalizer

logger = get_logger(__name__)


class IngestionStats(BaseModel):
    """Real-time metrics for ingested cloud telemetry."""

    total_events_ingested: int = 0
    valid_events_count: int = 0
    invalid_records_count: int = 0
    anomalies_detected: int = 0
    critical_findings_count: int = 0
    high_findings_count: int = 0
    medium_findings_count: int = 0
    low_findings_count: int = 0
    average_risk_score: float = 0.0
    provider_distribution: dict[str, int] = Field(default_factory=lambda: {"aws": 0, "azure": 0, "gcp": 0})
    last_ingestion_time: Optional[datetime] = None


class IngestionResult(BaseModel):
    """Response returned upon completion of an ingestion run."""

    filename: str
    status: str
    total_parsed: int
    successful_events: int
    failed_events: int
    duration_ms: float
    risk_summary: dict[str, Any]
    findings_generated: list[dict[str, Any]]
    sample_events: list[dict[str, Any]]


class IngestionStore:
    """
    In-memory storage & query cache for ingested security events and evaluation results.
    Ensures seamless dashboard functionality in both offline development and database modes.
    """

    def __init__(self, max_retained_events: int = 10000):
        self.max_retained = max_retained_events
        self.events: list[CloudSecurityEvent] = []
        self.assessments: list[RiskAssessment] = []
        self.findings: list[SecurityFinding] = []
        self.stats = IngestionStats()

    def record_batch(
        self,
        events: list[CloudSecurityEvent],
        results: list[RuleAssessmentResult],
    ) -> None:
        """Add new events and evaluation outcomes to the store."""
        for ev, res in zip(events, results, strict=False):
            self.events.append(ev)
            self.assessments.append(res.assessment)
            self.findings.extend(res.findings)

            # Update stats
            prov = ev.cloud_provider.value.lower()
            self.stats.provider_distribution[prov] = self.stats.provider_distribution.get(prov, 0) + 1
            if res.assessment.is_anomaly:
                self.stats.anomalies_detected += 1

            if res.assessment.severity == SeverityLevel.CRITICAL:
                self.stats.critical_findings_count += 1
            elif res.assessment.severity == SeverityLevel.HIGH:
                self.stats.high_findings_count += 1
            elif res.assessment.severity == SeverityLevel.MEDIUM:
                self.stats.medium_findings_count += 1
            else:
                self.stats.low_findings_count += 1

        # Keep recent slice if exceeding capacity
        if len(self.events) > self.max_retained:
            self.events = self.events[-self.max_retained :]
            self.assessments = self.assessments[-self.max_retained :]
            self.findings = self.findings[-self.max_retained :]

        self.stats.total_events_ingested = len(self.events)
        self.stats.valid_events_count = len(self.events)
        if self.assessments:
            self.stats.average_risk_score = round(
                sum(a.risk_score for a in self.assessments) / len(self.assessments), 2
            )
        self.stats.last_ingestion_time = datetime.now(timezone.utc)


# Singleton store instance
_global_ingestion_store = IngestionStore()


def get_ingestion_store() -> IngestionStore:
    return _global_ingestion_store


class IngestionPipeline:
    """
    Core pipeline orchestrating format parsing, canonical normalization,
    and instantaneous rule-based risk evaluation.
    """

    def __init__(
        self,
        risk_engine: Optional[RuleBasedRiskEngine] = None,
        store: Optional[IngestionStore] = None,
    ):
        if risk_engine is not None:
            self.risk_engine = risk_engine
        else:
            try:
                from app.services.ml.risk_engine import get_risk_assessment_service
                self.risk_engine = get_risk_assessment_service().rule_engine
            except Exception:
                self.risk_engine = RuleBasedRiskEngine()
        self.store = store or get_ingestion_store()

    def process_raw_records(self, records: list[dict[str, Any]], filename: str = "stream") -> IngestionResult:
        """
        Normalize a list of dictionary log records and evaluate risk scores.
        """
        start_time = time.perf_counter()
        normalized_events: list[CloudSecurityEvent] = []
        failed_count = 0

        for r in records:
            try:
                event = TelemetryNormalizer.normalize_record(r)
                normalized_events.append(event)
            except Exception as exc:
                logger.warning("Failed to normalize record", error=str(exc), raw_sample=str(r)[:200])
                failed_count += 1

        # Evaluate risk on normalized batch
        results = self.risk_engine.evaluate_batch(normalized_events)

        # Store results
        self.store.record_batch(normalized_events, results)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Collect top findings for response summary
        all_findings = []
        for res in results:
            for f in res.findings:
                all_findings.append({
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "cloud": f.cloud_provider.value.upper(),
                    "resourceId": f.resource_id,
                    "severity": f.severity.value.upper(),
                    "category": f.category,
                    "riskScore": f.risk_score,
                    "complianceViolation": f.compliance_violations,
                    "remediation": f.remediation_guidance,
                    "cliCommand": f.cli_remediation_command or "",
                    "terraform": f.terraform_remediation_snippet or "",
                })

        avg_score = (
            round(sum(r.assessment.risk_score for r in results) / len(results), 2)
            if results
            else 0.0
        )
        anomalies = sum(1 for r in results if r.assessment.is_anomaly)

        return IngestionResult(
            filename=filename,
            status="SUCCESS",
            total_parsed=len(records),
            successful_events=len(normalized_events),
            failed_events=failed_count,
            duration_ms=elapsed_ms,
            risk_summary={
                "average_risk_score": avg_score,
                "anomalies_detected": anomalies,
                "findings_count": len(all_findings),
                "high_critical_count": sum(
                    1 for r in results if r.assessment.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
                ),
            },
            findings_generated=all_findings[:10],  # Return first 10 for quick UI display
            sample_events=[
                {
                    "event_id": ev.event_id,
                    "timestamp": ev.timestamp.isoformat(),
                    "cloud_provider": ev.cloud_provider.value,
                    "action": ev.raw_action,
                    "canonical_action": ev.canonical_action.value,
                    "actor_name": ev.actor_name,
                    "resource_id": ev.resource_id,
                }
                for ev in normalized_events[:5]
            ],
        )

    def parse_csv_bytes(self, content: bytes, filename: str = "upload.csv") -> IngestionResult:
        """Parse raw CSV byte content."""
        decoded = content.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(decoded))
        records = [dict(row) for row in reader]
        return self.process_raw_records(records, filename=filename)

    def parse_json_bytes(self, content: bytes, filename: str = "upload.json") -> IngestionResult:
        """Parse raw JSON or CloudTrail JSON byte content."""
        decoded = content.decode("utf-8", errors="replace").strip()

        # Handle NDJSON / JSON Lines format
        if "\n" in decoded and not (decoded.startswith("[") or decoded.startswith("{")):
            records = []
            for line in decoded.splitlines():
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
            return self.process_raw_records(records, filename=filename)

        parsed = json.loads(decoded)

        # Handle AWS CloudTrail export format: {"Records": [...]}
        if isinstance(parsed, dict) and "Records" in parsed and isinstance(parsed["Records"], list):
            records = parsed["Records"]
        elif isinstance(parsed, list):
            records = parsed
        elif isinstance(parsed, dict):
            records = [parsed]
        else:
            records = []

        return self.process_raw_records(records, filename=filename)
