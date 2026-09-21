"""
CloudShield IQ — Baseline Rule-Based & Hybrid Risk Engine
==========================================================
Deterministic heuristic evaluation engine combined with ML anomaly detection
for calculating multi-cloud security risk scores, mapping severities, and
generating actionable findings.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
import uuid

from app.core.logging import get_logger
from app.core.taxonomy import SeverityLevel
from app.ml.models.anomaly_detector import IsolationForestAnomalyDetector
from app.ml.rules.base import BaseRiskRule, RuleMatch
from app.ml.rules.catalog import get_default_rules
from app.schemas.assessments import RiskAssessment, SecurityFinding
from app.schemas.events import CloudSecurityEvent

logger = get_logger(__name__)


@dataclass
class RuleAssessmentResult:
    """
    Complete evaluation container for an event processed by the risk engine.
    """

    assessment: RiskAssessment
    findings: list[SecurityFinding]
    matches: list[RuleMatch]


class RuleBasedRiskEngine:
    """
    Risk evaluation engine supporting deterministic security rules
    and machine learning anomaly detection.
    """

    def __init__(
        self,
        rules: Optional[list[BaseRiskRule]] = None,
        anomaly_detector: Optional[IsolationForestAnomalyDetector] = None,
        use_hybrid_scoring: bool = False,
    ):
        """
        Initialize engine with default or custom security rules and optional anomaly detector.
        """
        self.rules: list[BaseRiskRule] = rules if rules is not None else get_default_rules()
        self.anomaly_detector = anomaly_detector
        self.use_hybrid_scoring = use_hybrid_scoring
        logger.info(
            "RuleBasedRiskEngine initialized",
            active_rule_count=len(self.rules),
            has_anomaly_detector=anomaly_detector is not None,
            use_hybrid_scoring=use_hybrid_scoring,
        )

    def register_rule(self, rule: BaseRiskRule) -> None:
        """Register an additional custom risk rule."""
        self.rules.append(rule)
        logger.debug("Registered custom risk rule", rule_id=rule.rule_id)

    @staticmethod
    def map_score_to_severity(score: float) -> SeverityLevel:
        """
        Map a continuous numerical risk score (0.0 - 100.0) to categorical SeverityLevel.
        """
        if score >= 85.0:
            return SeverityLevel.CRITICAL
        elif score >= 60.0:
            return SeverityLevel.HIGH
        elif score >= 30.0:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    def evaluate_event(
        self,
        event: CloudSecurityEvent,
        precomputed_anomaly: Optional[AnomalyPrediction] = None,
    ) -> RuleAssessmentResult:
        """
        Evaluate a single canonical cloud security event against rules and ML model.

        Args:
            event: Canonical CloudSecurityEvent object.
            precomputed_anomaly: Optional pre-calculated ML anomaly prediction from batch inference.

        Returns:
            RuleAssessmentResult containing RiskAssessment, SecurityFindings, and RuleMatches.
        """
        matches: list[RuleMatch] = []
        raw_penalty = 0.0

        for rule in self.rules:
            try:
                match = rule.evaluate(event)
                if match is not None:
                    matches.append(match)
                    raw_penalty += match.penalty
            except Exception as exc:
                logger.error(
                    "Error executing rule evaluation",
                    rule_id=getattr(rule, "rule_id", "unknown"),
                    error=str(exc),
                )

        rule_score = min(100.0, round(raw_penalty, 2))

        # ML Anomaly Detection
        feature_impacts: dict[str, float] = {}
        if precomputed_anomaly is not None:
            anomaly_score = precomputed_anomaly.anomaly_score
            is_anomaly = precomputed_anomaly.is_anomaly
            model_version = self.anomaly_detector.model_version if self.anomaly_detector else "isolation-forest-v1"
            feature_impacts = precomputed_anomaly.feature_impacts
        elif self.anomaly_detector and self.anomaly_detector.is_trained:
            try:
                anom_pred = self.anomaly_detector.predict_event(event)
                anomaly_score = anom_pred.anomaly_score
                is_anomaly = anom_pred.is_anomaly
                model_version = self.anomaly_detector.model_version
                feature_impacts = anom_pred.feature_impacts
            except Exception as exc:
                logger.warning("ML anomaly prediction failed, falling back to proxy", error=str(exc))
                anomaly_score = min(1.0, round(rule_score / 100.0, 4))
                is_anomaly = rule_score >= 60.0
                model_version = "baseline-rules-v1"
        else:
            anomaly_score = min(1.0, round(rule_score / 100.0, 4))
            is_anomaly = rule_score >= 60.0
            model_version = "baseline-rules-v1"

        # Calculate final risk score
        if self.use_hybrid_scoring and self.anomaly_detector and self.anomaly_detector.is_trained:
            if rule_score > 0:
                hybrid = 0.65 * rule_score + 0.35 * (anomaly_score * 100.0)
                if is_anomaly:
                    hybrid += 15.0
            elif is_anomaly:
                hybrid = 35.0 + (anomaly_score * 25.0)
            else:
                hybrid = anomaly_score * 15.0
            risk_score = min(100.0, round(hybrid, 2))
        else:
            risk_score = rule_score

        severity = self.map_score_to_severity(risk_score)

        # Explainability attributes
        shap_proxy: dict[str, float] = {
            m.rule_id: round(m.penalty, 2) for m in matches
        }
        for k, v in feature_impacts.items():
            shap_proxy[k] = round(v * 10.0, 2)

        top_feature = matches[0].rule_id if matches else (list(feature_impacts.keys())[0] if feature_impacts else None)
        top_feature_impact = matches[0].penalty if matches else (list(feature_impacts.values())[0] * 10.0 if feature_impacts else 0.0)

        now_utc = datetime.now(timezone.utc)

        assessment = RiskAssessment(
            assessment_id=str(uuid.uuid4()),
            event_id=event.event_id,
            resource_id=event.resource_id,
            cloud_provider=event.cloud_provider,
            risk_score=risk_score,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            severity=severity,
            shap_values=shap_proxy,
            top_feature=top_feature,
            top_feature_impact=top_feature_impact,
            model_version=model_version,
            evaluated_at=now_utc,
        )

        findings: list[SecurityFinding] = []
        for match in matches:
            finding = SecurityFinding(
                finding_id=f"FND-{uuid.uuid4().hex[:8].upper()}",
                title=match.title,
                cloud_provider=event.cloud_provider,
                resource_id=event.resource_id or "unknown-resource",
                category=match.category,
                severity=self.map_score_to_severity(match.penalty),
                risk_score=min(100.0, match.penalty),
                shap_top_feature=match.rule_id,
                shap_impact=match.penalty,
                compliance_violations=match.compliance_violations,
                remediation_guidance=match.remediation_guidance,
                cli_remediation_command=match.cli_remediation_command,
                terraform_remediation_snippet=match.terraform_remediation_snippet,
                status="OPEN",
                detected_at=now_utc,
            )
            findings.append(finding)

        # If behavioral anomaly detected without explicit rule match
        if is_anomaly and not matches and self.use_hybrid_scoring:
            action_desc = getattr(event, "canonical_action", None) or getattr(event, "raw_action", "Action")
            action_str = action_desc.value if hasattr(action_desc, "value") else str(action_desc)
            findings.append(
                SecurityFinding(
                    finding_id=f"FND-ANOM-{uuid.uuid4().hex[:6].upper()}",
                    title=f"Statistical Anomaly Detected ({action_str})",
                    cloud_provider=event.cloud_provider,
                    resource_id=event.resource_id or "unknown-resource",
                    category="Anomaly Detection",
                    severity=severity,
                    risk_score=risk_score,
                    shap_top_feature=top_feature or "unusual_telemetry_deviation",
                    shap_impact=risk_score,
                    compliance_violations=["CIS-Controls-v8-Sec-8"],
                    remediation_guidance=(
                        f"Unusual statistical deviation detected for actor '{event.actor_name}'. "
                        "Audit recent access patterns and verify authorization credentials."
                    ),
                    cli_remediation_command=f"# Investigate activity log for actor: {event.actor_name}",
                    status="OPEN",
                    detected_at=now_utc,
                )
            )

        return RuleAssessmentResult(
            assessment=assessment,
            findings=findings,
            matches=matches,
        )

    def evaluate_batch(self, events: list[CloudSecurityEvent]) -> list[RuleAssessmentResult]:
        """
        Evaluate a sequence of canonical cloud security events with vectorized ML inference.
        """
        if not events:
            return []

        ml_preds: Optional[list[AnomalyPrediction]] = None
        if self.anomaly_detector and self.anomaly_detector.is_trained:
            try:
                ml_preds = self.anomaly_detector.predict_events(events)
            except Exception as exc:
                logger.warning("Batch ML anomaly prediction failed, falling back", error=str(exc))

        results: list[RuleAssessmentResult] = []
        for i, event in enumerate(events):
            anom = ml_preds[i] if ml_preds and i < len(ml_preds) else None
            results.append(self.evaluate_event(event, precomputed_anomaly=anom))
        return results
