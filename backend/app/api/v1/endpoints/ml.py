"""
CloudShield IQ — Machine Learning API Endpoints
================================================
REST endpoints for inspecting the active ML model, executing anomaly detection
on telemetry events, and triggering model re-training.
"""

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.logging import get_logger
from app.schemas.events import CloudSecurityEvent, CloudSecurityEventCreate
from app.services.ml.risk_engine import get_risk_assessment_service

logger = get_logger(__name__)
router = APIRouter()


class ModelInfoResponse(BaseModel):
    model_version: str
    algorithm: str
    is_trained: bool
    trained_at: Optional[str] = None
    training_records_count: int
    feature_count: int
    features: list[str]
    contamination: float
    n_estimators: int
    status: str
    metrics: dict[str, Any] = {}


class AnomalyPredictionItem(BaseModel):
    event_id: Optional[str] = None
    is_anomaly: bool
    anomaly_score: float
    raw_score: float
    feature_impacts: dict[str, float]
    evaluated_at: str


class AnomalyDetectionResponse(BaseModel):
    total_events: int
    anomalies_detected: int
    anomaly_rate: float
    predictions: list[AnomalyPredictionItem]


class RetrainRequest(BaseModel):
    contamination: float = Field(0.05, ge=0.01, le=0.5, description="Expected anomaly contamination fraction")
    n_estimators: int = Field(150, ge=10, le=500, description="Number of Isolation Forest decision trees")
    dataset_path: Optional[str] = Field(None, description="Optional custom dataset CSV filepath")


@router.get(
    "/model-info",
    summary="Get active ML model metadata and health",
    description="Returns current anomaly detection model specifications, feature dimensions, and metrics.",
    response_model=ModelInfoResponse,
    status_code=status.HTTP_200_OK,
)
async def get_model_info() -> dict[str, Any]:
    service = get_risk_assessment_service()
    return service.get_model_info()


@router.post(
    "/detect",
    summary="Run ML anomaly detection on telemetry events",
    description="Directly scores a batch of security events using the trained Isolation Forest pipeline.",
    response_model=AnomalyDetectionResponse,
    status_code=status.HTTP_200_OK,
)
async def detect_anomalies(
    payload: list[dict[str, Any]],
) -> AnomalyDetectionResponse:
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must contain at least one telemetry event.",
        )

    service = get_risk_assessment_service()
    predictions = service.anomaly_detector.predict_events(payload)

    anom_count = sum(1 for p in predictions if p.is_anomaly)
    total = len(predictions)
    rate = round(anom_count / total, 4) if total > 0 else 0.0

    items = [
        AnomalyPredictionItem(
            event_id=payload[i].get("event_id") if i < len(payload) else None,
            is_anomaly=p.is_anomaly,
            anomaly_score=p.anomaly_score,
            raw_score=p.raw_score,
            feature_impacts=p.feature_impacts,
            evaluated_at=p.evaluated_at,
        )
        for i, p in enumerate(predictions)
    ]

    return AnomalyDetectionResponse(
        total_events=total,
        anomalies_detected=anom_count,
        anomaly_rate=rate,
        predictions=items,
    )


@router.post(
    "/train",
    summary="Retrain Isolation Forest anomaly model",
    description="Retrains the anomaly detection pipeline on benchmark or uploaded security dataset.",
    response_model=ModelInfoResponse,
    status_code=status.HTTP_200_OK,
)
async def retrain_model(
    request: RetrainRequest = RetrainRequest(),
) -> dict[str, Any]:
    service = get_risk_assessment_service()
    try:
        updated_info = service.retrain_model(
            contamination=request.contamination,
            n_estimators=request.n_estimators,
            dataset_path=request.dataset_path,
        )
        return updated_info
    except Exception as exc:
        logger.error("Failed to retrain model", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model retraining failed: {exc}",
        )


# =============================================================================
# Phase 6: Supervised Risk Classification Endpoints (XGBoost)
# =============================================================================


class SupervisedModelInfoResponse(BaseModel):
    model_version: str
    algorithm: str
    is_trained: bool
    created_at: Optional[str] = None
    training_records_count: int
    feature_count: int
    features: list[str]
    classes: list[str]
    status: str
    metrics: dict[str, Any] = {}
    hyperparameters: dict[str, Any] = {}


class SupervisedPredictionItem(BaseModel):
    event_id: Optional[str] = None
    predicted_severity: str
    severity_probabilities: dict[str, float]
    predicted_risk_score: float
    confidence: float
    model_version: str


class SupervisedClassificationResponse(BaseModel):
    total_events: int
    severity_counts: dict[str, int]
    mean_risk_score: float
    predictions: list[SupervisedPredictionItem]


class RetrainSupervisedRequest(BaseModel):
    n_estimators: int = Field(120, ge=10, le=500, description="Number of gradient boosted trees")
    max_depth: int = Field(5, ge=2, le=12, description="Maximum tree depth")
    learning_rate: float = Field(0.08, ge=0.01, le=0.5, description="Learning rate")
    dataset_path: Optional[str] = Field(None, description="Optional custom dataset CSV filepath")


@router.get(
    "/risk-model-info",
    summary="Get active Supervised XGBoost model metadata and health",
    description="Returns current supervised risk model specifications, training metrics (F1, MAE, R2), and feature dimensions.",
    response_model=SupervisedModelInfoResponse,
    status_code=status.HTTP_200_OK,
)
async def get_risk_model_info() -> dict[str, Any]:
    service = get_risk_assessment_service()
    return service.get_supervised_model_info()


@router.post(
    "/classify-risk",
    summary="Run Supervised Risk Classification on telemetry events",
    description="Scores a batch of security events using the trained XGBoost multi-class severity and regression pipeline.",
    response_model=SupervisedClassificationResponse,
    status_code=status.HTTP_200_OK,
)
async def classify_risk(
    payload: list[dict[str, Any]],
) -> SupervisedClassificationResponse:
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must contain at least one telemetry event.",
        )

    service = get_risk_assessment_service()
    predictions = service.classify_risk(payload)

    sev_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    scores: list[float] = []
    items: list[SupervisedPredictionItem] = []

    for i, p in enumerate(predictions):
        sev_counts[p.predicted_severity] = sev_counts.get(p.predicted_severity, 0) + 1
        scores.append(p.predicted_risk_score)
        items.append(
            SupervisedPredictionItem(
                event_id=payload[i].get("event_id") if i < len(payload) else None,
                predicted_severity=p.predicted_severity,
                severity_probabilities=p.severity_probabilities,
                predicted_risk_score=p.predicted_risk_score,
                confidence=p.confidence,
                model_version=p.model_version,
            )
        )

    mean_score = round(sum(scores) / len(scores), 2) if scores else 0.0

    return SupervisedClassificationResponse(
        total_events=len(predictions),
        severity_counts=sev_counts,
        mean_risk_score=mean_score,
        predictions=items,
    )


@router.post(
    "/train-risk-model",
    summary="Retrain Supervised XGBoost risk model",
    description="Retrains the supervised multi-class severity and regression pipeline on benchmark or uploaded security dataset.",
    response_model=SupervisedModelInfoResponse,
    status_code=status.HTTP_200_OK,
)
async def train_risk_model(
    request: RetrainSupervisedRequest = RetrainSupervisedRequest(),
) -> dict[str, Any]:
    service = get_risk_assessment_service()
    try:
        updated_info = service.retrain_supervised_model(
            dataset_path=request.dataset_path,
            n_estimators=request.n_estimators,
            max_depth=request.max_depth,
            learning_rate=request.learning_rate,
        )
        return updated_info
    except Exception as exc:
        logger.error("Failed to retrain supervised model", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Supervised model retraining failed: {exc}",
        )


# =============================================================================
# Phase 7: TreeSHAP Explainability Endpoints
# =============================================================================


class FeatureImpactItem(BaseModel):
    feature_name: str
    display_name: str
    domain: str
    shap_value: float
    feature_value: Any
    direction: str
    description: str


class LocalExplanationResponse(BaseModel):
    event_id: Optional[str] = None
    base_value: float
    predicted_risk_score: float
    top_risk_drivers: list[FeatureImpactItem]
    top_risk_mitigators: list[FeatureImpactItem]
    all_attributions: dict[str, float]


class GlobalFeatureImportanceItem(BaseModel):
    feature_name: str
    display_name: str
    domain: str
    mean_abs_shap: float
    relative_percentage: float
    description: str


class GlobalAttributionsResponse(BaseModel):
    model_version: str
    base_value: float
    sample_count_analyzed: int
    top_global_features: list[GlobalFeatureImportanceItem]
    domain_distribution: dict[str, float]


class BatchExplanationResponse(BaseModel):
    total_events: int
    explanations: list[LocalExplanationResponse]


@router.get(
    "/explain/global",
    summary="Get global TreeSHAP feature attribution rankings",
    description="Returns global feature importance rankings and security domain contributions learned by TreeSHAP across multi-cloud infrastructure.",
    response_model=GlobalAttributionsResponse,
    status_code=status.HTTP_200_OK,
)
async def get_global_shap_attributions(
    top_k: int = Query(8, ge=3, le=50, description="Number of top global features to return"),
) -> dict[str, Any]:
    service = get_risk_assessment_service()
    summary = service.get_global_shap_attributions(top_k=top_k)
    return summary.to_dict()


@router.post(
    "/explain/event",
    summary="Calculate TreeSHAP local attribution for a single event",
    description="Deconstructs a security telemetry event into additive feature impacts, identifying top risk drivers and mitigators.",
    response_model=LocalExplanationResponse,
    status_code=status.HTTP_200_OK,
)
async def explain_security_event(
    payload: dict[str, Any],
    top_k: int = Query(5, ge=1, le=20, description="Top positive and negative drivers to highlight"),
) -> dict[str, Any]:
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must contain a valid security event dictionary.",
        )
    service = get_risk_assessment_service()
    try:
        explanation = service.explain_security_event(payload, top_k=top_k)
        return explanation.to_dict()
    except Exception as exc:
        logger.error("Failed to explain event with TreeSHAP", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"TreeSHAP event explanation failed: {exc}",
        )


@router.post(
    "/explain/batch",
    summary="Calculate TreeSHAP local attributions for multiple events",
    description="Scores a batch of security telemetry events with TreeSHAP additive feature breakdowns.",
    response_model=BatchExplanationResponse,
    status_code=status.HTTP_200_OK,
)
async def explain_security_events_batch(
    payload: list[dict[str, Any]],
    top_k: int = Query(5, ge=1, le=20, description="Top drivers and mitigators per event"),
) -> BatchExplanationResponse:
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must contain at least one telemetry event.",
        )
    service = get_risk_assessment_service()
    try:
        explanations = service.explain_events_batch(payload, top_k=top_k)
        return BatchExplanationResponse(
            total_events=len(explanations),
            explanations=[
                LocalExplanationResponse(
                    event_id=e.event_id,
                    base_value=e.base_value,
                    predicted_risk_score=e.predicted_risk_score,
                    top_risk_drivers=[
                        FeatureImpactItem(
                            feature_name=f.feature_name,
                            display_name=f.display_name,
                            domain=f.domain,
                            shap_value=f.shap_value,
                            feature_value=f.feature_value,
                            direction=f.direction,
                            description=f.description,
                        )
                        for f in e.top_risk_drivers
                    ],
                    top_risk_mitigators=[
                        FeatureImpactItem(
                            feature_name=f.feature_name,
                            display_name=f.display_name,
                            domain=f.domain,
                            shap_value=f.shap_value,
                            feature_value=f.feature_value,
                            direction=f.direction,
                            description=f.description,
                        )
                        for f in e.top_risk_mitigators
                    ],
                    all_attributions=e.all_attributions,
                )
                for e in explanations
            ],
        )
    except Exception as exc:
        logger.error("Failed to explain batch with TreeSHAP", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"TreeSHAP batch explanation failed: {exc}",
        )

