"""Pydantic v2 schemas for the NIDS FastAPI backend."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NetworkFlowInput(BaseModel):
    """Network flow input containing flow features and optional network metadata."""
    # Network identifiers (optional, used for CTI and logging)
    flow_id: Optional[str] = Field(None, description="Flow unique identifier")
    source_ip: Optional[str] = Field("192.168.10.50", description="Source IPv4 address")
    destination_ip: Optional[str] = Field("172.16.0.1", description="Destination IPv4 address")
    destination_port: Optional[int] = Field(80, description="Destination Port (e.g. 80, 443, 22)")
    protocol: Optional[int] = Field(6, description="Transport protocol (6=TCP, 17=UDP)")

    # Flow numeric features (dictionary mapping feature name to numeric value)
    features: Dict[str, float] = Field(
        default_factory=dict,
        description="Dictionary of numerical network flow features (e.g. 'Flow Duration', 'Bwd Packets/s')",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "source_ip": "172.16.0.1",
                "destination_ip": "192.168.10.50",
                "destination_port": 80,
                "protocol": 6,
                "features": {
                    "Destination Port": 80,
                    "Flow Duration": 120000,
                    "Flow Packets/s": 4500.5,
                    "Bwd Packets/s": 2200.0,
                    "Init_Win_bytes_forward": 29200,
                    "Average Packet Size": 512.0,
                },
            }
        }
    }


class BatchFlowInput(BaseModel):
    """Batch of network flows for bulk inference."""
    flows: List[NetworkFlowInput]


class PredictionResponse(BaseModel):
    """Single flow prediction response."""
    flow_id: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    predicted_class: str = Field(..., description="Multiclass attack prediction")
    is_malicious: bool = Field(..., description="Binary classification (True=Malicious, False=BENIGN)")
    confidence: float = Field(..., description="Model probability for predicted class (0.0 to 1.0)")
    probabilities: Dict[str, float] = Field(default_factory=dict)
    is_anomaly: bool = Field(..., description="Unsupervised Isolation Forest anomaly flag")
    anomaly_score: float = Field(..., description="Normalized anomaly score")
    risk_score: float = Field(..., description="Calculated multi-factor risk score (0 to 100)")
    risk_level: str = Field(..., description="LOW, MEDIUM, HIGH, or CRITICAL")
    justification: str = Field(..., description="Explainable rationale grounded in features & threat intel")
    recommended_action: str = Field(..., description="Operational response recommendation for SOC analysts")
    cti_reputation: Optional[float] = Field(None, description="Enriched CTI reputation score if available")
    latency_ms: float = Field(..., description="Inference latency in milliseconds")


class BatchPredictionResponse(BaseModel):
    """Batch prediction aggregated response."""
    total_flows: int
    attacks_detected: int
    anomalies_detected: int
    high_critical_risk_count: int
    predictions: List[PredictionResponse]


class AnomalyDetectionResponse(BaseModel):
    """Isolation Forest anomaly detection output."""
    is_anomaly: bool
    anomaly_score: float
    decision: str
    threshold: float


class ExplanationRequest(BaseModel):
    """Request for SHAP local flow explanation."""
    flow: NetworkFlowInput
    top_k: int = Field(5, description="Number of top influential features to return")


class ExplanationResponse(BaseModel):
    """SHAP explanation response."""
    predicted_class: str
    probability: float
    base_value: float
    top_positive_features: List[Dict[str, Any]]
    top_negative_features: List[Dict[str, Any]]
    all_feature_impacts: Dict[str, float]


class AlertItem(BaseModel):
    """Stored security alert model."""
    id: int
    timestamp: str
    flow_id: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    predicted_class: str
    confidence: float
    is_anomaly: bool
    anomaly_score: float
    risk_score: float
    risk_level: str
    justification: Optional[str]
    status: str


class AlertsListResponse(BaseModel):
    """List of alerts."""
    total: int
    alerts: List[AlertItem]


class StatisticsResponse(BaseModel):
    """System-wide threat intelligence and detection statistics."""
    total_alerts: int
    alerts_by_risk_level: Dict[str, int]
    attacks_by_class: Dict[str, int]
    average_risk_score: float
    system_status: str
    models_loaded: List[str]


class HealthResponse(BaseModel):
    """Service health response."""
    status: str
    version: str
    active_database: str
    models_active: Dict[str, bool]
    shap_active: bool
    total_alerts_stored: int

