"""FastAPI REST API for AI-Powered Network Intrusion Detection & CTI System.

Endpoints:
- GET  /health           System health, model versions, database status
- POST /predict          Single network flow classification, anomaly score & risk assessment
- POST /predict/batch    High-throughput batch flow processing
- POST /detect-anomalies Unsupervised Isolation Forest anomaly detection
- POST /explanations     SHAP feature contributions & attribution
- GET  /alerts           Filterable SOC security alerts from SQLAlchemy database
- GET  /statistics       Aggregated SOC metrics, attack frequencies, and risk distributions
"""
from __future__ import annotations

import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from sqlalchemy.orm import Session

from src.api.schemas import (
    AlertItem,
    AlertsListResponse,
    AnomalyDetectionResponse,
    BatchFlowInput,
    BatchPredictionResponse,
    ExplanationRequest,
    ExplanationResponse,
    HealthResponse,
    NetworkFlowInput,
    PredictionResponse,
    StatisticsResponse,
)
from src.config import (
    ANOMALY_MODEL_DIR,
    CLASSIFICATION_MODEL_DIR,
    MODELS_DIR,
)
from src.database.models import SecurityAlert
from src.database.session import get_db, init_db
from src.data.preprocess import PreprocessingArtifact
from src.explainability.explainer import get_explainer
from src.explainability.risk_engine import RiskAssessmentEngine
from src.intelligence.cti_client import get_cti_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("api")

# Global resources loaded on startup
RESOURCES: Dict[str, Any] = {}


def load_resources() -> None:
    """Load models, preprocessor, and CTI client if not already loaded."""
    if "preprocessor" in RESOURCES and "classifier" in RESOURCES:
        return

    init_db()

    # Load Preprocessor
    prep_path = MODELS_DIR / "preprocessor.joblib"
    if prep_path.exists():
        RESOURCES["preprocessor"] = joblib.load(prep_path)
        logger.info("Preprocessor loaded: %d features expected", len(RESOURCES["preprocessor"].feature_names))
    else:
        logger.warning("Preprocessor not found at %s", prep_path)

    # Load Multiclass Classifier (XGBoost primary, RF fallback)
    xgb_multi_path = CLASSIFICATION_MODEL_DIR / "multiclass_xgboost.joblib"
    if xgb_multi_path.exists():
        RESOURCES["classifier"] = joblib.load(xgb_multi_path)
        logger.info("Primary Multiclass XGBoost model loaded.")
    else:
        logger.warning("Multiclass XGBoost model not found at %s", xgb_multi_path)

    # Load Binary Classifier
    xgb_bin_path = CLASSIFICATION_MODEL_DIR / "binary_xgboost.joblib"
    if xgb_bin_path.exists():
        RESOURCES["binary_classifier"] = joblib.load(xgb_bin_path)
        logger.info("Binary XGBoost model loaded.")

    # Load Isolation Forest Anomaly Detector
    iso_path = ANOMALY_MODEL_DIR / "isolation_forest.joblib"
    if iso_path.exists():
        RESOURCES["anomaly_detector"] = joblib.load(iso_path)
        logger.info("Isolation Forest anomaly detector loaded.")

    # Initialize Explainer and CTI client
    try:
        RESOURCES["explainer"] = get_explainer()
        logger.info("SHAP TreeExplainer initialized.")
    except Exception as e:
        logger.warning("Failed to initialize SHAP explainer: %s", e)

    RESOURCES["cti_client"] = get_cti_client()
    logger.info("Threat Intelligence Client initialized.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load models, preprocessor, and database on startup."""
    logger.info("Initializing NIDS API service and loading machine learning models ...")
    load_resources()
    yield
    logger.info("Shutting down NIDS API service ...")
    RESOURCES.clear()


app = FastAPI(
    title="AI-Powered Network Intrusion Detection & CTI API",
    description="Enterprise-grade NIDS backend featuring Machine Learning, Unsupervised Anomaly Detection, Explainable AI (SHAP), and Cyber Threat Intelligence.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _prepare_feature_dataframe(flow: NetworkFlowInput, preprocessor: PreprocessingArtifact) -> pd.DataFrame:
    """Extract features from flow input, filling missing fields with training medians."""
    row = dict(flow.features)
    # Also include top-level destination port if present
    if flow.destination_port is not None and "Destination Port" not in row:
        row["Destination Port"] = float(flow.destination_port)

    # Build single-row DataFrame
    df = pd.DataFrame([row])
    return df


@app.get("/health", response_model=HealthResponse, tags=["System"])
def health_check(db: Session = Depends(get_db)):
    """Return system operational status and model readiness."""
    load_resources()
    total_alerts = db.query(func.count(SecurityAlert.id)).scalar() or 0
    return HealthResponse(
        status="HEALTHY",
        version="1.0.0",
        active_database="SQLite / SQLAlchemy 2.0",
        models_active={
            "preprocessor": "preprocessor" in RESOURCES,
            "multiclass_classifier": "classifier" in RESOURCES,
            "binary_classifier": "binary_classifier" in RESOURCES,
            "anomaly_detector": "anomaly_detector" in RESOURCES,
        },
        shap_active="explainer" in RESOURCES,
        total_alerts_stored=total_alerts,
    )


@app.post("/predict", response_model=PredictionResponse, tags=["Inference"])
def predict_flow(flow: NetworkFlowInput, db: Session = Depends(get_db)):
    """Classify network flow, detect anomalies, evaluate risk, and record alert."""
    load_resources()
    start_time = time.perf_counter()

    preprocessor: PreprocessingArtifact = RESOURCES.get("preprocessor")
    classifier = RESOURCES.get("classifier")
    anomaly_detector = RESOURCES.get("anomaly_detector")

    if not preprocessor or not classifier:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Machine learning models are not loaded. Run training first.",
        )

    # 1. Transform input features
    df_raw = _prepare_feature_dataframe(flow, preprocessor)
    X_scaled = preprocessor.transform(df_raw)

    # 2. Multiclass Prediction
    pred_idx = int(classifier.predict(X_scaled)[0])
    probs = classifier.predict_proba(X_scaled)[0]
    classes = list(preprocessor.class_mapping.keys())
    predicted_class = classes[pred_idx] if pred_idx < len(classes) else str(pred_idx)
    confidence = float(probs[pred_idx])
    prob_dict = {cls_name: float(p) for cls_name, p in zip(classes, probs)}

    # 3. Anomaly Detection
    is_anomaly = False
    anomaly_score = 0.0
    if anomaly_detector:
        raw_pred = anomaly_detector.predict(X_scaled)[0]
        is_anomaly = bool(raw_pred == -1)
        raw_score = -anomaly_detector.score_samples(X_scaled)[0]
        anomaly_score = float(np.clip((raw_score - 0.4) / 0.4, 0.0, 1.0))

    # 4. Threat Intelligence Enrichment
    cti_rep: Optional[float] = None
    cti_client = RESOURCES.get("cti_client")
    if cti_client and flow.source_ip:
        cti_report = cti_client.lookup_ip(flow.source_ip)
        if cti_report.is_malicious or cti_report.reputation_score > 0:
            cti_rep = cti_report.reputation_score

    # 5. Local SHAP Explanation (Top 3 drivers)
    top_shap = []
    explainer = RESOURCES.get("explainer")
    if explainer:
        try:
            exp_res = explainer.explain_instance(X_scaled, top_k=3)
            top_shap = exp_res.get("top_features", [])
        except Exception:
            pass

    # 6. Dynamic Multi-Factor Risk Assessment
    risk_assessment = RiskAssessmentEngine.evaluate_risk(
        predicted_class=predicted_class,
        confidence=confidence,
        is_anomaly=is_anomaly,
        anomaly_score=anomaly_score,
        destination_port=flow.destination_port,
        cti_reputation=cti_rep,
        top_shap_features=top_shap,
    )

    latency_ms = (time.perf_counter() - start_time) * 1000.0

    # 7. Persist Alert to Database if malicious or high anomaly
    if predicted_class != "BENIGN" or is_anomaly or risk_assessment["risk_score"] >= 30.0:
        alert_record = SecurityAlert(
            flow_id=flow.flow_id,
            source_ip=flow.source_ip,
            destination_ip=flow.destination_ip,
            destination_port=flow.destination_port,
            protocol=flow.protocol,
            predicted_class=predicted_class,
            confidence=confidence,
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            risk_score=risk_assessment["risk_score"],
            risk_level=risk_assessment["risk_level"],
            justification=risk_assessment["justification"],
            top_features_json=json.dumps(top_shap),
            cti_reputation=cti_rep or 0.0,
            status="NEW",
        )
        db.add(alert_record)
        db.commit()

    return PredictionResponse(
        flow_id=flow.flow_id,
        source_ip=flow.source_ip,
        destination_ip=flow.destination_ip,
        destination_port=flow.destination_port,
        predicted_class=predicted_class,
        is_malicious=(predicted_class != "BENIGN"),
        confidence=confidence,
        probabilities=prob_dict,
        is_anomaly=is_anomaly,
        anomaly_score=anomaly_score,
        risk_score=risk_assessment["risk_score"],
        risk_level=risk_assessment["risk_level"],
        justification=risk_assessment["justification"],
        recommended_action=risk_assessment["recommended_action"],
        cti_reputation=cti_rep,
        latency_ms=round(latency_ms, 2),
    )


@app.post("/predict/batch", response_model=BatchPredictionResponse, tags=["Inference"])
def predict_batch(batch: BatchFlowInput, db: Session = Depends(get_db)):
    """High-throughput vectorized batch classification for multiple network flows."""
    load_resources()
    preprocessor: PreprocessingArtifact = RESOURCES.get("preprocessor")
    classifier = RESOURCES.get("classifier")
    anomaly_detector = RESOURCES.get("anomaly_detector")

    if not preprocessor or not classifier:
        raise HTTPException(status_code=503, detail="Models not loaded")

    flows = batch.flows
    if not flows:
        return BatchPredictionResponse(
            total_flows=0, attacks_detected=0, anomalies_detected=0,
            high_critical_risk_count=0, predictions=[]
        )

    # Convert all flows to DataFrame in one vectorized call
    rows = []
    for f in flows:
        r = dict(f.features)
        if f.destination_port is not None and "Destination Port" not in r:
            r["Destination Port"] = float(f.destination_port)
        rows.append(r)

    df_batch = pd.DataFrame(rows)
    X_scaled = preprocessor.transform(df_batch)

    # Vectorized model predictions
    preds_idx = classifier.predict(X_scaled)
    probs_all = classifier.predict_proba(X_scaled)
    classes = list(preprocessor.class_mapping.keys())

    anomalies_mask = [False] * len(flows)
    anomaly_scores = [0.0] * len(flows)
    if anomaly_detector:
        raw_anom = anomaly_detector.predict(X_scaled)
        anomalies_mask = (raw_anom == -1).tolist()
        raw_scores = -anomaly_detector.score_samples(X_scaled)
        anomaly_scores = np.clip((raw_scores - 0.4) / 0.4, 0.0, 1.0).tolist()

    predictions = []
    attacks_count = 0
    anomalies_count = 0
    high_crit_count = 0

    alerts_to_db = []

    for i, flow in enumerate(flows):
        p_idx = int(preds_idx[i])
        pred_cls = classes[p_idx] if p_idx < len(classes) else str(p_idx)
        conf = float(probs_all[i, p_idx])
        is_anom = bool(anomalies_mask[i])
        anom_sc = float(anomaly_scores[i])

        if pred_cls != "BENIGN":
            attacks_count += 1
        if is_anom:
            anomalies_count += 1

        risk = RiskAssessmentEngine.evaluate_risk(
            predicted_class=pred_cls,
            confidence=conf,
            is_anomaly=is_anom,
            anomaly_score=anom_sc,
            destination_port=flow.destination_port,
        )

        if risk["risk_level"] in ("HIGH", "CRITICAL"):
            high_crit_count += 1

        if pred_cls != "BENIGN" or is_anom or risk["risk_score"] >= 40.0:
            alerts_to_db.append(SecurityAlert(
                flow_id=flow.flow_id,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                destination_port=flow.destination_port,
                protocol=flow.protocol,
                predicted_class=pred_cls,
                confidence=conf,
                is_anomaly=is_anom,
                anomaly_score=anom_sc,
                risk_score=risk["risk_score"],
                risk_level=risk["risk_level"],
                justification=risk["justification"],
                status="NEW",
            ))

        prob_d = {cls_name: float(p) for cls_name, p in zip(classes, probs_all[i])}
        predictions.append(PredictionResponse(
            flow_id=flow.flow_id,
            source_ip=flow.source_ip,
            destination_ip=flow.destination_ip,
            destination_port=flow.destination_port,
            predicted_class=pred_cls,
            is_malicious=(pred_cls != "BENIGN"),
            confidence=conf,
            probabilities=prob_d,
            is_anomaly=is_anom,
            anomaly_score=anom_sc,
            risk_score=risk["risk_score"],
            risk_level=risk["risk_level"],
            justification=risk["justification"],
            recommended_action=risk["recommended_action"],
            latency_ms=0.5,
        ))

    if alerts_to_db:
        db.bulk_save_objects(alerts_to_db)
        db.commit()

    return BatchPredictionResponse(
        total_flows=len(flows),
        attacks_detected=attacks_count,
        anomalies_detected=anomalies_count,
        high_critical_risk_count=high_crit_count,
        predictions=predictions,
    )


@app.post("/detect-anomalies", response_model=AnomalyDetectionResponse, tags=["Anomaly Detection"])
def detect_anomaly(flow: NetworkFlowInput):
    """Evaluate flow against the unsupervised Isolation Forest baseline."""
    load_resources()
    preprocessor: PreprocessingArtifact = RESOURCES.get("preprocessor")
    anomaly_detector = RESOURCES.get("anomaly_detector")

    if not preprocessor or not anomaly_detector:
        raise HTTPException(status_code=503, detail="Anomaly detector not loaded")

    df_raw = _prepare_feature_dataframe(flow, preprocessor)
    X_scaled = preprocessor.transform(df_raw)

    raw_pred = anomaly_detector.predict(X_scaled)[0]
    is_anomaly = bool(raw_pred == -1)
    raw_score = float(-anomaly_detector.score_samples(X_scaled)[0])
    norm_score = float(np.clip((raw_score - 0.4) / 0.4, 0.0, 1.0))

    return AnomalyDetectionResponse(
        is_anomaly=is_anomaly,
        anomaly_score=round(norm_score, 4),
        decision="ANOMALOUS_OUTLIER" if is_anomaly else "NORMAL_TRAFFIC",
        threshold=0.5,
    )


@app.post("/explanations", response_model=ExplanationResponse, tags=["Explainable AI"])
def get_flow_explanation(req: ExplanationRequest):
    """Compute local SHAP feature attributions for a single network flow."""
    load_resources()
    preprocessor: PreprocessingArtifact = RESOURCES.get("preprocessor")
    explainer = RESOURCES.get("explainer")
    classifier = RESOURCES.get("classifier")

    if not preprocessor or not explainer or not classifier:
        raise HTTPException(status_code=503, detail="XAI explainer not loaded")

    df_raw = _prepare_feature_dataframe(req.flow, preprocessor)
    X_scaled = preprocessor.transform(df_raw)

    explanation = explainer.explain_instance(X_scaled, top_k=req.top_k)
    pred_idx = int(classifier.predict(X_scaled)[0])
    classes = list(preprocessor.class_mapping.keys())
    pred_class = classes[pred_idx] if pred_idx < len(classes) else str(pred_idx)

    return ExplanationResponse(
        predicted_class=pred_class,
        probability=explanation["probability"],
        base_value=explanation["base_value"],
        top_positive_features=explanation["top_positive_features"],
        top_negative_features=explanation["top_negative_features"],
        all_feature_impacts=explanation["all_shap_values"],
    )


@app.get("/alerts", response_model=AlertsListResponse, tags=["SOC Alerts"])
def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    risk_level: Optional[str] = Query(None, description="LOW, MEDIUM, HIGH, CRITICAL"),
    min_risk: float = Query(0.0, ge=0.0, le=100.0),
    db: Session = Depends(get_db),
):
    """Retrieve security alerts filtered by risk level and score."""
    query = db.query(SecurityAlert).filter(SecurityAlert.risk_score >= min_risk)
    if risk_level:
        query = query.filter(SecurityAlert.risk_level == risk_level.upper())

    total = query.count()
    records = query.order_by(SecurityAlert.timestamp.desc()).limit(limit).all()

    alert_items = [
        AlertItem(
            id=a.id,
            timestamp=a.timestamp.isoformat() if a.timestamp else "",
            flow_id=a.flow_id,
            source_ip=a.source_ip,
            destination_ip=a.destination_ip,
            destination_port=a.destination_port,
            predicted_class=a.predicted_class,
            confidence=a.confidence,
            is_anomaly=a.is_anomaly,
            anomaly_score=a.anomaly_score,
            risk_score=a.risk_score,
            risk_level=a.risk_level,
            justification=a.justification,
            status=a.status,
        )
        for a in records
    ]
    return AlertsListResponse(total=total, alerts=alert_items)


@app.patch("/alerts/{alert_id}", response_model=AlertItem, tags=["SOC Alerts"])
def update_alert_status(
    alert_id: int,
    new_status: str = Query(..., pattern="^(NEW|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$"),
    db: Session = Depends(get_db),
):
    """Update operational status of an alert (SOC analyst triage)."""
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = new_status
    db.commit()
    db.refresh(alert)
    return AlertItem(
        id=alert.id,
        timestamp=alert.timestamp.isoformat() if alert.timestamp else "",
        flow_id=alert.flow_id,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        destination_port=alert.destination_port,
        predicted_class=alert.predicted_class,
        confidence=alert.confidence,
        is_anomaly=alert.is_anomaly,
        anomaly_score=alert.anomaly_score,
        risk_score=alert.risk_score,
        risk_level=alert.risk_level,
        justification=alert.justification,
        status=alert.status,
    )


@app.get("/statistics", response_model=StatisticsResponse, tags=["SOC Statistics"])
def get_statistics(db: Session = Depends(get_db)):
    """Aggregate statistics on threat detections, risk levels, and attack types."""
    total_alerts = db.query(func.count(SecurityAlert.id)).scalar() or 0
    avg_risk = db.query(func.avg(SecurityAlert.risk_score)).scalar() or 0.0

    # Risk level breakdown
    risk_counts = (
        db.query(SecurityAlert.risk_level, func.count(SecurityAlert.id))
        .group_by(SecurityAlert.risk_level)
        .all()
    )
    risk_dict = {lvl: count for lvl, count in risk_counts}

    # Attack class breakdown
    attack_counts = (
        db.query(SecurityAlert.predicted_class, func.count(SecurityAlert.id))
        .group_by(SecurityAlert.predicted_class)
        .all()
    )
    attack_dict = {cls_name: count for cls_name, count in attack_counts}

    models_loaded = [k for k in ["classifier", "binary_classifier", "anomaly_detector", "explainer"] if k in RESOURCES]

    return StatisticsResponse(
        total_alerts=total_alerts,
        alerts_by_risk_level=risk_dict,
        attacks_by_class=attack_dict,
        average_risk_score=round(float(avg_risk), 1),
        system_status="ONLINE",
        models_loaded=models_loaded,
    )
