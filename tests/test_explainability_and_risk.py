"""Unit tests for Explainable AI (SHAP) and Dynamic Risk Assessment."""
import numpy as np
import pytest

from src.explainability.explainer import get_explainer
from src.explainability.risk_engine import RiskAssessmentEngine


def test_risk_assessment_engine_benign():
    result = RiskAssessmentEngine.evaluate_risk(
        predicted_class="BENIGN",
        confidence=0.98,
        is_anomaly=False,
    )
    assert result["risk_level"] == "LOW"
    assert result["risk_score"] < 25.0
    assert "BENIGN" in result["justification"]


def test_risk_assessment_engine_critical_ddos():
    result = RiskAssessmentEngine.evaluate_risk(
        predicted_class="DDoS",
        confidence=0.99,
        is_anomaly=True,
        anomaly_score=0.85,
        destination_port=80,
    )
    assert result["risk_level"] == "CRITICAL"
    assert result["risk_score"] >= 80.0
    assert "DDoS" in result["justification"]
    assert "Isolation Forest" in result["justification"]


def test_risk_assessment_engine_port_and_cti_boost():
    result = RiskAssessmentEngine.evaluate_risk(
        predicted_class="BruteForce",
        confidence=0.90,
        destination_port=22,
        cti_reputation=90.0,
    )
    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert "SSH" in result["justification"]
    assert "Threat Intelligence" in result["justification"]


def test_explainer_local_instance():
    explainer = get_explainer()
    dummy_input = np.zeros((1, len(explainer.feature_names)))
    explanation = explainer.explain_instance(dummy_input, top_k=3)

    assert "probability" in explanation
    assert "top_features" in explanation
    assert len(explanation["top_features"]) <= 3
    assert "all_shap_values" in explanation

