"""Unit tests for ML models and evaluation metrics."""
import numpy as np
import pytest

from src.detection.evaluate import (
    calculate_binary_metrics,
    calculate_multiclass_metrics,
)
from src.detection.models import (
    get_anomaly_detector,
    get_binary_models,
    get_multiclass_models,
)


def test_binary_metrics_exact_calculation():
    # 2 TN, 1 FP, 1 FN, 2 TP
    y_true = np.array([0, 0, 0, 1, 1, 1])
    y_pred = np.array([0, 0, 1, 0, 1, 1])
    y_prob = np.array([[0.8, 0.2], [0.9, 0.1], [0.4, 0.6], [0.7, 0.3], [0.2, 0.8], [0.1, 0.9]])

    metrics = calculate_binary_metrics(y_true, y_pred, y_prob)

    assert metrics["tn"] == 2
    assert metrics["fp"] == 1
    assert metrics["fn"] == 1
    assert metrics["tp"] == 2
    assert pytest.approx(metrics["accuracy"], 0.01) == 4 / 6
    assert pytest.approx(metrics["fpr"], 0.01) == 1 / 3
    assert pytest.approx(metrics["fnr"], 0.01) == 1 / 3
    assert metrics["roc_auc"] is not None


def test_multiclass_metrics_calculation():
    y_true = np.array([0, 1, 2, 0, 1, 2])
    y_pred = np.array([0, 1, 2, 0, 2, 1])
    class_names = ["BENIGN", "DoS", "PortScan"]

    metrics = calculate_multiclass_metrics(y_true, y_pred, class_names=class_names)
    assert metrics["accuracy"] == 4 / 6
    assert "precision_macro" in metrics
    assert "recall_macro" in metrics
    assert "per_class_report" in metrics


def test_model_instantiations():
    bin_models = get_binary_models()
    assert "LogisticRegression" in bin_models
    assert "RandomForest" in bin_models
    assert "XGBoost" in bin_models

    mul_models = get_multiclass_models(num_classes=8)
    assert "LogisticRegression" in mul_models
    assert "RandomForest" in mul_models
    assert "XGBoost" in mul_models

    iso = get_anomaly_detector(contamination=0.1)
    assert iso is not None

