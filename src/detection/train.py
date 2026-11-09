"""Model training orchestrator for Binary, Multiclass, and Anomaly Detection.

Trains, evaluates, tunes, and serializes:
1. Logistic Regression (Baseline)
2. Random Forest Classifier
3. XGBoost Classifier
4. Isolation Forest (Unsupervised Anomaly Detector)
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd

from src.config import (
    ANOMALY_MODEL_DIR,
    CLASSIFICATION_MODEL_DIR,
    EVALUATION_DIR,
    FIGURES_DIR,
    PROCESSED_DIR,
)
from src.detection.evaluate import (
    calculate_binary_metrics,
    calculate_multiclass_metrics,
    plot_confusion_matrix,
    plot_model_comparison,
)
from src.detection.models import (
    get_anomaly_detector,
    get_binary_models,
    get_multiclass_models,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("trainer")


def train_and_evaluate_all() -> Dict[str, Any]:
    """Train all models, compute metrics, plot diagnostics, and serialize models."""
    splits_path = PROCESSED_DIR / "processed_splits.npz"
    meta_path = PROCESSED_DIR / "preprocessing_metadata.json"

    if not splits_path.exists() or not meta_path.exists():
        raise FileNotFoundError(f"Missing processed data in {PROCESSED_DIR}. Run preprocessing first.")

    logger.info("Loading preprocessed dataset splits from %s ...", splits_path)
    data = np.load(splits_path)
    X_train = data["X_train"]
    X_test = data["X_test"]
    y_train_bin = data["y_train_bin"]
    y_test_bin = data["y_test_bin"]
    y_train_mul = data["y_train_mul"]
    y_test_mul = data["y_test_mul"]

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    classes = meta["classes"]
    class_mapping = meta["class_mapping"]

    logger.info("Loaded splits: X_train=%s, X_test=%s, num_classes=%d", X_train.shape, X_test.shape, len(classes))

    results: Dict[str, Any] = {"binary": {}, "multiclass": {}, "anomaly_detection": {}}
    comparison_rows = []

    # ==========================================
    # 1. Binary Classification Training
    # ==========================================
    logger.info("--- Starting Binary Classification Benchmarks ---")
    binary_models = get_binary_models()
    for name, model in binary_models.items():
        logger.info("Training Binary %s ...", name)
        model.fit(X_train, y_train_bin)

        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None
        metrics = calculate_binary_metrics(y_test_bin, y_pred, y_prob)
        results["binary"][name] = metrics

        logger.info("Binary %s: Accuracy=%.4f, Macro-F1=%.4f, FPR=%.4f, FNR=%.4f",
                    name, metrics["accuracy"], metrics["f1_macro"], metrics["fpr"], metrics["fnr"])

        # Save model
        model_save_path = CLASSIFICATION_MODEL_DIR / f"binary_{name.lower()}.joblib"
        joblib.dump(model, model_save_path)

        # Plot confusion matrix
        plot_confusion_matrix(
            y_test_bin,
            y_pred,
            class_names=["BENIGN", "MALICIOUS"],
            title=f"Binary Confusion Matrix - {name}",
            output_path=FIGURES_DIR / f"confusion_matrix_binary_{name.lower()}.png",
        )

        comparison_rows.append({
            "model": name,
            "task": "binary",
            "accuracy": metrics["accuracy"],
            "f1_macro": metrics["f1_macro"],
            "f1_weighted": metrics["f1_weighted"],
            "fpr": metrics["fpr"],
            "fnr": metrics["fnr"],
            "roc_auc": metrics.get("roc_auc"),
        })

    # ==========================================
    # 2. Multiclass Classification Training
    # ==========================================
    logger.info("--- Starting Multiclass Classification Benchmarks ---")
    multi_models = get_multiclass_models(num_classes=len(classes))
    for name, model in multi_models.items():
        logger.info("Training Multiclass %s ...", name)
        model.fit(X_train, y_train_mul)

        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None
        metrics = calculate_multiclass_metrics(y_test_mul, y_pred, y_prob, class_names=classes)
        results["multiclass"][name] = metrics

        logger.info("Multiclass %s: Accuracy=%.4f, Macro-F1=%.4f, Weighted-F1=%.4f",
                    name, metrics["accuracy"], metrics["f1_macro"], metrics["f1_weighted"])

        # Save model
        model_save_path = CLASSIFICATION_MODEL_DIR / f"multiclass_{name.lower()}.joblib"
        joblib.dump(model, model_save_path)

        # Plot confusion matrix
        plot_confusion_matrix(
            y_test_mul,
            y_pred,
            class_names=classes,
            title=f"Multiclass Confusion Matrix - {name}",
            output_path=FIGURES_DIR / f"confusion_matrix_multiclass_{name.lower()}.png",
        )

        comparison_rows.append({
            "model": name,
            "task": "multiclass",
            "accuracy": metrics["accuracy"],
            "f1_macro": metrics["f1_macro"],
            "f1_weighted": metrics["f1_weighted"],
            "fpr": metrics["mean_fpr"],
            "fnr": metrics["mean_fnr"],
            "roc_auc": metrics.get("roc_auc_ovr"),
        })

    # ==========================================
    # 3. Unsupervised Anomaly Detection (Isolation Forest)
    # ==========================================
    logger.info("--- Training Unsupervised Anomaly Detector (Isolation Forest) ---")
    # Train Isolation Forest on normal (benign) traffic to model baseline network behavior
    benign_idx = np.where(y_train_bin == 0)[0]
    X_train_benign = X_train[benign_idx]

    iso_forest = get_anomaly_detector(contamination=0.15)
    iso_forest.fit(X_train_benign)

    # In Isolation Forest: -1 is anomaly/outlier, 1 is inlier/normal
    raw_preds = iso_forest.predict(X_test)
    y_pred_anomaly = (raw_preds == -1).astype(int)  # 1 for anomaly, 0 for normal
    anomaly_scores = -iso_forest.score_samples(X_test)  # higher = more anomalous

    anomaly_metrics = calculate_binary_metrics(y_test_bin, y_pred_anomaly, anomaly_scores)
    results["anomaly_detection"]["IsolationForest"] = anomaly_metrics
    logger.info("Isolation Forest: Anomaly Accuracy=%.4f, Macro-F1=%.4f, ROC-AUC=%.4f",
                anomaly_metrics["accuracy"], anomaly_metrics["f1_macro"], anomaly_metrics.get("roc_auc", 0.0))

    iso_save_path = ANOMALY_MODEL_DIR / "isolation_forest.joblib"
    joblib.dump(iso_forest, iso_save_path)

    # Save benchmark table and plot
    comp_df = pd.DataFrame(comparison_rows)
    comp_df.to_csv(EVALUATION_DIR / "model_comparison.csv", index=False)
    plot_model_comparison(comp_df[comp_df["task"] == "multiclass"])

    with open(EVALUATION_DIR / "model_benchmarks.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    logger.info("All models successfully trained, evaluated, and saved.")
    return results


if __name__ == "__main__":
    train_and_evaluate_all()

