"""Evaluation metrics, diagnostic analysis, and publication-ready visualizations.

Calculates:
- Accuracy, Precision (Macro/Weighted), Recall (Macro/Weighted), F1-Score (Macro/Weighted)
- False Positive Rate (FPR) and False Negative Rate (FNR)
- ROC-AUC (Binary and Multiclass One-vs-Rest)
- Confusion Matrix plots and error breakdown
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from src.config import FIGURES_DIR

logger = logging.getLogger(__name__)


def calculate_binary_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: Optional[np.ndarray] = None,
) -> Dict[str, Any]:
    """Calculate complete binary classification metrics including FPR and FNR."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "fpr": fpr,
        "fnr": fnr,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }

    if y_prob is not None:
        try:
            # Check if prob is 2D or 1D
            prob = y_prob[:, 1] if y_prob.ndim == 2 else y_prob
            metrics["roc_auc"] = float(roc_auc_score(y_true, prob))
        except Exception:
            metrics["roc_auc"] = None

    return metrics


def calculate_multiclass_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: Optional[np.ndarray] = None,
    class_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Calculate comprehensive multiclass metrics and per-class performance."""
    cm = confusion_matrix(y_true, y_pred)
    n_classes = len(cm)

    # Per-class FPR and FNR calculation
    fpr_list, fnr_list = [], []
    for i in range(n_classes):
        tp = cm[i, i]
        fn = cm[i, :].sum() - tp
        fp = cm[:, i].sum() - tp
        tn = cm.sum() - (tp + fn + fp)
        fpr_i = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr_i = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        fpr_list.append(fpr_i)
        fnr_list.append(fnr_i)

    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "precision_weighted": float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall_weighted": float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "mean_fpr": float(np.mean(fpr_list)),
        "mean_fnr": float(np.mean(fnr_list)),
        "confusion_matrix": cm.tolist(),
    }

    if y_prob is not None:
        try:
            metrics["roc_auc_ovr"] = float(
                roc_auc_score(y_true, y_prob, multi_class="ovr", average="macro")
            )
        except Exception:
            metrics["roc_auc_ovr"] = None

    if class_names:
        report = classification_report(
            y_true, y_pred, target_names=class_names, output_dict=True, zero_division=0
        )
        metrics["per_class_report"] = report

    return metrics


def plot_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: List[str],
    title: str,
    output_path: Path,
) -> Path:
    """Generate and save publication-quality confusion matrix heatmap."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cm = confusion_matrix(y_true, y_pred)
    cm_norm = cm.astype("float") / np.maximum(cm.sum(axis=1)[:, np.newaxis], 1)

    fig, ax = plt.subplots(figsize=(8, 6.5))
    sns.heatmap(
        cm_norm,
        annot=True,
        fmt=".2f",
        cmap="Blues",
        xticklabels=class_names,
        yticklabels=class_names,
        ax=ax,
        cbar_kws={"label": "Normalized Proportion"},
    )
    ax.set_title(title, fontsize=12, pad=12)
    ax.set_xlabel("Predicted Class", fontsize=10)
    ax.set_ylabel("True Class", fontsize=10)
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    fig.tight_layout()
    fig.savefig(output_path, dpi=200)
    plt.close(fig)
    return output_path


def plot_model_comparison(
    comparison_df: pd.DataFrame,
    output_path: Path = FIGURES_DIR / "model_benchmark_comparison.png",
) -> Path:
    """Generate side-by-side performance comparison bar plot."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(10, 5))
    metrics_to_plot = ["accuracy", "f1_macro", "f1_weighted"]
    plot_df = comparison_df.melt(
        id_vars=["model", "task"],
        value_vars=[m for m in metrics_to_plot if m in comparison_df.columns],
        var_name="Metric",
        value_name="Score",
    )
    sns.barplot(data=plot_df, x="model", y="Score", hue="Metric", palette="Blues_d", ax=ax)
    ax.set_title("Machine Learning Model Performance Comparison (NIDS)", fontsize=13)
    ax.set_ylim(0.7, 1.02)
    ax.set_ylabel("Score", fontsize=10)
    ax.set_xlabel("Model Architecture", fontsize=10)
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(output_path, dpi=200)
    plt.close(fig)
    return output_path

