"""SHAP Explainable AI (XAI) engine for Network Intrusion Detection.

Provides:
- Global feature importance (TreeExplainer)
- Local individual flow explanations with feature contributions
- Publication-quality summary and beeswarm plots
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sys
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import shap

from src.config import CLASSIFICATION_MODEL_DIR, FIGURES_DIR, MODELS_DIR, PROCESSED_DIR
from src.data.preprocess import PreprocessingArtifact

# Defensive alias for pickle unpickling
setattr(sys.modules["__main__"], "PreprocessingArtifact", PreprocessingArtifact)

logger = logging.getLogger(__name__)


class NIDSExplainer:
    """SHAP explainer wrapping the trained XGBoost or Random Forest model."""

    def __init__(
        self,
        model_path: Optional[Path] = None,
        preprocessor_path: Optional[Path] = None,
        background_samples: int = 100,
    ):
        self.model_path = model_path or (CLASSIFICATION_MODEL_DIR / "binary_xgboost.joblib")
        self.preprocessor_path = preprocessor_path or (MODELS_DIR / "preprocessor.joblib")

        logger.info("Initializing NIDSExplainer with model: %s", self.model_path)
        self.model = joblib.load(self.model_path)
        self.preprocessor = joblib.load(self.preprocessor_path)
        self.feature_names = self.preprocessor.feature_names

        # Load background data for TreeExplainer
        splits_path = PROCESSED_DIR / "processed_splits.npz"
        if splits_path.exists():
            data = np.load(splits_path)
            X_train = data["X_train"]
            # Use representative background sample
            rng = np.random.default_rng(42)
            bg_idx = rng.choice(len(X_train), size=min(background_samples, len(X_train)), replace=False)
            self.background = X_train[bg_idx]
        else:
            self.background = np.zeros((10, len(self.feature_names)))

        self.explainer = shap.TreeExplainer(self.model, data=self.background)

    def explain_instance(
        self,
        features: np.ndarray,
        top_k: int = 5,
    ) -> Dict[str, Any]:
        """Generate local SHAP explanation for a single network flow."""
        if features.ndim == 1:
            features = features.reshape(1, -1)

        shap_values = self.explainer(features)
        values = shap_values.values[0]
        base_val = float(shap_values.base_values[0])

        prob = float(self.model.predict_proba(features)[0, 1])
        prediction = int(prob >= 0.5)

        # Pair features with SHAP contributions
        contributions = []
        for name, val, feat_raw in zip(self.feature_names, values, features[0]):
            contributions.append({
                "feature": name,
                "shap_value": float(val),
                "feature_value": float(feat_raw),
                "abs_importance": float(abs(val)),
            })

        contributions.sort(key=lambda x: x["abs_importance"], reverse=True)
        top_positive = [c for c in contributions if c["shap_value"] > 0][:top_k]
        top_negative = [c for c in contributions if c["shap_value"] < 0][:top_k]

        return {
            "prediction": prediction,
            "probability": prob,
            "base_value": base_val,
            "top_features": contributions[:top_k],
            "top_positive_features": top_positive,
            "top_negative_features": top_negative,
            "all_shap_values": {c["feature"]: c["shap_value"] for c in contributions},
        }

    def generate_global_importance(
        self,
        sample_size: int = 300,
        output_path: Path = FIGURES_DIR / "shap_global_importance.png",
    ) -> Dict[str, float]:
        """Compute mean absolute SHAP values across a test sample and generate plot."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        splits_path = PROCESSED_DIR / "processed_splits.npz"
        data = np.load(splits_path)
        X_test = data["X_test"]

        rng = np.random.default_rng(42)
        idx = rng.choice(len(X_test), size=min(sample_size, len(X_test)), replace=False)
        sample = X_test[idx]

        shap_values = self.explainer(sample)
        mean_abs_shap = np.abs(shap_values.values).mean(axis=0)

        importance_df = pd.DataFrame({
            "feature": self.feature_names,
            "importance": mean_abs_shap,
        }).sort_values("importance", ascending=False)

        # Plot global importance bar plot
        fig, ax = plt.subplots(figsize=(10, 6.5))
        top_20 = importance_df.head(20)
        sns.barplot(data=top_20, y="feature", x="importance", color="#1f77b4", ax=ax)
        ax.set_title("Global Feature Importance (Mean |SHAP Value| - XGBoost)", fontsize=12)
        ax.set_xlabel("Mean Absolute SHAP Value (Impact on Model Output)", fontsize=10)
        ax.set_ylabel("")
        fig.tight_layout()
        fig.savefig(output_path, dpi=200)
        plt.close(fig)

        return dict(zip(importance_df["feature"], importance_df["importance"]))


# Singleton instance helper
_EXPLAINER_INSTANCE: Optional[NIDSExplainer] = None


def get_explainer() -> NIDSExplainer:
    global _EXPLAINER_INSTANCE
    if _EXPLAINER_INSTANCE is None:
        _EXPLAINER_INSTANCE = NIDSExplainer()
    return _EXPLAINER_INSTANCE


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    explainer = get_explainer()
    importance = explainer.generate_global_importance()
    print("Top 5 SHAP features:", list(importance.items())[:5])
