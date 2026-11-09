"""Machine Learning model architectures and configurations for NIDS.

Provides:
- Baseline: Logistic Regression (L2 regularized)
- Ensemble Tree: Random Forest Classifier (balanced class weights)
- Gradient Boosting: XGBoost Classifier
- Unsupervised: Isolation Forest Anomaly Detector
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier

from src.config import RANDOM_STATE

logger = logging.getLogger(__name__)


def get_binary_models(random_state: int = RANDOM_STATE) -> Dict[str, Any]:
    """Return dictionary of binary classification model instances."""
    return {
        "LogisticRegression": LogisticRegression(
            C=1.0,
            max_iter=1000,
            class_weight="balanced",
            solver="lbfgs",
            random_state=random_state,
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=120,
            max_depth=16,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight="balanced",
            n_jobs=-1,
            random_state=random_state,
        ),
        "XGBoost": XGBClassifier(
            n_estimators=120,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=random_state,
            n_jobs=-1,
        ),
    }


def get_multiclass_models(num_classes: int = 8, random_state: int = RANDOM_STATE) -> Dict[str, Any]:
    """Return dictionary of multiclass classification model instances."""
    return {
        "LogisticRegression": LogisticRegression(
            C=1.0,
            max_iter=1000,
            class_weight="balanced",
            solver="lbfgs",
            random_state=random_state,
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=120,
            max_depth=18,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=random_state,
        ),
        "XGBoost": XGBClassifier(
            n_estimators=130,
            max_depth=7,
            learning_rate=0.1,
            subsample=0.85,
            colsample_bytree=0.85,
            objective="multi:softprob",
            num_class=num_classes,
            eval_metric="mlogloss",
            random_state=random_state,
            n_jobs=-1,
        ),
    }


def get_anomaly_detector(
    contamination: float = 0.15,
    random_state: int = RANDOM_STATE,
) -> IsolationForest:
    """Return configured Isolation Forest for unsupervised network anomaly detection."""
    return IsolationForest(
        n_estimators=150,
        max_samples=0.8,
        contamination=contamination,
        bootstrap=False,
        n_jobs=-1,
        random_state=random_state,
    )
