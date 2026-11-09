"""Data cleaning, feature engineering, selection, and preprocessing pipelines.

Implements strict anti-leakage principles:
- Identifiers (IPs, Ports, Flow IDs, Timestamps) excluded from ML features.
- All imputation, scaling, and feature selection statistics fitted STRICTLY on train split.
- Constant columns and extreme collinear features removed.
- Stratified sampling preserving all minority attack instances.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, RobustScaler

from src.config import (
    BENIGN_LABEL,
    LABEL_COL,
    MODELS_DIR,
    PROCESSED_DIR,
    RANDOM_STATE,
    SOURCE_FILE_COL,
)
from src.data.schema import IDENTIFIER_COLUMNS

logger = logging.getLogger(__name__)

CONSTANT_FEATURES = [
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
]

DUPLICATE_COLUMNS = [
    "Fwd Header Length.1",
]

# Standard academic taxonomic grouping for CICIDS2017 attacks
ATTACK_TAXONOMY = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "Heartbleed": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack - Brute Force": "BruteForce",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Bot": "Botnet",
    "Infiltration": "Infiltration",
}


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Clean raw dataset: drop empty labels, normalize columns, handle inf/nans."""
    df = df.copy()
    # Strip whitespace from column names if present
    df.columns = [str(c).strip() for c in df.columns]

    # Filter out missing/null/nan labels
    df = df.dropna(subset=[LABEL_COL])
    df = df[df[LABEL_COL].astype(str).str.lower() != "nan"]
    df = df[df[LABEL_COL].astype(str).str.strip() != ""]

    # Drop constant features that provide zero variance
    to_drop = [c for c in CONSTANT_FEATURES if c in df.columns]
    # Drop known duplicate columns
    to_drop.extend([c for c in DUPLICATE_COLUMNS if c in df.columns])
    if to_drop:
        df = df.drop(columns=to_drop, errors="ignore")

    # Replace inf and -inf with NaN for subsequent median imputation
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    # Assign taxonomy labels
    df["multiclass_label"] = df[LABEL_COL].map(lambda x: ATTACK_TAXONOMY.get(str(x), "Other"))
    df["binary_label"] = (df[LABEL_COL] != BENIGN_LABEL).astype(int)

    return df


def get_feature_columns(df: pd.DataFrame) -> list[str]:
    """Return numeric flow feature names excluding all identifiers and labels."""
    excluded = set(IDENTIFIER_COLUMNS) | {
        LABEL_COL,
        SOURCE_FILE_COL,
        "binary_label",
        "multiclass_label",
        "Label",
        "source_file",
        "Flow ID",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Timestamp",
        "Protocol",
    }
    features = [
        c for c in df.columns
        if c not in excluded and pd.api.types.is_numeric_dtype(df[c])
    ]
    return sorted(features)


def remove_collinear_features(
    X_train: pd.DataFrame,
    threshold: float = 0.98,
) -> list[str]:
    """Identify and drop redundant collinear features using training data only."""
    corr_matrix = X_train.corr().abs()
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    to_drop = [col for col in upper.columns if any(upper[col] > threshold)]
    selected = [c for c in X_train.columns if c not in to_drop]
    logger.info("Collinearity filter: dropped %d features with |r| > %.2f; %d features retained",
                len(to_drop), threshold, len(selected))
    return selected


def sample_balanced_stratified(
    df: pd.DataFrame,
    target_samples: int = 150_000,
    random_state: int = RANDOM_STATE,
) -> pd.DataFrame:
    """Sample dataset keeping 100% of minority attack classes while sampling dominant classes."""
    if len(df) <= target_samples:
        return df

    classes = df["multiclass_label"].value_counts()
    sampled_dfs = []

    # Minority threshold: classes with fewer than 5,000 samples are 100% retained
    minority_classes = classes[classes < 5000].index
    majority_classes = classes[classes >= 5000].index

    for c in minority_classes:
        sampled_dfs.append(df[df["multiclass_label"] == c])

    minority_count = sum(len(d) for d in sampled_dfs)
    remaining_budget = target_samples - minority_count
    majority_total = sum(classes[c] for c in majority_classes)

    for c in majority_classes:
        ratio = classes[c] / majority_total
        n_c = max(100, int(remaining_budget * ratio))
        sub = df[df["multiclass_label"] == c]
        sampled_dfs.append(sub.sample(n=min(n_c, len(sub)), random_state=random_state))

    out_df = pd.concat(sampled_dfs, ignore_index=True).sample(frac=1.0, random_state=random_state)
    logger.info("Sampled %d rows across %d classes (retaining 100%% of rare attack categories)",
                len(out_df), out_df["multiclass_label"].nunique())
    return out_df


class PreprocessingArtifact:
    """Container holding preprocessor pipeline, encoders, and feature names."""
    __module__ = "src.data.preprocess"

    def __init__(
        self,
        pipeline: Pipeline,
        feature_names: list[str],
        label_encoder: LabelEncoder,
        class_mapping: dict[str, int],
        medians: dict[str, float],
    ):
        self.pipeline = pipeline
        self.feature_names = feature_names
        self.label_encoder = label_encoder
        self.class_mapping = class_mapping
        self.medians = medians

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transform raw input DataFrame to model-ready scaled numpy array."""
        X = df.copy()
        # Ensure all expected feature columns exist
        for col in self.feature_names:
            if col not in X.columns:
                X[col] = self.medians.get(col, 0.0)
        X = X[self.feature_names].replace([np.inf, -np.inf], np.nan)
        return self.pipeline.transform(X)


def fit_preprocessing_pipeline(
    X_train: pd.DataFrame,
    y_train_multi: pd.Series,
) -> Tuple[PreprocessingArtifact, np.ndarray, np.ndarray]:
    """Fit imputation, scaling, and label encoding strictly on training data."""
    # 1. Feature selection: drop extreme collinearity
    selected_features = remove_collinear_features(X_train, threshold=0.98)
    X_train_sel = X_train[selected_features].copy()

    # Calculate medians for fallback inference
    medians = X_train_sel.median(numeric_only=True).to_dict()

    # 2. Scikit-learn Pipeline: median imputation followed by robust scaling
    pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", RobustScaler(quantile_range=(5.0, 95.0), unit_variance=True)),
        ]
    )

    X_train_transformed = pipeline.fit_transform(X_train_sel)

    # 3. Label Encoder for multiclass targets
    le = LabelEncoder()
    y_train_encoded = le.fit_transform(y_train_multi)
    class_mapping = {cls_name: int(idx) for idx, cls_name in enumerate(le.classes_)}

    artifact = PreprocessingArtifact(
        pipeline=pipeline,
        feature_names=selected_features,
        label_encoder=le,
        class_mapping=class_mapping,
        medians=medians,
    )

    return artifact, X_train_transformed, y_train_encoded


def run_preprocessing_pipeline(
    df: pd.DataFrame,
    sample_size: int = 150_000,
    test_size: float = 0.20,
    random_state: int = RANDOM_STATE,
    output_dir: Path = PROCESSED_DIR,
) -> dict:
    """Complete end-to-end preprocessing run."""
    logger.info("Cleaning raw dataframe (rows: %d) ...", len(df))
    cleaned_df = clean_dataframe(df)

    logger.info("Performing balanced sampling (target: %d) ...", sample_size)
    sampled_df = sample_balanced_stratified(cleaned_df, target_samples=sample_size, random_state=random_state)

    raw_features = get_feature_columns(sampled_df)
    X_raw = sampled_df[raw_features]
    y_binary = sampled_df["binary_label"]
    y_multi = sampled_df["multiclass_label"]

    logger.info("Splitting train/test (test_size=%.2f, stratified by multiclass label) ...", test_size)
    (
        X_train_raw,
        X_test_raw,
        y_train_bin,
        y_test_bin,
        y_train_mul,
        y_test_mul,
    ) = train_test_split(
        X_raw,
        y_binary,
        y_multi,
        test_size=test_size,
        stratify=y_multi,
        random_state=random_state,
    )

    logger.info("Fitting preprocessing pipeline on training split only ...")
    artifact, X_train_proc, y_train_enc = fit_preprocessing_pipeline(X_train_raw, y_train_mul)
    X_test_proc = artifact.transform(X_test_raw)
    y_test_enc = artifact.label_encoder.transform(y_test_mul)

    output_dir.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # Save artifact
    artifact_path = MODELS_DIR / "preprocessor.joblib"
    joblib.dump(artifact, artifact_path)
    logger.info("Saved preprocessor artifact to %s", artifact_path)

    # Save feature names and metadata JSON
    meta = {
        "n_raw_features": len(raw_features),
        "n_selected_features": len(artifact.feature_names),
        "selected_features": artifact.feature_names,
        "classes": list(artifact.class_mapping.keys()),
        "class_mapping": artifact.class_mapping,
        "train_samples": int(X_train_proc.shape[0]),
        "test_samples": int(X_test_proc.shape[0]),
        "class_distribution_train": y_train_mul.value_counts().to_dict(),
        "class_distribution_test": y_test_mul.value_counts().to_dict(),
    }
    meta_path = output_dir / "preprocessing_metadata.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    # Save processed numpy arrays / DataFrames for fast model training
    np.savez_compressed(
        output_dir / "processed_splits.npz",
        X_train=X_train_proc,
        X_test=X_test_proc,
        y_train_bin=y_train_bin.to_numpy(),
        y_test_bin=y_test_bin.to_numpy(),
        y_train_mul=y_train_enc,
        y_test_mul=y_test_enc,
    )

    # Save a test dataframe slice with identifiers intact for realistic evaluation and API testing
    test_slice = sampled_df.loc[X_test_raw.index[:2000]].copy()
    test_slice.to_csv(output_dir / "test_sample_flows.csv", index=False)

    logger.info("Preprocessing complete. Artifacts written to %s", output_dir)
    return meta


if __name__ == "__main__":
    from src.data.loader import load_dataset
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    df_raw = load_dataset()
    meta = run_preprocessing_pipeline(df_raw, sample_size=150_000)
    print("Preprocessing successfully executed:", meta["n_selected_features"], "features retained.")
