"""Unit tests for data preprocessing and anti-leakage feature pipeline."""
import numpy as np
import pandas as pd
import pytest

from src.data.preprocess import (
    ATTACK_TAXONOMY,
    clean_dataframe,
    fit_preprocessing_pipeline,
    get_feature_columns,
    remove_collinear_features,
    sample_balanced_stratified,
)


@pytest.fixture
def sample_raw_df():
    data = {
        "Destination Port": [80, 443, 22, 8080, 21],
        "Flow Duration": [1000, 2000, 500, 1500, 3000],
        "Bwd Packets/s": [10.0, 20.0, np.inf, 5.0, 15.0],
        "Flow Packets/s": [100.0, np.nan, 30.0, 50.0, 75.0],
        "Bwd PSH Flags": [0, 0, 0, 0, 0],  # Constant
        "Fwd Header Length.1": [20, 20, 20, 20, 20],  # Duplicate
        "Source IP": ["192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8", "1.1.1.1"],
        "Destination IP": ["172.16.0.2", "192.168.1.2", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
        "Timestamp": ["04/07/2017 08:00", "04/07/2017 09:00", "05/07/2017 10:00", "05/07/2017 11:00", "06/07/2017 12:00"],
        "Label": ["BENIGN", "DoS Hulk", "PortScan", "nan", "SSH-Patator"],
    }
    return pd.DataFrame(data)


def test_clean_dataframe_drops_nan_labels_and_constants(sample_raw_df):
    cleaned = clean_dataframe(sample_raw_df)
    assert len(cleaned) == 4  # Dropped "nan" label row
    assert "Bwd PSH Flags" not in cleaned.columns
    assert "Fwd Header Length.1" not in cleaned.columns
    assert "binary_label" in cleaned.columns
    assert "multiclass_label" in cleaned.columns
    assert cleaned["multiclass_label"].tolist() == ["BENIGN", "DoS", "PortScan", "BruteForce"]


def test_get_feature_columns_excludes_identifiers(sample_raw_df):
    cleaned = clean_dataframe(sample_raw_df)
    feats = get_feature_columns(cleaned)
    assert "Source IP" not in feats
    assert "Destination IP" not in feats
    assert "Timestamp" not in feats
    assert "Label" not in feats
    assert "Destination Port" in feats
    assert "Flow Duration" in feats


def test_fit_and_transform_pipeline():
    X = pd.DataFrame({
        "feat1": [1.0, 2.0, 3.0, 4.0, 5.0],
        "feat2": [10.0, np.nan, 30.0, 40.0, 50.0],
        "feat3": [100.0, 200.0, 300.0, 400.0, 500.0],
    })
    y = pd.Series(["BENIGN", "DoS", "BENIGN", "PortScan", "DoS"])
    artifact, X_proc, y_enc = fit_preprocessing_pipeline(X, y)

    assert X_proc.shape[0] == 5
    assert not np.isnan(X_proc).any()
    assert len(y_enc) == 5

    # Test transform on unseen data with missing values & inf
    X_unseen = pd.DataFrame({"feat1": [2.5], "feat2": [np.inf], "feat3": [350.0]})
    transformed = artifact.transform(X_unseen)
    assert transformed.shape == (1, len(artifact.feature_names))
    assert not np.isnan(transformed).any()

