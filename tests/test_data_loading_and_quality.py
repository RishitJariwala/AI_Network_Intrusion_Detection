"""Tests for the loader and data-quality audits (synthetic fixtures)."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src.data import loader, quality
from src.data.schema import EXPECTED_N_COLS_TRAFFIC_LABELLING, FLOW_FEATURE_COLUMNS


def test_normalise_label_repairs_web_attack_dash():
    assert loader.normalise_label("Web Attack \x96 Brute Force") == "Web Attack - Brute Force"
    assert loader.normalise_label("Web Attack � XSS") == "Web Attack - XSS"
    assert loader.normalise_label("Web Attack - Sql Injection") == "Web Attack - Sql Injection"
    assert loader.normalise_label("  BENIGN ") == "BENIGN"
    assert loader.normalise_label("DoS Hulk") == "DoS Hulk"


def test_columns_are_stripped_and_label_present(df_tl):
    assert all(c == c.strip() for c in df_tl.columns)
    assert "Label" in df_tl.columns and "source_file" in df_tl.columns
    assert "Web Attack - Brute Force" in set(df_tl["Label"])


def test_schema_matches_synthetic_layout(df_tl, df_cve):
    assert set(FLOW_FEATURE_COLUMNS).issubset(df_tl.columns)
    # loader adds exactly one helper column (source_file)
    assert df_tl.shape[1] == EXPECTED_N_COLS_TRAFFIC_LABELLING + 1


def test_layout_detection(df_tl, df_cve):
    assert loader.detect_layout(df_tl) == "traffic_labelling"
    assert loader.detect_layout(df_cve) == "machine_learning_cve"


def test_empty_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        loader.load_dataset(tmp_path)


def test_missing_label_column_raises(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("a,b\n1,2\n")
    with pytest.raises(ValueError):
        loader.load_csv(p)


def test_integer_downcast_is_lossless(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text(" Flow Duration, Label\n 120000000, BENIGN\n 5, DoS Hulk\n")
    df = loader.load_csv(p)
    assert df["Flow Duration"].tolist() == [120000000, 5]


def test_invalid_value_summary_counts_injected_defects(df_tl):
    s = quality.invalid_value_summary(df_tl)
    assert s["rows_with_inf"] > 0 and s["rows_with_nan"] > 0
    assert s["rows_with_nan_or_inf"] <= s["rows_with_nan"] + s["rows_with_inf"]


def test_column_audit_flags_inf_and_negative(df_tl):
    a = quality.column_audit(df_tl)
    assert a.loc["Flow Bytes/s", "n_pos_inf"] > 0
    assert a.loc["Flow Packets/s", "n_missing"] > 0
    assert a.loc["Init_Win_bytes_forward", "n_negative"] >= 1


def test_audit_does_not_mutate_input(df_tl):
    before = df_tl.copy(deep=True)
    quality.column_audit(df_tl)
    quality.duplicate_audit(df_tl)
    quality.invalid_value_summary(df_tl)
    pd.testing.assert_frame_equal(before, df_tl)


def test_duplicate_audit_detects_planted_duplicates(df_tl):
    d = quality.duplicate_audit(df_tl)
    assert d["feature_duplicate_rows"] > 0
    assert d["n_unique_feature_vectors"] + d["feature_duplicate_rows"] == d["n_rows"]


def test_duplicate_audit_detects_label_conflict():
    df = pd.DataFrame({
        "f1": [1.0, 1.0, 2.0], "f2": [5, 5, 6],
        "Label": ["BENIGN", "DoS Hulk", "BENIGN"], "source_file": ["a", "b", "a"],
    })
    d = quality.duplicate_audit(df)
    assert d["conflicting_label_groups"] == 1
    assert d["cross_file_duplicate_vectors"] == 1


def test_imbalance_summary(df_tl):
    s = quality.imbalance_summary(df_tl)
    assert s["benign"] + s["malicious"] == len(df_tl)
    assert "Heartbleed" in s["classes_below_100_samples"]


def test_ip_audit_present_only_for_traffic_labelling(df_tl, df_cve):
    ips = quality.ip_audit(df_tl)
    assert ips is not None and ips["Source IP"]["flows_public"] > 0
    assert quality.ip_audit(df_cve) is None
    assert quality.timestamp_audit(df_cve) is None
    assert quality.flow_id_audit(df_cve) is None


def test_timestamp_audit_parses_day_first(df_tl):
    ts = quality.timestamp_audit(df_tl)
    assert (ts["n_unparseable"] == 0).all()
    assert ts["first"].min().month == 7


def test_correlated_pairs_finds_duplicate_header_column(df_tl):
    pairs = quality.correlated_pairs(df_tl, threshold=0.99)
    found = ((pairs.feature_a == "Fwd Header Length") & (pairs.feature_b == "Fwd Header Length.1")).any()
    assert found


def test_feature_columns_exclude_identifiers(df_tl):
    feats = quality.feature_columns(df_tl)
    assert not {"Source IP", "Flow ID", "Timestamp", "Label", "source_file", "Source Port"} & set(feats)
    assert len(feats) == len(FLOW_FEATURE_COLUMNS)


def test_no_inf_after_replace_roundtrip(df_tl):
    feats = quality.feature_columns(df_tl)
    cleaned = df_tl[feats].replace([np.inf, -np.inf], np.nan)
    assert not np.isinf(cleaned.to_numpy(dtype="float64", na_value=np.nan)).any()
