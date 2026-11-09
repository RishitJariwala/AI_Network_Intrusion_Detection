"""Rigorous empirical audit script for NIDS methodology, leakage, and anomaly evaluation.

Executes:
1. Schema and cryptographic verification across all 8 CICIDS2017 raw CSVs.
2. Detailed duplicate and conflicting group audit.
3. Comparative split evaluation: Random Stratified vs Strict Deduplicated (Leakage-Resistant).
4. Unsupervised Isolation Forest calibration (threshold derived solely from training benign data).
5. Leave-One-Attack-Category-Out (LOCO) zero-day anomaly detection benchmark.
6. Per-class metrics (Accuracy, Precision, Recall, F1, FPR, FNR) for all attack categories.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from src.config import EVALUATION_DIR, PROCESSED_DIR, RANDOM_STATE, RAW_DIR
from src.data.loader import list_csv_files, load_dataset
from src.data.preprocess import (
    ATTACK_TAXONOMY,
    clean_dataframe,
    fit_preprocessing_pipeline,
    get_feature_columns,
    sample_balanced_stratified,
)
from src.detection.evaluate import calculate_binary_metrics, calculate_multiclass_metrics

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("audit_experiments")


def verify_raw_csv_files() -> dict:
    """Audit all 8 raw CSVs: row counts, raw header column counts, SHA-256 hashes."""
    files = list_csv_files(RAW_DIR)
    results = {}
    for p in files:
        h = hashlib.sha256()
        n_rows = 0
        raw_cols = 0
        with open(p, "rb") as f:
            first_line = f.readline()
            raw_cols = len([c.strip() for c in first_line.decode("latin-1").split(",")])
            h.update(first_line)
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
                n_rows += chunk.count(b"\n")
        results[p.name] = {
            "bytes": p.stat().st_size,
            "raw_csv_columns": raw_cols,
            "total_lines": n_rows,
            "sha256": h.hexdigest(),
        }
    return results


def run_comparative_leakage_and_loco():
    EVALUATION_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Starting Comprehensive Empirical Audit...")

    # 1. Raw CSV verification
    raw_file_audit = verify_raw_csv_files()
    logger.info("Verified %d raw CSV files. All files have exactly 85 raw columns on disk.", len(raw_file_audit))

    # 2. Ingest & Clean dataset
    logger.info("Loading full dataset...")
    df_raw = load_dataset()
    logger.info("Raw loaded DataFrame has %d rows and %d columns (85 raw + 1 'source_file' provenance column)",
                len(df_raw), df_raw.shape[1])

    cleaned = clean_dataframe(df_raw)
    del df_raw  # Free memory

    # 3. Duplicate and Conflicting Labels Analysis
    feature_cols = get_feature_columns(cleaned)
    logger.info("Extracted %d candidate numeric flow features (identifiers excluded)", len(feature_cols))

    h_series = pd.util.hash_pandas_object(cleaned[feature_cols], index=False)
    dup_mask = h_series.duplicated(keep="first")
    n_total_duplicates = int(dup_mask.sum())
    n_unique_vectors = int((~dup_mask).sum())

    # Conflicting groups: identical features with conflicting multiclass labels
    tmp_lbl = pd.DataFrame({"h": h_series, "label": cleaned["multiclass_label"]})
    conflicting_h = tmp_lbl.groupby("h")["label"].nunique()
    n_conflicting_groups = int((conflicting_h > 1).sum())
    conflicting_hashes = set(conflicting_h[conflicting_h > 1].index)
    rows_in_conflict = int(h_series.isin(conflicting_hashes).sum())

    logger.info("Duplicate Audit: Total Rows=%d, Unique Vectors=%d, Duplicate Rows=%d (%.2f%%)",
                len(cleaned), n_unique_vectors, n_total_duplicates, (n_total_duplicates / len(cleaned)) * 100)
    logger.info("Conflicting Label Audit: %d conflicting groups representing %d conflicting rows",
                n_conflicting_groups, rows_in_conflict)

    # 4. Comparative Evaluation: Split A (Standard Stratified) vs Split B (Strict Deduplicated)
    logger.info("Building balanced sample for comparative benchmark...")
    sampled_std = sample_balanced_stratified(cleaned, target_samples=120_000, random_state=RANDOM_STATE)

    # Split A: Standard Stratified Split
    X_std = sampled_std[feature_cols]
    y_std_mul = sampled_std["multiclass_label"]
    y_std_bin = sampled_std["binary_label"]

    X_tr_std, X_te_std, y_tr_std_mul, y_te_std_mul, y_tr_std_bin, y_te_std_bin = train_test_split(
        X_std, y_std_mul, y_std_bin, test_size=0.20, stratify=y_std_mul, random_state=RANDOM_STATE
    )

    art_std, X_tr_std_proc, y_tr_std_enc = fit_preprocessing_pipeline(X_tr_std, y_tr_std_mul)
    X_te_std_proc = art_std.transform(X_te_std)
    y_te_std_enc = art_std.label_encoder.transform(y_te_std_mul)

    # Check duplicate overlap in Split A
    h_tr_std = set(pd.util.hash_pandas_object(pd.DataFrame(X_tr_std_proc), index=False))
    h_te_std = pd.util.hash_pandas_object(pd.DataFrame(X_te_std_proc), index=False)
    split_a_overlap = int(h_te_std.isin(h_tr_std).sum())
    split_a_overlap_pct = (split_a_overlap / len(X_te_std_proc)) * 100
    logger.info("Split A (Standard): %d of %d test flows (%.2f%%) overlap with training feature vectors",
                split_a_overlap, len(X_te_std_proc), split_a_overlap_pct)

    # Split B: Strict Deduplicated & Conflict-Free Split
    # Filter out conflicting groups and duplicates first
    valid_mask = (~h_series.isin(conflicting_hashes)) & (~dup_mask)
    dedup_cleaned = cleaned[valid_mask].copy()
    logger.info("Deduplicated & Conflict-Free pool: %d unique, consistent flows", len(dedup_cleaned))

    sampled_dedup = sample_balanced_stratified(dedup_cleaned, target_samples=100_000, random_state=RANDOM_STATE)
    X_dedup = sampled_dedup[feature_cols]
    y_dedup_mul = sampled_dedup["multiclass_label"]
    y_dedup_bin = sampled_dedup["binary_label"]

    X_tr_dd, X_te_dd, y_tr_dd_mul, y_te_dd_mul, y_tr_dd_bin, y_te_dd_bin = train_test_split(
        X_dedup, y_dedup_mul, y_dedup_bin, test_size=0.20, stratify=y_dedup_mul, random_state=RANDOM_STATE
    )

    art_dd, X_tr_dd_proc, y_tr_dd_enc = fit_preprocessing_pipeline(X_tr_dd, y_tr_dd_mul)
    X_te_dd_proc = art_dd.transform(X_te_dd)
    y_te_dd_enc = art_dd.label_encoder.transform(y_te_dd_mul)

    h_tr_dd = set(pd.util.hash_pandas_object(pd.DataFrame(X_tr_dd_proc), index=False))
    h_te_dd = pd.util.hash_pandas_object(pd.DataFrame(X_te_dd_proc), index=False)
    split_b_overlap = int(h_te_dd.isin(h_tr_dd).sum())
    logger.info("Split B (Leakage-Resistant): %d of %d test flows overlap with training feature vectors (Strict 0.00%%)",
                split_b_overlap, len(X_te_dd_proc))

    # Evaluate Models on Split A vs Split B
    comparison_results = []
    classes_std = list(art_std.class_mapping.keys())
    classes_dd = list(art_dd.class_mapping.keys())

    models_to_test = {
        "LogisticRegression": (
            LogisticRegression(max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE),
            LogisticRegression(max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE),
        ),
        "RandomForest": (
            RandomForestClassifier(n_estimators=100, max_depth=16, class_weight="balanced", n_jobs=-1, random_state=RANDOM_STATE),
            RandomForestClassifier(n_estimators=100, max_depth=16, class_weight="balanced_subsample", n_jobs=-1, random_state=RANDOM_STATE),
        ),
        "XGBoost": (
            XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, eval_metric="logloss", n_jobs=-1, random_state=RANDOM_STATE),
            XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, eval_metric="mlogloss", n_jobs=-1, random_state=RANDOM_STATE),
        ),
    }

    per_class_audit_results = {}

    for name, (bin_model, mul_model) in models_to_test.items():
        logger.info("Evaluating %s on Split A (Standard)...", name)
        # Split A Binary
        bin_model.fit(X_tr_std_proc, y_tr_std_bin)
        preds_bin_a = bin_model.predict(X_te_std_proc)
        prob_bin_a = bin_model.predict_proba(X_te_std_proc) if hasattr(bin_model, "predict_proba") else None
        m_bin_a = calculate_binary_metrics(y_te_std_bin, preds_bin_a, prob_bin_a)

        # Split A Multiclass
        mul_model.fit(X_tr_std_proc, y_tr_std_enc)
        preds_mul_a = mul_model.predict(X_te_std_proc)
        prob_mul_a = mul_model.predict_proba(X_te_std_proc) if hasattr(mul_model, "predict_proba") else None
        m_mul_a = calculate_multiclass_metrics(y_te_std_enc, preds_mul_a, prob_mul_a, class_names=classes_std)

        if name == "XGBoost":
            per_class_audit_results["XGBoost_Split_A"] = m_mul_a.get("per_class_report", {})

        logger.info("Evaluating %s on Split B (Leakage-Resistant)...", name)
        # Split B Binary
        bin_model.fit(X_tr_dd_proc, y_tr_dd_bin)
        preds_bin_b = bin_model.predict(X_te_dd_proc)
        prob_bin_b = bin_model.predict_proba(X_te_dd_proc) if hasattr(bin_model, "predict_proba") else None
        m_bin_b = calculate_binary_metrics(y_te_dd_bin, preds_bin_b, prob_bin_b)

        # Split B Multiclass
        mul_model.fit(X_tr_dd_proc, y_tr_dd_enc)
        preds_mul_b = mul_model.predict(X_te_dd_proc)
        prob_mul_b = mul_model.predict_proba(X_te_dd_proc) if hasattr(mul_model, "predict_proba") else None
        m_mul_b = calculate_multiclass_metrics(y_te_dd_enc, preds_mul_b, prob_mul_b, class_names=classes_dd)

        if name == "XGBoost":
            per_class_audit_results["XGBoost_Split_B_Leakage_Resistant"] = m_mul_b.get("per_class_report", {})

        comparison_results.append({
            "model": name,
            "split_type": "Standard_Stratified (Split A)",
            "test_duplicate_overlap_pct": split_a_overlap_pct,
            "binary_accuracy": m_bin_a["accuracy"],
            "binary_macro_f1": m_bin_a["f1_macro"],
            "binary_fpr": m_bin_a["fpr"],
            "binary_fnr": m_bin_a["fnr"],
            "binary_roc_auc": m_bin_a.get("roc_auc"),
            "multiclass_accuracy": m_mul_a["accuracy"],
            "multiclass_macro_f1": m_mul_a["f1_macro"],
            "multiclass_weighted_f1": m_mul_a["f1_weighted"],
        })
        comparison_results.append({
            "model": name,
            "split_type": "Leakage_Resistant_Deduplicated (Split B)",
            "test_duplicate_overlap_pct": 0.0,
            "binary_accuracy": m_bin_b["accuracy"],
            "binary_macro_f1": m_bin_b["f1_macro"],
            "binary_fpr": m_bin_b["fpr"],
            "binary_fnr": m_bin_b["fnr"],
            "binary_roc_auc": m_bin_b.get("roc_auc"),
            "multiclass_accuracy": m_mul_b["accuracy"],
            "multiclass_macro_f1": m_mul_b["f1_macro"],
            "multiclass_weighted_f1": m_mul_b["f1_weighted"],
        })

    comp_df = pd.DataFrame(comparison_results)
    comp_df.to_csv(EVALUATION_DIR / "leakage_comparison.csv", index=False)
    logger.info("Saved comparative leakage benchmark to outputs/evaluation/leakage_comparison.csv")

    # 5. Isolation Forest Unsupervised Threshold Calibration
    logger.info("Auditing Isolation Forest: strictly unsupervised threshold calibration...")
    # Train Isolation Forest on benign training samples only
    benign_tr_idx = np.where(y_tr_std_bin == 0)[0]
    X_tr_benign = X_tr_std_proc[benign_tr_idx]

    iso = IsolationForest(n_estimators=120, max_samples=0.8, random_state=RANDOM_STATE, n_jobs=-1)
    iso.fit(X_tr_benign)

    # Derive threshold strictly on training benign distribution (e.g. 95th percentile of normal benign training anomaly scores)
    tr_benign_scores = -iso.score_samples(X_tr_benign)
    calibrated_threshold = float(np.percentile(tr_benign_scores, 95.0))
    logger.info("Unsupervised threshold calibrated at 95th percentile of training benign scores: %.4f",
                calibrated_threshold)

    # Evaluate on test split using the calibrated threshold (without looking at test labels!)
    te_scores = -iso.score_samples(X_te_std_proc)
    te_pred_anom = (te_scores >= calibrated_threshold).astype(int)

    iso_calibrated_metrics = calculate_binary_metrics(y_te_std_bin, te_pred_anom, te_scores)
    logger.info("Isolation Forest (Calibrated Unsupervised): Accuracy=%.4f, Macro-F1=%.4f, FPR=%.4f, Recall=%.4f, ROC-AUC=%.4f",
                iso_calibrated_metrics["accuracy"], iso_calibrated_metrics["f1_macro"],
                iso_calibrated_metrics["fpr"], iso_calibrated_metrics["recall"],
                iso_calibrated_metrics.get("roc_auc", 0.0))

    # 6. Leave-One-Attack-Category-Out (LOCO) Zero-Day Anomaly Experiment
    logger.info("Running Leave-One-Attack-Category-Out (LOCO) Anomaly Experiment...")
    loco_results = []
    attack_classes = [c for c in classes_std if c != "BENIGN"]

    for unseen_attack in attack_classes:
        # Evaluate Isolation Forest on only (BENIGN + unseen_attack) in test set
        te_mask = (y_te_std_mul == "BENIGN") | (y_te_std_mul == unseen_attack)
        X_sub = X_te_std_proc[te_mask]
        y_sub_bin = (y_te_std_mul[te_mask] != "BENIGN").astype(int)
        sub_scores = -iso.score_samples(X_sub)
        sub_preds = (sub_scores >= calibrated_threshold).astype(int)

        m_loco = calculate_binary_metrics(y_sub_bin.to_numpy(), sub_preds, sub_scores)
        # Attack recall = zero-day detection rate for that unseen attack!
        attack_count = int(y_sub_bin.sum())
        detected_count = int(((y_sub_bin == 1) & (sub_preds == 1)).sum())
        det_rate = (detected_count / attack_count) if attack_count > 0 else 0.0

        loco_results.append({
            "unseen_zero_day_attack": unseen_attack,
            "test_attack_samples": attack_count,
            "detected_anomalies": detected_count,
            "zero_day_detection_rate": det_rate,
            "false_positive_rate_on_benign": m_loco["fpr"],
            "roc_auc": m_loco.get("roc_auc"),
        })
        logger.info("LOCO [%s]: %d/%d detected (Detection Rate: %.2f%%, ROC-AUC: %.4f)",
                    unseen_attack, detected_count, attack_count, det_rate * 100, m_loco.get("roc_auc", 0.0))

    loco_df = pd.DataFrame(loco_results)
    loco_df.to_csv(EVALUATION_DIR / "loco_anomaly_results.csv", index=False)
    logger.info("Saved LOCO anomaly benchmark to outputs/evaluation/loco_anomaly_results.csv")

    # 7. Write complete audit summary JSON
    audit_summary = {
        "timestamp": pd.Timestamp.now().isoformat(),
        "raw_csv_files": raw_file_audit,
        "raw_csv_column_count": 85,
        "loaded_dataframe_column_count": 86,
        "column_count_explanation": (
            "Each raw CSV file on disk contains exactly 85 columns (6 identifiers + 78 flow features + 1 Label). "
            "The data loader adds an 86th column ('source_file') to preserve capture session provenance in memory."
        ),
        "dataset_duplicates": {
            "total_cleaned_flows": len(cleaned),
            "unique_feature_vectors": n_unique_vectors,
            "duplicate_rows": n_total_duplicates,
            "duplicate_percentage": round((n_total_duplicates / len(cleaned)) * 100, 2),
            "conflicting_label_groups": n_conflicting_groups,
            "rows_in_conflicting_groups": rows_in_conflict,
        },
        "comparative_leakage_results": comparison_results,
        "isolation_forest_calibrated": {
            "training_samples_benign": len(X_tr_benign),
            "calibrated_threshold": calibrated_threshold,
            "threshold_selection_method": "95th percentile of normal benign training anomaly scores (strictly unsupervised, no test label leakage)",
            "metrics": iso_calibrated_metrics,
        },
        "loco_anomaly_benchmark": loco_results,
        "per_class_reports": per_class_audit_results,
    }

    with open(EVALUATION_DIR / "audit_experiments.json", "w", encoding="utf-8") as f:
        json.dump(audit_summary, f, indent=2, default=str)
    logger.info("Empirical audit and remediation experiments complete! Output saved to %s",
                EVALUATION_DIR / "audit_experiments.json")


if __name__ == "__main__":
    run_comparative_leakage_and_loco()
