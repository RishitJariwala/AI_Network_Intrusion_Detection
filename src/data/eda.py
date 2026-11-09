"""Exploratory data analysis: figures and a machine-readable summary.

All numbers in outputs/evaluation/eda_summary.json come from executing these functions on the
real data. The report must quote that file, never retyped values.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import seaborn as sns  # noqa: E402

from src.config import BENIGN_LABEL, EVALUATION_DIR, FIGURES_DIR, LABEL_COL, SOURCE_FILE_COL  # noqa: E402
from src.data import quality  # noqa: E402
from src.data.loader import detect_layout  # noqa: E402

sns.set_theme(style="whitegrid", context="notebook")


def _save(fig: plt.Figure, name: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / name
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_label_distribution(df: pd.DataFrame, out_dir: Path = FIGURES_DIR) -> Path:
    dist = quality.label_distribution(df)
    fig, ax = plt.subplots(figsize=(9, 5))
    sns.barplot(x=dist["count"], y=dist.index, ax=ax, color="#3b6ea5")
    ax.set_xscale("log")
    ax.set_xlabel("Flows (log scale)")
    ax.set_ylabel("")
    ax.set_title("CICIDS2017 class distribution")
    for i, v in enumerate(dist["count"]):
        ax.text(v, i, f" {v:,}", va="center", fontsize=8)
    return _save(fig, "eda_label_distribution.png", out_dir)


def plot_label_by_file(df: pd.DataFrame, out_dir: Path = FIGURES_DIR) -> Path:
    ct = quality.label_by_file(df)
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.heatmap(np.log10(ct + 1), annot=ct.to_numpy(), fmt=",d", cmap="Blues", ax=ax,
                cbar_kws={"label": "log10(count + 1)"}, annot_kws={"size": 7})
    ax.set_title("Attack labels by capture file (annotations show raw counts)")
    ax.set_xlabel("")
    ax.set_ylabel("")
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right", fontsize=7)
    return _save(fig, "eda_label_by_file.png", out_dir)


def plot_invalid_values(audit: pd.DataFrame, out_dir: Path = FIGURES_DIR) -> Path | None:
    bad = audit[(audit["n_missing"] + audit["n_pos_inf"] + audit["n_neg_inf"]) > 0]
    if bad.empty:
        return None
    bad = bad.assign(total=bad["n_missing"] + bad["n_pos_inf"] + bad["n_neg_inf"]).sort_values("total")
    fig, ax = plt.subplots(figsize=(8, max(2.5, 0.4 * len(bad) + 1)))
    ax.barh(bad.index, bad["n_missing"], label="NaN", color="#c9a227")
    ax.barh(bad.index, bad["n_pos_inf"] + bad["n_neg_inf"], left=bad["n_missing"], label="+/-inf",
            color="#b03a2e")
    ax.set_xlabel("Rows")
    ax.set_title("Features containing NaN or infinite values")
    ax.legend()
    return _save(fig, "eda_invalid_values.png", out_dir)


def plot_correlation(df: pd.DataFrame, top_n: int = 30, sample: int = 200_000,
                     out_dir: Path = FIGURES_DIR) -> Path:
    feats = quality.feature_columns(df)
    data = df[feats]
    if len(data) > sample:
        data = data.sample(sample, random_state=42)
    data = data.replace([np.inf, -np.inf], np.nan).dropna()
    data = data.loc[:, data.nunique() > 1]
    y = (df.loc[data.index, LABEL_COL] != BENIGN_LABEL).astype(int)
    target_corr = data.corrwith(y).abs().sort_values(ascending=False)
    cols = target_corr.head(top_n).index
    fig, ax = plt.subplots(figsize=(11, 9))
    sns.heatmap(data[cols].corr(), cmap="coolwarm", center=0, ax=ax, square=True,
                cbar_kws={"label": "Pearson r"})
    ax.set_title(f"Correlation among the {top_n} features most correlated with the malicious flag")
    plt.setp(ax.get_xticklabels(), fontsize=7)
    plt.setp(ax.get_yticklabels(), fontsize=7)
    return _save(fig, "eda_correlation.png", out_dir)


def run_eda(df: pd.DataFrame, figures_dir: Path = FIGURES_DIR,
            evaluation_dir: Path = EVALUATION_DIR) -> dict:
    """Run every audit, save figures and tables, write eda_summary.json, return the summary."""
    evaluation_dir.mkdir(parents=True, exist_ok=True)
    audit = quality.column_audit(df)
    pairs = quality.correlated_pairs(df, threshold=0.95)

    summary = {
        "layout": detect_layout(df),
        "n_rows": int(len(df)),
        "n_columns": int(df.shape[1]),
        "n_feature_columns": len(quality.feature_columns(df)),
        "source_files": sorted(df[SOURCE_FILE_COL].unique().tolist()),
        "invalid_values": quality.invalid_value_summary(df),
        "constant_features": audit.index[audit["is_constant"]].tolist(),
        "features_with_negative_values": audit.index[audit["n_negative"] > 0].tolist(),
        "imbalance": quality.imbalance_summary(df),
        "duplicates": quality.duplicate_audit(df),
        "n_feature_pairs_abs_corr_ge_0.95": int(len(pairs)),
        "flow_ids": quality.flow_id_audit(df),
        "ips": quality.ip_audit(df),
    }
    ts = quality.timestamp_audit(df)
    if ts is not None:
        ts_out = ts.copy()
        ts_out["first"] = ts_out["first"].astype(str)
        ts_out["last"] = ts_out["last"].astype(str)
        summary["timestamps_per_file"] = ts_out.to_dict(orient="index")

    quality.label_distribution(df).to_csv(evaluation_dir / "eda_label_distribution.csv")
    quality.label_by_file(df).to_csv(evaluation_dir / "eda_label_by_file.csv")
    audit.to_csv(evaluation_dir / "eda_column_audit.csv")
    pairs.to_csv(evaluation_dir / "eda_correlated_pairs.csv", index=False)

    figs = [
        plot_label_distribution(df, figures_dir),
        plot_label_by_file(df, figures_dir),
        plot_invalid_values(audit, figures_dir),
        plot_correlation(df, out_dir=figures_dir),
    ]
    summary["figures"] = [p.name for p in figs if p is not None]

    with open(evaluation_dir / "eda_summary.json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, default=str)
    return summary
