"""Data-quality audits for CICIDS2017-style flow data.

Every function is read-only and returns plain DataFrames / dicts so results can be logged,
plotted, and quoted in the report. No function modifies its input.
"""
from __future__ import annotations

import ipaddress

import numpy as np
import pandas as pd

from src.config import BENIGN_LABEL, LABEL_COL, SOURCE_FILE_COL

NON_FEATURE_COLS = {
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Protocol",
    "Timestamp", LABEL_COL, SOURCE_FILE_COL,
}


def feature_columns(df: pd.DataFrame) -> list[str]:
    """Numeric flow-feature columns (identifiers, label and bookkeeping excluded)."""
    return [
        c for c in df.columns
        if c not in NON_FEATURE_COLS and pd.api.types.is_numeric_dtype(df[c])
    ]


def column_audit(df: pd.DataFrame) -> pd.DataFrame:
    """Per-feature audit: dtype, missing, +/-inf, negatives, unique values, constant flag."""
    rows = []
    for c in feature_columns(df):
        s = df[c]
        is_float = pd.api.types.is_float_dtype(s)
        vals = s.to_numpy(dtype="float64", na_value=np.nan)
        rows.append({
            "feature": c,
            "dtype": str(s.dtype),
            "n_missing": int(np.isnan(vals).sum()),
            "n_pos_inf": int(np.isposinf(vals).sum()) if is_float else 0,
            "n_neg_inf": int(np.isneginf(vals).sum()) if is_float else 0,
            "n_negative": int((vals < 0).sum()),
            "n_unique": int(s.nunique(dropna=True)),
            "is_constant": bool(s.nunique(dropna=True) <= 1),
        })
    return pd.DataFrame(rows).set_index("feature")


def invalid_value_summary(df: pd.DataFrame) -> dict:
    """Dataset-level counts of rows containing NaN / inf, and which columns are responsible."""
    feats = feature_columns(df)
    block = df[feats].to_numpy(dtype="float64", na_value=np.nan)
    has_nan = np.isnan(block).any(axis=1)
    has_inf = np.isinf(block).any(axis=1)
    return {
        "n_rows": int(len(df)),
        "rows_with_nan": int(has_nan.sum()),
        "rows_with_inf": int(has_inf.sum()),
        "rows_with_nan_or_inf": int((has_nan | has_inf).sum()),
    }


def label_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Count and percentage per label, sorted descending."""
    counts = df[LABEL_COL].value_counts()
    out = pd.DataFrame({"count": counts, "percent": (counts / counts.sum() * 100).round(4)})
    out.index.name = LABEL_COL
    return out


def label_by_file(df: pd.DataFrame) -> pd.DataFrame:
    """Label x source-file contingency table (shows which attacks live in which capture file)."""
    return pd.crosstab(df[LABEL_COL], df[SOURCE_FILE_COL])


def imbalance_summary(df: pd.DataFrame) -> dict:
    """Binary and multiclass imbalance indicators."""
    dist = df[LABEL_COL].value_counts()
    benign = int(dist.get(BENIGN_LABEL, 0))
    malicious = int(dist.sum() - benign)
    return {
        "benign": benign,
        "malicious": malicious,
        "malicious_fraction": round(malicious / max(len(df), 1), 6),
        "n_classes": int(dist.size),
        "largest_class": str(dist.idxmax()),
        "smallest_class": str(dist.idxmin()),
        "imbalance_ratio_max_min": round(float(dist.max() / max(dist.min(), 1)), 2),
        "classes_below_100_samples": sorted(dist[dist < 100].index.tolist()),
    }


def duplicate_audit(df: pd.DataFrame) -> dict:
    """Duplicate analysis on flow features (identifiers excluded).

    * feature_duplicate_rows : rows whose feature vector appeared earlier (same or different label).
    * conflicting_groups     : distinct feature vectors that carry more than one label
                               (label noise; cannot be learned and inflates error).
    * cross_file_duplicate_vectors : feature vectors present in more than one source file
                               (a direct train/test leakage risk if files are split).
    """
    feats = feature_columns(df)
    h = pd.util.hash_pandas_object(df[feats], index=False)
    tmp = pd.DataFrame({
        "h": h.to_numpy(),
        LABEL_COL: df[LABEL_COL].to_numpy(),
        SOURCE_FILE_COL: df[SOURCE_FILE_COL].to_numpy() if SOURCE_FILE_COL in df else "unknown",
    })
    g = tmp.groupby("h")
    n_unique_vectors = g.ngroups
    label_counts = g[LABEL_COL].nunique()
    file_counts = g[SOURCE_FILE_COL].nunique()
    dup_mask = tmp.duplicated("h", keep="first")
    return {
        "n_rows": int(len(df)),
        "n_unique_feature_vectors": int(n_unique_vectors),
        "feature_duplicate_rows": int(dup_mask.sum()),
        "feature_duplicate_percent": round(float(dup_mask.mean() * 100), 4),
        "conflicting_label_groups": int((label_counts > 1).sum()),
        "rows_in_conflicting_groups": int(tmp["h"].isin(label_counts[label_counts > 1].index).sum()),
        "cross_file_duplicate_vectors": int((file_counts > 1).sum()),
        "duplicates_by_label": tmp[dup_mask][LABEL_COL].value_counts().to_dict(),
    }


def correlated_pairs(df: pd.DataFrame, threshold: float = 0.95, sample: int = 200_000,
                     seed: int = 42) -> pd.DataFrame:
    """Feature pairs with |Pearson r| >= threshold (inf/NaN rows dropped; constant columns skipped)."""
    feats = feature_columns(df)
    data = df[feats]
    if len(data) > sample:
        data = data.sample(sample, random_state=seed)
    data = data.replace([np.inf, -np.inf], np.nan).dropna()
    data = data.loc[:, data.nunique() > 1]
    corr = data.corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape, dtype=bool), k=1))
    pairs = upper.stack().reset_index()
    pairs.columns = ["feature_a", "feature_b", "abs_corr"]
    return pairs[pairs["abs_corr"] >= threshold].sort_values("abs_corr", ascending=False).reset_index(drop=True)


def timestamp_audit(df: pd.DataFrame) -> pd.DataFrame | None:
    """Parse Timestamp (day-first, as in the published CSVs) and summarise per source file.

    Returns None when the dataset version has no Timestamp column. Unparseable values are
    counted, not silently dropped. Timestamps in the originals carry no AM/PM marker, so
    hour-of-day must be validated against the published attack schedule before being relied upon.
    """
    if "Timestamp" not in df.columns:
        return None
    ts = pd.to_datetime(df["Timestamp"], dayfirst=True, errors="coerce")
    out = (
        pd.DataFrame({SOURCE_FILE_COL: df[SOURCE_FILE_COL], "ts": ts})
        .groupby(SOURCE_FILE_COL)["ts"]
        .agg(first="min", last="max", n_unparseable=lambda s: int(s.isna().sum()))
    )
    return out


def ip_audit(df: pd.DataFrame) -> dict | None:
    """Private/public split of IPs and top source IPs per attack label.

    Returns None when the dataset has no IP columns (MachineLearningCVE version).
    """
    if not {"Source IP", "Destination IP"}.issubset(df.columns):
        return None

    def is_private(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast

    result: dict = {}
    for col in ("Source IP", "Destination IP"):
        uniq = df[col].dropna().unique()
        flag = {ip: is_private(ip) for ip in uniq}
        mapped = df[col].map(flag)
        result[col] = {
            "n_unique": int(len(uniq)),
            "flows_private_or_reserved": int(mapped.sum()),
            "flows_public": int((~mapped.fillna(False).astype(bool)).sum()),
        }
    mal = df[df[LABEL_COL] != BENIGN_LABEL]
    top = (
        mal.groupby(LABEL_COL)["Source IP"]
        .agg(lambda s: s.value_counts().head(3).to_dict())
        .to_dict()
    )
    result["top_source_ips_per_attack"] = top
    return result


def flow_id_audit(df: pd.DataFrame) -> dict | None:
    """Repeated Flow IDs indicate CICFlowMeter flow splits (related-flow leakage risk)."""
    if "Flow ID" not in df.columns:
        return None
    vc = df["Flow ID"].value_counts()
    return {
        "n_unique_flow_ids": int(vc.size),
        "n_flows": int(len(df)),
        "flow_ids_repeated": int((vc > 1).sum()),
        "max_repeats_single_flow_id": int(vc.max()),
    }
