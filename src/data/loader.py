"""Memory-conscious, lossless loader for CICIDS2017 CSV files.

Handles both public layouts:
  * MachineLearningCVE      - 78 features + Label, no IPs/timestamps.
  * TrafficLabelling        - adds Flow ID, Source/Destination IP, Source Port, Protocol, Timestamp.

Design rules:
  * Raw files are never modified.
  * Column names are whitespace-stripped (the originals carry leading spaces).
  * Labels are normalised (the en-dash in "Web Attack - ..." is corrupted by encoding in the originals).
  * Integer columns are downcast losslessly; float columns stay float64 so duplicate analysis is exact.
    Cast to float32 explicitly at modelling time if memory is tight.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterable

import pandas as pd

from src.config import LABEL_COL, RAW_DIR, SOURCE_FILE_COL

logger = logging.getLogger(__name__)

_NON_ASCII = re.compile(r"\s*[^\x20-\x7E]+\s*")


def normalise_label(label: object) -> str:
    """Strip whitespace and repair the corrupted dash in 'Web Attack <dash> X' labels."""
    text = str(label).strip()
    if text.lower().startswith("web attack"):
        text = _NON_ASCII.sub(" - ", text)
        text = re.sub(r"\s*-\s*", " - ", text)
    return text


def list_csv_files(raw_dir: Path | str = RAW_DIR) -> list[Path]:
    """Return CSV files under raw_dir (recursive), sorted by name."""
    raw_dir = Path(raw_dir)
    return sorted(p for p in raw_dir.rglob("*.csv") if p.is_file())


def load_csv(path: Path | str, nrows: int | None = None) -> pd.DataFrame:
    """Load one CICIDS2017 CSV with normalised columns and labels."""
    path = Path(path)
    df = pd.read_csv(
        path,
        nrows=nrows,
        encoding="utf-8",
        encoding_errors="replace",
        low_memory=False,
        skipinitialspace=True,
    )
    df.columns = [str(c).strip() for c in df.columns]
    if LABEL_COL not in df.columns:
        raise ValueError(f"{path.name}: no '{LABEL_COL}' column found. Columns: {list(df.columns)[:5]}...")
    df[LABEL_COL] = df[LABEL_COL].map(normalise_label)
    df = _downcast_integers(df)
    df[SOURCE_FILE_COL] = path.name
    return df


def _downcast_integers(df: pd.DataFrame) -> pd.DataFrame:
    """Lossless integer downcast; float columns are left untouched."""
    for col in df.select_dtypes(include="integer").columns:
        df[col] = pd.to_numeric(df[col], downcast="integer")
    return df


def load_dataset(
    raw_dir: Path | str = RAW_DIR,
    files: Iterable[Path | str] | None = None,
    nrows_per_file: int | None = None,
) -> pd.DataFrame:
    """Load and concatenate all CSVs. Adds a `source_file` column (capture day/session proxy)."""
    paths = [Path(p) for p in files] if files is not None else list_csv_files(raw_dir)
    if not paths:
        raise FileNotFoundError(
            f"No CSV files found in {raw_dir}. See docs/DATASET_ACQUISITION.md for download steps."
        )
    frames = []
    for p in paths:
        logger.info("Loading %s", p.name)
        frames.append(load_csv(p, nrows=nrows_per_file))
    columns = [list(f.columns) for f in frames]
    if any(c != columns[0] for c in columns[1:]):
        logger.warning("Column sets differ across files; concatenation will introduce NaNs.")
    return pd.concat(frames, ignore_index=True)


def detect_layout(df: pd.DataFrame) -> str:
    """Return 'traffic_labelling' if IP/timestamp columns exist, else 'machine_learning_cve'."""
    has_ids = {"Source IP", "Destination IP", "Timestamp"}.issubset(df.columns)
    return "traffic_labelling" if has_ids else "machine_learning_cve"
