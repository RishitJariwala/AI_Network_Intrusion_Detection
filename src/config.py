"""Central project paths and constants. Import from here; never hard-code paths elsewhere."""
from __future__ import annotations

from pathlib import Path

import os

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = PROJECT_ROOT / "data"
# NIDS_RAW_DIR lets you keep the multi-GB dataset on another drive without copying it.
RAW_DIR = Path(os.getenv("NIDS_RAW_DIR", DATA_DIR / "raw"))
PROCESSED_DIR = DATA_DIR / "processed"
EXTERNAL_DIR = DATA_DIR / "external"

MODELS_DIR = PROJECT_ROOT / "models"
CLASSIFICATION_MODEL_DIR = MODELS_DIR / "classification"
ANOMALY_MODEL_DIR = MODELS_DIR / "anomaly_detection"

# NIDS_OUTPUTS_DIR redirects figures/evaluation files (used when testing with synthetic data).
OUTPUTS_DIR = Path(os.getenv("NIDS_OUTPUTS_DIR", PROJECT_ROOT / "outputs"))
FIGURES_DIR = OUTPUTS_DIR / "figures"
EVALUATION_DIR = OUTPUTS_DIR / "evaluation"
PREDICTIONS_DIR = OUTPUTS_DIR / "predictions"

REPORTS_DIR = PROJECT_ROOT / "reports"

RANDOM_STATE = 42

# Normalised (whitespace-stripped) column names used throughout the project.
LABEL_COL = "Label"
SOURCE_FILE_COL = "source_file"
IDENTIFIER_COLS = [
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Timestamp",
]
BENIGN_LABEL = "BENIGN"


def ensure_dirs() -> None:
    """Create every project output directory if it does not exist."""
    for d in (
        RAW_DIR, PROCESSED_DIR, EXTERNAL_DIR, CLASSIFICATION_MODEL_DIR,
        ANOMALY_MODEL_DIR, FIGURES_DIR, EVALUATION_DIR, PREDICTIONS_DIR, REPORTS_DIR,
    ):
        d.mkdir(parents=True, exist_ok=True)
