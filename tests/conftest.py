"""Shared fixtures. Synthetic data is used ONLY to test code paths, never to produce results."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def synthetic_dir(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("synthetic_cicids")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "make_synthetic_cicids.py"),
         "--out", str(out), "--rows", "8000", "--layout", "traffic_labelling"],
        check=True, capture_output=True,
    )
    return out


@pytest.fixture(scope="session")
def synthetic_cve_dir(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("synthetic_cve")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "make_synthetic_cicids.py"),
         "--out", str(out), "--rows", "8000", "--layout", "machine_learning_cve"],
        check=True, capture_output=True,
    )
    return out


@pytest.fixture(scope="session")
def df_tl(synthetic_dir):
    from src.data.loader import load_dataset
    return load_dataset(synthetic_dir)


@pytest.fixture(scope="session")
def df_cve(synthetic_cve_dir):
    from src.data.loader import load_dataset
    return load_dataset(synthetic_cve_dir)
