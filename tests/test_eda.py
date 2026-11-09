"""Smoke test: EDA pipeline runs end-to-end on synthetic data and writes its artefacts."""
from __future__ import annotations

import json

from src.data.eda import run_eda


def test_run_eda_writes_summary_and_figures(df_tl, tmp_path):
    figs, ev = tmp_path / "figs", tmp_path / "eval"
    summary = run_eda(df_tl, figures_dir=figs, evaluation_dir=ev)
    assert summary["layout"] == "traffic_labelling"
    assert (ev / "eda_summary.json").exists()
    assert json.loads((ev / "eda_summary.json").read_text())["n_rows"] == len(df_tl)
    for name in summary["figures"]:
        assert (figs / name).stat().st_size > 1000
    assert "eda_label_distribution.png" in summary["figures"]
