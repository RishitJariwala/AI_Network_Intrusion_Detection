"""Check that data/raw holds a usable CICIDS2017 copy and report what version it is.

Run from the project root:
    python scripts/verify_dataset.py
    python scripts/verify_dataset.py --raw-dir D:\\datasets\\CICIDS2017

Reads only the header and a small sample of each file, so it is fast and memory-light.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.config import RAW_DIR  # noqa: E402
from src.data.loader import detect_layout, list_csv_files, load_csv  # noqa: E402
from src.data.schema import FLOW_FEATURE_COLUMNS, IDENTIFIER_COLUMNS  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-dir", default=str(RAW_DIR))
    a = ap.parse_args()

    files = list_csv_files(a.raw_dir)
    if not files:
        print(f"[FAIL] No CSV files in {a.raw_dir}. See docs/DATASET_ACQUISITION.md.")
        return 1

    print(f"Found {len(files)} CSV file(s) in {a.raw_dir}\n")
    expected = set(FLOW_FEATURE_COLUMNS)
    layouts, ok = set(), True
    for p in files:
        df = load_csv(p, nrows=2000)
        cols = set(df.columns)
        layout = detect_layout(df)
        layouts.add(layout)
        missing = sorted(expected - cols)
        extra = sorted(cols - expected - set(IDENTIFIER_COLUMNS) - {"Label", "source_file"})
        size_mb = p.stat().st_size / 1_048_576
        print(f"{p.name:<60} {size_mb:8.1f} MB  cols={df.shape[1] - 1:<3} layout={layout}")
        if missing:
            ok = False
            print(f"    [WARN] schema.py expects columns not in file: {missing[:8]}")
        if extra:
            print(f"    [INFO] columns not in schema.py: {extra[:8]}")

    # Reproducibility manifest: size + SHA-256 of every file, saved for the report appendix.
    import hashlib
    from src.config import EVALUATION_DIR
    rows = []
    for p in files:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h.update(block)
        rows.append({"file": p.name, "bytes": p.stat().st_size, "sha256": h.hexdigest()})
    EVALUATION_DIR.mkdir(parents=True, exist_ok=True)
    manifest = EVALUATION_DIR / "dataset_manifest.csv"
    pd.DataFrame(rows).to_csv(manifest, index=False)
    print(f"\nManifest written: {manifest}")

    print()
    if len(layouts) > 1:
        ok = False
        print(f"[WARN] Mixed layouts across files: {sorted(layouts)}. Use one version only.")
    if layouts == {"machine_learning_cve"}:
        print("[NOTE] This copy has no IPs/timestamps. Group-aware splitting and CTI enrichment "
              "will be limited. The TrafficLabelling version is preferred (docs/DATASET_ACQUISITION.md).")
    print("[OK] Dataset verified." if ok else "[ATTENTION] Review warnings above before Phase 1.")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
