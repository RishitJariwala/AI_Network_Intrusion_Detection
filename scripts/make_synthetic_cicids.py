"""Generate a SYNTHETIC CICIDS2017-shaped dataset for testing code paths only.

The values are random draws with crude class-conditional shifts. They carry NO information about
real network traffic. Never report any metric computed on this data as a project result.
Output defaults to a temp-style directory, never data/raw.

Usage:
    python scripts/make_synthetic_cicids.py --out data/synthetic_test --rows 20000 --layout traffic_labelling
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.data.schema import FLOW_FEATURE_COLUMNS, IDENTIFIER_COLUMNS  # noqa: E402

LABELS = {
    "BENIGN": 0.80, "DoS Hulk": 0.06, "PortScan": 0.05, "DDoS": 0.04, "DoS GoldenEye": 0.01,
    "FTP-Patator": 0.01, "SSH-Patator": 0.01, "Bot": 0.005, "Web Attack \x96 Brute Force": 0.005,
    "Infiltration": 0.0005, "Heartbleed": 0.0002,
}
FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]
DAY_OF_FILE = {FILES[0]: 3, FILES[1]: 4, FILES[2]: 5, FILES[3]: 7}


def make_frame(n: int, file_name: str, layout: str, rng: np.random.Generator) -> pd.DataFrame:
    labels = list(LABELS)
    p = np.array(list(LABELS.values()))
    if file_name.startswith("Monday"):
        lab = np.array(["BENIGN"] * n)
    else:
        lab = rng.choice(labels, size=n, p=p / p.sum())
    shift = {l: (i * 0.35) for i, l in enumerate(labels)}
    s = np.array([shift[l] for l in lab])
    data = {}
    for j, col in enumerate(FLOW_FEATURE_COLUMNS):
        base = rng.lognormal(mean=2.0 + (j % 5) * 0.4, sigma=1.0, size=n)
        data[col] = np.round(base * (1 + s * ((j % 3) - 1) * 0.3), 3)
    df = pd.DataFrame(data)
    df["Destination Port"] = rng.choice([80, 443, 22, 21, 53, 8080, 445], size=n).astype(int)
    df["Flow Duration"] = rng.integers(1, 120_000_000, size=n)
    df["Fwd Header Length.1"] = df["Fwd Header Length"]
    # real-world defects the loader and audits must survive
    bad = rng.choice(n, size=max(n // 200, 1), replace=False)
    df.loc[bad[: len(bad) // 2], "Flow Bytes/s"] = np.inf
    df.loc[bad[len(bad) // 2:], "Flow Packets/s"] = np.nan
    df.loc[bad[:3], "Init_Win_bytes_forward"] = -1
    df["Label"] = lab
    if layout == "traffic_labelling":
        day = DAY_OF_FILE[file_name]
        src = [f"192.168.10.{i}" for i in rng.integers(2, 60, size=n)]
        dst = [f"172.16.0.{i}" for i in rng.integers(1, 5, size=n)]
        pub = rng.random(n) < 0.05
        src = np.where(pub, "8.8.8.8", src)
        sp = rng.integers(1024, 65535, size=n)
        dp = df["Destination Port"].to_numpy()
        df.insert(0, "Flow ID", [f"{d}-{s_}-{a}-{b}-6" for d, s_, a, b in zip(dst, src, sp, dp)])
        df.insert(1, "Source IP", src)
        df.insert(2, "Source Port", sp)
        df.insert(3, "Destination IP", dst)
        df.insert(5, "Protocol", 6)
        minutes = rng.integers(0, 600, size=n)
        df.insert(6, "Timestamp", [f"{day}/7/2017 {8 + m // 60}:{m % 60:02d}" for m in minutes])
        # duplicate some rows to exercise duplicate analysis
    dup = df.sample(n // 100, random_state=1)
    df = pd.concat([df, dup], ignore_index=True)
    # pad column names with a leading space like the originals
    df.columns = [f" {c}" if c not in ("Flow ID",) else c for c in df.columns]
    return df


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/synthetic_test")
    ap.add_argument("--rows", type=int, default=20000)
    ap.add_argument("--layout", choices=["traffic_labelling", "machine_learning_cve"],
                    default="traffic_labelling")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(a.seed)
    for f in FILES:
        df = make_frame(a.rows // len(FILES), f, a.layout, rng)
        # original files contain a cp1252 en-dash byte (0x96); reproduce it
        df.to_csv(out / f, index=False, encoding="latin-1", errors="replace")
        print(f"wrote {out / f}  rows={len(df)} cols={df.shape[1]}")
    print("SYNTHETIC DATA - for code testing only. Not real traffic.")


if __name__ == "__main__":
    main()
