"""Download and unpack official CICIDS2017 TrafficLabelling dataset from verified academic mirror.

Usage:
    python scripts/download_datasets.py [--unsw]
"""
from __future__ import annotations

import argparse
import logging
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.config import DATA_DIR, EXTERNAL_DIR, RAW_DIR  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dataset_downloader")

CICIDS_URL = (
    "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/csvs/GeneratedLabelledFlows.zip"
)
UNSW_TRAIN_URL = (
    "https://huggingface.co/datasets/rdpahalavan/UNSW-NB15/resolve/main/UNSW_NB15_training-set.csv"
)
UNSW_TEST_URL = (
    "https://huggingface.co/datasets/rdpahalavan/UNSW-NB15/resolve/main/UNSW_NB15_testing-set.csv"
)


def download_file(url: str, dest_path: Path) -> Path:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if dest_path.exists() and dest_path.stat().st_size > 1024:
        logger.info("File already exists: %s (%d bytes)", dest_path, dest_path.stat().st_size)
        return dest_path

    logger.info("Downloading %s -> %s", url, dest_path)
    req = urllib.request.Request(url, headers={"User-Agent": "NIDS-Acquisition/1.0"})

    class ProgressHook:
        def __init__(self):
            self.last_reported = -1

        def __call__(self, block_num, block_size, total_size):
            downloaded = block_num * block_size
            if total_size > 0:
                pct = int((downloaded / total_size) * 100)
                if pct % 10 == 0 and pct != self.last_reported:
                    self.last_reported = pct
                    logger.info("Progress: %d%% (%d / %d MB)", pct, downloaded // (1024 * 1024), total_size // (1024 * 1024))

    urllib.request.urlretrieve(url, dest_path, reporthook=ProgressHook())
    logger.info("Download completed: %s", dest_path)
    return dest_path


def extract_cicids(zip_path: Path, target_dir: Path) -> list[Path]:
    logger.info("Extracting %s into %s ...", zip_path.name, target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    extracted_files = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            # Skip directories or MacOS metadata (__MACOSX)
            if member.is_dir() or member.filename.startswith("__MACOSX"):
                continue
            filename = Path(member.filename).name
            if not filename.endswith(".csv"):
                continue
            dest_file = target_dir / filename
            if not dest_file.exists() or dest_file.stat().st_size == 0:
                with zf.open(member) as source, open(dest_file, "wb") as target:
                    target.write(source.read())
                logger.info("Extracted %s (%.1f MB)", filename, dest_file.stat().st_size / (1024 * 1024))
            else:
                logger.info("Already extracted: %s", filename)
            extracted_files.append(dest_file)
    return extracted_files


def main() -> int:
    parser = argparse.ArgumentParser(description="Acquire CICIDS2017 & UNSW-NB15 datasets.")
    parser.add_argument("--unsw", action="store_true", help="Also download UNSW-NB15 dataset files.")
    args = parser.parse_args()

    zip_dest = EXTERNAL_DIR / "GeneratedLabelledFlows.zip"
    try:
        download_file(CICIDS_URL, zip_dest)
        csv_files = extract_cicids(zip_dest, RAW_DIR)
        logger.info("Successfully acquired %d CICIDS2017 raw CSV files in %s", len(csv_files), RAW_DIR)
    except Exception as e:
        logger.error("Failed to acquire CICIDS2017: %s", e)
        return 1

    if args.unsw:
        try:
            logger.info("Downloading optional UNSW-NB15 files...")
            download_file(UNSW_TRAIN_URL, EXTERNAL_DIR / "UNSW_NB15_training-set.csv")
            download_file(UNSW_TEST_URL, EXTERNAL_DIR / "UNSW_NB15_testing-set.csv")
            logger.info("UNSW-NB15 acquisition successful.")
        except Exception as e:
            logger.warning("Could not download UNSW-NB15: %s", e)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

