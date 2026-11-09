# Dataset Acquisition: CICIDS2017

## Which version to use

CICIDS2017 is distributed in two common packages. They describe the same capture but differ in content.

| Package | Columns | IPs, ports, timestamps, Flow ID | Use |
|---|---|---|---|
| TrafficLabelling (published by the dataset authors as generated labelled flows) | about 85 | Yes | **Preferred.** Enables time-aware and endpoint-aware splitting, flow-structure analysis and meaningful CTI enrichment. |
| MachineLearningCVE (also called MachineLearningCSV) | about 79 | No | Fallback. Fewer columns, no leakage controls based on time or endpoints. |

The Kaggle mirror `chethuhn/cicids2017` referenced in the supplied script is believed to be the MachineLearningCVE package. Confirm with `python scripts/verify_dataset.py`; if it reports `layout=machine_learning_cve`, the copy has no IPs or timestamps.

## Download steps (Windows PowerShell)

1. Open the official dataset page: https://www.unb.ca/cic/datasets/ids-2017.html and follow its download instructions (the authors may ask for a short registration form).
2. Download the **TrafficLabelling** package. Extract the CSV files into `data\raw\` inside the project, or anywhere else and set:

   ```powershell
   $env:NIDS_RAW_DIR = "D:\datasets\CICIDS2017"
   ```
3. Verify:

   ```powershell
   python scripts\verify_dataset.py
   ```
   This reports each file's size, column count and detected layout, flags differences from `src/data/schema.py`, and writes `outputs/evaluation/dataset_manifest.csv` (file sizes and SHA-256) for the report appendix.

Expected: about 8 CSV files and roughly 2.8 million flows in total. These figures come from the published dataset description and must be confirmed by the EDA output, not assumed.

## Notes on the supplied download scripts

Neither script was executed against live servers (the build sandbox cannot reach them), so their behaviour is untested.

- `download_cicids2017.py`: its file list has seven entries while its docstring says eight. The Thursday and Friday file names look incomplete or incorrect compared with the commonly distributed set (the Thursday web-attack and infiltration files and the Friday DDoS file). The S3 URLs could not be verified. Manual download is recommended.
- `download_kaggle_cicids.py`: needs Kaggle credentials; the `chmod 600` hint is Unix-specific and unnecessary on Windows. Provides the no-IP package.
- Both compute `RAW_DATA_DIR` as three directories above the script, which only works for one specific location in the tree.

## Corrected-label versions

Published research documents labelling and flow-construction errors in the original CICIDS2017 files (Engelen et al., 2021; Lanvin et al., 2022) and offers corrected data. The student must locate the authors' current download pages and verify both citations before they appear in the report. Results on the original files may be optimistic; the report will state this limitation, and a corrected-label comparison is a planned add-on.

## Licence and use

Academic and research use only, as stated by the dataset authors. Do not redistribute the raw or processed data in the public repository. `.gitignore` excludes `data/`.

## Optional: UNSW-NB15

Stretch goal for a cross-dataset generalisation test. Its features are produced by a different toolchain and overlap only partly with CICFlowMeter features; compatibility will be documented before any claim is made.
