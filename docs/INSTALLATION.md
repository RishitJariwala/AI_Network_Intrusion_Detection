# Argus NIDS: Installation & Deployment Guide

This guide provides end-to-end instructions for installing, configuring, and verifying the **Argus NIDS** system on macOS, Linux, and Windows.

---

## 1. Prerequisites

- **Python Version:** Python 3.11 or Python 3.12 (64-bit recommended)
- **Memory (RAM):** 8 GB minimum (16 GB recommended for multi-GB raw dataset processing)
- **Disk Space:** 5 GB free disk space (for raw captures, processed arrays, and model binaries)
- **Git** (optional, for version control)

---

## 2. Step-by-Step Installation

### Step 2.1: Clone or Open the Workspace
```bash
cd AI_Network_Intrusion_Detection
```

### Step 2.2: Initialize Python Virtual Environment
```bash
# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 2.3: Upgrade Package Installer & Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```
*Note: If `uv` is installed on your system, you can accelerate installation with `uv pip install -r requirements.txt`.*

### Step 2.4: Environment Configuration
Copy the template configuration to create your active `.env` file:
```bash
cp .env.example .env
```
Optionally edit `.env` to configure threat intelligence API keys and database endpoints:
```ini
# Database Connection (Defaults to SQLite if omitted)
DATABASE_URL=sqlite:///data/nids_security.db

# Cyber Threat Intelligence API Keys (Optional; system falls back to curated local IOCs if omitted)
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
OTX_API_KEY=your_alienvault_otx_api_key_here
```

---

## 3. Dataset Acquisition & Verification

To automatically download the official 270 MB CICIDS2017 `TrafficLabelling` package (extracting to ~1.1 GB of 8 CSV files):
```bash
python scripts/download_datasets.py
```
Verify dataset schema, column counts, and cryptographic hashes:
```bash
python main.py verify-data
```
Expected output:
```
Found 8 CSV file(s) in data/raw
...
[OK] Dataset verified.
```

---

## 4. Pipeline Execution & Model Training

Execute the end-to-end pipeline using the unified CLI:

```bash
# 1. Exploratory Data Analysis (generates figures & eda_summary.json)
python main.py eda

# 2. Anti-Leakage Preprocessing & Feature Selection
python main.py preprocess --sample-size 150000

# 3. Model Training, Evaluation & Benchmarking (XGBoost, RF, LogReg, Isolation Forest)
python main.py train

# 4. Generate Global SHAP Feature Importances
python main.py explain
```

---

## 5. Running Automated Verification Tests

Execute the complete pytest suite (39 automated tests covering data loading, EDA, preprocessing, models, XAI, CTI, database, and API):
```bash
python main.py test
# or:
pytest -v
```

---

## 6. Launching Services

### Option A: Launch FastAPI REST Service
```bash
python main.py serve-api --port 8000
```
- Swagger UI Documentation: `http://localhost:8000/docs`
- Health Endpoint: `http://localhost:8000/health`

### Option B: Launch Streamlit SOC Dashboard
```bash
python main.py dashboard --port 8501
```
- Dashboard UI: `http://localhost:8501`

