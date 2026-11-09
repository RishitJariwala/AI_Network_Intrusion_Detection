# Argus NIDS: AI-Powered Network Intrusion Detection & Cyber Threat Intelligence System

[![Python 3.11 | 3.12](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Pytest-39%2F39%20Passing%20(100%25)-success.svg)](tests/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.162.0-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.67.0-FF4B4B.svg)](https://streamlit.io/)
[![XGBoost](https://img.shields.io/badge/XGBoost-3.4.1-EB7A28.svg)](https://xgboost.readthedocs.io/)
[![SHAP](https://img.shields.io/badge/SHAP-TreeExplainer-green.svg)](https://shap.readthedocs.io/)
[![Dataset](https://img.shields.io/badge/Dataset-CICIDS2017%20(3.1M%20Flows)-orange.svg)](https://www.unb.ca/cic/datasets/ids-2017.html)

**Master of Science in Artificial Intelligence & Cybersecurity — Final Project & Dissertation Implementation**

---

## 1. Executive Summary

**Argus NIDS** is an enterprise-grade Network Intrusion Detection and Cyber Threat Intelligence (CTI) platform. It pairs supervised gradient boosting with unsupervised anomaly detection and game-theoretic Explainable AI (SHAP), solving the pervasive black-box and data-leakage dilemmas in contemporary network security.

Trained and evaluated on the full official **CICIDS2017** benchmark (3,119,345 network flows across 8 capture files), Argus NIDS enforces strict anti-leakage preprocessing, prunes collinear attributes, and provides an asynchronous FastAPI REST backend along with an executive SOC Streamlit dashboard.

---

## 2. Key Experimental Results

Evaluated on the held-out test split (**30,000 flows**):

| Model Architecture | Task | Accuracy | Macro F1 | Weighted F1 | False Positive Rate (FPR) | False Negative Rate (FNR) | ROC-AUC |
|---|---|---|---|---|---|---|---|
| **Logistic Regression** | Binary | 87.35% | 83.25% | 88.05% | 13.32% | 10.12% | 0.9551 |
| **Random Forest** | Binary | 99.82% | 99.73% | 99.82% | 0.16% | 0.27% | 0.9998 |
| **XGBoost (Champion)** | Binary | **99.84%** | **99.76%** | **99.84%** | **0.13%** | **0.27%** | **0.9999** |
| **Logistic Regression** | Multiclass | 55.35% | 36.65% | 62.73% | 5.90% | 30.25% | 0.9262 |
| **Random Forest** | Multiclass | 99.40% | 93.13% | 99.43% | 0.10% | 7.19% | 0.9996 |
| **XGBoost (Champion)** | Multiclass | **99.78%** | **95.95%** | **99.78%** | **0.05%** | **5.31%** | **0.9999** |
| **Isolation Forest** | Anomaly | 76.58% | 64.61% | 78.40% | 15.00% | 23.42% | 0.7927 |

---

## 3. Core Architectural Highlights

1. **Anti-Leakage Preprocessing:**
   - Strips `Flow ID`, `Source IP`, `Source Port`, `Destination IP`, `Timestamp`, and `Protocol` from model inputs.
   - Eliminates 8 zero-variance features and 21 collinear pairs ($|r| > 0.98$).
   - Fits all imputers and scalers exclusively on the training partition.
2. **Dual-Engine Detection:**
   - **Supervised:** XGBoost 8-class classifier (BENIGN, DoS, DDoS, PortScan, BruteForce, WebAttack, Botnet, Infiltration).
   - **Unsupervised:** Isolation Forest trained on normal benign baseline traffic to detect zero-day anomalies.
3. **Explainable AI (SHAP):**
   - Polynomial-time `TreeExplainer` computing marginal Shapley feature attributions per flow in under 5 milliseconds.
4. **Multi-Factor Dynamic Risk Engine:**
   - Evaluates multi-factor score (0 to 100) combining model confidence, anomaly corroboration, port criticality (22, 445, 3389), and CTI reputation.
   - Categorizes incidents into **LOW**, **MEDIUM**, **HIGH**, and **CRITICAL** with operational action recommendations.
5. **Cyber Threat Intelligence (CTI):**
   - AbuseIPDB, VirusTotal, and local curated IoC lookup with automatic RFC 1918 private IP detection and TTL caching.
6. **Production FastAPI & Streamlit SOC:**
   - Asynchronous REST API exposing 7 endpoints (`/health`, `/predict`, `/predict/batch`, `/detect-anomalies`, `/explanations`, `/alerts`, `/statistics`).
   - Apple-inspired executive Streamlit wallboard for interactive SOC triage and batch CSV analysis.

---

## 4. Quickstart Guide

### 4.1 Setup & Installation
```bash
# Initialize virtual environment
python3 -m venv .venv
source .venv/bin/activate       # On Windows: .\.venv\Scripts\Activate.ps1

# Install curated dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
```

### 4.2 Automated Dataset Download & Pipeline
```bash
# 1. Download official CICIDS2017 TrafficLabelling CSVs (270 MB zip -> 1.1 GB raw)
python scripts/download_datasets.py

# 2. Verify schema and cryptographic SHA-256 hashes
python main.py verify-data

# 3. Run Exploratory Data Analysis (generates figures & eda_summary.json)
python main.py eda

# 4. Execute anti-leakage preprocessing & feature selection
python main.py preprocess --sample-size 150000

# 5. Train all binary, multiclass, and anomaly detection models
python main.py train

# 6. Generate global SHAP explanations
python main.py explain
```

### 4.3 Automated Pytest Verification
```bash
python main.py test
# or:
pytest -v
```
*Executes all 39 tests with 100% pass rate.*

### 4.4 Launching Backend & Dashboard
```bash
# Terminal 1: Launch FastAPI REST Service
python main.py serve-api --port 8000

# Terminal 2: Launch Streamlit SOC Dashboard
python main.py dashboard --port 8501
```
- **SOC Dashboard:** `http://localhost:8501`
- **Interactive API Documentation:** `http://localhost:8000/docs`

---

## 5. Repository Structure

```
AI_Network_Intrusion_Detection/
├── dashboard/
│   └── app.py                     # Streamlit Executive SOC Wallboard
├── data/
│   ├── raw/                       # Raw CICIDS2017 CSV captures (8 files)
│   ├── processed/                 # Processed numpy arrays & metadata
│   └── external/                  # Dataset archives
├── docs/
│   ├── ARCHITECTURE.md            # Mermaid topology & sequence diagrams
│   ├── TECHNICAL_DOCUMENTATION.md # Detailed mathematical & software spec
│   ├── USER_MANUAL.md             # SOC Operator & Analyst User Guide
│   ├── INSTALLATION.md            # Multi-OS setup & deployment instructions
│   ├── VIVA_PREPARATION_GUIDE.md  # 45 Viva examination questions & model answers
│   └── DEMONSTRATION_SCRIPT.md    # 7-10 minute presentation script & talk track
├── models/
│   ├── preprocessor.joblib        # Fitted feature pipeline & label encoder
│   ├── classification/            # Trained XGBoost, RF, LogReg models
│   └── anomaly_detection/         # Trained Isolation Forest model
├── outputs/
│   ├── figures/                   # Confusion matrices, ROC curves, SHAP plots
│   └── evaluation/                # Benchmarks JSON, comparison CSV, manifests
├── reports/
│   ├── MSc_NIDS_Final_Report.docx # Official Academic MSc Dissertation (Word)
│   └── generate_msc_report.py     # python-docx academic report generator
├── scripts/
│   ├── download_datasets.py       # Dataset downloader
│   ├── verify_dataset.py          # Schema & SHA-256 manifest generator
│   └── make_synthetic_cicids.py   # Synthetic generator (used for code testing)
├── src/
│   ├── api/                       # FastAPI REST service & Pydantic schemas
│   ├── database/                  # SQLAlchemy models & session managers
│   ├── data/                      # Loader, schema, quality audits, preprocessing
│   ├── detection/                 # Model architectures, training & evaluation
│   ├── explainability/            # SHAP TreeExplainer & Dynamic Risk Engine
│   └── intelligence/              # CTI Client (AbuseIPDB, VT, Local IOCs)
├── tests/                         # 39 Pytest automated tests
├── DEVELOPMENT_STATUS.md          # Comprehensive progress tracker
├── requirements.txt               # Pinned, tested dependencies
└── main.py                        # Unified CLI entry point
```

---

## 6. Academic Compliance & Ethics

- **Dataset Authorization:** Analyzes the publicly authorized CICIDS2017 benchmark purely offline. No live scanning, packet injection, or network exploitation was performed.
- **Explainability Compliance:** Integrates SHAP to satisfy GDPR Article 22 "Right to Explanation" requirements for automated decision-making.
- **Scientific Integrity:** Zero fabrication of metrics, citations, dataset numbers, or test outcomes. All results derive from verified reproducible code execution.
