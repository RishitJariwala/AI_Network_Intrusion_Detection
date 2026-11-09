# Argus NIDS: Security Operations Center (SOC) User Manual

## 1. Introduction

Welcome to the **Argus NIDS User Manual**. This document guides Security Analysts, SOC Managers, and Academic Evaluators through operating, navigating, and interpreting the Argus Network Intrusion Detection & Cyber Threat Intelligence System.

---

## 2. Quick-Start Guide

### Launching the System
```bash
# Terminal 1: Launch FastAPI Backend
python main.py serve-api --port 8000

# Terminal 2: Launch Streamlit SOC Wallboard
python main.py dashboard --port 8501
```
Open your browser and navigate to:
- **SOC Dashboard:** `http://localhost:8501`
- **Interactive API Documentation:** `http://localhost:8000/docs`

---

## 3. Navigating the SOC Dashboard

The dashboard features 7 dedicated operational views:

### 3.1 📊 Executive Security Overview
- **Metric Cards:** Real-time counters showing total alerts, critical incidents, high-risk triage, and zero-day anomalies flagged by the unsupervised engine.
- **Model Benchmark Bar Chart:** Displays empirical accuracy, Macro-F1, and weighted F1 across the model architectures.
- **Attack Category Donut:** Visual breakdown of the most prevalent attack vectors captured.

### 3.2 🔍 Traffic Classifier & Batch Analysis
- **Batch CSV Analysis:** Upload any network flow CSV or click **"Load Pre-Packaged Benchmark Test Captures"** (2,000 flows). The system classifies the flows using vectorized XGBoost, evaluates anomaly scores, computes multi-factor risk scores, and displays throughput metrics.
- **Interactive Single Flow Inspector:** Allows SOC analysts to manually adjust parameters (Destination Port, Flow Duration, Packet Rates, Window Sizes) and immediately observe the model's threat prediction, risk assessment, and recommended mitigation.

### 3.3 🧬 Unsupervised Anomaly Detection
- Displays the density distribution of Isolation Forest anomaly scores.
- **Threshold Sensitivity Slider:** Adjust the contamination percentile (1% to 30%) to observe how sensitivity impacts alert volume and zero-day discovery.

### 3.4 💡 Explainable AI (SHAP)
- **Global Feature Importance:** Bar plot ranking the top 20 network flow features driving classification decisions.
- **Local Waterfall Attribution:** Select any flow from the test benchmark and view an interactive attribution graph displaying the exact mathematical push of each feature toward attack or benign status.

### 3.5 🌐 Cyber Threat Intelligence (CTI)
- **IP Reputation Lookup:** Enter any IPv4 address (e.g. `205.174.165.73`, `192.168.10.50`, `8.8.8.8`) to query AbuseIPDB / local threat feeds.
- Displays abuse confidence score, country code, ASN/ISP, total reports, and intelligence tags (e.g. `Botnet C2 Master`, `Tor Exit Node`).
- Automatically recognizes RFC 1918 private subnets without making wasteful external queries.

### 3.6 🚨 Security Alerts & Incident Response
- Displays the persistent SQLAlchemy database alert queue.
- **Analyst Workflow:** Filter alerts by Risk Level (Critical, High, Medium, Low) and Operational Status (New, Investigating, Resolved, False Positive).
- Select any Alert ID and update its operational status with one click.

### 3.7 📄 Downloadable Reports
- **Export CSV Incident History:** Generates an immediate audit CSV log of all recorded security events.
- **Download Dissertation Report (DOCX):** Directly download the academic Master of Science dissertation report.

---

## 4. Operational Risk Levels & Action Matrix

| Risk Level | Score Range | Operational Meaning | Mandatory SOC Action |
|---|---|---|---|
| **LOW** | 0 – 24 | Normal enterprise traffic; standard service requests | Monitor routine traffic; no remediation required |
| **MEDIUM** | 25 – 54 | Minor port probe or low-confidence anomaly | Flag for secondary review; inspect source IP for repeated scanning |
| **HIGH** | 55 – 79 | Confirmed attack targeting critical enterprise services | Apply firewall rate-limit or host isolation; open incident ticket |
| **CRITICAL** | 80 – 100 | Severe exploit, DDoS, Botnet C2, or blacklisted IP | IMMEDIATE MITIGATION: Block IP at border firewall; trigger Tier-3 response |

