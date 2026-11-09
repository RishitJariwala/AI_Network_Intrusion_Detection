# Argus NIDS: 7–10 Minute Master Demonstration Script

**Audience:** MSc Examination Panel, Academic Supervisors, and Cybersecurity Peer Reviewers  
**Demonstrator:** Postgraduate Candidate / Senior AI Engineer  
**Duration:** 8 to 10 Minutes  
**Prerequisites:** Two open terminals, one browser window pointed at `http://localhost:8501` (Dashboard) and one at `http://localhost:8000/docs` (FastAPI Swagger UI).

---

## Timeline & Scene Overview

| Time | Phase | Target Screen / Tool | Key Message / Objective |
|---|---|---|---|
| **0:00 – 1:30** | Introduction & Problem Context | Title Slide / Overview Wallboard | Motivation, limitations of signature NIDS, and problem of data leakage. |
| **1:30 – 3:00** | Data Quality & Anti-Leakage Pipeline | Terminal / EDA Artifacts | Audit of 3.1M flows in CICIDS2017, collinearity pruning, and leakage prevention. |
| **3:00 – 4:30** | Dual-Engine Model Benchmarking | Dashboard: Benchmark Tab | XGBoost 99.84% accuracy, FPR 0.13%, and Isolation Forest zero-day anomaly detection. |
| **4:30 – 6:00** | Explainable AI (SHAP) in Action | Dashboard: SHAP Attribution Tab | Local waterfall attribution of flagged packets, Shapley value mathematical guarantees. |
| **6:00 – 7:30** | CTI Enrichment & Dynamic Risk Engine | Dashboard: CTI & Single Flow Tab | Corroborating AbuseIPDB reputation, critical ports, and 4-tier risk assessment. |
| **7:30 – 8:45** | High-Throughput API & Database | FastAPI `/docs` & Triage Tab | Asynchronous REST endpoints, SQLAlchemy alert management, and automated tests. |
| **8:45 – 10:00** | Summary, Ethics & Transition to Q&A | Summary Slide / Q&A Prompt | Key achievements, compliance with GDPR right to explanation, opening for questions. |

---

## Detailed Step-by-Step Talk Track

### [0:00 – 1:30] Introduction & Problem Motivation
**Action:** Share screen displaying the **Executive Security Overview** on the Streamlit Wallboard (`http://localhost:8501`).

> *"Good morning, esteemed members of the examination committee. Today, I am proud to present Argus NIDS — an AI-Powered Network Intrusion Detection and Cyber Threat Intelligence System.
> 
> Modern enterprise Security Operations Centers face an acute crisis: traditional signature-based detection systems like Snort or Suricata fail completely against polymorphic zero-day exploits. Meanwhile, early machine learning intrusion detection models suffered from a fatal flaw: the 'black-box' dilemma, where analysts receive an opaque probability score without any causal rationale.
> 
> Furthermore, extensive academic research has identified pervasive methodological flaws in published NIDS literature: models that achieve 99.9% accuracy by committing severe data leakage — memorizing static attacker IP addresses rather than intrinsic network protocol behaviors.
> 
> Argus NIDS solves these fundamental problems by uniting anti-leakage preprocessing, dual-engine supervised and unsupervised AI, mathematical explainability via SHAP, and live Cyber Threat Intelligence feeds into a unified operational platform."*

---

### [1:30 – 3:00] Dataset Realities & Anti-Leakage Pipeline
**Action:** Click to **Traffic Classifier** view and reference the dataset ingestion metrics.

> *"To ground our research in genuine enterprise telemetry, we ingested the complete, official CICIDS2017 benchmark from the Canadian Institute for Cybersecurity — encompassing 3,119,345 raw network traffic flows across 8 capture files and 85 telemetry features.
> 
> Our rigorous data-quality audit uncovered critical defects: corrupted Latin-1 en-dashes in Web Attack labels, 289,960 NaN records, 2,867 infinite values caused by zero-duration division, and extreme class imbalance exceeding 206,000 to 1.
> 
> Crucially, our audit proved that attacker IP 172.16.0.1 was responsible for over 90% of all attack instances. To prevent catastrophic data leakage, our preprocessing pipeline systematically strips Source IP, Destination IP, Flow ID, and Timestamps from the training matrix. We pruned 21 redundant collinear features with Pearson |r| greater than 0.98, applied median imputation and robust quantile scaling fitted strictly on the training partition, and retained 100% of all rare attack instances through balanced stratified sampling."*

---

### [3:00 – 4:30] Dual-Engine Detection & Empirical Benchmarks
**Action:** Switch to **Executive Overview: Model Performance Comparison** chart.

> *"We evaluated four distinct algorithmic architectures across binary, multiclass, and unsupervised paradigms:
> 
> 1. Our baseline, Logistic Regression, attained only 55.35% multiclass accuracy, mathematically demonstrating that network attack manifolds cannot be linearly separated.
> 2. Balanced Random Forest achieved 99.40% multiclass accuracy.
> 3. Our champion model, Gradient Boosted XGBoost, achieved 99.84% binary accuracy with a remarkably low False Positive Rate of just 0.13%, a False Negative Rate of 0.27%, and an overall ROC-AUC of 0.9999. In the 8-class multiclass taxonomy, XGBoost achieved 99.78% accuracy and 95.95% Macro-F1 across all attack categories.
> 4. To protect against novel zero-day exploits, we integrated an unsupervised Isolation Forest trained exclusively on normal benign traffic, attaining a zero-day anomaly detection ROC-AUC of 0.7927."*

---

### [4:30 – 6:00] Explainable AI (SHAP) in Action
**Action:** Switch to the **Explainable AI (SHAP)** tab and select a flow from the test set. Click **Generate SHAP Waterfall Attribution**.

> *"Let us now examine the core innovation: Explainable AI. In compliance with the European Union GDPR 'Right to Explanation', an operator cannot rely on an opaque probability.
> 
> Here on screen is our SHAP TreeExplainer, computing exact Shapley additive feature attributions in real time. Notice how the waterfall graph transparently decomposes the model's decision:
> - Destination Port 80 and high backward packet rate push the prediction strongly to the right — increasing attack probability by plus 42%.
> - Initial window bytes forward of zero confirm an automated SYN flood script, adding another plus 31%.
> - Conversely, normal packet size variance pushes back toward benign.
> 
> For the first time, the SOC analyst sees the exact mathematical justification behind the alert."*

---

### [6:00 – 7:30] Cyber Threat Intelligence & Multi-Factor Risk Engine
**Action:** Switch to the **Cyber Threat Intelligence (CTI)** tab, enter IP `205.174.165.73`, and execute query. Then demonstrate the **Single Flow Inspector**.

> *"Algorithmic classification is powerful, but defense-in-depth requires contextual intelligence. Here, our CTI engine enriches the source IP. Notice that when we query 205.174.165.73 — the known Ares Botnet C2 master from the CICIDS2017 capture — the engine flags it with an Abuse Confidence of 100%, an external reputation of 95/100, and tags it as a confirmed Botnet Master.
> 
> Our Dynamic Risk Assessment Engine correlates these signals:
> 1. The supervised model probability.
> 2. The unsupervised Isolation Forest outlier score.
> 3. Target port criticality (e.g. Port 22 SSH or Port 445 SMB).
> 4. External CTI reputation.
> 
> It computes a normalized score from 0 to 100, classifying the incident as Critical and producing actionable operational guidance: 'IMMEDIATE MITIGATION: Block IP at border firewall; trigger Tier-3 response'."*

---

### [7:30 – 8:45] Production Backend, REST API & Automated Tests
**Action:** Switch to browser tab displaying `http://localhost:8000/docs` (FastAPI Swagger UI).

> *"Argus NIDS is not merely an experimental prototype; it is an enterprise-grade software artifact.
> 
> Running on FastAPI, our backend exposes 7 production endpoints: /health, /predict, /predict/batch, /detect-anomalies, /explanations, /alerts, and /statistics. In vectorized batch mode, the API achieves a processing throughput exceeding 12,000 flows per second with sub-millisecond per-packet latency.
> 
> All alerts and analyst status triages are persisted via SQLAlchemy 2.0 ORM, supporting local SQLite and production PostgreSQL.
> 
> Furthermore, software reliability is verified by an automated test suite of 39 pytest tests covering data loaders, preprocessing pipelines, model metrics, XAI attributions, database transactions, and REST endpoints — all passing with a 100% pass rate in under 15 seconds."*

---

### [8:45 – 10:00] Conclusion & Academic Defense
**Action:** Return to **Executive Security Overview** or summary slide.

> *"To summarize: Argus NIDS successfully resolves the core challenges of contemporary network security:
> 1. It eliminates endpoint data leakage, proving true behavioral generalization.
> 2. It delivers state-of-the-art 99.84% accuracy with a 0.13% False Positive Rate.
> 3. It provides mathematically rigorous XAI explanations via SHAP.
> 4. It unifies machine learning with Threat Intelligence and multi-factor risk scoring.
> 
> All deliverables — including the 47 KB academic DOCX dissertation report, full source code, trained models, test suite, and interactive dashboard — are fully verified and packaged.
> 
> Thank you for your time and attention. I am now delighted to take your questions."*

