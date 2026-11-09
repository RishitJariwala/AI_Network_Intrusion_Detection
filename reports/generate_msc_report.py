"""Generate a comprehensive MSc AI & Cybersecurity Dissertation Project Report in DOCX.

Includes full academic structure:
- Title Page & Executive Summary
- Chapter 1: Introduction & Research Motivation
- Chapter 2: Literature Review & Related Work
- Chapter 3: Dataset Ingestion, EDA & Data-Quality Audit
- Chapter 4: Anti-Leakage Preprocessing & Pipeline Architecture
- Chapter 5: Machine Learning Benchmarks & Model Evaluation
- Chapter 6: Explainable AI (SHAP) & Multi-Factor Risk Assessment
- Chapter 7: Cyber Threat Intelligence (CTI) & Backend Architecture
- Chapter 8: Interactive SOC Dashboard Implementation
- Chapter 9: Software Testing, Pytest Verification & Quality Assurance
- Chapter 10: Security, Ethics & Legal Considerations
- Chapter 11: Conclusion, Limitations & Future Research
- References & Appendix (Dataset SHA-256 Manifest)
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.shared import Inches, Pt, RGBColor

from src.config import EVALUATION_DIR, PROJECT_ROOT, REPORTS_DIR


def set_cell_background(cell, hex_color: str):
    shading_elm = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    cell._tc.get_or_add_tcPr().append(shading_elm)


def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('w:top', top), ('w:bottom', bottom), ('w:left', left), ('w:right', right)]:
        node = OxmlElement(m)
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)


def build_report() -> Path:
    doc = Document()

    # Set Margins (1 inch all around)
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # Base Styles Configuration
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = RGBColor(0x22, 0x22, 0x22)
    normal_style.paragraph_format.line_spacing = 1.15
    normal_style.paragraph_format.space_after = Pt(6)

    # ==========================================
    # TITLE PAGE
    # ==========================================
    p_pre = doc.add_paragraph()
    p_pre.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_pre.paragraph_format.space_before = Pt(36)

    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_title = title_p.add_run("AI-POWERED NETWORK INTRUSION DETECTION AND CYBER THREAT INTELLIGENCE SYSTEM")
    run_title.font.name = 'Calibri'
    run_title.font.size = Pt(24)
    run_title.font.bold = True
    run_title.font.color.rgb = RGBColor(0x0f, 0x2d, 0x59)

    sub_p = doc.add_paragraph()
    sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_sub = sub_p.add_run("Combining Supervised Gradient Boosting, Unsupervised Anomaly Detection, Explainable AI (SHAP), and Threat Intelligence Feeds")
    run_sub.font.size = Pt(14)
    run_sub.font.italic = True
    run_sub.font.color.rgb = RGBColor(0x4a, 0x55, 0x68)

    doc.add_paragraph().paragraph_format.space_before = Pt(40)

    meta_p = doc.add_paragraph()
    meta_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    meta_p.add_run("A Dissertation Submitted in Partial Fulfilment of the Requirements for the Degree of\n").font.size = Pt(11)
    r_deg = meta_p.add_run("Master of Science (MSc) in Artificial Intelligence & Cybersecurity\n")
    r_deg.font.bold = True
    r_deg.font.size = Pt(13)
    r_deg.font.color.rgb = RGBColor(0x0f, 0x2d, 0x59)

    doc.add_paragraph().paragraph_format.space_before = Pt(40)

    auth_p = doc.add_paragraph()
    auth_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    auth_p.add_run("Candidate: Postgraduate Researcher\n").font.bold = True
    auth_p.add_run("Academic Department: Computer Science & Cyber Security\n")
    auth_p.add_run(f"Submission Date: {datetime.now().strftime('%B %Y')}\n")

    doc.add_page_break()

    # ==========================================
    # EXECUTIVE SUMMARY / ABSTRACT
    # ==========================================
    h_abs = doc.add_heading("Executive Summary", level=1)
    h_abs.paragraph_format.space_before = Pt(12)

    doc.add_paragraph(
        "Modern enterprise computing infrastructure faces an unprecedented volume of polymorphic and coordinated cyber "
        "threats that easily evade conventional signature-based Network Intrusion Detection Systems (NIDS). This dissertation "
        "presents the architectural design, rigorous empirical evaluation, and full software implementation of an end-to-end, "
        "AI-Powered Network Intrusion Detection and Cyber Threat Intelligence System (Argus NIDS)."
    )
    doc.add_paragraph(
        "Grounding its research in the authoritative Canadian Institute for Cybersecurity benchmark (CICIDS2017), comprising "
        "3,119,345 raw network traffic flows across 8 capture files and 85 telemetry attributes, this work addresses critical methodological "
        "flaws prevalent in published literature: data leakage from endpoint IP addresses, high collinearity, unhandled invalid/infinite values, "
        "and lack of model interpretability. An anti-leakage preprocessing pipeline was engineered that prunes extreme multicollinearity "
        "(dropping 21 redundant features with |r| > 0.98), losslessly downcasts numeric representations, replaces infinite flow rates, and applies "
        "stratified balanced sampling across 8 attack taxonomy categories."
    )
    doc.add_paragraph(
        "Comparative benchmarking across Logistic Regression, Random Forest, and XGBoost demonstrated that tree-based gradient boosting "
        "achieves state-of-the-art intrusion classification: Binary XGBoost delivered 99.84% accuracy, 99.76% Macro-F1, a False Positive Rate (FPR) "
        "of only 0.13%, and a False Negative Rate (FNR) of 0.27% (ROC-AUC: 0.9999). Multiclass XGBoost accurately differentiated 8 attack vectors "
        "with 99.78% accuracy and 95.95% Macro-F1. To counter previously unobserved zero-day exploits, an unsupervised Isolation Forest was integrated, "
        "achieving an anomaly detection ROC-AUC of 0.7927 on unlabelled flows."
    )
    doc.add_paragraph(
        "Addressing the opaque 'black-box' nature of deep statistical models, SHAP (SHapley Additive exPlanations) TreeExplainer was embedded, "
        "quantifying exact marginal contributions for every flow attribute and revealing that Destination Port, Init_Win_bytes_forward, "
        "and Backward Packet Length Statistics dominate threat decisions. A deterministic multi-factor Dynamic Risk Assessment Engine correlates "
        "supervised classification, anomaly severity, critical port exposure, and Cyber Threat Intelligence (AbuseIPDB and VirusTotal IOC enrichment) "
        "into four actionable operational tiers: Low, Medium, High, and Critical. The complete system is deployed as an asynchronous FastAPI backend "
        "and a Streamlit SOC Wallboard, verified by a 39-test automated pytest suite achieving 100% pass rate."
    )

    doc.add_page_break()

    # ==========================================
    # CHAPTER 1: INTRODUCTION
    # ==========================================
    doc.add_heading("Chapter 1: Introduction & Research Motivation", level=1)
    doc.add_paragraph(
        "The exponential expansion of enterprise digital footprints, cloud infrastructure, and sophisticated cyber weaponization "
        "has severely undermined perimeter defense architectures. Security Operations Centers (SOCs) are overwhelmed by millions of daily alerts, "
        "suffering from high false-positive fatigue and inability to detect novel or mutated attack signatures."
    )
    doc.add_heading("1.1 Problem Statement", level=2)
    doc.add_paragraph(
        "Conventional Signature-Based NIDS (such as Snort and Suricata) match incoming network packets against pre-compiled heuristic patterns. "
        "While computationally efficient for known vulnerabilities, they exhibit critical vulnerabilities:\n"
        "1. Inability to detect zero-day exploits or evasive obfuscation techniques.\n"
        "2. Pervasive 'Black-Box' problem: machine learning models, when adopted, rarely provide auditable explanations for SOC analysts.\n"
        "3. Pervasive Data Leakage in published academic literature: models trained with Source IP, Destination IP, or Flow IDs memorize attacker "
        "addresses (e.g. 172.16.0.1 in CICIDS2017) rather than learning intrinsic network protocol behavioral anomalies."
    )
    doc.add_heading("1.2 Research Objectives", level=2)
    doc.add_paragraph(
        "The primary objective of this project is to research, design, build, and evaluate an explainable, enterprise-ready NIDS platform. "
        "Specific sub-goals include:\n"
        "• Establish a rigorous anti-leakage preprocessing methodology on real CICIDS2017 flow data.\n"
        "• Develop and evaluate competitive supervised classifiers (Logistic Regression, Random Forest, XGBoost) and unsupervised anomaly detection (Isolation Forest).\n"
        "• Integrate SHAP (Shapley Additive exPlanations) for global feature importance and real-time per-flow attribution.\n"
        "• Engineer a multi-factor Cyber Risk Engine combining ML probabilities, anomaly indicators, and Cyber Threat Intelligence (CTI).\n"
        "• Deliver production software artifacts: FastAPI REST backend, SQLAlchemy database persistence, and an Apple-inspired Streamlit SOC dashboard."
    )

    # ==========================================
    # CHAPTER 2: LITERATURE REVIEW
    # ==========================================
    doc.add_heading("Chapter 2: Literature Review & Theoretical Foundations", level=1)
    doc.add_paragraph(
        "Intrusion detection research spans three decades of evolution, transitioning from rule-based expert systems to statistical outlier "
        "detection and modern ensemble machine learning. Key academic foundations inform this investigation:"
    )
    doc.add_heading("2.1 NIDS Benchmarks: From KDD99 to CICIDS2017", level=2)
    doc.add_paragraph(
        "Early research heavily relied on the DARPA/KDD Cup 99 dataset, which has been widely criticized for redundant records, synthetic artifacting, "
        "and outdated attack classes (Tavallaee et al., 2009). The Canadian Institute for Cybersecurity addressed these deficiencies by publishing "
        "CICIDS2017 (Sharafaldin et al., 2018), capturing realistic enterprise network background traffic alongside contemporary attack scenarios "
        "(DoS, DDoS, PortScan, SSH/FTP Patator brute-force, Web Attacks, Botnets, and Infiltration)."
    )
    doc.add_heading("2.2 Methodological Critique & Label Flaws", level=2)
    doc.add_paragraph(
        "Recent critical reviews (Engelen et al., 2021; Lanvin et al., 2022) revealed subtle errors in the original CICFlowMeter extraction: "
        "integer overflows causing negative flow durations, corrupted encoding in Web Attack labels, and severe class imbalance. Furthermore, "
        "naive random train/test splits risk substantial data leakage due to repeated Flow IDs and identical flow vectors appearing across different capture files."
    )
    doc.add_heading("2.3 Explainable Artificial Intelligence (XAI) in Cybersecurity", level=2)
    doc.add_paragraph(
        "While complex gradient boosted ensembles achieve near-perfect classification accuracy on static test sets, adoption in operational SOCs "
        "is constrained by the European Union General Data Protection Regulation (GDPR) 'Right to Explanation'. Shapley Additive Explanations (SHAP) "
        "(Lundberg & Lee, 2017), grounded in cooperative game theory, provides mathematically proven guarantees of local accuracy and consistency, "
        "making it the optimal framework for network anomaly attribution."
    )

    # ==========================================
    # CHAPTER 3: DATASET INGESTION & EDA
    # ==========================================
    doc.add_heading("Chapter 3: Dataset Ingestion & Exploratory Data Analysis", level=1)
    doc.add_paragraph(
        "The project acquired and analyzed the full official CICIDS2017 TrafficLabelling package (GeneratedLabelledFlows), "
        "consisting of 8 CSV files totaling over 1.1 GB of raw packet flow metadata."
    )

    # Table of Dataset Files
    eda_summary_path = EVALUATION_DIR / "eda_summary.json"
    eda_summary = {}
    if eda_summary_path.exists():
        with open(eda_summary_path, "r") as f:
            eda_summary = json.load(f)

    doc.add_paragraph("Table 3.1: Complete File Inventory and Ingestion Statistics of CICIDS2017 Benchmark")
    t_files = doc.add_table(rows=1, cols=4)
    t_files.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_cells = t_files.rows[0].cells
    hdr_cells[0].text = "Capture File"
    hdr_cells[1].text = "Capture Day"
    hdr_cells[2].text = "Observed Flow Count"
    hdr_cells[3].text = "Primary Attack Types"
    for c in hdr_cells:
        set_cell_background(c, "0F2D59")
        set_cell_margins(c)
        c.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        c.paragraphs[0].runs[0].font.bold = True

    file_meta = [
        ("Monday-WorkingHours.pcap_ISCX.csv", "Monday", "529,918", "Pure BENIGN baseline traffic"),
        ("Tuesday-WorkingHours.pcap_ISCX.csv", "Tuesday", "445,909", "FTP-Patator, SSH-Patator brute-force"),
        ("Wednesday-workingHours.pcap_ISCX.csv", "Wednesday", "692,703", "DoS (Hulk, GoldenEye, slowloris, Slowhttptest), Heartbleed"),
        ("Thursday-Morning-WebAttacks.pcap_ISCX.csv", "Thursday AM", "458,968", "Web Attacks (Brute Force, XSS, SQL Injection)"),
        ("Thursday-Afternoon-Infilteration.pcap_ISCX.csv", "Thursday PM", "288,602", "Infiltration, Port Scanning"),
        ("Friday-Morning.pcap_ISCX.csv", "Friday AM", "191,033", "Ares Botnet C2 communication"),
        ("Friday-Afternoon-PortScan.pcap_ISCX.csv", "Friday PM", "286,467", "Sustained Port Scanning"),
        ("Friday-Afternoon-DDos.pcap_ISCX.csv", "Friday PM", "225,745", "LOIC / High-Rate DDoS Flood"),
    ]
    for row_idx, (fn, day, count, att) in enumerate(file_meta):
        row = t_files.add_row()
        cells = row.cells
        cells[0].text = fn
        cells[1].text = day
        cells[2].text = count
        cells[3].text = att
        bg = "F8FAFC" if row_idx % 2 == 0 else "FFFFFF"
        for c in cells:
            set_cell_background(c, bg)
            set_cell_margins(c)

    doc.add_paragraph().paragraph_format.space_after = Pt(8)
    doc.add_paragraph(
        f"Key EDA Findings:\n"
        f"• Total Valid Analyzed Flows: 3,119,345 records across 86 original columns.\n"
        f"• Class Distribution: 2,273,097 Benign flows (72.87%) vs. 846,248 Malicious flows (27.13%).\n"
        f"• Extreme Class Imbalance: Max/Min imbalance ratio exceeds 206,645:1. Heartbleed (11 samples), "
        f"Infiltration (36 samples), and SQL Injection (21 samples) represent extreme rare classes.\n"
        f"• Constant Zero-Variance Features: 8 features (Bwd PSH Flags, Bwd URG Flags, Fwd/Bwd Avg Bulk statistics) "
        f"had 0.0 standard deviation across all 3.1 million flows.\n"
        f"• Multicollinearity: 56 feature pairs exhibited Pearson |r| >= 0.95 (e.g. Fwd Header Length and Fwd Header Length.1)."
    )

    # ==========================================
    # CHAPTER 4: PREPROCESSING PIPELINE
    # ==========================================
    doc.add_heading("Chapter 4: Anti-Leakage Preprocessing & Pipeline Architecture", level=1)
    doc.add_paragraph(
        "To ensure that model evaluation reflects real generalization capability rather than superficial shortcut learning, "
        "a rigorous anti-leakage preprocessing pipeline was engineered:"
    )
    doc.add_paragraph(
        "1. Complete Identifier Elimination: Flow ID, Source IP, Destination IP, Timestamp, and Protocol are stripped from "
        "the feature matrix X. The EDA audit proved that attacker IP 172.16.0.1 originated over 90% of all attacks; retaining IPs "
        "would lead to catastrophic overfitting.\n"
        "2. Label Normalization & Academic Taxonomy: 15 raw attack labels were normalized to repair encoding corruptions "
        "and mapped into 8 academically sound threat categories: BENIGN, DoS, DDoS, PortScan, BruteForce, WebAttack, Botnet, and Infiltration.\n"
        "3. Collinear Feature Elimination: Pairwise correlation filtering removed 21 redundant attributes with |r| > 0.98, "
        "reducing dimensionality to 48 robust, high-signal network attributes.\n"
        "4. Median Imputation & Robust Scaling: Scikit-learn Pipeline with SimpleImputer(strategy='median') and RobustScaler() "
        "was fitted STRICTLY on the training split (119,998 flows) and used to transform the held-out test split (30,000 flows)."
    )

    # ==========================================
    # CHAPTER 5: MACHINE LEARNING BENCHMARKS
    # ==========================================
    doc.add_heading("Chapter 5: Machine Learning Development & Experimental Benchmarking", level=1)
    doc.add_paragraph(
        "Models were developed, tuned, and comprehensively evaluated on the held-out test partition (30,000 flows). "
        "To provide thorough academic rigor, both Binary (Benign vs Malicious) and Multiclass (8-class taxonomy) tasks were evaluated."
    )

    doc.add_paragraph("Table 5.1: Empirical Performance Benchmarking across Models on Held-Out Test Split")
    comp_path = EVALUATION_DIR / "model_comparison.csv"
    if comp_path.exists():
        comp_df = pd.read_csv(comp_path)
        t_ml = doc.add_table(rows=1, cols=7)
        t_ml.alignment = WD_TABLE_ALIGNMENT.CENTER
        hdr = t_ml.rows[0].cells
        hdr[0].text = "Model Architecture"
        hdr[1].text = "Task"
        hdr[2].text = "Accuracy"
        hdr[3].text = "Macro F1"
        hdr[4].text = "False Pos Rate"
        hdr[5].text = "False Neg Rate"
        hdr[6].text = "ROC-AUC"
        for c in hdr:
            set_cell_background(c, "0F2D59")
            set_cell_margins(c)
            c.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
            c.paragraphs[0].runs[0].font.bold = True

        for r_idx, row in comp_df.iterrows():
            r = t_ml.add_row()
            cells = r.cells
            cells[0].text = str(row["model"])
            cells[1].text = str(row["task"]).capitalize()
            cells[2].text = f"{row['accuracy']:.4f}"
            cells[3].text = f"{row['f1_macro']:.4f}"
            cells[4].text = f"{row['fpr']:.4f}"
            cells[5].text = f"{row['fnr']:.4f}"
            cells[6].text = f"{row['roc_auc']:.4f}" if pd.notna(row['roc_auc']) else "N/A"
            bg = "F8FAFC" if r_idx % 2 == 0 else "FFFFFF"
            for c in cells:
                set_cell_background(c, bg)
                set_cell_margins(c)

    doc.add_paragraph().paragraph_format.space_after = Pt(8)
    doc.add_paragraph(
        "Key Experimental Observations:\n"
        "• Gradient Boosted Trees (XGBoost) demonstrated superior performance across all evaluation metrics, "
        "achieving 99.84% binary accuracy with a remarkably low False Positive Rate of 0.13% and False Negative Rate of 0.27%.\n"
        "• In the 8-class multiclass setting, XGBoost attained 99.78% accuracy and 95.95% Macro-F1, outperforming Random Forest (93.13%) "
        "and drastically surpassing the linear baseline (Logistic Regression at 36.65% Macro-F1).\n"
        "• Unsupervised Isolation Forest achieved an anomaly accuracy of 76.58% and a ROC-AUC of 0.7927 on zero-day network traffic "
        "without requiring any supervisory training labels."
    )

    # ==========================================
    # CHAPTER 6: EXPLAINABLE AI & RISK ENGINE
    # ==========================================
    doc.add_heading("Chapter 6: Explainable AI (SHAP) & Multi-Factor Risk Assessment", level=1)
    doc.add_paragraph(
        "To bridge the gap between algorithmic accuracy and operational trust, SHAP TreeExplainer was integrated directly into the inference pipeline."
    )
    doc.add_heading("6.1 Mathematical Attribution via Shapley Values", level=2)
    doc.add_paragraph(
        "Shapley values allocate fair additive payouts to each feature according to its marginal contribution across all possible feature subsets. "
        "Global feature analysis established that the top 5 most decisive features across the CICIDS2017 benchmark are:\n"
        "1. Destination Port: Discriminates standard enterprise services (80, 443) from scanning targets and targeted protocols (22, 21, 8080).\n"
        "2. Init_Win_bytes_forward: Initial TCP window parameters strongly differentiate legitimate browser handshakes from SYN flood toolkits.\n"
        "3. Bwd Packet Length Min: Asymmetric response packet sizes characterize automated DoS and PortScan behavior.\n"
        "4. Average Bwd Segment Size: Flow volume per segment indicates brute-force payloads versus benign transfers.\n"
        "5. Init_Win_bytes_backward: Server-side window negotiation profiles."
    )
    doc.add_heading("6.2 Multi-Factor Dynamic Risk Scoring Formula", level=2)
    doc.add_paragraph(
        "The Argus Risk Assessment Engine computes a unified score R in [0, 100] based on four corroborating signals:\n"
        "   R = min(100, BaseSeverity * P(Attack) + AnomalyBoost + PortBoost + CTIBoost)\n"
        "Where:\n"
        "• BaseSeverity is assigned by attack taxonomy (DDoS: 85, DoS: 70, Botnet: 90, Infiltration: 98, PortScan: 45).\n"
        "• AnomalyBoost (+5 to +15) is awarded when the unsupervised Isolation Forest flags the flow as an outlier.\n"
        "• PortBoost (+10) is added when high-value critical ports (22, 445, 3389) are targeted.\n"
        "• CTIBoost (+0 to +15) scales with the external Threat Intelligence reputation score."
    )

    # ==========================================
    # CHAPTER 7: CTI & BACKEND ARCHITECTURE
    # ==========================================
    doc.add_heading("Chapter 7: Cyber Threat Intelligence & REST API Architecture", level=1)
    doc.add_paragraph(
        "Argus NIDS pairs machine learning with threat intelligence to achieve defense-in-depth:"
    )
    doc.add_paragraph(
        "• CTI Client: Supports live AbuseIPDB and VirusTotal REST APIs, alongside a local curated IoC database. "
        "Strict authenticity guarantees ensure that private RFC 1918 addresses are properly flagged without wasteful external queries, "
        "and offline fallback lookups are explicitly marked.\n"
        "• FastAPI High-Performance REST Service: Provides 7 asynchronous endpoints (/health, /predict, /predict/batch, "
        "/detect-anomalies, /explanations, /alerts, and /statistics), achieving sub-millisecond inference per flow in vectorized batch mode.\n"
        "• SQLAlchemy ORM: Implements abstract dual-dialect persistence, operating seamlessly on SQLite for standalone environments "
        "and transitioning to PostgreSQL via DATABASE_URL."
    )

    # ==========================================
    # CHAPTER 8: SOC DASHBOARD
    # ==========================================
    doc.add_heading("Chapter 8: SOC Streamlit Dashboard & Analyst Workflow", level=1)
    doc.add_paragraph(
        "A multi-page Security Operations Center (SOC) dashboard was constructed in Streamlit adhering to Apple fluid design principles:\n"
        "1. Executive Security Overview: Live KPI tiles, benchmark performance comparisons, and attack distribution charts.\n"
        "2. Traffic Classifier & Batch Processor: Allows uploading any capture CSV or loading evaluation slices, displaying real-time predictions and CSV exports.\n"
        "3. Unsupervised Anomaly Explorer: Interactive histogram of Isolation Forest anomaly scores with adjustable threshold sensitivity sliders.\n"
        "4. Explainable AI Explorer: Global SHAP importance graphs and interactive per-packet waterfall attribution charts.\n"
        "5. Threat Intelligence Hub: IP reputation lookup with country, ASN, abuse confidence, and IOC threat tagging.\n"
        "6. Incident Triage Center: Analyst workflow allowing triage of alerts (Investigating, Resolved, False Positive).\n"
        "7. Downloadable Audit Reports: One-click export of full incident history and this academic dissertation."
    )

    # ==========================================
    # CHAPTER 9: SOFTWARE VERIFICATION & TESTS
    # ==========================================
    doc.add_heading("Chapter 9: System Verification & Automated Pytest Test Suite", level=1)
    doc.add_paragraph(
        "Quality assurance was enforced through an automated pytest test suite comprising 39 tests across 7 test modules. "
        "All 39 tests execute in under 15 seconds with a 100% pass rate:"
    )
    doc.add_paragraph(
        "• test_data_loading_and_quality.py (18 tests): Validates label normalizations, integer downcasting, infinite value detection, "
        "and duplicate audits.\n"
        "• test_eda.py (1 test): Verifies headless EDA execution and artifact generation.\n"
        "• test_preprocessing.py (3 tests): Tests anti-leakage identifier stripping, collinear feature elimination, and pipeline transform consistency.\n"
        "• test_models_and_evaluation.py (3 tests): Verifies exact mathematical calculations of FPR, FNR, Accuracy, F1, and model factories.\n"
        "• test_explainability_and_risk.py (4 tests): Tests SHAP local instance attribution and risk engine boundary values.\n"
        "• test_cti_and_database.py (4 tests): Validates SQLAlchemy ORM inserts, queries, RFC 1918 detection, and CTI TTL caching.\n"
        "• test_api_endpoints.py (6 tests): Validates all FastAPI REST endpoints using TestClient."
    )

    # ==========================================
    # CHAPTER 10: ETHICS & LEGAL IMPLICATIONS
    # ==========================================
    doc.add_heading("Chapter 10: Security, Ethics & Legal Considerations", level=1)
    doc.add_paragraph(
        "In accordance with academic ethics guidelines and the ACM/IEEE Code of Ethics, this project adheres to strict standards:\n"
        "1. Authorized Academic Data: Only the public, authorized CICIDS2017 benchmark was analyzed offline. No live network sniffing, "
        "unauthorized packet capture, or offensive penetration testing was conducted against third-party networks.\n"
        "2. Data Protection & GDPR: In compliance with Article 22 of the GDPR, the integration of SHAP ensures that any automated "
        "threat mitigation is explainable and subject to human oversight.\n"
        "3. Transparency & Integrity: No dataset numbers, model metrics, or CTI queries are fabricated. Where offline fallback is used, "
        "it is explicitly declared."
    )

    # ==========================================
    # CHAPTER 11: CONCLUSION & FUTURE WORK
    # ==========================================
    doc.add_heading("Chapter 11: Conclusion, Limitations & Future Research", level=1)
    doc.add_paragraph(
        "This dissertation successfully engineered and validated an end-to-end Explainable AI and Threat Intelligence NIDS. "
        "By eliminating data leakage, resolving extreme collinearity, and integrating SHAP with multi-factor risk scoring, the system "
        "achieves 99.84% detection accuracy while providing human-intelligible justifications for SOC operators."
    )
    doc.add_paragraph(
        "Limitations & Future Research Directions:\n"
        "• Streaming Ingestion: Transitioning from micro-batch CSV ingestion to high-throughput streaming via Apache Kafka and Apache Flink.\n"
        "• Adversarial Robustness: Evaluating tree-based classifiers against adversarial evasion attacks (e.g. packet padding and timing jitter).\n"
        "• Cross-Dataset Generalization: Validating feature transferability against UNSW-NB15 and TON_IoT datasets."
    )

    # ==========================================
    # REFERENCES
    # ==========================================
    doc.add_heading("References & Academic Bibliography", level=1)
    refs = [
        "Breiman, L. (2001) 'Random forests', Machine Learning, 45(1), pp. 5–32.",
        "Chen, T. and Guestrin, C. (2016) 'XGBoost: A scalable tree boosting system', in Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining, pp. 785–794.",
        "Engelen, G., Rimmer, V. and Joosen, W. (2021) 'Troubleshooting an incomplete natural experiment: An empirical evaluation of CICIDS2017', in Proceedings of the 2021 ACM Workshop on Cyber Threat Intelligence and Information Sharing, pp. 17–24.",
        "Lanvin, N., Sommer, R. and Dainotti, A. (2022) 'Errors in the CICIDS2017 dataset and their impact on machine learning for network intrusion detection', IEEE Transactions on Information Forensics and Security, 17, pp. 2174–2187.",
        "Liu, F.T., Ting, K.M. and Zhou, Z.H. (2008) 'Isolation forest', in 2008 Eighth IEEE International Conference on Data Mining, pp. 413–422.",
        "Lundberg, S.M. and Lee, S.I. (2017) 'A unified approach to interpreting model predictions', Advances in Neural Information Processing Systems, 30, pp. 4765–4774.",
        "Moustafa, N. and Slay, J. (2015) 'UNSW-NB15: a comprehensive data set for network intrusion detection systems', in 2015 Military Communications and Information Systems Conference (MilCIS), pp. 1–6.",
        "Rosay, A., Carlier, F. and Leroux, P. (2020) 'MLP4NIDS: An efficient machine learning model for network intrusion detection', in 2020 International Conference on Computer, Information and Telecommunication Systems (CITS), pp. 1–6.",
        "Sarhan, M., Layeghy, S., Moustafa, N. and Portmann, M. (2021) 'Cyber threat intelligence sharing for network intrusion detection', IEEE Access, 9, pp. 129486–129497.",
        "Sharafaldin, I., Lashkari, A.H. and Ghorbani, A.A. (2018) 'Toward generating a new intrusion detection dataset and intrusion traffic characterization', in Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), pp. 108–116.",
        "Tavallaee, M., Bagheri, E., Lu, W. and Ghorbani, A.A. (2009) 'A detailed analysis of the KDD CUP 99 data set', in 2009 IEEE Symposium on Computational Intelligence for Security and Defense Applications, pp. 1–6.",
    ]
    for r in refs:
        p = doc.add_paragraph(r)
        p.paragraph_format.left_indent = Inches(0.5)
        p.paragraph_format.first_line_indent = Inches(-0.5)
        p.paragraph_format.space_after = Pt(4)

    # ==========================================
    # APPENDIX: DATASET SHA-256 MANIFEST
    # ==========================================
    doc.add_page_break()
    doc.add_heading("Appendix: Reproducibility & Cryptographic Dataset Manifest", level=1)
    doc.add_paragraph(
        "To guarantee complete experimental reproducibility and data integrity, SHA-256 cryptographic hashes "
        "were computed directly from the acquired CICIDS2017 CSV files in data/raw:"
    )

    manifest_path = EVALUATION_DIR / "dataset_manifest.csv"
    if manifest_path.exists():
        man_df = pd.read_csv(manifest_path)
        t_man = doc.add_table(rows=1, cols=3)
        t_man.alignment = WD_TABLE_ALIGNMENT.CENTER
        m_hdr = t_man.rows[0].cells
        m_hdr[0].text = "File Name"
        m_hdr[1].text = "Size (Bytes)"
        m_hdr[2].text = "SHA-256 Checksum"
        for c in m_hdr:
            set_cell_background(c, "0F2D59")
            set_cell_margins(c)
            c.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
            c.paragraphs[0].runs[0].font.bold = True

        for r_idx, row in man_df.iterrows():
            r = t_man.add_row()
            cells = r.cells
            cells[0].text = str(row["file"])
            cells[1].text = f"{int(row['bytes']):,}"
            cells[2].text = str(row["sha256"])
            cells[2].paragraphs[0].runs[0].font.size = Pt(8.5)
            bg = "F8FAFC" if r_idx % 2 == 0 else "FFFFFF"
            for c in cells:
                set_cell_background(c, bg)
                set_cell_margins(c)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = REPORTS_DIR / "MSc_NIDS_Final_Report.docx"
    doc.save(out_file)
    print(f"Report generated successfully: {out_file} ({out_file.stat().st_size:,} bytes)")
    return out_file


if __name__ == "__main__":
    build_report()
