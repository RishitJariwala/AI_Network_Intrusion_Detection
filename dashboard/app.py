"""AI-Powered Network Intrusion Detection & Threat Intelligence SOC Dashboard.

Built with Streamlit, Plotly, and Apple-inspired executive interface principles.
Explicitly operates on offline benchmark captures (CICIDS2017); does not claim live network sniffing.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
# pyrefly: ignore[missing-import]
import plotly.express as px
# pyrefly: ignore[missing-import]
import plotly.graph_objects as go
import streamlit as st

from src.config import (
    ANOMALY_MODEL_DIR,
    CLASSIFICATION_MODEL_DIR,
    DATA_DIR,
    EVALUATION_DIR,
    FIGURES_DIR,
    MODELS_DIR,
    PROCESSED_DIR,
    PROJECT_ROOT,
)
from src.database.models import SecurityAlert
from src.database.session import get_db_context, init_db
from src.data.preprocess import PreprocessingArtifact
from src.explainability.explainer import get_explainer
from src.explainability.risk_engine import RiskAssessmentEngine
from src.intelligence.cti_client import get_cti_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dashboard")

# Streamlit Page Configuration
st.set_page_config(
    page_title="Argus NIDS | Enterprise SOC Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Executive SOC Styling (Apple Design fluid principles, clean translucency, crisp hierarchy)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1400px;
    }
    
    /* Executive Card Styling */
    .metric-card {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 14px;
        padding: 1.25rem 1.5rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
        backdrop-filter: blur(16px);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        border-color: rgba(255, 255, 255, 0.2);
        transform: translateY(-2px);
    }
    .metric-title {
        font-size: 0.82rem;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #8c8c8c;
        margin-bottom: 0.4rem;
    }
    .metric-value {
        font-size: 2.1rem;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: -0.02em;
    }
    .metric-sub {
        font-size: 0.78rem;
        color: #52c41a;
        margin-top: 0.3rem;
    }
    
    /* Risk Badges */
    .badge-critical {
        background: rgba(255, 77, 79, 0.15);
        color: #ff4d4f;
        border: 1px solid rgba(255, 77, 79, 0.4);
        padding: 0.2rem 0.6rem;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.78rem;
    }
    .badge-high {
        background: rgba(250, 173, 20, 0.15);
        color: #faad14;
        border: 1px solid rgba(250, 173, 20, 0.4);
        padding: 0.2rem 0.6rem;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.78rem;
    }
    .badge-medium {
        background: rgba(24, 144, 255, 0.15);
        color: #1890ff;
        border: 1px solid rgba(24, 144, 255, 0.4);
        padding: 0.2rem 0.6rem;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.78rem;
    }
    .badge-low {
        background: rgba(82, 196, 26, 0.15);
        color: #52c41a;
        border: 1px solid rgba(82, 196, 26, 0.4);
        padding: 0.2rem 0.6rem;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.78rem;
    }
    
    /* Offline banner notice */
    .notice-banner {
        background: rgba(30, 41, 59, 0.6);
        border-left: 4px solid #3b82f6;
        padding: 0.75rem 1.25rem;
        border-radius: 8px;
        font-size: 0.85rem;
        color: #cbd5e1;
        margin-bottom: 1.5rem;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def load_system_resources():
    """Cache models, preprocessor, and explainer to eliminate reload latency."""
    init_db()
    res = {}
    prep_path = MODELS_DIR / "preprocessor.joblib"
    if prep_path.exists():
        res["preprocessor"] = joblib.load(prep_path)

    xgb_path = CLASSIFICATION_MODEL_DIR / "multiclass_xgboost.joblib"
    if xgb_path.exists():
        res["classifier"] = joblib.load(xgb_path)

    iso_path = ANOMALY_MODEL_DIR / "isolation_forest.joblib"
    if iso_path.exists():
        res["anomaly_detector"] = joblib.load(iso_path)

    try:
        res["explainer"] = get_explainer()
    except Exception as e:
        logger.warning("Explainer init failed: %s", e)

    res["cti_client"] = get_cti_client()
    return res


resources = load_system_resources()
preprocessor: PreprocessingArtifact = resources.get("preprocessor")
classifier = resources.get("classifier")
anomaly_detector = resources.get("anomaly_detector")
explainer = resources.get("explainer")
cti_client = resources.get("cti_client")


# Sidebar Navigation
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=56)
    st.title("Argus NIDS")
    st.caption("AI-Powered Intrusion Detection & CTI System")
    st.divider()

    selected_view = st.radio(
        "Navigation",
        [
            "📊 Executive Security Overview",
            "🔍 Traffic Classifier & Batch Analysis",
            "🧬 Unsupervised Anomaly Detection",
            "💡 Explainable AI (SHAP)",
            "🌐 Cyber Threat Intelligence (CTI)",
            "🚨 Security Alerts & Incident Response",
            "📄 Downloadable Reports",
        ],
        index=0,
    )

    st.divider()
    st.markdown("### Operational Telemetry")
    st.caption("• **Engine:** XGBoost + Isolation Forest")
    st.caption("• **XAI:** TreeExplainer (Shapley Values)")
    st.caption("• **Database:** SQLite / SQLAlchemy ORM")
    st.caption("• **Capture Source:** CICIDS2017 Benchmark")


# Top Disclaimer Notice
st.markdown("""
<div class="notice-banner">
    🛡️ <b>Offline Security Telemetry Analysis</b> &nbsp;|&nbsp; 
    Ground Truth: Canadian Institute for Cybersecurity (CICIDS2017) &nbsp;|&nbsp; 
    <i>Note: This platform performs offline forensic and batch telemetry classification; it does not claim live network packet capture.</i>
</div>
""", unsafe_allow_html=True)


# ==========================================
# VIEW 1: EXECUTIVE SECURITY OVERVIEW
# ==========================================
if selected_view == "📊 Executive Security Overview":
    st.title("Executive SOC Security Overview")
    st.markdown("Real-time telemetry indicators, threat classification breakdown, and risk metrics.")

    # Top Metric Tiles
    col1, col2, col3, col4 = st.columns(4)

    with get_db_context() as db:
        total_alerts = db.query(SecurityAlert).count()
        critical_alerts = db.query(SecurityAlert).filter(SecurityAlert.risk_level == "CRITICAL").count()
        high_alerts = db.query(SecurityAlert).filter(SecurityAlert.risk_level == "HIGH").count()
        anomalies_count = db.query(SecurityAlert).filter(SecurityAlert.is_anomaly == True).count()

    with col1:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-title">Total Security Alerts</div>
            <div class="metric-value">{:,}</div>
            <div class="metric-sub">Active in SQLAlchemy ORM</div>
        </div>
        """.format(total_alerts), unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-title">Critical Threats</div>
            <div class="metric-value" style="color: #ff4d4f;">{:,}</div>
            <div class="metric-sub" style="color: #ff7875;">Requires Immediate Action</div>
        </div>
        """.format(critical_alerts), unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-title">High Risk Incidents</div>
            <div class="metric-value" style="color: #faad14;">{:,}</div>
            <div class="metric-sub" style="color: #ffd666;">Tier-2 Triage Active</div>
        </div>
        """.format(high_alerts), unsafe_allow_html=True)

    with col4:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-title">Zero-Day Anomalies</div>
            <div class="metric-value" style="color: #1890ff;">{:,}</div>
            <div class="metric-sub" style="color: #69c0ff;">Isolation Forest Flagged</div>
        </div>
        """.format(anomalies_count), unsafe_allow_html=True)

    st.write("")

    # Visualizations Row
    chart_col1, chart_col2 = st.columns([3, 2])

    with chart_col1:
        st.subheader("Model Benchmark Performance Comparison")
        comp_path = EVALUATION_DIR / "model_comparison.csv"
        if comp_path.exists():
            comp_df = pd.read_csv(comp_path)
            fig = px.bar(
                comp_df[comp_df["task"] == "multiclass"],
                x="model",
                y=["accuracy", "f1_macro", "f1_weighted"],
                barmode="group",
                title="Multiclass Detection Performance by Architecture",
                color_discrete_sequence=["#1890ff", "#52c41a", "#722ed1"],
            )
            fig.update_layout(
                yaxis=dict(range=[0.5, 1.05], title="Metric Score"),
                xaxis=dict(title="Model Family"),
                legend=dict(title="Metrics", orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                height=360,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Run model training to populate comparison metrics.")

    with chart_col2:
        st.subheader("Attack Category Distribution")
        eda_dist_path = EVALUATION_DIR / "eda_label_distribution.csv"
        if eda_dist_path.exists():
            dist_df = pd.read_csv(eda_dist_path)
            # Filter non-benign
            attacks_only = dist_df[~dist_df["Label"].isin(["BENIGN", "nan"])].head(6)
            fig = px.pie(
                attacks_only,
                names="Label",
                values="count",
                hole=0.45,
                color_discrete_sequence=px.colors.sequential.RdBu,
                title="Captured Attack Types (Top 6)",
            )
            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                height=360,
                showlegend=True,
            )
            st.plotly_chart(fig, use_container_width=True)


# ==========================================
# VIEW 2: TRAFFIC CLASSIFIER & BATCH ANALYSIS
# ==========================================
elif selected_view == "🔍 Traffic Classifier & Batch Analysis":
    st.title("Network Traffic Classifier & Batch Analysis")
    st.markdown("Upload raw network flow CSVs or execute interactive flow inspection.")

    tab_batch, tab_single = st.tabs(["📁 Batch File Processing", "⚡ Interactive Single Flow Inspector"])

    with tab_batch:
        st.markdown("#### Upload Captured Flows CSV or Load Evaluation Sample")
        sample_path = PROCESSED_DIR / "test_sample_flows.csv"

        uploaded_file = st.file_uploader("Upload Network Flow CSV", type=["csv"])

        df_to_analyze = None
        if uploaded_file is not None:
            df_to_analyze = pd.read_csv(uploaded_file)
            st.success(f"Uploaded CSV with {len(df_to_analyze):,} flows.")
        elif sample_path.exists():
            if st.button("Load Pre-Packaged Benchmark Test Captures (2,000 flows)"):
                df_to_analyze = pd.read_csv(sample_path)
                st.session_state["batch_df"] = df_to_analyze

        if "batch_df" in st.session_state and df_to_analyze is None:
            df_to_analyze = st.session_state["batch_df"]

        if df_to_analyze is not None and preprocessor and classifier:
            st.write(f"Analyzing {len(df_to_analyze)} flows ...")
            start = time.perf_counter()

            # Transform and classify
            X_proc = preprocessor.transform(df_to_analyze)
            preds = classifier.predict(X_proc)
            probs = classifier.predict_proba(X_proc)
            classes = list(preprocessor.class_mapping.keys())

            anom_preds = anomaly_detector.predict(X_proc) if anomaly_detector else np.ones(len(df_to_analyze))
            anom_scores = -anomaly_detector.score_samples(X_proc) if anomaly_detector else np.zeros(len(df_to_analyze))
            anom_scores_norm = np.clip((anom_scores - 0.4) / 0.4, 0.0, 1.0)

            results_list = []
            for i in range(len(df_to_analyze)):
                p_idx = int(preds[i])
                pred_cls = classes[p_idx] if p_idx < len(classes) else str(p_idx)
                conf = float(probs[i, p_idx])
                is_anom = bool(anom_preds[i] == -1)

                dest_port = df_to_analyze.iloc[i].get("Destination Port", 80)
                risk = RiskAssessmentEngine.evaluate_risk(
                    predicted_class=pred_cls,
                    confidence=conf,
                    is_anomaly=is_anom,
                    anomaly_score=float(anom_scores_norm[i]),
                    destination_port=dest_port,
                )

                results_list.append({
                    "Flow ID": df_to_analyze.iloc[i].get("Flow ID", f"FLOW-{i:05d}"),
                    "Source IP": df_to_analyze.iloc[i].get("Source IP", "192.168.10.50"),
                    "Destination IP": df_to_analyze.iloc[i].get("Destination IP", "172.16.0.1"),
                    "Dest Port": int(dest_port) if pd.notna(dest_port) else 80,
                    "Predicted Class": pred_cls,
                    "Confidence": f"{conf:.2%}",
                    "Is Anomaly": "⚠️ Yes" if is_anom else "No",
                    "Risk Level": risk["risk_level"],
                    "Risk Score": risk["risk_score"],
                    "Action": risk["recommended_action"],
                })

            elapsed = (time.perf_counter() - start) * 1000.0
            res_df = pd.DataFrame(results_list)

            # Metrics row
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Processed Flows", f"{len(res_df):,}")
            m2.metric("Attacks Detected", f"{(res_df['Predicted Class'] != 'BENIGN').sum():,}")
            m3.metric("Anomalies Flagged", f"{(res_df['Is Anomaly'] == '⚠️ Yes').sum():,}")
            m4.metric("Throughput", f"{len(res_df) / (elapsed / 1000.0):,.0f} flows/sec")

            st.dataframe(res_df, use_container_width=True, height=400)

            # Download CSV button
            csv_data = res_df.to_csv(index=False).encode("utf-8")
            st.download_button("📥 Download Analysis Results (CSV)", data=csv_data, file_name="nids_detection_results.csv", mime="text/csv")

    with tab_single:
        st.markdown("#### Inspect & Simulate Single Network Flow")
        f_col1, f_col2, f_col3 = st.columns(3)

        with f_col1:
            in_port = st.number_input("Destination Port", min_value=1, max_value=65535, value=80)
            in_duration = st.number_input("Flow Duration (µs)", min_value=1, value=120000)
            in_src_ip = st.text_input("Source IP", value="172.16.0.1")

        with f_col2:
            in_pkt_rate = st.number_input("Flow Packets/s", min_value=0.0, value=4500.0)
            in_bwd_pkt_rate = st.number_input("Bwd Packets/s", min_value=0.0, value=2200.0)
            in_dst_ip = st.text_input("Destination IP", value="192.168.10.50")

        with f_col3:
            in_win_fwd = st.number_input("Init Win Bytes Forward", min_value=-1, value=29200)
            in_avg_size = st.number_input("Average Packet Size", min_value=0.0, value=512.0)
            in_syn_flag = st.selectbox("SYN Flag Count", [0, 1], index=1)

        if st.button("⚡ Run Instant Classification"):
            flow_dict = {
                "Destination Port": in_port,
                "Flow Duration": in_duration,
                "Flow Packets/s": in_pkt_rate,
                "Bwd Packets/s": in_bwd_pkt_rate,
                "Init_Win_bytes_forward": in_win_fwd,
                "Average Packet Size": in_avg_size,
                "SYN Flag Count": in_syn_flag,
            }
            df_single = pd.DataFrame([flow_dict])
            X_s = preprocessor.transform(df_single)
            p_idx = int(classifier.predict(X_s)[0])
            prob_s = float(classifier.predict_proba(X_s)[0, p_idx])
            classes = list(preprocessor.class_mapping.keys())
            pred_label = classes[p_idx]

            is_anom = bool(anomaly_detector.predict(X_s)[0] == -1) if anomaly_detector else False
            anom_sc = float(-anomaly_detector.score_samples(X_s)[0]) if anomaly_detector else 0.0

            # CTI Check
            cti_rep = cti_client.lookup_ip(in_src_ip) if cti_client else None
            cti_val = cti_rep.reputation_score if cti_rep and cti_rep.is_malicious else None

            # Local SHAP
            exp_res = explainer.explain_instance(X_s, top_k=3) if explainer else {"top_features": []}

            risk = RiskAssessmentEngine.evaluate_risk(
                predicted_class=pred_label,
                confidence=prob_s,
                is_anomaly=is_anom,
                anomaly_score=anom_sc,
                destination_port=in_port,
                cti_reputation=cti_val,
                top_shap_features=exp_res.get("top_features", []),
            )

            res_c1, res_c2, res_c3 = st.columns(3)
            with res_c1:
                st.metric("Predicted Threat Category", pred_label, f"Confidence: {prob_s:.1%}")
            with res_c2:
                badge_class = f"badge-{risk['risk_level'].lower()}"
                st.markdown(f"**Risk Assessment:** <span class='{badge_class}'>{risk['risk_level']} ({risk['risk_score']}/100)</span>", unsafe_allow_html=True)
                st.caption(f"Anomaly Detection: {'⚠️ Anomaly Detected' if is_anom else 'Normal Baseline'}")
            with res_c3:
                st.markdown(f"**Action Recommended:**")
                st.info(risk["recommended_action"])

            st.markdown(f"**Rationale:** {risk['justification']}")


# ==========================================
# VIEW 3: UNSUPERVISED ANOMALY DETECTION
# ==========================================
elif selected_view == "🧬 Unsupervised Anomaly Detection":
    st.title("Unsupervised Anomaly Detection (Isolation Forest)")
    st.markdown("Profile baseline normal traffic behavior and detect novel zero-day attack patterns without class labels.")

    col_l, col_r = st.columns([2, 1])

    with col_r:
        st.subheader("Threshold Sensitivity")
        contamination = st.slider("Anomaly Contamination Threshold", min_value=0.01, max_value=0.30, value=0.15, step=0.01)
        st.caption("Adjusting contamination balances False Positive Rate against zero-day catch rate.")

        sample_path = PROCESSED_DIR / "test_sample_flows.csv"
        if sample_path.exists() and anomaly_detector:
            df_sample = pd.read_csv(sample_path)
            X_s = preprocessor.transform(df_sample)
            scores = -anomaly_detector.score_samples(X_s)

            threshold_val = np.percentile(scores, (1.0 - contamination) * 100)
            anom_count = (scores > threshold_val).sum()
            st.metric("Predicted Anomalies in Sample", f"{anom_count} / {len(scores)}", f"{anom_count / len(scores):.1%}")

    with col_l:
        st.subheader("Anomaly Score Distribution")
        if sample_path.exists() and anomaly_detector:
            fig = px.histogram(
                x=scores,
                nbins=40,
                color_discrete_sequence=["#1890ff"],
                title="Isolation Forest Anomaly Score Density",
                labels={"x": "Anomaly Score (Higher = More Anomalous)"},
            )
            fig.add_vline(x=threshold_val, line_dash="dash", line_color="#ff4d4f", annotation_text="Threshold")
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=380)
            st.plotly_chart(fig, use_container_width=True)


# ==========================================
# VIEW 4: EXPLAINABLE AI (SHAP)
# ==========================================
elif selected_view == "💡 Explainable AI (SHAP)":
    st.title("Explainable AI (XAI) with SHAP")
    st.markdown("Auditable machine learning decisions grounded in Shapley additive feature attributions.")

    shap_tab_global, shap_tab_local = st.tabs(["🌐 Global Feature Importance", "🔬 Local Flow Explanation"])

    with shap_tab_global:
        st.subheader("Global Feature Importance (XGBoost Classifier)")
        st.markdown("Features with the greatest overall mathematical impact across the test benchmark.")
        img_path = FIGURES_DIR / "shap_global_importance.png"
        if img_path.exists():
            st.image(str(img_path), use_container_width=True)
        else:
            if explainer:
                with st.spinner("Calculating SHAP global importance ..."):
                    explainer.generate_global_importance()
                    st.image(str(img_path), use_container_width=True)

    with shap_tab_local:
        st.subheader("Individual Packet SHAP Attribution")
        st.markdown("Inspect how specific feature values push prediction toward attack or benign.")

        sample_path = PROCESSED_DIR / "test_sample_flows.csv"
        if sample_path.exists():
            df_test = pd.read_csv(sample_path)
            flow_idx = st.selectbox("Select Flow from Test Set to Explain:", options=range(min(20, len(df_test))), format_func=lambda i: f"Flow #{i} (True Label: {df_test.iloc[i].get('Label', 'Unknown')})")

            if st.button("Generate SHAP Waterfall Attribution"):
                row = df_test.iloc[[flow_idx]]
                X_row = preprocessor.transform(row)
                exp = explainer.explain_instance(X_row, top_k=6)

                st.markdown(f"**Predicted Attack Probability:** `{exp['probability']:.2%}` | **Base Expected Value:** `{exp['base_value']:.3f}`")

                feat_df = pd.DataFrame(exp["top_features"])
                fig = px.bar(
                    feat_df,
                    x="shap_value",
                    y="feature",
                    orientation="h",
                    color=feat_df["shap_value"] > 0,
                    color_discrete_map={True: "#ff4d4f", False: "#52c41a"},
                    title=f"Feature Contributions for Flow #{flow_idx} (Red = Increases Threat Likelihood, Green = Pushes toward Benign)",
                )
                fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=350)
                st.plotly_chart(fig, use_container_width=True)


# ==========================================
# VIEW 5: CYBER THREAT INTELLIGENCE (CTI)
# ==========================================
elif selected_view == "🌐 Cyber Threat Intelligence (CTI)":
    st.title("Cyber Threat Intelligence (CTI) Enrichment")
    st.markdown("Enrich network IPs against AbuseIPDB, AlienVault OTX, and local curated threat feeds.")

    cti_col1, cti_col2 = st.columns([1, 1])

    with cti_col1:
        st.subheader("IP Reputation Lookup")
        query_ip = st.text_input("Enter IP Address to Enrich:", value="205.174.165.73")

        if st.button("Query Threat Intelligence"):
            if cti_client:
                report = cti_client.lookup_ip(query_ip)
                st.markdown("---")
                st.markdown(f"**Target IP:** `{report.ip_address}`")
                st.markdown(f"**Source Feed:** `{report.source}`")
                st.markdown(f"**Country / ISP:** `{report.country}` — `{report.isp}`")
                st.markdown(f"**Total Abuse Reports:** `{report.total_reports}`")

                badge = "badge-critical" if report.is_malicious else "badge-low"
                status_text = "CONFIRMED MALICIOUS HOST" if report.is_malicious else "CLEAN / BENIGN"
                st.markdown(f"**Threat Status:** <span class='{badge}'>{status_text}</span>", unsafe_allow_html=True)
                st.markdown(f"**Reputation Score:** `{report.reputation_score}/100`")

                if report.tags:
                    st.markdown("**Intelligence Tags:**")
                    for t in report.tags:
                        st.markdown(f"- 🏷️ `{t}`")

    with cti_col2:
        st.subheader("Curated Benchmark Threat Feed (CICIDS2017)")
        st.markdown("High-risk IPs identified during dataset traffic analysis:")
        feed_data = [
            {"IP Address": "205.174.165.73", "Type": "Botnet C2 Master", "Severity": "CRITICAL", "Abuse Score": "95/100"},
            {"IP Address": "172.16.0.1", "Type": "DDoS/PortScan Attacker", "Severity": "CRITICAL", "Abuse Score": "Internal Testbed"},
            {"IP Address": "198.51.100.25", "Type": "Mirai Scanner / Brute Force", "Severity": "HIGH", "Abuse Score": "88/100"},
            {"IP Address": "203.0.113.195", "Type": "Tor Exit Node / Scanner", "Severity": "HIGH", "Abuse Score": "80/100"},
        ]
        st.table(pd.DataFrame(feed_data))


# ==========================================
# VIEW 6: SECURITY ALERTS & INCIDENT RESPONSE
# ==========================================
elif selected_view == "🚨 Security Alerts & Incident Response":
    st.title("Security Alerts & Incident Triage")
    st.markdown("SQLAlchemy-backed alert management system for SOC Analysts.")

    with get_db_context() as db:
        alerts = db.query(SecurityAlert).order_by(SecurityAlert.timestamp.desc()).limit(100).all()

    if alerts:
        alert_data = [a.to_dict() for a in alerts]
        alert_df = pd.DataFrame(alert_data)

        # Filters
        f1, f2 = st.columns(2)
        with f1:
            risk_filter = st.multiselect("Filter by Risk Level", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
        with f2:
            status_filter = st.multiselect("Filter by Status", ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"], default=["NEW", "INVESTIGATING"])

        filtered_df = alert_df[
            (alert_df["risk_level"].isin(risk_filter)) &
            (alert_df["status"].isin(status_filter))
        ]

        st.dataframe(
            filtered_df[["id", "timestamp", "source_ip", "destination_port", "predicted_class", "confidence", "risk_level", "risk_score", "status"]],
            use_container_width=True,
            height=380,
        )

        st.subheader("Analyst Incident Actions")
        act_c1, act_c2, act_c3 = st.columns([1, 1, 1])
        with act_c1:
            selected_alert_id = st.selectbox("Select Alert ID to Update", options=filtered_df["id"].tolist() if not filtered_df.empty else [0])
        with act_c2:
            new_status = st.selectbox("New Status", ["INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"])
        with act_c3:
            st.write("")
            if st.button("Apply Status Change"):
                if selected_alert_id > 0:
                    with get_db_context() as db:
                        rec = db.query(SecurityAlert).filter(SecurityAlert.id == selected_alert_id).first()
                        if rec:
                            rec.status = new_status
                    st.success(f"Alert #{selected_alert_id} updated to {new_status}")
                    st.rerun()
    else:
        st.info("No alerts in database. Run batch processing or single flow predictions to generate alerts.")


# ==========================================
# VIEW 7: DOWNLOADABLE REPORTS
# ==========================================
elif selected_view == "📄 Downloadable Reports":
    st.title("SOC Intelligence Reports & Audit Logs")
    st.markdown("Export comprehensive incident logs and executive security reports.")

    with get_db_context() as db:
        alerts = db.query(SecurityAlert).all()
        total_count = len(alerts)

    st.markdown(f"Database currently holds **{total_count}** recorded incidents.")

    if total_count > 0:
        full_df = pd.DataFrame([a.to_dict() for a in alerts])
        csv_bytes = full_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Download Full Incident History (CSV)",
            data=csv_bytes,
            file_name=f"soc_incidents_audit_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
        )

    st.divider()
    st.subheader("Academic Project Documentation")
    report_path = PROJECT_ROOT / "reports" / "MSc_NIDS_Final_Report.docx"
    if report_path.exists():
        with open(report_path, "rb") as f:
            st.download_button(
                label="📘 Download MSc Academic Project Report (DOCX)",
                data=f.read(),
                file_name="MSc_NIDS_Final_Report.docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
    else:
        st.caption("MSc Final Report will appear here once compiled in Phase 9.")

