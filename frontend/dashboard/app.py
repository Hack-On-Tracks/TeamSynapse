"""CipherSentinel - Next-Generation AI-Powered Insider Threat Detection Platform.

Streamlit SOC Dashboard featuring real-time telemetry analytics, multi-table risk scoring,
interactive temporal replay slider, MITRE ATT&CK mapping, and grounded AI copilot.
"""
from __future__ import annotations

import os
import time
import datetime
import requests
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import sys
import streamlit as st

# Auto-launch with streamlit runner if invoked directly via bare 'python app.py'
if not st.runtime.exists():
    from streamlit.web import cli as stcli
    sys.argv = ["streamlit", "run", __file__]
    sys.exit(stcli.main())

# ==========================================
# PAGE CONFIGURATION & DARK THEME STYLING
# ==========================================
st.set_page_config(
    page_title="CipherSentinel | Insider Threat SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    /* Global Background and Fonts */
    .stApp {
        background-color: #070d1e;
        color: #e2e8f0;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0b132b;
        border-right: 1px solid #1e293b;
    }

    /* Metric Cards */
    .metric-card {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 18px 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        margin-bottom: 12px;
    }
    .metric-title {
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94a3b8;
    }
    .metric-value {
        font-size: 1.85rem;
        font-weight: 700;
        color: #38bdf8;
        margin-top: 4px;
    }
    .metric-sub {
        font-size: 0.8rem;
        color: #64748b;
        margin-top: 2px;
    }

    /* Severity Badges */
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.2);
        color: #ef4444;
        border: 1px solid #ef4444;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
    }
    .badge-high {
        background-color: rgba(249, 115, 22, 0.2);
        color: #f97316;
        border: 1px solid #f97316;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
    }
    .badge-medium {
        background-color: rgba(234, 179, 8, 0.2);
        color: #eab308;
        border: 1px solid #eab308;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
    }
    .badge-low {
        background-color: rgba(34, 197, 94, 0.2);
        color: #22c55e;
        border: 1px solid #22c55e;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
    }

    /* Cyber Glow Dividers */
    .cyber-divider {
        height: 2px;
        background: linear-gradient(90deg, #0284c7, #38bdf8, transparent);
        margin: 20px 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ==========================================
# STATE & BACKEND CLIENT HELPERS
# ==========================================
API_BASE = os.getenv("API_BASE", "http://localhost:8000")

if "auth_token" not in st.session_state:
    st.session_state.auth_token = None
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "replay_day" not in st.session_state:
    st.session_state.replay_day = 14


def get_headers():
    if st.session_state.auth_token:
        return {"Authorization": f"Bearer {st.session_state.auth_token}"}
    return {}


def api_post(endpoint: str, json_data=None, files=None):
    url = f"{API_BASE}{endpoint}"
    try:
        resp = requests.post(url, json=json_data, files=files, headers=get_headers(), timeout=15)
        if resp.status_code == 401:
            st.session_state.auth_token = None
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def api_get(endpoint: str, params=None):
    url = f"{API_BASE}{endpoint}"
    try:
        resp = requests.get(url, params=params, headers=get_headers(), timeout=15)
        if resp.status_code == 401:
            st.session_state.auth_token = None
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def check_api_health():
    try:
        r = requests.get(f"{API_BASE}/health", timeout=0.8)
        return r.status_code == 200
    except Exception:
        return False


api_online = check_api_health()

# Auto-login with default admin if API is online and no token exists
if api_online and not st.session_state.auth_token:
    try:
        login_res = requests.post(
            f"{API_BASE}/auth/token",
            json={"username": "admin", "password": "admin123"},
            timeout=1.0,
        )
        if login_res.status_code == 200:
            data = login_res.json()
            st.session_state.auth_token = data.get("access_token")
            st.session_state.current_user = data.get("user")
    except Exception:
        pass


# ==========================================
# SIDEBAR CONTROLS & NAVIGATION
# ==========================================
with st.sidebar:
    st.markdown("### 🛡️ **CipherSentinel**")
    st.caption("Insider Threat Defense Platform v0.1.0")

    # API Status Indicator
    if api_online:
        st.success("🟢 API Connected", icon="✅")
    else:
        st.warning("🟠 API Offline (Showing Demo Data)", icon="⚠️")
        st.caption("Run `python run.py` to start both API & UI.")

    # Auth Section
    with st.expander("🔐 Security Credentials", expanded=not bool(st.session_state.auth_token)):
        if st.session_state.auth_token and st.session_state.current_user:
            st.write(f"Logged in: **{st.session_state.current_user.get('username')}**")
            st.caption(f"Role: {st.session_state.current_user.get('role')}")
            if st.button("Log Out", key="logout_btn"):
                st.session_state.auth_token = None
                st.session_state.current_user = None
                st.rerun()
        else:
            with st.form("login_form"):
                u = st.text_input("Username", value="admin")
                p = st.text_input("Password", value="admin123", type="password")
                submit = st.form_submit_button("Authenticate")
                if submit:
                    res = requests.post(
                        f"{API_BASE}/auth/token",
                        json={"username": u, "password": p},
                    )
                    if res.status_code == 200:
                        data = res.json()
                        st.session_state.auth_token = data.get("access_token")
                        st.session_state.current_user = data.get("user")
                        st.success("Authenticated successfully!")
                        st.rerun()
                    else:
                        st.error("Invalid credentials")

    st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

    # Navigation Tabs
    page = st.radio(
        "Navigation",
        [
            "Executive SOC Overview",
            "Data Ingestion & Detectors",
            "Cross-Table Scoring",
            "Visual Analytics & Replay",
            "Threat Case Management",
            "GenAI Security Copilot",
            "Audit Trail & Settings",
        ],
        index=0,
    )

    st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

    # Global Filters
    st.markdown("#### ⚙️ **Investigation Filters**")
    min_score_filter = st.slider("Min Risk Score Cutoff", 0, 100, 20, step=5)
    severity_filter = st.selectbox("Severity Classification", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    entity_search = st.text_input("Search Entity / User ID", placeholder="e.g. U102, 192.168.1.45")

    st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

    # Interactive Replay Slider
    st.markdown("#### ⏱️ **Timeline Replay Slider**")
    replay_day = st.slider(
        "Observation Day (Replay)",
        min_value=1,
        max_value=30,
        value=st.session_state.replay_day,
        help="Scrub through historical days to observe threat escalation.",
    )
    st.session_state.replay_day = replay_day


# Helper: Render Severity Tag
def render_severity_badge(sev: str) -> str:
    s = str(sev).upper()
    if s == "CRITICAL":
        return "<span class='badge-critical'>CRITICAL</span>"
    elif s == "HIGH":
        return "<span class='badge-high'>HIGH</span>"
    elif s == "MEDIUM":
        return "<span class='badge-medium'>MEDIUM</span>"
    return "<span class='badge-low'>LOW</span>"


# ==========================================
# PAGE 1: EXECUTIVE SOC OVERVIEW
# ==========================================
if page == "Executive SOC Overview":
    st.markdown("## 🛡️ Executive Threat Matrix & SOC Command")
    st.caption("Consolidated situational awareness for enterprise insider threats and exfiltration signals.")

    # Fetch Scored Entities
    scores_res = api_get("/score/scores", params={"min_score": min_score_filter, "severity": severity_filter, "limit": 150})
    cases_res = api_get("/score/cases", params={"limit": 100})

    scores = scores_res if isinstance(scores_res, list) else []
    cases = cases_res if isinstance(cases_res, list) else []

    # If backend is offline or no scores generated yet, use interactive demo dataset
    if not scores and not api_online:
        st.info("💡 **Interactive Preview Mode**: Showing synthesized enterprise insider telemetry. Start backend (`python run.py`) to connect live database.")
        demo_scores = [
            {"entity_id": "U102_SecOps", "composite_score": 92.4, "severity": "CRITICAL", "confidence": 0.88, "sub_volume": 0.94, "sub_novelty": 0.85, "sub_auth": 0.60, "sub_dns": 0.78, "sub_timing": 0.82, "mitre_tactics": "T1048.003 - Exfiltration", "primary_indicator": "Massive Outbound Transfer (550MB to unseen IP at 02:30 AM)", "table_sources": "network_flows, auth_logs"},
            {"entity_id": "U045_Finance", "composite_score": 78.6, "severity": "HIGH", "confidence": 0.82, "sub_volume": 0.42, "sub_novelty": 0.80, "sub_auth": 0.75, "sub_dns": 0.65, "sub_timing": 0.70, "mitre_tactics": "T1078.002 - Initial Access", "primary_indicator": "Brute-Force & Off-Hours Domain Controller Access", "table_sources": "auth_logs"},
            {"entity_id": "192.168.1.185", "composite_score": 68.2, "severity": "HIGH", "confidence": 0.79, "sub_volume": 0.35, "sub_novelty": 0.60, "sub_auth": 0.20, "sub_dns": 0.92, "sub_timing": 0.50, "mitre_tactics": "T1071.004 - C2", "primary_indicator": "High Entropy DNS Queries (>4.2 entropy, potential tunneling)", "table_sources": "dns_queries"},
            {"entity_id": "U012_Engineering", "composite_score": 48.0, "severity": "MEDIUM", "confidence": 0.72, "sub_volume": 0.40, "sub_novelty": 0.45, "sub_auth": 0.10, "sub_dns": 0.20, "sub_timing": 0.35, "mitre_tactics": "T1071.001 - Web Protocols", "primary_indicator": "Unusual bulk code sync to external repository", "table_sources": "network_flows"},
            {"entity_id": "U088_Marketing", "composite_score": 24.5, "severity": "LOW", "confidence": 0.65, "sub_volume": 0.20, "sub_novelty": 0.15, "sub_auth": 0.05, "sub_dns": 0.10, "sub_timing": 0.10, "mitre_tactics": "T1029 - Execution", "primary_indicator": "Standard daytime web browsing", "table_sources": "network_flows"},
        ]
        scores = [s for s in demo_scores if s["composite_score"] >= min_score_filter and (severity_filter == "ALL" or s["severity"] == severity_filter)]

    if not cases and not api_online:
        cases = [
            {"case_id": "CASE-U102_SecOps-20261015", "entity_id": "U102_SecOps", "case_score": 92.4, "severity": "CRITICAL", "confidence": 0.88, "status": "OPEN", "title": "Suspected Data Exfiltration via Encrypted Tunnel", "description": "Entity transferred 550MB to an unclassified external IP at 2:30 AM on a weekend with Tier-3 asset credentials.", "evidence_summary": "Volume=0.94, Novelty=0.85, Auth=0.60, Timing=0.82"},
            {"case_id": "CASE-U045_Finance-20261015", "entity_id": "U045_Finance", "case_score": 78.6, "severity": "HIGH", "confidence": 0.82, "status": "INVESTIGATING", "title": "Multiple Failed Authentication Spikes Across Subnets", "description": "14 failed authentication attempts within 3 minutes followed by privileged share access.", "evidence_summary": "Auth=0.75, Novelty=0.80, Timing=0.70"},
        ]

    if entity_search:
        scores = [s for s in scores if entity_search.lower() in str(s.get("entity_id", "")).lower()]

    # KPI Metric Cards
    total_entities = len(scores)
    critical_count = len([s for s in scores if s.get("severity") == "CRITICAL"])
    high_count = len([s for s in scores if s.get("severity") == "HIGH"])
    open_cases = len([c for c in cases if c.get("status") == "OPEN"])
    avg_score = round(np.mean([s.get("composite_score", 0) for s in scores]), 1) if scores else 0.0

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(
            f"""<div class='metric-card'>
            <div class='metric-title'>Entities Monitored</div>
            <div class='metric-value'>{total_entities}</div>
            <div class='metric-sub'>Active in current filter</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f"""<div class='metric-card'>
            <div class='metric-title'>Critical Threats</div>
            <div class='metric-value' style='color:#ef4444;'>{critical_count}</div>
            <div class='metric-sub'>Risk Score ≥ 80</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            f"""<div class='metric-card'>
            <div class='metric-title'>High Risk</div>
            <div class='metric-value' style='color:#f97316;'>{high_count}</div>
            <div class='metric-sub'>Risk Score 60-79</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            f"""<div class='metric-card'>
            <div class='metric-title'>Open SOC Cases</div>
            <div class='metric-value' style='color:#38bdf8;'>{open_cases}</div>
            <div class='metric-sub'>Prioritized for triage</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with col5:
        st.markdown(
            f"""<div class='metric-card'>
            <div class='metric-title'>Mean Risk Index</div>
            <div class='metric-value'>{avg_score}</div>
            <div class='metric-sub'>Normalized 0-100</div>
            </div>""",
            unsafe_allow_html=True,
        )

    st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

    # Visualizations Row
    chart_col1, chart_col2 = st.columns([1, 1])

    with chart_col1:
        st.subheader("Severity Distribution")
        if scores:
            sev_df = pd.DataFrame(scores)
            sev_counts = sev_df["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            color_map = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#22c55e",
            }
            fig_pie = px.pie(
                sev_counts,
                names="Severity",
                values="Count",
                hole=0.55,
                color="Severity",
                color_discrete_map=color_map,
            )
            fig_pie.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#e2e8f0"},
                margin=dict(t=20, b=20, l=20, r=20),
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No threat scores available. Ingest telemetry and run cross-table scoring.")

    with chart_col2:
        st.subheader("Top Signal Categories (Radar)")
        if scores:
            df_radar = pd.DataFrame(scores)
            avg_signals = {
                "Data Volume": df_radar["sub_volume"].mean() if "sub_volume" in df_radar else 0.2,
                "Novelty/Dest": df_radar["sub_novelty"].mean() if "sub_novelty" in df_radar else 0.2,
                "Auth Failures": df_radar["sub_auth"].mean() if "sub_auth" in df_radar else 0.1,
                "DNS Tunnelling": df_radar["sub_dns"].mean() if "sub_dns" in df_radar else 0.1,
                "Off-Hours Timing": df_radar["sub_timing"].mean() if "sub_timing" in df_radar else 0.15,
            }
            categories = list(avg_signals.keys())
            values = list(avg_signals.values())
            # close polygon
            categories.append(categories[0])
            values.append(values[0])

            fig_radar = go.Figure()
            fig_radar.add_trace(
                go.Scatterpolar(
                    r=values,
                    theta=categories,
                    fill="toself",
                    fillcolor="rgba(56, 189, 248, 0.25)",
                    line=dict(color="#38bdf8", width=2),
                    name="Enterprise Avg",
                )
            )
            fig_radar.update_layout(
                polar=dict(
                    radialaxis=dict(visible=True, range=[0, 1], gridcolor="#1e293b", linecolor="#1e293b"),
                    angularaxis=dict(gridcolor="#1e293b", linecolor="#1e293b"),
                    bgcolor="#0b132b",
                ),
                paper_bgcolor="rgba(0,0,0,0)",
                font={"color": "#e2e8f0"},
                margin=dict(t=20, b=20, l=20, r=20),
            )
            st.plotly_chart(fig_radar, use_container_width=True)
        else:
            st.info("No signal breakdown available.")

    # High-Priority Entities Table
    st.subheader("Priority Alert Queue")
    if scores:
        display_data = []
        for s in scores[:15]:
            display_data.append({
                "Entity ID": s.get("entity_id"),
                "Risk Score": s.get("composite_score"),
                "Severity": s.get("severity"),
                "Confidence": f"{int(s.get('confidence', 0) * 100)}%",
                "Primary Indicator": s.get("primary_indicator"),
                "MITRE Technique": s.get("mitre_tactics"),
                "Telemetry Sources": s.get("table_sources"),
            })
        st.dataframe(pd.DataFrame(display_data), use_container_width=True, hide_index=True)
    else:
        st.warning("No data matching current filters.")


# ==========================================
# PAGE 2: DATA INGESTION & DETECTORS
# ==========================================
elif page == "Data Ingestion & Detectors":
    st.markdown("## 📥 Telemetry Ingestion & Anomaly Detection")
    st.caption("Ingest enterprise logs into DuckDB and execute machine learning anomaly detection.")

    tab1, tab2 = st.tabs(["Upload & Ingestion", "Run Anomaly Detectors"])

    with tab1:
        st.subheader("Ingest Telemetry File")
        uploaded_file = st.file_uploader("Upload CSV Telemetry (Network flows, Auth logs, DNS, File events)", type=["csv"])
        if uploaded_file is not None:
            st.write("File preview:")
            preview_df = pd.read_csv(uploaded_file)
            st.dataframe(preview_df.head(5), use_container_width=True)

            if st.button("Ingest to DuckDB & Parquet"):
                uploaded_file.seek(0)
                files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "text/csv")}
                res = api_post("/data/upload", files=files)
                if "error" not in res:
                    st.success(f"Successfully ingested {res.get('rows')} rows into table `{res.get('table_name')}`!")
                else:
                    st.error(f"Ingestion failed: {res.get('error')}")

        st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)
        st.subheader("Available Database Tables")
        tables_res = api_get("/detect/tables")
        if isinstance(tables_res, dict) and "tables" in tables_res:
            st.write("Current DuckDB Tables:", tables_res.get("tables"))
        else:
            st.info("No telemetry tables loaded yet.")

    with tab2:
        st.subheader("Isolation Forest Anomaly Detection")
        tables_res = api_get("/detect/tables")
        available_tables = tables_res.get("tables", []) if isinstance(tables_res, dict) else []

        if not available_tables:
            st.warning("Please upload a telemetry CSV in the Ingestion tab first.")
        else:
            selected_table = st.selectbox("Select Target Telemetry Table", available_tables)
            contamination = st.slider("Expected Contamination Rate", 0.001, 0.10, 0.02, step=0.005)
            custom_cols = st.text_input("Feature columns (comma-separated, leave blank for all numeric columns)")

            if st.button("Execute Detector", type="primary"):
                feature_list = [c.strip() for c in custom_cols.split(",") if c.strip()] if custom_cols else []
                payload = {
                    "table_name": selected_table,
                    "contamination": contamination,
                    "feature_columns": feature_list,
                }
                with st.spinner("Training Isolation Forest and scoring telemetry..."):
                    det_res = api_post("/detect/detect", json_data=payload)
                if "error" not in det_res:
                    anomalies = det_res.get("anomalies", {})
                    outlier_count = sum(1 for v in anomalies.values() if v == -1)
                    st.success(f"Detection Complete! Isolated {outlier_count} anomalies out of {len(anomalies)} records.")
                    st.info("Results persisted back to DuckDB table with `anomaly_flag` and `anomaly_score`.")
                else:
                    st.error(f"Detection failed: {det_res.get('error')}")


# ==========================================
# PAGE 3: CROSS-TABLE SCORING
# ==========================================
elif page == "Cross-Table Scoring":
    st.markdown("## ⚖️ Multi-Table Threat Fusion & Aggregation")
    st.caption("Correlate signals across multiple tables to calculate composite entity risk and open triage cases.")

    st.subheader("Configure Scoring Weights")
    w_col1, w_col2, w_col3, w_col4, w_col5 = st.columns(5)
    with w_col1:
        w_vol = st.slider("Volume / Exfil", 0.0, 1.0, 0.30, 0.05)
    with w_col2:
        w_nov = st.slider("Novelty / Rare Dst", 0.0, 1.0, 0.25, 0.05)
    with w_col3:
        w_auth = st.slider("Auth Failures", 0.0, 1.0, 0.20, 0.05)
    with w_col4:
        w_dns = st.slider("DNS Tunnelling", 0.0, 1.0, 0.15, 0.05)
    with w_col5:
        w_tim = st.slider("Off-Hours Timing", 0.0, 1.0, 0.10, 0.05)

    tables_res = api_get("/detect/tables")
    available_tables = tables_res.get("tables", []) if isinstance(tables_res, dict) else []

    selected_tables = st.multiselect(
        "Select Telemetry Tables to Aggregate (leave blank for all discovered tables)",
        available_tables,
        default=available_tables[:3] if available_tables else [],
    )

    if st.button("Run Cross-Table Aggregation Engine", type="primary"):
        payload = {
            "table_names": selected_tables if selected_tables else None,
            "weights": {
                "volume": w_vol,
                "novelty": w_nov,
                "auth": w_auth,
                "dns": w_dns,
                "timing": w_tim,
            },
        }
        with st.spinner("Aggregating multi-source telemetry in DuckDB..."):
            agg_res = api_post("/score/aggregate", json_data=payload)

        if "error" not in agg_res:
            st.success(
                f"Successfully scored {agg_res.get('entities_scored', 0)} entities! "
                f"Opened {agg_res.get('cases_opened', 0)} investigation cases."
            )
            st.dataframe(pd.DataFrame(agg_res.get("results", [])), use_container_width=True)
        else:
            st.error(f"Scoring aggregation failed: {agg_res.get('error')}")


# ==========================================
# PAGE 4: VISUAL ANALYTICS & REPLAY
# ==========================================
elif page == "Visual Analytics & Replay":
    st.markdown("## 📊 Visual Analytics & Interactive Replay Studio")
    st.caption("Scrub through attack progression timelines, explore risk clusters, and inspect telemetry correlations.")

    scores_res = api_get("/score/scores", params={"limit": 200})
    scores = scores_res if isinstance(scores_res, list) else []

    if not scores:
        st.info("No scored telemetry available. Run Cross-Table Scoring to populate analytics.")
    else:
        df = pd.DataFrame(scores)

        # Replay Controller Callout
        st.info(
            f"⏱️ **Current Observation Day: Day {st.session_state.replay_day}**. "
            "Use the sidebar replay slider to scrub time forwards and backwards."
        )

        row1_col1, row1_col2 = st.columns(2)

        with row1_col1:
            st.subheader("Risk Score vs Data Exfiltration Volume")
            fig_scatter = px.scatter(
                df,
                x="sub_volume",
                y="composite_score",
                color="severity",
                size="composite_score",
                hover_data=["entity_id", "primary_indicator", "mitre_tactics", "confidence"],
                color_discrete_map={
                    "CRITICAL": "#ef4444",
                    "HIGH": "#f97316",
                    "MEDIUM": "#eab308",
                    "LOW": "#22c55e",
                },
                labels={"sub_volume": "Volume Subscore (0-1)", "composite_score": "Composite Risk Index (0-100)"},
            )
            fig_scatter.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="#0b132b",
                font={"color": "#e2e8f0"},
            )
            st.plotly_chart(fig_scatter, use_container_width=True)

        with row1_col2:
            st.subheader("Top 10 High-Risk Entities")
            top10 = df.sort_values(by="composite_score", ascending=True).tail(10)
            fig_bar = px.bar(
                top10,
                x="composite_score",
                y="entity_id",
                orientation="h",
                color="severity",
                color_discrete_map={
                    "CRITICAL": "#ef4444",
                    "HIGH": "#f97316",
                    "MEDIUM": "#eab308",
                    "LOW": "#22c55e",
                },
                labels={"composite_score": "Risk Index", "entity_id": "Entity / Host"},
            )
            fig_bar.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="#0b132b",
                font={"color": "#e2e8f0"},
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        # Temporal Risk Simulation / Day Progression
        st.subheader("Entity Temporal Progression (Replay Simulation)")
        # Synthesize time series simulation for top entities based on replay day
        entities = df["entity_id"].head(5).tolist()
        days = list(range(max(1, st.session_state.replay_day - 10), st.session_state.replay_day + 1))
        prog_records = []
        for ent in entities:
            base_score = float(df.loc[df["entity_id"] == ent, "composite_score"].iloc[0])
            for d in days:
                noise = np.sin(d * 0.5) * 6
                s = max(5.0, min(100.0, base_score * (d / float(st.session_state.replay_day)) + noise))
                prog_records.append({"Day": f"Day {d:02d}", "Entity": ent, "Risk Score": round(s, 1)})

        prog_df = pd.DataFrame(prog_records)
        fig_line = px.line(
            prog_df,
            x="Day",
            y="Risk Score",
            color="Entity",
            markers=True,
            title="Temporal Risk Escalation Trajectory",
        )
        fig_line.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#0b132b",
            font={"color": "#e2e8f0"},
        )
        st.plotly_chart(fig_line, use_container_width=True)


# ==========================================
# PAGE 5: THREAT CASE MANAGEMENT
# ==========================================
elif page == "Threat Case Management":
    st.markdown("## 📁 Threat Case Management & Analyst Triage")
    st.caption("Actionable case bundles with MITRE ATT&CK techniques, evidence summaries, and status updates.")

    cases_res = api_get("/score/cases")
    cases = cases_res if isinstance(cases_res, list) else []

    status_filter = st.selectbox("Filter Case Status", ["ALL", "OPEN", "INVESTIGATING", "MITIGATED", "FALSE_POSITIVE"])
    if status_filter != "ALL":
        cases = [c for c in cases if c.get("status") == status_filter]

    if not cases:
        st.info("No cases matching the current status filter.")
    else:
        for c in cases:
            sev = c.get("severity", "LOW")
            case_id = c.get("case_id")
            score = c.get("case_score", 0)

            with st.expander(f"Case {case_id} — {c.get('entity_id')} (Score: {score} | {sev})", expanded=sev == "CRITICAL"):
                c_col1, c_col2 = st.columns([3, 1])
                with c_col1:
                    st.write(f"**Title**: {c.get('title')}")
                    st.write(f"**Description**: {c.get('description')}")
                    st.write(f"**Evidence**: `{c.get('evidence_summary')}`")
                    st.write(f"**Confidence**: {int(c.get('confidence', 0) * 100)}%")
                    st.write(f"**Current Status**: `{c.get('status')}`")
                with c_col2:
                    st.write("**Triage Actions**")
                    if st.button("Mark Investigating", key=f"inv_{case_id}"):
                        api_post(f"/score/case/{case_id}/status", json_data={"status": "INVESTIGATING"})
                        st.rerun()
                    if st.button("Mitigate Threat", key=f"mit_{case_id}"):
                        api_post(f"/score/case/{case_id}/status", json_data={"status": "MITIGATED"})
                        st.rerun()
                    if st.button("False Positive", key=f"fp_{case_id}"):
                        api_post(f"/score/case/{case_id}/status", json_data={"status": "FALSE_POSITIVE"})
                        st.rerun()


# ==========================================
# PAGE 6: GENAI SECURITY COPILOT
# ==========================================
elif page == "GenAI Security Copilot":
    st.markdown("## 🤖 GenAI Security Copilot")
    st.caption("Interactive analyst copilot grounded in real-time telemetry, threat scores, and MITRE tactics.")

    # Context grounder
    scores_res = api_get("/score/scores", params={"limit": 5})
    scores = scores_res if isinstance(scores_res, list) else []

    top_threats = ""
    if scores:
        top_threats = "\n".join(
            [f"- {s.get('entity_id')}: Score {s.get('composite_score')}, Severity {s.get('severity')}, Indicator: {s.get('primary_indicator')}" for s in scores]
        )

    # Display chat history
    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Quick Prompt Shortcuts
    st.caption("Quick Queries:")
    quick_col1, quick_col2, quick_col3 = st.columns(3)
    preset_prompt = None
    if quick_col1.button("🚨 Analyze Critical Threats"):
        preset_prompt = "Summarize the most critical insider threats detected and recommend containment actions."
    if quick_col2.button("🔍 Explain MITRE Techniques"):
        preset_prompt = "Explain the MITRE ATT&CK tactics identified across our high-scoring entities."
    if quick_col3.button("📝 Draft Incident Brief"):
        preset_prompt = "Draft an executive incident briefing based on current telemetry findings."

    prompt_input = st.chat_input("Ask CipherSentinel Copilot...") or preset_prompt

    if prompt_input:
        st.session_state.chat_history.append({"role": "user", "content": prompt_input})
        with st.chat_message("user"):
            st.markdown(prompt_input)

        # Build grounded prompt
        grounded_prompt = f"""
You are CipherSentinel Copilot, an elite cybersecurity assistant for insider threat defense.
Current Threat Intelligence Context from DuckDB:
{top_threats if top_threats else 'No active critical cases.'}

Analyst Query: {prompt_input}

Provide a precise, grounded, professional SOC response with actionable recommendations.
"""
        with st.chat_message("assistant"):
            with st.spinner("Analyzing threat intelligence..."):
                gen_res = api_post("/genai/generate", json_data={"prompt": grounded_prompt, "model": "llama2"})
                answer = gen_res.get("answer", "Unable to generate response.") if isinstance(gen_res, dict) else str(gen_res)
                source = gen_res.get("source", "model") if isinstance(gen_res, dict) else "model"
                st.markdown(answer)
                st.caption(f"Engine: {source}")

        st.session_state.chat_history.append({"role": "assistant", "content": f"{answer}\n\n*(Engine: {source})*"})


# ==========================================
# PAGE 7: AUDIT TRAIL & SETTINGS
# ==========================================
elif page == "Audit Trail & Settings":
    st.markdown("## 📜 Security Audit Trail & System Health")
    st.caption("Immutable audit log of all system authentication, ingestion, and detection actions.")

    tab1, tab2 = st.tabs(["Audit Logs", "System Diagnostics"])

    with tab1:
        st.subheader("Authentication & System Audit Logs")
        audit_res = api_get("/auth/audit-logs", params={"limit": 50})
        if isinstance(audit_res, list) and audit_res:
            st.dataframe(pd.DataFrame(audit_res), use_container_width=True, hide_index=True)
        else:
            st.info("No audit events recorded yet.")

    with tab2:
        st.subheader("System Architecture Diagnostics")
        st.json({
            "FastAPI Backend": f"{API_BASE} (Online: {check_api_health()})",
            "DuckDB Database": os.getenv("DUCKDB_PATH", "./data/duckdb.db"),
            "Authentication": "PBKDF2 SHA-256 + JWT Bearer",
            "Detector Model": "Scikit-Learn IsolationForest + Rule Fusion",
            "GenAI Endpoint": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/api"),
        })
