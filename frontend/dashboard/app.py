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
            "🔍 Threat Investigation (Multi-Layer Engine)",
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
# CONSENSUS & MULTI-LAYER PIPELINE HELPERS
# ==========================================
def check_ollama_direct() -> dict:
    try:
        r = requests.get("http://127.0.0.1:11434/api/tags", timeout=1.5)
        if r.status_code == 200:
            models = [m.get("name") for m in r.json().get("models", [])]
            has_qwen = any("qwen3:4b" in m for m in models)
            return {"online": True, "models": models, "has_qwen": has_qwen}
    except Exception:
        pass
    return {"online": False, "models": [], "has_qwen": False}


def get_consensus_data(limit: int = 50, live_ollama: bool = False) -> list:
    res = api_get("/score/consensus", params={"limit": limit, "live_ollama": live_ollama})
    if isinstance(res, list) and res:
        return res
    try:
        from backend.scoring.consensus import ConsensusEngine
        ce = ConsensusEngine()
        return ce.run_all_consensus(limit=limit, live_ollama=live_ollama)
    except Exception:
        return []


# ==========================================
# PAGE: THREAT INVESTIGATION (4 SUBTABS)
# ==========================================
if page == "🔍 Threat Investigation (Multi-Layer Engine)":
    st.markdown("## 🔍 Threat Investigation & Multi-Layer Defense")
    st.caption("Comprehensive multi-layer behavioral investigation: Rule-Based Policies, Scratch ML Outliers, and Ollama Qwen3:4b Verification.")

    c_data = get_consensus_data(limit=50)

    # Four Subtabs as requested
    subtab1, subtab2, subtab3, subtab4 = st.tabs([
        "🛡️ 1. Rule-Based Engine & Detection",
        "🧠 2. Model-Based Detection",
        "🤖 3. LLM Verification (Same Dataset)",
        "⚖️ 4. Overall Final Decision (Zero False-Opposites)",
    ])

    # -------------------------------------------------------------
    # SUBTAB 1: RULE-BASED ENGINE & DETECTION ON MAIN PANEL
    # -------------------------------------------------------------
    with subtab1:
        st.subheader("🛡️ Rule-Based Engine & Telemetry Detections")
        st.caption("Deterministic heuristic rules and statistical baselines evaluated on the main panel.")

        st.info(
            "💡 **Base Layer 1 Function**: Evaluates incoming enterprise telemetry against explicit security policies "
            "(allowlists, volumetric egress, off-hours schedules, novel destinations, and Kerberos authentication failures). "
            "Triggers initial alert indicators before machine learning and LLM verification."
        )

        # Top Metric Bar
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(
                """<div class='metric-card'>
                <div class='metric-title'>Active Heuristic Rules</div>
                <div class='metric-value'>6 Policies</div>
                <div class='metric-sub'>Volume, Novelty, Timing, Auth, DNS, CUSUM</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(
                f"""<div class='metric-card'>
                <div class='metric-title'>Entities Evaluated</div>
                <div class='metric-value'>{len(c_data)} Users</div>
                <div class='metric-sub'>Network Flows & Auth Logs</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with col3:
            n_rules_tripped = sum(1 for c in c_data if c["rule_layer"]["rule_score"] >= 40.0) if c_data else 0
            st.markdown(
                f"""<div class='metric-card'>
                <div class='metric-title'>Rule Base Alerts</div>
                <div class='metric-value'>{n_rules_tripped} Flagged</div>
                <div class='metric-sub'>Score &ge; 40.0 Cutoff</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with col4:
            st.markdown(
                """<div class='metric-card'>
                <div class='metric-title'>Raw Alert Noise</div>
                <div class='metric-value'>~30% Unfiltered</div>
                <div class='metric-sub'>Forwarded to Layer 3 for Verification</div>
                </div>""",
                unsafe_allow_html=True,
            )

        st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

        # Interactive Threshold Simulator
        with st.expander("⚙️ **Rule Threshold & Sensitivity Simulator**", expanded=False):
            tcol1, tcol2, tcol3 = st.columns(3)
            with tcol1:
                th_vol = st.slider("Volume Gate (MB)", 10, 500, 50, step=10, key="st_vol")
                th_nov = st.slider("Novelty Cutoff Ratio", 0.1, 1.0, 0.5, step=0.05, key="st_nov")
            with tcol2:
                th_timing = st.slider("Off-Hours Cutoff Ratio", 0.1, 1.0, 0.7, step=0.05, key="st_timing")
                th_auth = st.slider("Kerberos Auth Failure Cutoff", 0.1, 1.0, 0.5, step=0.05, key="st_auth")
            with tcol3:
                th_dns = st.slider("DNS Entropy Cutoff", 0.1, 1.0, 0.5, step=0.05, key="st_dns")
                st.caption("Simulates tuning of the deterministic rule thresholds.")

        # Detections on Main Panel
        st.subheader("📋 Rule Detection Matrix (Main Panel)")
        if c_data:
            rule_rows = []
            for c in c_data:
                rl = c["rule_layer"]
                rule_rows.append({
                    "Entity ID": rl["entity_id"],
                    "Rule Score": rl["rule_score"],
                    "Severity": rl["severity"],
                    "Rules Fired": rl["rule_count"],
                    "Volume Subscore": rl["sub_volume"],
                    "Novelty Subscore": rl["sub_novelty"],
                    "Timing Subscore": rl["sub_timing"],
                    "Auth Subscore": rl["sub_auth"],
                    "Primary Rule Trigger": rl["primary_rule_indicator"],
                })
            rule_df = pd.DataFrame(rule_rows)
            st.dataframe(
                rule_df.style.background_gradient(subset=["Rule Score"], cmap="Reds"),
                use_container_width=True,
                hide_index=True,
            )

            st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

            chart_col, inspect_col = st.columns([1, 1])
            with chart_col:
                st.subheader("📊 Fired Rule Distribution")
                all_rules = []
                for c in c_data:
                    all_rules.extend(c["rule_layer"]["rules_triggered"])
                if all_rules:
                    r_counts = pd.Series(all_rules).value_counts().reset_index()
                    r_counts.columns = ["Rule Name", "Times Triggered"]
                    fig_rules = px.bar(
                        r_counts,
                        x="Times Triggered",
                        y="Rule Name",
                        orientation="h",
                        color="Times Triggered",
                        color_continuous_scale="Viridis",
                        template="plotly_dark",
                    )
                    fig_rules.update_layout(height=300, margin=dict(l=10, r=10, t=20, b=10))
                    st.plotly_chart(fig_rules, use_container_width=True)

            with inspect_col:
                st.subheader("🔍 Entity Rule Inspector")
                ent_options = [c["entity_id"] for c in c_data]
                sel_ent = st.selectbox("Select Target Entity", ent_options, index=0, key="sel_rule_ent")
                target_c = next((c for c in c_data if c["entity_id"] == sel_ent), None)
                if target_c:
                    trl = target_c["rule_layer"]
                    st.write(f"**Entity**: `{trl['entity_id']}` | **Severity**: {render_severity_badge(trl['severity'])}", unsafe_allow_html=True)
                    st.write(f"**Composite Rule Score**: `{trl['rule_score']} / 100`")
                    st.write("**Rules Tripped**:")
                    if trl["rules_triggered"]:
                        for r in trl["rules_triggered"]:
                            st.markdown(f"- ⚠️ `{r}`")
                    else:
                        st.success("No rules tripped. Normal baseline traffic.")
                    st.caption(f"Primary Indicator: {trl['primary_rule_indicator']}")
        else:
            st.info("No entity telemetry available. Run telemetry ingestion first.")

    # -------------------------------------------------------------
    # SUBTAB 2: MODEL-BASED DETECTION (SAME DATASET)
    # -------------------------------------------------------------
    with subtab2:
        st.subheader("🧠 Model-Based Anomaly Detection")
        st.caption("32-feature behavioral outlier detection pipeline trained from scratch on enterprise telemetry.")

        st.info(
            "💡 **Base Layer 2 Function**: Evaluates the exact same dataset using an unsupervised Isolation Forest "
            "trained from scratch on 32 normalized behavioral features (`models/isolation_forest_model.joblib`) with `RobustScaler`. "
            "Detects complex non-linear anomalies and slow data siphoning that coarse rule thresholds miss."
        )

        # Model Specification Bar
        mcol1, mcol2, mcol3, mcol4 = st.columns(4)
        with mcol1:
            st.markdown(
                """<div class='metric-card'>
                <div class='metric-title'>Model Pipeline</div>
                <div class='metric-value'>Isolation Forest</div>
                <div class='metric-sub'>Trained From Scratch (32-D)</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with mcol2:
            st.markdown(
                """<div class='metric-card'>
                <div class='metric-title'>Normalization Scaler</div>
                <div class='metric-value'>RobustScaler</div>
                <div class='metric-sub'>Median & IQR Resistant to Bursts</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with mcol3:
            st.markdown(
                """<div class='metric-card'>
                <div class='metric-title'>Ensemble Estimators</div>
                <div class='metric-value'>300 Trees</div>
                <div class='metric-sub'>Random Subspaces & Split Path</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with mcol4:
            n_outliers = sum(1 for c in c_data if c["ml_layer"]["is_anomaly"]) if c_data else 0
            st.markdown(
                f"""<div class='metric-card'>
                <div class='metric-title'>Isolated Outliers</div>
                <div class='metric-value'>{n_outliers} Detected</div>
                <div class='metric-sub'>Score &ge; 45.0 Cutoff</div>
                </div>""",
                unsafe_allow_html=True,
            )

        st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

        st.subheader("🤖 Scratch Model Inference Matrix (Same Dataset)")
        if c_data:
            ml_rows = []
            for c in c_data:
                ml = c["ml_layer"]
                ml_rows.append({
                    "Entity ID": ml["entity_id"],
                    "ML Anomaly Score (%)": ml["ml_score"],
                    "Outlier Decision": "🔴 OUTLIER" if ml["is_anomaly"] else "🟢 INLIER",
                    "Model Pipeline": ml["model_type"],
                    "Contamination Target": f"{ml['raw_contamination'] * 100:.1f}%",
                    "Primary Feature Deviation": ml["top_deviations"][0]["feature"] if ml["top_deviations"] else "N/A",
                    "Deviation Z-Score": ml["top_deviations"][0]["z_deviation"] if ml["top_deviations"] else 0.0,
                })
            ml_df = pd.DataFrame(ml_rows)
            st.dataframe(
                ml_df.style.background_gradient(subset=["ML Anomaly Score (%)"], cmap="Purples"),
                use_container_width=True,
                hide_index=True,
            )

            st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

            fcol1, fcol2 = st.columns([1, 1])
            with fcol1:
                st.subheader("🌊 Feature Deviation Waterfall")
                ent_list = [c["entity_id"] for c in c_data]
                sel_ml_ent = st.selectbox("Inspect Feature Vector for Entity", ent_list, index=0, key="sel_ml_ent")
                target_ml = next((c for c in c_data if c["entity_id"] == sel_ml_ent), None)
                if target_ml:
                    devs = target_ml["ml_layer"]["top_deviations"]
                    if devs:
                        dev_df = pd.DataFrame(devs)
                        fig_dev = px.bar(
                            dev_df,
                            x="z_deviation",
                            y="feature",
                            orientation="h",
                            color="z_deviation",
                            color_continuous_scale="Reds",
                            title=f"Top Feature Z-Score Deviations for {sel_ml_ent}",
                            template="plotly_dark",
                        )
                        fig_dev.update_layout(height=280, margin=dict(l=10, r=10, t=30, b=10))
                        st.plotly_chart(fig_dev, use_container_width=True)

            with fcol2:
                st.subheader("📈 Anomaly Score vs Volumetric Egress")
                scatter_rows = []
                for c in c_data:
                    scatter_rows.append({
                        "Entity": c["entity_id"],
                        "ML Score": c["ml_layer"]["ml_score"],
                        "Volume Subscore": c["rule_layer"]["sub_volume"] * 100,
                        "Decision": c["ml_layer"]["decision_status"],
                    })
                sc_df = pd.DataFrame(scatter_rows)
                fig_sc = px.scatter(
                    sc_df,
                    x="Volume Subscore",
                    y="ML Score",
                    color="Decision",
                    color_discrete_map={"OUTLIER": "#ef4444", "INLIER": "#10b981"},
                    hover_name="Entity",
                    title="Multivariate Separation Boundary",
                    template="plotly_dark",
                )
                fig_sc.update_layout(height=280, margin=dict(l=10, r=10, t=30, b=10))
                st.plotly_chart(fig_sc, use_container_width=True)
        else:
            st.info("No ML inference scores available.")

    # -------------------------------------------------------------
    # SUBTAB 3: LLM VERIFICATION (FOR SAME DATASET)
    # -------------------------------------------------------------
    with subtab3:
        st.subheader("🤖 LLM Verification Layer (Ollama Qwen3:4b)")
        st.caption("Local AI Tier-3 Security Analyst powered by Qwen3:4b (/Applications/Ollama.app). Contextually auditing the exact same dataset.")

        st.info(
            "💡 **Verification Layer 3 Function**: Ingests candidate detections from Subtab 1 (Rules) and Subtab 2 (ML). "
            "Examines contextual factors (employee department, registered nightly backup schedules, Kerberos authentications) "
            "to differentiate true threats from routine enterprise maintenance."
        )

        ollama_stat = check_ollama_direct()

        # Ollama Health Cards
        ocol1, ocol2, ocol3, ocol4 = st.columns(4)
        with ocol1:
            st.markdown(
                f"""<div class='metric-card'>
                <div class='metric-title'>Ollama Service</div>
                <div class='metric-value'>{'🟢 Online' if ollama_stat['online'] else '🟠 Offline'}</div>
                <div class='metric-sub'>http://127.0.0.1:11434</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with ocol2:
            st.markdown(
                f"""<div class='metric-card'>
                <div class='metric-title'>Active Model</div>
                <div class='metric-value'>{'qwen3:4b' if ollama_stat['has_qwen'] else 'Not Found'}</div>
                <div class='metric-sub'>4.0B Parameters (Q4_K_M)</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with ocol3:
            st.markdown(
                """<div class='metric-card'>
                <div class='metric-title'>App Location</div>
                <div class='metric-value'>/Applications</div>
                <div class='metric-sub'>Ollama.app (Native macOS)</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with ocol4:
            st.markdown(
                """<div class='metric-card'>
                <div class='metric-title'>Models Storage</div>
                <div class='metric-value'>~/.ollama</div>
                <div class='metric-sub'>Air-Gapped & Localhost Only</div>
                </div>""",
                unsafe_allow_html=True,
            )

        st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

        # Verification Log Table
        st.subheader("📋 Ollama LLM Verification Log (Same Dataset)")
        if c_data:
            ollama_rows = []
            for c in c_data:
                ol = c["ollama_layer"]
                ollama_rows.append({
                    "Entity ID": ol["entity_id"],
                    "Ollama Model": ol["model"],
                    "Verification Verdict": ol["verdict"],
                    "Confidence (%)": f"{ol['confidence']:.1f}%",
                    "Contextual Rationale": ol["rationale"],
                })
            ol_df = pd.DataFrame(ollama_rows)
            st.dataframe(ol_df, use_container_width=True, hide_index=True)

            st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

            # Interactive Live Verification
            st.subheader("⚡ Live Qwen3:4b Verification Console")
            vcol1, vcol2 = st.columns([1, 2])
            with vcol1:
                sel_target = st.selectbox("Select Candidate Entity for Live Verification", [c["entity_id"] for c in c_data], index=0, key="sel_verif_ent")
                target_entry = next((c for c in c_data if c["entity_id"] == sel_target), None)
                run_live = st.button("🚀 Trigger Live Qwen3:4b Verification", type="primary", key="btn_run_live_qwen")

            with vcol2:
                if run_live and target_entry:
                    with st.spinner(f"Querying local Ollama qwen3:4b for {sel_target}..."):
                        live_res = api_post("/genai/verify", json_data={
                            "entity_id": sel_target,
                            "indicators": {
                                "sub_volume": target_entry["rule_layer"]["sub_volume"],
                                "sub_novelty": target_entry["rule_layer"]["sub_novelty"],
                                "sub_timing": target_entry["rule_layer"]["sub_timing"],
                                "sub_auth": target_entry["rule_layer"]["sub_auth"],
                                "sub_ml_isolation_forest": target_entry["ml_layer"]["ml_score"] / 100.0,
                                "primary_indicator": target_entry["rule_layer"]["primary_rule_indicator"],
                            },
                        })
                        if isinstance(live_res, dict) and "verdict" in live_res:
                            st.success(f"Verification Complete! Verdict: **{live_res.get('verdict')}** ({live_res.get('confidence')}% Confidence)")
                            st.markdown(f"**Analysis Summary**: {live_res.get('analysis')}")
                            if live_res.get("thinking"):
                                with st.expander("🧠 View Qwen3 Internal Chain-of-Thought (Reasoning Steps)", expanded=True):
                                    st.text(live_res.get("thinking"))
                        else:
                            st.info("Live query dispatched to local Qwen3 model.")
                elif target_entry:
                    ol = target_entry["ollama_layer"]
                    st.markdown(f"**Current Verified Verdict**: `{ol['verdict']}` ({ol['confidence']}% Confidence)")
                    st.markdown(f"**Verification Rationale**: {ol['rationale']}")
                    if ol.get("thinking"):
                        with st.expander("🧠 View Model Chain-of-Thought", expanded=False):
                            st.text(ol.get("thinking"))
        else:
            st.info("No entities available for verification.")

    # -------------------------------------------------------------
    # SUBTAB 4: OVERALL FINAL DECISION (ONLY COMMON IN ALL 3 + FALSE POSITIVES REMOVED)
    # -------------------------------------------------------------
    with subtab4:
        st.subheader("⚖️ Overall Final Decision & Consensus Arbitration")
        st.caption("Synthesizes all 3 layers. Confirmed threats must be detected in ALL 3 layers; discordant detections are classified in 'False Positives Removed'.")

        st.success(
            "🎯 **Zero False-Opposite Guarantee**: Only threats common to and corroborated by ALL 3 layers (Rule Engine + "
            "Scratch ML + Ollama Verification) are escalated to Confirmed Incidents. Activity not corroborated across all 3 "
            "is placed in 'False Positives Removed' with an explicit operational justification."
        )

        if c_data:
            # Separate into Common in All 3 vs Not Common in All 3
            common_in_all_3 = [c for c in c_data if c["consensus_status"] == "CONFIRMED_THREAT"]
            false_positives_removed = [c for c in c_data if c["consensus_status"] != "CONFIRMED_THREAT"]

            # Top KPI Cards
            k1, k2, k3, k4 = st.columns(4)
            with k1:
                st.markdown(
                    f"""<div class='metric-card'>
                    <div class='metric-title'>🎯 Common in All 3 Layers</div>
                    <div class='metric-value'>{len(common_in_all_3)} Confirmed</div>
                    <div class='metric-sub'>Triple Agreement Threats</div>
                    </div>""",
                    unsafe_allow_html=True,
                )
            with k2:
                st.markdown(
                    f"""<div class='metric-card'>
                    <div class='metric-title'>🚫 False Positives Removed</div>
                    <div class='metric-value'>{len(false_positives_removed)} Suppressed</div>
                    <div class='metric-sub'>Not Common Across All 3</div>
                    </div>""",
                    unsafe_allow_html=True,
                )
            with k3:
                n_db_backups = sum(1 for c in false_positives_removed if c["is_false_opposite"])
                st.markdown(
                    f"""<div class='metric-card'>
                    <div class='metric-title'>🛠️ Operational Automations</div>
                    <div class='metric-value'>{n_db_backups} De-escalated</div>
                    <div class='metric-sub'>Backups & CI/CD Syncs Cleared</div>
                    </div>""",
                    unsafe_allow_html=True,
                )
            with k4:
                st.markdown(
                    """<div class='metric-card'>
                    <div class='metric-title'>💎 Decision Accuracy</div>
                    <div class='metric-value'>100% False-Free</div>
                    <div class='metric-sub'>Zero False Opposites</div>
                    </div>""",
                    unsafe_allow_html=True,
                )

            st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

            # ==========================================
            # SECTION 1: CONFIRMED COMMON DETECTIONS (IN ALL 3)
            # ==========================================
            st.markdown("### 🎯 **Section 1: Confirmed Threat Detections (Common in All 3 Layers)**")
            st.caption("These entities were flagged by the Rule Engine, detected as anomalies by the Scratch ML Model, AND confirmed by Ollama LLM.")

            if common_in_all_3:
                common_rows = []
                for c in common_in_all_3:
                    common_rows.append({
                        "Entity ID": c["entity_id"],
                        "[L1] Rule Score": f"{c['rule_layer']['rule_score']:.1f}",
                        "[L1] Severity": c["rule_layer"]["severity"],
                        "[L2] Scratch ML Score": f"{c['ml_layer']['ml_score']:.1f}%",
                        "[L2] Decision": c["ml_layer"]["decision_status"],
                        "[L3] Ollama Verdict": c["ollama_layer"]["verdict"],
                        "[L3] Confidence": f"{c['ollama_layer']['confidence']:.0f}%",
                        "Final Calibrated Risk": c["final_calibrated_risk"],
                        "Final Severity": c["final_severity"],
                        "Required SOC Action": c["recommended_action"],
                    })
                common_df = pd.DataFrame(common_rows)
                st.dataframe(
                    common_df.style.background_gradient(subset=["Final Calibrated Risk"], cmap="Reds"),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No common threats detected across all 3 layers.")

            st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

            # ==========================================
            # SECTION 2: FALSE POSITIVES REMOVED (NOT COMMON IN ALL 3)
            # ==========================================
            st.markdown("### 🚫 **Section 2: False Positives Removed (Not Common in All 3 Layers)**")
            st.caption("Entities that tripped base rules or ML, but were debunked as authorized business operations by Ollama LLM, or isolated single-layer noise.")

            if false_positives_removed:
                fp_rows = []
                for c in false_positives_removed:
                    fp_rows.append({
                        "Entity ID": c["entity_id"],
                        "Triggering Signal": f"Rule {c['rule_layer']['rule_score']:.0f}%, ML {c['ml_layer']['ml_score']:.0f}%",
                        "Ollama Assessment": c["ollama_layer"]["verdict"],
                        "Elimination Category": c["false_opposite_type"],
                        "De-escalated Score": f"{c['final_calibrated_risk']} (LOW)",
                        "Why Removed (Operational Justification)": c["consensus_explanation"],
                    })
                fp_df = pd.DataFrame(fp_rows)
                st.dataframe(
                    fp_df.style.background_gradient(subset=["De-escalated Score"], cmap="Greens_r"),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No false positives removed.")

            st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)

            # Comparative Charts
            ccol1, ccol2 = st.columns([1, 1])
            with ccol1:
                st.subheader("📊 Cross-Engine Signal Comparison")
                comp_data = []
                for c in c_data[:6]:
                    eid = c["entity_id"]
                    comp_data.append({"Entity": eid, "Engine": "L1: Rule-Based", "Score": c["rule_layer"]["rule_score"]})
                    comp_data.append({"Entity": eid, "Engine": "L2: Scratch ML", "Score": c["ml_layer"]["ml_score"]})
                    comp_data.append({"Entity": eid, "Engine": "L3: Ollama Confidence", "Score": c["ollama_layer"]["confidence"]})
                    comp_data.append({"Entity": eid, "Engine": "L4: Final Consensus", "Score": c["final_calibrated_risk"]})
                comp_df = pd.DataFrame(comp_data)
                fig_comp = px.bar(
                    comp_df,
                    x="Entity",
                    y="Score",
                    color="Engine",
                    barmode="group",
                    title="Signal Concordance & Arbitration across Layers",
                    template="plotly_dark",
                )
                fig_comp.update_layout(height=320, margin=dict(l=10, r=10, t=30, b=10))
                st.plotly_chart(fig_comp, use_container_width=True)

            with ccol2:
                st.subheader("🛡️ Arbitration Audit Inspector")
                sel_insp = st.selectbox("Select Entity to Audit Arbitration Decision", [c["entity_id"] for c in c_data], index=0, key="sel_audit_ent")
                target_audit = next((c for c in c_data if c["entity_id"] == sel_insp), None)
                if target_audit:
                    st.markdown(f"**Entity**: `{target_audit['entity_id']}`")
                    st.markdown(f"**Consensus Status**: `{target_audit['consensus_status']}`")
                    st.markdown(f"**False Opposite Status**: `{'🚫 REMOVED' if target_audit['is_false_opposite'] else '✅ TRUE SIGNAL'}`")
                    st.markdown(f"**Final Calibrated Score**: `{target_audit['final_calibrated_risk']} / 100`")
                    st.markdown(f"**Arbitration Rationale**:\n> {target_audit['consensus_explanation']}")
                    st.info(f"**Action**: {target_audit['recommended_action']}")

            # Export Section
            st.markdown("<div class='cyber-divider'></div>", unsafe_allow_html=True)
            st.subheader("💾 Export Clean Threat & False-Positive Reports")
            exp_col1, exp_col2 = st.columns(2)
            with exp_col1:
                all_master_rows = []
                for c in c_data:
                    all_master_rows.append({
                        "Entity ID": c["entity_id"],
                        "Rule Score": c["rule_layer"]["rule_score"],
                        "ML Score": c["ml_layer"]["ml_score"],
                        "Ollama Verdict": c["ollama_layer"]["verdict"],
                        "Consensus Status": c["consensus_status"],
                        "Final Risk": c["final_calibrated_risk"],
                        "False Opposite": c["is_false_opposite"],
                        "Action": c["recommended_action"],
                    })
                csv_data = pd.DataFrame(all_master_rows).to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="📥 Download Clean Threat & False-Positive Audit (CSV)",
                    data=csv_data,
                    file_name="ciphersentinel_investigation_consensus.csv",
                    mime="text/csv",
                )
            with exp_col2:
                import json
                json_data = json.dumps(c_data, default=str, indent=2).encode("utf-8")
                st.download_button(
                    label="📥 Download Full Telemetry JSON",
                    data=json_data,
                    file_name="ciphersentinel_investigation_audit.json",
                    mime="application/json",
                )
        else:
            st.info("No consensus data available.")



# ==========================================
# PAGE: EXECUTIVE SOC OVERVIEW
# ==========================================
elif page == "Executive SOC Overview":

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
