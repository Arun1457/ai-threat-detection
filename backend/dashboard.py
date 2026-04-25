# dashboard.py
# AI-Driven Unified Threat Detection Platform
# Full SIEM + SOAR Dashboard

import os
import time
import datetime
import requests
import joblib
import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from streamlit_autorefresh import st_autorefresh
from generate_report import generate_pdf_report

import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from auth import login, logout

# ─────────────────────────────────────────────
# PAGE CONFIG — must be first Streamlit call
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="AI Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────
BASE_DIR   = os.environ.get(
    "THREAT_BASE_DIR",
    r"C:\study material\AI_driven threat detection system and response platform"
)
PRED_FILE  = os.path.join(BASE_DIR, "data",    "predicted_logs.csv")
MODEL_FILE = os.path.join(BASE_DIR, "models",  "threat_model.pkl")
FEAT_FILE  = os.path.join(BASE_DIR, "models",  "feature_columns.pkl")

# ─────────────────────────────────────────────
# THREAT INTELLIGENCE
# ─────────────────────────────────────────────
VT_API_KEY     = "YOUR_VIRUSTOTAL_API_KEY"   # replace with yours
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"        # replace with yours

def vt_check_ip(ip):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_API_KEY}, timeout=8
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0), stats.get("suspicious", 0), stats.get("harmless", 0)
    except:
        pass
    return None, None, None

def shodan_check_ip(ip):
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY}, timeout=8
        )
        if r.status_code == 200:
            d = r.json()
            return d.get("org", "N/A"), d.get("country_name", "N/A"), d.get("ports", [])
    except:
        pass
    return None, None, None

# ─────────────────────────────────────────────
# SESSION STATE INIT
# ─────────────────────────────────────────────
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "blocked_ips" not in st.session_state:
    st.session_state["blocked_ips"] = []
if "action_log" not in st.session_state:
    st.session_state["action_log"] = []

# ─────────────────────────────────────────────
# LOGIN GATE
# ─────────────────────────────────────────────
if not st.session_state["logged_in"]:
    login()
    st.stop()

# ─────────────────────────────────────────────
# AUTO REFRESH every 60 seconds
# ─────────────────────────────────────────────
st_autorefresh(interval=60_000, limit=None, key="autorefresh")

# ─────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────
@st.cache_data(ttl=60)
def load_data():
    df = pd.read_csv(PRED_FILE, low_memory=False)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df

try:
    data = load_data()
except FileNotFoundError:
    st.error(f"predicted_logs.csv not found. Run predict.py first.\nExpected: {PRED_FILE}")
    st.stop()

# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown(f"### 🛡️ AI Threat Platform")
    st.markdown(f"👤 **{st.session_state.get('user', 'User')}**")
    st.markdown("---")

    st.markdown("#### Filters")

    severity_opts = ["All"] + sorted(data["severity"].dropna().unique().tolist()) if "severity" in data.columns else ["All"]
    sel_severity  = st.selectbox("Severity", severity_opts)

    category_opts = ["All"] + sorted(data["attack_category"].dropna().unique().tolist()) if "attack_category" in data.columns else ["All"]
    sel_category  = st.selectbox("Attack Type", category_opts)

    anomaly_only  = st.checkbox("Show anomalies only", value=False)

    st.markdown("---")
    st.markdown("#### Navigation")
    page = st.radio("", ["📊 Dashboard", "🔍 Threat Intel", "⚡ SOAR Response", "📋 Log Table"])

    st.markdown("---")
    if st.button("🚪 Logout", use_container_width=True):
        logout()
        st.rerun()

    st.markdown(f"<p style='font-size:11px;color:gray'>Last refresh: {datetime.datetime.now().strftime('%H:%M:%S')}</p>", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# APPLY FILTERS
# ─────────────────────────────────────────────
filtered = data.copy()
if sel_severity != "All" and "severity" in filtered.columns:
    filtered = filtered[filtered["severity"] == sel_severity]
if sel_category != "All" and "attack_category" in filtered.columns:
    filtered = filtered[filtered["attack_category"] == sel_category]
if anomaly_only and "predicted_anomaly" in filtered.columns:
    filtered = filtered[filtered["predicted_anomaly"] == 1]

# ─────────────────────────────────────────────
# COLOUR MAP
# ─────────────────────────────────────────────
SEV_COLOR = {
    "Critical": "#E24B4A",
    "High":     "#EF9F27",
    "Medium":   "#FAC775",
    "Low":      "#639922",
    "Normal":   "#1D9E75",
}

# ══════════════════════════════════════════════
#  PAGE: DASHBOARD
# ══════════════════════════════════════════════
if page == "📊 Dashboard":

    st.markdown("## 🛡️ AI-Powered Threat Detection Dashboard")
    st.markdown(f"Showing **{len(filtered):,}** of **{len(data):,}** total records")

    # ── Blinking alert bar ──────────────────
    n_critical = (filtered["severity"] == "Critical").sum() if "severity" in filtered.columns else 0
    if n_critical > 0:
        st.markdown(f"""
        <div style='background:rgba(226,75,74,0.15);border:1px solid #E24B4A;
                    border-radius:8px;padding:10px;text-align:center;
                    color:#E24B4A;font-weight:500;margin-bottom:12px'>
            🚨 {n_critical:,} CRITICAL THREATS ACTIVE — AI MONITORING LIVE
        </div>""", unsafe_allow_html=True)

    # ── KPI cards ───────────────────────────
    k1, k2, k3, k4, k5 = st.columns(5)

    total      = len(filtered)
    n_anomaly  = int(filtered["predicted_anomaly"].sum()) if "predicted_anomaly" in filtered.columns else 0
    n_high     = int((filtered["severity"].isin(["Critical","High"])).sum()) if "severity" in filtered.columns else 0
    avg_risk   = round(filtered["ai_risk_score"].mean(), 1) if "ai_risk_score" in filtered.columns else 0
    n_types    = filtered["attack_category"].nunique() if "attack_category" in filtered.columns else 0

    k1.metric("Total Events",     f"{total:,}")
    k2.metric("Anomalies",        f"{n_anomaly:,}", delta=f"{n_anomaly/total*100:.1f}%" if total else "0%")
    k3.metric("High/Critical",    f"{n_high:,}")
    k4.metric("Avg AI Risk",      f"{avg_risk}")
    k5.metric("Attack Types",     f"{n_types}")

    st.markdown("---")

    # ── Row 1: Severity pie + Attack category bar ──
    c1, c2 = st.columns(2)

    with c1:
        st.markdown("#### Severity Distribution")
        if "severity" in filtered.columns:
            sev_counts = filtered["severity"].value_counts()
            fig = px.pie(
                values=sev_counts.values,
                names=sev_counts.index,
                hole=0.45,
                color=sev_counts.index,
                color_discrete_map=SEV_COLOR,
            )
            fig.update_traces(textposition="inside", textinfo="percent+label")
            fig.update_layout(showlegend=False, margin=dict(t=10,b=10,l=10,r=10), height=300)
            st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.markdown("#### Attack Types")
        if "attack_category" in filtered.columns:
            cat = filtered["attack_category"].value_counts().head(10)
            fig = px.bar(
                x=cat.values, y=cat.index,
                orientation="h",
                labels={"x": "Count", "y": ""},
                color=cat.values,
                color_continuous_scale="Reds",
            )
            fig.update_layout(showlegend=False, coloraxis_showscale=False,
                              margin=dict(t=10,b=10,l=10,r=10), height=300)
            st.plotly_chart(fig, use_container_width=True)

    # ── Row 2: Timeline ─────────────────────
    st.markdown("#### Anomalies Over Time")
    if "timestamp" in filtered.columns and "predicted_anomaly" in filtered.columns:
        ts = (filtered.set_index("timestamp")
                      .resample("10min")["predicted_anomaly"]
                      .sum()
                      .reset_index())
        fig = px.area(ts, x="timestamp", y="predicted_anomaly",
                      labels={"timestamp": "Time", "predicted_anomaly": "Anomalies"},
                      color_discrete_sequence=["#E24B4A"])
        fig.update_layout(margin=dict(t=10,b=10,l=10,r=10), height=250)
        st.plotly_chart(fig, use_container_width=True)

    # ── Row 3: AI Risk Score histogram ──────
    st.markdown("#### AI Risk Score Distribution")
    if "ai_risk_score" in filtered.columns:
        fig = px.histogram(filtered, x="ai_risk_score", nbins=40,
                           color_discrete_sequence=["#EF9F27"],
                           labels={"ai_risk_score": "AI Risk Score"})
        fig.update_layout(margin=dict(t=10,b=10,l=10,r=10), height=220)
        st.plotly_chart(fig, use_container_width=True)

    # ── Top destination ports ────────────────
    st.markdown("#### Top Targeted Ports")
    if "Destination Port" in filtered.columns:
        ports = filtered[filtered["predicted_anomaly"]==1]["Destination Port"].value_counts().head(10)
        fig = px.bar(x=ports.index.astype(str), y=ports.values,
                     labels={"x": "Port", "y": "Attack Count"},
                     color_discrete_sequence=["#534AB7"])
        fig.update_layout(margin=dict(t=10,b=10,l=10,r=10), height=220)
        st.plotly_chart(fig, use_container_width=True)


# ══════════════════════════════════════════════
#  PAGE: THREAT INTEL
# ══════════════════════════════════════════════
elif page == "🔍 Threat Intel":
    st.markdown("## 🔍 Threat Intelligence Center")
    st.markdown("Query VirusTotal and Shodan for real-time IP reputation.")

    col1, col2 = st.columns([2, 1])
    with col1:
        lookup_ip = st.text_input("Enter IP address to investigate", placeholder="e.g. 8.8.8.8")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        run_ti = st.button("🚀 Run Lookup", use_container_width=True)

    if run_ti and lookup_ip:
        c1, c2 = st.columns(2)

        with c1:
            st.markdown("#### 🦠 VirusTotal")
            with st.spinner("Querying VirusTotal ..."):
                mal, sus, har = vt_check_ip(lookup_ip)
            if mal is not None:
                st.metric("Malicious",  mal)
                st.metric("Suspicious", sus)
                st.metric("Harmless",   har)
                total_flags = (mal or 0) + (sus or 0)
                if total_flags >= 5:
                    st.error("🔴 HIGH RISK IP")
                elif total_flags >= 1:
                    st.warning("🟡 Suspicious IP")
                else:
                    st.success("🟢 Clean IP")
            else:
                st.warning("VT lookup failed — check API key or rate limit")

        with c2:
            st.markdown("#### 📡 Shodan")
            with st.spinner("Querying Shodan ..."):
                org, country, ports = shodan_check_ip(lookup_ip)
            if org is not None:
                st.write(f"**Org:** {org}")
                st.write(f"**Country:** {country}")
                st.write(f"**Open Ports:** {ports}")
                risky = [p for p in (ports or []) if p in [21,22,23,3389,445,3306,6379,27017]]
                if risky:
                    st.error(f"⚠️ Risky ports open: {risky}")
                else:
                    st.success("No high-risk ports detected")
            else:
                st.warning("Shodan lookup failed — check API key")

    st.markdown("---")
    st.markdown("#### 🤖 Auto-flagged IPs from predictions")
    st.info("In a real deployment these would be extracted from network flow source IPs. CICIDS dataset uses anonymised IPs — use the manual lookup above with real IPs from your network.")


# ══════════════════════════════════════════════
#  PAGE: SOAR RESPONSE
# ══════════════════════════════════════════════
elif page == "⚡ SOAR Response":
    st.markdown("## ⚡ SOAR — Automated Response Engine")

    if "predicted_anomaly" not in filtered.columns:
        st.warning("No prediction data available.")
        st.stop()

    threats = filtered[filtered["predicted_anomaly"] == 1].copy()

    if threats.empty:
        st.success("✅ No active threats in current filter.")
    else:
        st.markdown(f"**{len(threats):,} threats detected** — AI is recommending actions:")
        st.markdown("---")

        # Auto-response rules
        auto_blocked = threats[threats["ai_risk_score"] >= 80] if "ai_risk_score" in threats.columns else pd.DataFrame()
        investigating = threats[(threats["ai_risk_score"] >= 50) & (threats["ai_risk_score"] < 80)] if "ai_risk_score" in threats.columns else pd.DataFrame()
        monitoring    = threats[threats["ai_risk_score"] < 50] if "ai_risk_score" in threats.columns else pd.DataFrame()

        r1, r2, r3 = st.columns(3)
        r1.metric("🚫 Auto-Blocked",  len(auto_blocked))
        r2.metric("🔍 Investigating", len(investigating))
        r3.metric("👁️ Monitoring",    len(monitoring))

        st.markdown("---")

        # Show top 10 threats with action buttons
        st.markdown("#### Top Threats — Manual Actions")
        top_threats = threats.sort_values("ai_risk_score", ascending=False).head(10)

        for i, (idx, row) in enumerate(top_threats.iterrows()):
            sev   = row.get("severity", "Unknown")
            risk  = row.get("ai_risk_score", 0)
            cat   = row.get("attack_category", "Unknown")
            port  = row.get("Destination Port", "N/A")
            prob  = row.get("anomaly_prob", 0)
            color = SEV_COLOR.get(sev, "#888")

            with st.expander(f"[{sev}] {cat} — Risk Score: {risk:.0f}  |  Port: {port}", expanded=(i==0)):
                d1, d2, d3 = st.columns(3)
                d1.metric("Severity",     sev)
                d2.metric("AI Risk",      f"{risk:.0f}/100")
                d3.metric("Anomaly Prob", f"{prob:.2%}")

                # Recommended action
                if risk >= 80:
                    st.error(f"🚫 RECOMMENDED: Auto-block | Isolate source")
                elif risk >= 50:
                    st.warning(f"🔍 RECOMMENDED: Investigate | Alert SOC team")
                else:
                    st.info(f"👁️ RECOMMENDED: Monitor | Log for review")

                b1, b2, b3 = st.columns(3)
                if b1.button("🚫 Block", key=f"block_{i}"):
                    st.session_state["blocked_ips"].append(f"Flow_{idx}")
                    st.session_state["action_log"].append({
                        "time": datetime.datetime.now().strftime("%H:%M:%S"),
                        "action": "BLOCKED",
                        "target": f"Flow_{idx}",
                        "category": cat,
                    })
                    st.success(f"✅ Flow_{idx} blocked!")

                if b2.button("🔍 Investigate", key=f"inv_{i}"):
                    st.session_state["action_log"].append({
                        "time": datetime.datetime.now().strftime("%H:%M:%S"),
                        "action": "INVESTIGATING",
                        "target": f"Flow_{idx}",
                        "category": cat,
                    })
                    st.warning(f"🔍 Investigation started for Flow_{idx}")

                if b3.button("✅ Dismiss", key=f"dis_{i}"):
                    st.session_state["action_log"].append({
                        "time": datetime.datetime.now().strftime("%H:%M:%S"),
                        "action": "DISMISSED",
                        "target": f"Flow_{idx}",
                        "category": cat,
                    })
                    st.info("Dismissed.")

        # Action log
        if st.session_state["action_log"]:
            st.markdown("---")
            st.markdown("#### 📋 Action Log (this session)")
            log_df = pd.DataFrame(st.session_state["action_log"])
            st.dataframe(log_df, use_container_width=True)

            # Download action log
            st.download_button(
                "⬇️ Download Action Log",
                data=log_df.to_csv(index=False).encode(),
                file_name="soar_action_log.csv",
                mime="text/csv",
            )


# ══════════════════════════════════════════════
#  PAGE: LOG TABLE
# ══════════════════════════════════════════════
elif page == "📋 Log Table":
    st.markdown("## 📋 Predicted Log Table")
    st.markdown(f"Showing **{min(500, len(filtered)):,}** of **{len(filtered):,}** filtered records")

    # Colour rows by severity
    def highlight_row(row):
        colors = {
            "Critical": "background-color:#7a1f1f;color:white",
            "High":     "background-color:#7a4f0a;color:white",
            "Medium":   "background-color:#7a6e0a;color:black",
            "Low":      "background-color:#1a4a1a;color:white",
            "Normal":   "",
        }
        sev = row.get("severity", "Normal")
        c   = colors.get(sev, "")
        return [c] * len(row)

    display_cols = [c for c in [
        "timestamp", "attack_category", "severity", "ai_risk_score",
        "anomaly_prob", "predicted_anomaly",
        "Destination Port", "Flow Duration",
        "Total Fwd Packets", "Total Backward Packets",
        "Flow Bytes/s",
    ] if c in filtered.columns]

    st.dataframe(
        filtered[display_cols].head(500).style.apply(highlight_row, axis=1),
        use_container_width=True,
        height=500,
    )

    # Download
    st.download_button(
        "⬇️ Download Filtered Logs (CSV)",
        data=filtered[display_cols].to_csv(index=False).encode(),
        file_name="filtered_threat_logs.csv",
        mime="text/csv",
    )

# ─────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────
st.markdown("---")
st.markdown("---")
st.markdown("#### 📄 Generate Threat Report")

col_r1, col_r2 = st.columns([2, 1])
with col_r1:
    st.write("Export a full PDF report with KPIs, severity breakdown, attack analysis and SOAR summary.")
with col_r2:
    if st.button("📥 Generate PDF Report", use_container_width=True):
        with st.spinner("Generating PDF report ..."):
            try:
                report_path = generate_pdf_report(data=filtered)
                # Read the file and offer download
                with open(report_path, "rb") as f:
                    pdf_bytes = f.read()
                st.download_button(
                    label="⬇️ Download Report PDF",
                    data=pdf_bytes,
                    file_name=f"threat_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
                st.success(f"✅ Report ready!")
            except Exception as e:
                st.error(f"Report generation failed: {e}")
st.markdown(
    "<p style='text-align:center;font-size:12px;color:gray'>"
    "AI-Driven Unified Threat Detection & Response Platform · "
    "Konkan Gyanpeeth College of Engineering · 2024-25"
    "</p>",
    unsafe_allow_html=True,
)
