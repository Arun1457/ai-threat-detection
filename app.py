# app.py  ← Streamlit Cloud entry point
import os, sys
import numpy as np
import pandas as pd
import streamlit as st

# ─────────────────────────────────────────────
# PATH SETUP
# ─────────────────────────────────────────────
ROOT     = os.path.dirname(os.path.abspath(__file__))
BACKEND  = os.path.join(ROOT, "backend")
DATA_DIR = os.path.join(ROOT, "data")
MDL_DIR  = os.path.join(ROOT, "models")
RPT_DIR  = os.path.join(ROOT, "reports")

for d in [DATA_DIR, MDL_DIR, RPT_DIR]:
    os.makedirs(d, exist_ok=True)

sys.path.insert(0, BACKEND)

PRED_FILE = os.path.join(DATA_DIR, "predicted_logs.csv")
os.environ["THREAT_BASE_DIR"] = ROOT

# ─────────────────────────────────────────────
# DEMO DATA GENERATOR
# ─────────────────────────────────────────────
def generate_demo_data():
    st.info("⚙️ First-time setup: generating demo data...")

    np.random.seed(42)
    n = 50_000

    attack_cats = ["DoS Attack", "DDoS Attack", "Port Scan",
                   "Brute Force", "Botnet", "Web Attack",
                   "Infiltration", "Normal"]

    # Normalise weights so they always sum to exactly 1.0
    weights = np.array([0.18, 0.09, 0.11, 0.02, 0.01, 0.01, 0.00, 0.58], dtype=float)
    weights = weights / weights.sum()

    categories = np.random.choice(attack_cats, size=n, p=weights)
    is_attack  = (categories != "Normal").astype(int)

    base_prob = np.where(
        is_attack == 1,
        np.random.uniform(0.7, 1.0, n),
        np.random.uniform(0.0, 0.2, n)
    )

    def sev(p):
        if p >= 0.80: return "Critical"
        if p >= 0.60: return "High"
        if p >= 0.40: return "Medium"
        if p >= 0.20: return "Low"
        return "Normal"

    severities  = [sev(p) for p in base_prob]
    risk_scores = np.clip(base_prob * 90 + is_attack * 10 + np.random.uniform(-5, 5, n), 0, 100).round(1)
    timestamps  = pd.date_range("2024-01-01 08:00", periods=n, freq="3s")
    port_pool   = [80, 443, 22, 21, 3389, 8080, 53, 25, 1433, 3306, 16113, 65534, 458, 1032, 9999]
    ports       = np.random.choice(port_pool, size=n)

    df = pd.DataFrame({
        "timestamp":              timestamps,
        "Label":                  categories,
        "attack_category":        categories,
        "predicted_anomaly":      is_attack,
        "anomaly_prob":           base_prob.round(6),
        "anomaly_flag":           is_attack,
        "severity":               severities,
        "ai_risk_score":          risk_scores,
        "Destination Port":       ports,
        "Flow Duration":          np.random.randint(0, 120_000_000, n),
        "Total Fwd Packets":      np.random.randint(1, 50_000, n),
        "Total Backward Packets": np.random.randint(0, 30_000, n),
        "Flow Bytes/s":           np.random.uniform(0, 2_000_000, n).round(2),
        "Flow Packets/s":         np.random.uniform(0, 10_000, n).round(2),
        "Fwd Packet Length Max":  np.random.randint(0, 65535, n),
        "Bwd Packet Length Max":  np.random.randint(0, 65535, n),
    })

    df.to_csv(PRED_FILE, index=False)
    st.success(f"✅ Demo data ready — {n:,} records generated.")

# ─────────────────────────────────────────────
# GENERATE DEMO DATA IF NEEDED THEN RUN DASHBOARD
# ─────────────────────────────────────────────
if not os.path.exists(PRED_FILE):
    generate_demo_data()

import importlib.util
dash_path = os.path.join(BACKEND, "dashboard.py")
spec      = importlib.util.spec_from_file_location("dashboard", dash_path)
dash_mod  = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dash_mod)
