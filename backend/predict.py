# predict.py
# AI-Driven Unified Threat Detection Platform
# Step 3: Run predictions on combined_cicids.csv → predicted_logs.csv

import pandas as pd
import numpy as np
import os
import joblib
from severity_engine import assign_severity, assign_ai_risk_score, get_attack_category

# ─────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────
BASE_DIR   = r"C:\study material\AI_driven threat detection system and response platform"
DATA_FILE  = os.path.join(BASE_DIR, "data", "combined_cicids.csv")
MODEL_FILE = os.path.join(BASE_DIR, "models", "threat_model.pkl")
FEAT_FILE  = os.path.join(BASE_DIR, "models", "feature_columns.pkl")
OUT_FILE   = os.path.join(BASE_DIR, "data", "predicted_logs.csv")

# ─────────────────────────────────────────────
# 1. Load model + features
# ─────────────────────────────────────────────
print("🔧 Loading model and feature list ...")
model    = joblib.load(MODEL_FILE)
features = joblib.load(FEAT_FILE)
print(f"   Model loaded — {len(features)} features")

# ─────────────────────────────────────────────
# 2. Load data — sample 50k for dashboard speed
#    (full 2.8M would make the dashboard too slow)
# ─────────────────────────────────────────────
print("\n📂 Loading data ...")
data = pd.read_csv(DATA_FILE, low_memory=False)
print(f"   Full dataset: {data.shape[0]:,} rows")

# Stratified sample: keep attack ratio
normal  = data[data["anomaly_flag"] == 0].sample(n=30_000, random_state=42)
attacks = data[data["anomaly_flag"] == 1].sample(n=20_000, random_state=42)
data    = pd.concat([normal, attacks], ignore_index=True)
data    = data.sample(frac=1, random_state=42).reset_index(drop=True)
print(f"   Sampled: {len(data):,} rows (30k normal + 20k attacks)")

# ─────────────────────────────────────────────
# 3. Prepare features
# ─────────────────────────────────────────────
label_col = data["Label"].copy() if "Label" in data.columns else None

X = data.drop(columns=["Label", "anomaly_flag"], errors="ignore")
X = X.select_dtypes(include=[np.number])
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

# Align to trained feature columns
for col in features:
    if col not in X.columns:
        X[col] = 0
X = X[features]

# ─────────────────────────────────────────────
# 4. Predict
# ─────────────────────────────────────────────
print("\n🚀 Running predictions ...")
data["predicted_anomaly"] = model.predict(X)
data["anomaly_prob"]      = model.predict_proba(X)[:, 1]
print(f"   Anomalies detected: {data['predicted_anomaly'].sum():,}")

# ─────────────────────────────────────────────
# 5. Add severity + risk score + attack category
# ─────────────────────────────────────────────
print("🏷️  Assigning severity and risk scores ...")
data["severity"]      = data["anomaly_prob"].apply(assign_severity)
data["ai_risk_score"] = data.apply(assign_ai_risk_score, axis=1)

if label_col is not None:
    data["attack_category"] = label_col.apply(get_attack_category)
else:
    data["attack_category"] = "Unknown"

# ─────────────────────────────────────────────
# 6. Add a readable timestamp column
#    (CICIDS has no timestamps — we simulate a 7-day window)
# ─────────────────────────────────────────────
import datetime
base_time = datetime.datetime(2024, 1, 1, 8, 0, 0)
time_range = pd.date_range(start=base_time, periods=len(data), freq="3s")
data["timestamp"] = time_range

# ─────────────────────────────────────────────
# 7. Save
# ─────────────────────────────────────────────
# Keep only dashboard-relevant columns + key features
KEEP_COLS = [
    "timestamp", "Label", "attack_category",
    "predicted_anomaly", "anomaly_prob",
    "severity", "ai_risk_score",
    # Key CICIDS network features for display
    "Destination Port", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Flow Bytes/s", "Flow Packets/s",
    "Fwd Packet Length Max", "Bwd Packet Length Max",
    "anomaly_flag",
]
KEEP_COLS = [c for c in KEEP_COLS if c in data.columns]
output = data[KEEP_COLS]

output.to_csv(OUT_FILE, index=False)
print(f"\n💾 Predicted logs saved → {OUT_FILE}")
print(f"   Shape: {output.shape[0]:,} rows × {output.shape[1]} columns")

# Summary
print("\n📊 Severity breakdown:")
print(output["severity"].value_counts().to_string())
print("\n📊 Attack categories:")
print(output["attack_category"].value_counts().head(10).to_string())
print("\n✅ Done! Run dashboard.py next.")
