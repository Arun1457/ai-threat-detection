# ─────────────────────────────────────────────────────────────────────────────
# REPLACE the PATHS block at the top of dashboard.py with this:
# (Find the section that starts with "# PATHS" and replace those 4 lines)
# ─────────────────────────────────────────────────────────────────────────────

import os

# Works locally AND on Streamlit Cloud
BASE_DIR   = os.environ.get(
    "THREAT_BASE_DIR",
    r"C:\study material\AI_driven threat detection system and response platform"
)
PRED_FILE  = os.path.join(BASE_DIR, "data",    "predicted_logs.csv")
MODEL_FILE = os.path.join(BASE_DIR, "models",  "threat_model.pkl")
FEAT_FILE  = os.path.join(BASE_DIR, "models",  "feature_columns.pkl")
