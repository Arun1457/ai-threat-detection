# severity_engine.py
# AI-Driven Unified Threat Detection Platform
# Assigns severity and AI risk score to each predicted row

import numpy as np

# ─────────────────────────────────────────────
# Severity from anomaly probability score
# ─────────────────────────────────────────────
def assign_severity(prob: float) -> str:
    """
    Takes the model's anomaly probability (0.0 to 1.0)
    and returns a severity label.
    """
    if prob >= 0.80:
        return "Critical"
    elif prob >= 0.60:
        return "High"
    elif prob >= 0.40:
        return "Medium"
    elif prob >= 0.20:
        return "Low"
    else:
        return "Normal"


# ─────────────────────────────────────────────
# AI Risk Score (0–100) from row data
# ─────────────────────────────────────────────
def assign_ai_risk_score(row) -> float:
    """
    Composite risk score combining:
    - Anomaly probability
    - Severity weight
    - Traffic volume signals
    """
    score = 0.0

    # Base: anomaly probability
    prob = row.get("anomaly_prob", 0.0)
    score += prob * 50   # max 50 pts from probability

    # Severity weight
    severity = row.get("severity", "Normal")
    severity_pts = {
        "Critical": 40,
        "High":     30,
        "Medium":   15,
        "Low":       5,
        "Normal":    0,
    }
    score += severity_pts.get(severity, 0)

    # Bonus: high packet rate signals (if col exists)
    fwd_packets = row.get("Total Fwd Packets", 0)
    if fwd_packets > 10000:
        score += 10

    # Bonus: large flow bytes (potential exfiltration)
    flow_bytes = row.get("Flow Bytes/s", 0)
    if flow_bytes > 1_000_000:
        score += 10

    # Cap at 100
    return min(round(score, 1), 100.0)


# ─────────────────────────────────────────────
# Attack type label from original Label column
# ─────────────────────────────────────────────
ATTACK_CATEGORIES = {
    "BENIGN":                       "Normal",
    "DOS HULK":                     "DoS Attack",
    "DOS GOLDENEYE":                "DoS Attack",
    "DOS SLOWLORIS":                "DoS Attack",
    "DOS SLOWHTTPTEST":             "DoS Attack",
    "DDOS":                         "DDoS Attack",
    "PORTSCAN":                     "Port Scan",
    "FTP-PATATOR":                  "Brute Force",
    "SSH-PATATOR":                  "Brute Force",
    "BOT":                          "Botnet",
    "WEB ATTACK \x97 BRUTE FORCE": "Web Attack",
    "WEB ATTACK \x97 XSS":         "Web Attack",
    "WEB ATTACK \x97 SQL INJECTION":"Web Attack",
    "INFILTRATION":                 "Infiltration",
    "HEARTBLEED":                   "Heartbleed",
}

def get_attack_category(label: str) -> str:
    if not isinstance(label, str):
        return "Unknown"
    return ATTACK_CATEGORIES.get(label.strip().upper(), "Unknown Attack")
