# train_model.py
# AI-Driven Unified Threat Detection Platform
# Step 2: Train RandomForest on combined CICIDS data

import pandas as pd
import numpy as np
import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report, confusion_matrix,
                             accuracy_score, roc_auc_score)

# ─────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────
BASE_DIR   = r"C:\study material\AI_driven threat detection system and response platform"
DATA_FILE  = os.path.join(BASE_DIR, "data", "combined_cicids.csv")
MODEL_DIR  = os.path.join(BASE_DIR, "models")
MODEL_FILE = os.path.join(MODEL_DIR, "threat_model.pkl")
FEAT_FILE  = os.path.join(MODEL_DIR, "feature_columns.pkl")

os.makedirs(MODEL_DIR, exist_ok=True)

# ─────────────────────────────────────────────
# 1. Load data
# ─────────────────────────────────────────────
print("📂 Loading combined_cicids.csv ...")
data = pd.read_csv(DATA_FILE, low_memory=False)
print(f"   Shape: {data.shape[0]:,} rows × {data.shape[1]} columns")

# ─────────────────────────────────────────────
# 2. Smart sampling — keep full dataset balanced
#    Max 200k normal + all attacks (557k) to stay fast
# ─────────────────────────────────────────────
print("\n⚖️  Balancing dataset for training speed ...")

normal   = data[data["anomaly_flag"] == 0].sample(n=200_000, random_state=42)
attacks  = data[data["anomaly_flag"] == 1]   # keep ALL attack rows ~557k

data = pd.concat([normal, attacks], ignore_index=True)
data = data.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle

print(f"   Normal rows  : {(data['anomaly_flag']==0).sum():,}")
print(f"   Attack rows  : {(data['anomaly_flag']==1).sum():,}")
print(f"   Total        : {len(data):,}")

# ─────────────────────────────────────────────
# 3. Features & target
# ─────────────────────────────────────────────
DROP = ["Label", "anomaly_flag"]
X = data.drop(columns=[c for c in DROP if c in data.columns])
y = data["anomaly_flag"]

# Keep only numeric columns
X = X.select_dtypes(include=[np.number])

# Remove any remaining inf / nan
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

print(f"\n🔢 Feature count: {X.shape[1]}")
print(f"   Features: {list(X.columns[:8])} ... (showing first 8)")

# ─────────────────────────────────────────────
# 4. Train / test split
# ─────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\n📊 Train: {len(X_train):,}  |  Test: {len(X_test):,}")

# ─────────────────────────────────────────────
# 5. Train model
# ─────────────────────────────────────────────
print("\n🚀 Training RandomForest (this takes ~5-10 min) ...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,           # cap depth → faster + prevents overfit
    min_samples_leaf=5,
    n_jobs=-1,              # use all CPU cores
    random_state=42,
    class_weight="balanced" # handles any remaining imbalance
)
model.fit(X_train, y_train)
print("✅ Training complete!")

# ─────────────────────────────────────────────
# 6. Evaluate
# ─────────────────────────────────────────────
print("\n📈 Evaluating ...")
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

acc    = accuracy_score(y_test, y_pred)
auc    = roc_auc_score(y_test, y_prob)

print(f"\n   Accuracy : {acc*100:.2f}%")
print(f"   ROC-AUC  : {auc:.4f}")
print(f"\n{classification_report(y_test, y_pred, target_names=['Normal','Attack'])}")

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
print("Confusion Matrix:")
print(f"   TN={cm[0,0]:,}  FP={cm[0,1]:,}")
print(f"   FN={cm[1,0]:,}  TP={cm[1,1]:,}")

# Top 10 important features
feat_imp = pd.Series(model.feature_importances_, index=X.columns)
top10    = feat_imp.sort_values(ascending=False).head(10)
print("\n🔑 Top 10 important features:")
for feat, score in top10.items():
    print(f"   {feat:<35} {score:.4f}")

# ─────────────────────────────────────────────
# 7. Save model + feature list
# ─────────────────────────────────────────────
joblib.dump(model, MODEL_FILE)
joblib.dump(list(X.columns), FEAT_FILE)

print(f"\n💾 Model saved    → {MODEL_FILE}")
print(f"💾 Features saved → {FEAT_FILE}")
print("\n✅ Done! Run predict.py next.")