# preprocess.py
# AI-Driven Unified Threat Detection Platform
# Step 1: Load, clean and merge all CICIDS CSV files

import pandas as pd
import numpy as np
import os
import glob

# ─────────────────────────────────────────────
# PATHS — edit only this block if needed
# ─────────────────────────────────────────────
BASE_DIR  = r"C:\study material\AI_driven threat detection system and response platform"
DATA_DIR  = os.path.join(BASE_DIR, "data")
OUT_FILE  = os.path.join(DATA_DIR, "combined_cicids.csv")

# ─────────────────────────────────────────────
# 1. Load all CSVs from data/
# ─────────────────────────────────────────────
csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))

if not csv_files:
    raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")

print(f"Found {len(csv_files)} CSV file(s):")
for f in csv_files:
    print(f"  → {os.path.basename(f)}")

frames = []
for f in csv_files:
    try:
        df = pd.read_csv(f, encoding="utf-8", low_memory=False)
        df.columns = df.columns.str.strip()          # remove leading/trailing spaces
        df["source_file"] = os.path.basename(f)      # track which file each row came from
        frames.append(df)
        print(f"  ✅ {os.path.basename(f)}: {df.shape[0]:,} rows, {df.shape[1]} cols")
    except Exception as e:
        print(f"  ⚠️  Skipped {os.path.basename(f)}: {e}")

data = pd.concat(frames, ignore_index=True)
print(f"\n📦 Combined: {data.shape[0]:,} rows × {data.shape[1]} columns")

# ─────────────────────────────────────────────
# 2. Standardise the Label column → anomaly_flag
# ─────────────────────────────────────────────
if "Label" not in data.columns:
    raise ValueError("No 'Label' column found. Check your CICIDS CSV files.")

print(f"\n🏷️  Unique labels found:\n{data['Label'].value_counts().to_string()}")

# BENIGN = 0, everything else = 1
data["anomaly_flag"] = (data["Label"].str.strip().str.upper() != "BENIGN").astype(int)
print(f"\n  Normal (0): {(data['anomaly_flag']==0).sum():,}")
print(f"  Anomaly (1): {(data['anomaly_flag']==1).sum():,}")

# ─────────────────────────────────────────────
# 3. Clean
# ─────────────────────────────────────────────
print("\n🧹 Cleaning data...")

# Drop rows where all feature columns are NaN
data.dropna(how="all", inplace=True)

# Replace inf values with NaN then fill
data.replace([np.inf, -np.inf], np.nan, inplace=True)

# Drop columns that are >60% NaN
threshold = 0.6
before = data.shape[1]
data.dropna(thresh=int(threshold * len(data)), axis=1, inplace=True)
print(f"  Dropped {before - data.shape[1]} columns with >{int(threshold*100)}% missing values")

# Fill remaining NaNs with column median (numeric) or 'Unknown' (object)
for col in data.columns:
    if data[col].dtype in [np.float64, np.int64, np.float32, np.int32]:
        data[col].fillna(data[col].median(), inplace=True)
    else:
        data[col].fillna("Unknown", inplace=True)

print(f"  Remaining nulls: {data.isnull().sum().sum()}")

# ─────────────────────────────────────────────
# 4. Drop non-numeric / identifier columns
#    (keep Label as string for reference, drop source_file)
# ─────────────────────────────────────────────
DROP_COLS = ["source_file"]   # Label kept for reference
data.drop(columns=[c for c in DROP_COLS if c in data.columns], inplace=True)

# ─────────────────────────────────────────────
# 5. Save
# ─────────────────────────────────────────────
data.to_csv(OUT_FILE, index=False)
print(f"\n💾 Saved cleaned data → {OUT_FILE}")
print(f"   Final shape: {data.shape[0]:,} rows × {data.shape[1]} columns")
print("\n✅ Preprocessing complete! Run train_model.py next.")