#!/usr/bin/env python3
"""
Standalone tester for full_ml_pipeline.joblib (the friend's authoritative pipeline)
===================================================================================
The pipeline is self-contained: it does ALL preprocessing internally
(drop columns -> one-hot `protocol` -> StandardScaler -> RandomForest). So you
feed it a RAW CSV with the same 102-column schema as dataset_final.csv and it
returns predictions directly. No separate scaler, no manual feature building.

Usage:
    python test_model.py                      # tests on ../ML dataset/dataset_final.csv
    python test_model.py path/to/your_raw.csv # tests on your newly generated CSV

Requirements:
    pip install scikit-learn==1.6.1 imbalanced-learn
    (column_dropper.py must sit next to this file — it registers the custom
     ColumnDropper class so the pipeline can unpickle.)

A ground-truth `attack_type` column is optional: if present you get a full scored
report; otherwise you get the predictions + flagged rows.
"""
import os
import sys
import warnings

import joblib
import numpy as np
import pandas as pd

import column_dropper  # noqa: F401 — registers ColumnDropper into __main__ for unpickling

warnings.filterwarnings("ignore")  # silence sklearn version-mismatch noise

HERE = os.path.dirname(os.path.abspath(__file__))
PIPELINE_PATH = os.path.join(HERE, "full_ml_pipeline.joblib")
DEFAULT_DATA = os.path.join(HERE, "..", "ML dataset", "dataset_final.csv")

# Label mapping is FIXED at TRAINING time (insertion order of attack_type in
# dataset_final.csv). It was verified empirically against the pipeline's own
# predictions. Do NOT recompute this from the test CSV via pd.unique() — that is
# row-order dependent and will silently mislabel everything if the new data's
# rows are in a different order.
INT_TO_LABEL = {
    0: "normal",
    1: "ICMP Flood",
    2: "SYN Flood",
    3: "ARP Spoofing",
    4: "UDP Flood",
    5: "Port Scan",
    6: "Control Plane Saturation",
}


def main():
    data_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DATA
    if not os.path.exists(PIPELINE_PATH):
        sys.exit(f"ERROR: pipeline not found at {PIPELINE_PATH}")
    if not os.path.exists(data_path):
        sys.exit(f"ERROR: data file not found: {data_path}")

    try:
        pipe = joblib.load(PIPELINE_PATH)
    except ModuleNotFoundError as e:
        sys.exit(f"ERROR loading pipeline ({e}). Run: pip install imbalanced-learn")

    df = pd.read_csv(data_path, low_memory=False)
    print(f"Testing on: {data_path}  ({len(df):,} rows)")

    # The pipeline does its own column dropping / encoding / scaling.
    try:
        num_pred = pipe.predict(df)
    except Exception as e:
        sys.exit(
            f"ERROR during prediction: {e}\n"
            "Most likely your CSV is missing feature columns the pipeline expects. "
            "Generate it with this repo's traffic_capture.py (full 102-col schema)."
        )

    pred_name = np.array([INT_TO_LABEL.get(int(p), f"class_{p}") for p in num_pred])

    out = df.copy()
    out["predicted_class"] = pred_name
    out_path = os.path.splitext(data_path)[0] + "_predictions.csv"
    out.to_csv(out_path, index=False)
    print(f"Predictions written to: {out_path}\n")

    print("Predicted class distribution:")
    print(pd.Series(pred_name).value_counts().to_string(), "\n")

    if "attack_type" in df.columns:
        from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
        y_true = df["attack_type"].astype(str).values
        acc = accuracy_score(y_true, pred_name)
        print(f"Overall accuracy: {acc * 100:.2f}%\n")
        print(classification_report(y_true, pred_name, digits=3, zero_division=0))
        labels = sorted(set(y_true) | set(pred_name))
        cm = confusion_matrix(y_true, pred_name, labels=labels)
        print("Confusion matrix (rows=true, cols=pred):")
        print("labels:", labels)
        print(cm)
    else:
        print("No 'attack_type' column -> showing flagged (non-normal) rows only.")
        flagged = out[out["predicted_class"] != "normal"]
        print(f"{len(flagged)}/{len(out)} rows flagged as an attack.")
        print(flagged[["src_ip", "dst_ip", "protocol", "predicted_class"]].head(20).to_string()
              if "src_ip" in out.columns else flagged.head(20).to_string())


if __name__ == "__main__":
    main()
