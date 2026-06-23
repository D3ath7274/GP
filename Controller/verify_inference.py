#!/usr/bin/env python3
"""
Train/serve-skew verification for the RF inference path.

Proves that ml_inference.py reproduces the notebook's preprocessing EXACTLY, by
comparing its predictions on the raw training rows against the model's own
predictions taken from the notebook ("ground truth").

PREREQUISITES
  1. ml_models/rf_model.joblib   (from the notebook save cell)
  2. dataset_v2_master_training.csv
  3. rf_reference_predictions.csv  — produced in the notebook right after CELL 38:
         import pandas as pd
         pd.DataFrame({'pred': rf_final.predict(x_standrized_v2)}) \
           .to_csv('rf_reference_predictions.csv', index=False)
     (predictions on ALL rows, in file order — they align 1:1 with the training CSV)

USAGE (run from the Controller/ directory)
  python3 verify_inference.py \
      --model-dir ml_models \
      --data dataset_v2_master_training.csv \
      --ref  rf_reference_predictions.csv

EXIT CODE: 0 if 100% match (safe to deploy), 1 otherwise.
"""
import argparse
import sys

import pandas as pd

from ml_inference import MLInferenceEngine


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--model-dir', default='ml_models')
    ap.add_argument('--data', default='dataset_v2_master_training.csv')
    ap.add_argument('--ref', default='rf_reference_predictions.csv')
    args = ap.parse_args()

    eng = MLInferenceEngine(args.model_dir)
    if not eng.is_loaded:
        print("FAIL: engine not loaded — is ml_models/rf_model.joblib present and sklearn installed?")
        return 1

    raw = pd.read_csv(args.data, low_memory=False)
    print(f"loaded {len(raw)} rows from {args.data}")

    # our path: run every raw row through the deployed inference chain
    mine = [r[1] for r in eng.predict_batch(raw.to_dict('records'))]

    try:
        ref = pd.read_csv(args.ref)['pred'].astype(str).tolist()
    except Exception as e:
        print(f"NOTE: reference file '{args.ref}' not usable ({e}).")
        print("      Generate it in the notebook (see this file's docstring) for the real test.")
        # Fallback: at least show our own prediction distribution + that it runs.
        from collections import Counter
        print("inference prediction distribution:", dict(Counter(mine)))
        return 1

    if len(ref) != len(mine):
        print(f"FAIL: row count mismatch — inference={len(mine)} reference={len(ref)} "
              f"(reference must be predictions on ALL training rows, in file order)")
        return 1

    matches = sum(1 for a, b in zip(mine, ref) if a == b)
    pct = 100.0 * matches / len(ref)
    print(f"\nMATCH: {matches}/{len(ref)} = {pct:.2f}%")

    if matches != len(ref):
        mism = [(i, mine[i], ref[i]) for i in range(len(ref)) if mine[i] != ref[i]]
        print(f"\n{len(mism)} mismatches (first 15):")
        for i, m, r in mism[:15]:
            print(f"  row {i}: inference={m!r}  reference={r!r}")
        print("\nRESULT: FAIL ❌ — the deployed preprocessing differs from training. "
              "Check column alignment (encoded_columns / final_columns order, "
              "get_dummies, the double-drop of device_pkt_rate_deviation).")
        return 1

    print("\nRESULT: PASS ✅ — deployed inference is identical to the notebook. Safe to deploy.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
