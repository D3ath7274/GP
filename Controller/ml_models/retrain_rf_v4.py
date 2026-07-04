#!/usr/bin/env python3
"""
Retrain the Random Forest (Tier 3) on the current v4 dataset while preserving the
EXACT feature schema the controller already expects, so the output is a drop-in
replacement for rf_pipeline.joblib.

Why this exists: the deployed RF was trained on the older v2 data. Chapter 5 showed
that when it is scored on the larger v4 collection its recall on the minority
flood/scan/spoof classes has fallen (dataset drift) — the model is under-confident on
real attacks. Retraining on v4 with the same schema restores high-confidence detection
across all classes without changing anything the controller has to load.

What it does (and does NOT re-derive):
  * Inherits drop_initial, the 86 one-hot columns, the 66 selected columns, and the RF
    hyperparameters straight from the existing rf_pipeline.joblib — so the 66-feature
    contract and the pipeline structure are identical.
  * Re-fits ONLY the StandardScaler (on the v4 train split) and re-fits the RF on v4.
  * Wraps them back into the same [RFPreprocessor -> RandomForestClassifier] pipeline
    and pickles it against ml_inference.RFPreprocessor (which the controller imports),
    so it loads with no __main__ hacks.

IMPORTANT: run this on the TRAINING machine with **scikit-learn 1.6.1** (the version the
controller runs). A model pickled by a newer sklearn may fail to load on 1.6.1.

Usage:
  cd Controller/ml_models
  python3 retrain_rf_v4.py \
      --csv "../../ML dataset/dataset_v4_master_training.csv" \
      --old rf_pipeline.joblib \
      --out rf_pipeline_v4.joblib          # then verify the report, then:
  # cp rf_pipeline.joblib rf_pipeline.v2.bak && mv rf_pipeline_v4.joblib rf_pipeline.joblib
  # scp rf_pipeline.joblib  <t530>:~/GP/Controller/ml_models/   ; restart the controller

Add --smote to oversample the minority classes with SMOTE (on top of class_weight),
which can push minority recall higher still at some cost in precision.
"""
import argparse
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

HERE = os.path.dirname(os.path.abspath(__file__))
CTRL = os.path.dirname(HERE)                       # .../Controller
sys.path.insert(0, CTRL)
import ml_inference                                # defines/loads ml_inference.RFPreprocessor
RFPreprocessor = ml_inference.RFPreprocessor


def build_encoded(df, drop_initial, encoded_columns):
    """Replicate RFPreprocessor.transform up to (but not including) the scaler:
    drop id/meta/target cols -> one-hot protocol -> reindex to the 86 encoded cols."""
    drop = [c for c in drop_initial if c in df.columns]
    drop += [c for c in df.columns if str(c).startswith('meta_')]
    d = df.drop(columns=drop, errors='ignore')
    d = pd.get_dummies(d, prefix='protocol')
    d = d.reindex(columns=encoded_columns, fill_value=0)
    d = d.apply(pd.to_numeric, errors='coerce').fillna(0.0)
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', required=True, help='v4 training CSV (has attack_type + protocol)')
    ap.add_argument('--old', default=os.path.join(HERE, 'rf_pipeline.joblib'),
                    help='deployed pipeline to inherit the schema + hyperparameters from')
    ap.add_argument('--out', default=os.path.join(HERE, 'rf_pipeline_v4.joblib'))
    ap.add_argument('--test-size', type=float, default=0.2)
    ap.add_argument('--smote', action='store_true', help='SMOTE-oversample minority classes')
    a = ap.parse_args()

    # --- inherit the exact schema + hyperparameters from the deployed pipeline ---
    old = joblib.load(a.old)
    pre_old = old.steps[0][1]
    drop_initial = list(pre_old.drop_initial)
    encoded_columns = list(pre_old.encoded_columns)
    final_columns = list(pre_old.final_columns)
    rf = clone(old.steps[1][1])          # unfitted RF with identical hyperparameters
    rf.set_params(n_jobs=1)              # never spawn a multiprocessing pool (eventlet-safe)
    print(f"Inherited: {len(encoded_columns)} encoded cols -> {len(final_columns)} selected; "
          f"RF={rf.get_params()['n_estimators']} trees, max_depth={rf.get_params()['max_depth']}, "
          f"min_samples_leaf={rf.get_params()['min_samples_leaf']}, "
          f"class_weight={rf.get_params()['class_weight']}")

    # --- load v4, split on RAW rows (stratified), then preprocess each side ---
    df = pd.read_csv(a.csv, low_memory=False)
    if 'attack_type' not in df.columns:
        raise SystemExit("CSV has no 'attack_type' column — is this the v4 training file?")
    y = df['attack_type'].astype(str)
    enc = build_encoded(df, drop_initial, encoded_columns)
    Xtr_enc, Xte_enc, ytr, yte = train_test_split(
        enc, y, test_size=a.test_size, stratify=y, random_state=42)

    # re-fit the scaler on the TRAIN split only (no leakage), then select the 66 cols
    scaler = StandardScaler().fit(Xtr_enc.values)
    Xtr = pd.DataFrame(scaler.transform(Xtr_enc.values), columns=encoded_columns)[final_columns]
    Xte = pd.DataFrame(scaler.transform(Xte_enc.values), columns=encoded_columns)[final_columns]

    if a.smote:
        from imblearn.over_sampling import SMOTE
        n_min = ytr.value_counts().min()
        Xtr, ytr = SMOTE(random_state=42, k_neighbors=min(5, max(1, n_min - 1))).fit_resample(Xtr, ytr)
        print(f"SMOTE -> {Xtr.shape[0]} training rows")

    print("Training Random Forest on v4 ...")
    rf.fit(Xtr, ytr)

    yp = rf.predict(Xte)
    print("\n=== Held-out report (v4, %d%% split, seed 42) ===" % int(a.test_size * 100))
    print(classification_report(yte, yp, digits=4))
    print("macro-F1 = %.4f  |  weighted-F1 = %.4f"
          % (f1_score(yte, yp, average='macro'), f1_score(yte, yp, average='weighted')))

    # --- reassemble the identical pipeline and save ---
    pre = RFPreprocessor(drop_initial=drop_initial, encoded_columns=encoded_columns,
                         final_columns=final_columns, scaler=scaler)
    pipe = Pipeline([('prep', pre), ('rf', rf)])
    pipe.classes_ = rf.classes_
    joblib.dump(pipe, a.out)
    import sklearn
    print(f"\nSaved {a.out}  (scikit-learn {sklearn.__version__} — deploy target is 1.6.1)")
    print("Verify the report above, then swap it in for rf_pipeline.joblib and restart the controller.")


if __name__ == '__main__':
    main()
