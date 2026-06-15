#!/usr/bin/env python3
"""
ML Model Training Pipeline — SDN-IPS Framework
=================================================
Trains a production-ready ML ensemble for real-time attack detection
from the dataset_final.csv collected by the traffic capture module.

Architecture:
  1. Binary Classifier (LightGBM ensemble) — normal vs attack
  2. Attack Type Classifier (LightGBM multi-class) — 6 attack types
  3. Anomaly Detector (Isolation Forest) — zero-day detection

Usage:
    python3 train_model.py --dataset ../../results/dataset_final.csv --output ../ml_models/
    python3 train_model.py --dataset ../../results/dataset_final.csv --output ../ml_models/ --tune

Dependencies:
    pip install lightgbm scikit-learn pandas numpy optuna joblib
"""

import os
import sys
import json
import time
import argparse
import warnings
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from collections import Counter

from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    accuracy_score, precision_score, recall_score, roc_auc_score
)
from sklearn.ensemble import IsolationForest, RandomForestClassifier, VotingClassifier
from sklearn.utils.class_weight import compute_sample_weight

try:
    import lightgbm as lgb
    HAS_LGBM = True
except ImportError:
    HAS_LGBM = False
    print("[WARN] LightGBM not installed. Using RandomForest only.")
    print("       Install with: pip install lightgbm")

try:
    import optuna
    HAS_OPTUNA = True
    optuna.logging.set_verbosity(optuna.logging.WARNING)
except ImportError:
    HAS_OPTUNA = False

warnings.filterwarnings('ignore', category=UserWarning)


# =============================================================================
# Configuration
# =============================================================================

# Columns to drop before training
META_COLUMNS = [
    'meta_window_id', 'meta_src_mac_oui', 'meta_device_name',
    'meta_attack_tool', 'meta_attack_intensity', 'meta_mininet_event',
    'meta_controller_load', 'meta_backlog_drops',
]

LABEL_COLUMNS = ['label', 'attack_type', 'snort_sid']

IDENTIFIER_COLUMNS = ['timestamp', 'src_ip', 'dst_ip']

# Columns that are constant-zero in the dataset (no discriminative power)
CONSTANT_ZERO_COLUMNS = [
    'is_registered_iot', 'is_gateway', 'multicast_ratio',
    'arp_gratuitous_count', 'arp_unsolicited_count',
    'mac_ip_binding_changes', 'ip_mac_binding_changes',
]

# Protocol will be one-hot encoded
CATEGORICAL_COLUMNS = ['protocol']


# =============================================================================
# Data Loading & Preprocessing
# =============================================================================

def load_and_preprocess(dataset_path):
    """Load CSV, clean, and prepare for training."""
    print(f"\n{'='*60}")
    print(f"  Loading Dataset")
    print(f"{'='*60}")

    df = pd.read_csv(dataset_path, low_memory=False)
    print(f"  Loaded: {len(df)} rows, {len(df.columns)} columns")

    # --- Drop columns ---
    drop_cols = META_COLUMNS + IDENTIFIER_COLUMNS + CONSTANT_ZERO_COLUMNS
    # Also drop snort_sid (label identification)
    drop_cols.append('snort_sid')
    existing_drop = [c for c in drop_cols if c in df.columns]
    df_clean = df.drop(columns=existing_drop, errors='ignore')
    print(f"  Dropped {len(existing_drop)} columns (meta/identifiers/constant-zero)")

    # --- Extract labels ---
    y_binary = (df_clean['label'].astype(int) > 0).astype(int)  # 0=normal, 1=attack
    y_attack_type = df_clean['attack_type'].copy()
    df_clean = df_clean.drop(columns=['label', 'attack_type'], errors='ignore')

    # --- One-hot encode protocol ---
    if 'protocol' in df_clean.columns:
        protocol_dummies = pd.get_dummies(df_clean['protocol'], prefix='proto')
        df_clean = df_clean.drop(columns=['protocol'])
        df_clean = pd.concat([df_clean, protocol_dummies], axis=1)
        print(f"  One-hot encoded 'protocol' → {list(protocol_dummies.columns)}")

    # --- Handle remaining non-numeric ---
    for col in df_clean.columns:
        if df_clean[col].dtype == object:
            try:
                df_clean[col] = pd.to_numeric(df_clean[col], errors='coerce')
            except Exception:
                print(f"  Dropping non-numeric column: {col}")
                df_clean = df_clean.drop(columns=[col])

    # --- Fill NaN/inf ---
    df_clean = df_clean.replace([np.inf, -np.inf], np.nan)
    nan_counts = df_clean.isna().sum()
    if nan_counts.sum() > 0:
        nan_cols = nan_counts[nan_counts > 0]
        print(f"  Filling {len(nan_cols)} columns with NaN values (median fill)")
        df_clean = df_clean.fillna(df_clean.median())

    # --- Report ---
    print(f"\n  Training features: {len(df_clean.columns)}")
    print(f"  Label distribution:")
    print(f"    Normal (0): {(y_binary == 0).sum()} ({100*(y_binary == 0).mean():.1f}%)")
    print(f"    Attack (1): {(y_binary == 1).sum()} ({100*(y_binary == 1).mean():.1f}%)")
    print(f"  Attack types: {dict(Counter(y_attack_type[y_binary == 1]))}")

    feature_names = list(df_clean.columns)
    X = df_clean.values.astype(np.float32)

    return X, y_binary.values, y_attack_type.values, feature_names


# =============================================================================
# Hyperparameter Tuning (Optuna)
# =============================================================================

def tune_lightgbm(X, y, n_trials=50, timeout=600):
    """Tune LightGBM hyperparameters using Optuna."""
    if not HAS_OPTUNA or not HAS_LGBM:
        print("  Skipping tuning (requires optuna + lightgbm)")
        return {}

    print(f"\n{'='*60}")
    print(f"  Hyperparameter Tuning (Optuna, {n_trials} trials, {timeout}s timeout)")
    print(f"{'='*60}")

    scale_pos_weight = (y == 0).sum() / max((y == 1).sum(), 1)

    def objective(trial):
        params = {
            'objective': 'binary',
            'metric': 'binary_logloss',
            'verbosity': -1,
            'scale_pos_weight': scale_pos_weight,
            'n_estimators': trial.suggest_int('n_estimators', 100, 1000),
            'max_depth': trial.suggest_int('max_depth', 3, 12),
            'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3, log=True),
            'num_leaves': trial.suggest_int('num_leaves', 15, 127),
            'min_child_samples': trial.suggest_int('min_child_samples', 5, 50),
            'subsample': trial.suggest_float('subsample', 0.6, 1.0),
            'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
            'reg_alpha': trial.suggest_float('reg_alpha', 1e-8, 10.0, log=True),
            'reg_lambda': trial.suggest_float('reg_lambda', 1e-8, 10.0, log=True),
        }

        model = lgb.LGBMClassifier(**params, random_state=42, n_jobs=-1)
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        scores = []
        for train_idx, val_idx in cv.split(X, y):
            model.fit(X[train_idx], y[train_idx])
            preds = model.predict(X[val_idx])
            scores.append(f1_score(y[val_idx], preds))
        return np.mean(scores)

    study = optuna.create_study(direction='maximize')
    study.optimize(objective, n_trials=n_trials, timeout=timeout)

    print(f"  Best F1: {study.best_value:.4f}")
    print(f"  Best params: {study.best_params}")
    return study.best_params


# =============================================================================
# Model Training
# =============================================================================

def train_binary_model(X, y, feature_names, best_params=None):
    """Train the binary classifier (normal vs attack)."""
    print(f"\n{'='*60}")
    print(f"  Training Binary Classifier")
    print(f"{'='*60}")

    scale_pos_weight = (y == 0).sum() / max((y == 1).sum(), 1)
    print(f"  Scale pos weight: {scale_pos_weight:.2f}")

    if HAS_LGBM:
        # LightGBM with tuned or default params
        lgbm_params = {
            'objective': 'binary',
            'metric': 'binary_logloss',
            'verbosity': -1,
            'scale_pos_weight': scale_pos_weight,
            'n_estimators': 500,
            'max_depth': 8,
            'learning_rate': 0.05,
            'num_leaves': 63,
            'min_child_samples': 20,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'reg_alpha': 0.1,
            'reg_lambda': 1.0,
            'random_state': 42,
            'n_jobs': -1,
        }
        if best_params:
            lgbm_params.update(best_params)

        lgbm_model = lgb.LGBMClassifier(**lgbm_params)
    else:
        lgbm_model = None

    # Random Forest (secondary)
    rf_model = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced_subsample',
        random_state=42,
        n_jobs=-1,
    )

    # Cross-validated evaluation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    if lgbm_model:
        # Ensemble: LightGBM (weight 3) + RF (weight 2)
        ensemble = VotingClassifier(
            estimators=[('lgbm', lgbm_model), ('rf', rf_model)],
            voting='soft',
            weights=[3, 2],
        )
        print(f"  Model: VotingClassifier(LightGBM×3 + RandomForest×2)")
    else:
        ensemble = rf_model
        print(f"  Model: RandomForestClassifier (LightGBM not available)")

    # Cross-validation predictions
    print(f"  Running 5-fold stratified cross-validation...")
    y_pred_cv = cross_val_predict(ensemble, X, y, cv=cv, method='predict')
    y_proba_cv = cross_val_predict(ensemble, X, y, cv=cv, method='predict_proba')

    # Metrics
    acc = accuracy_score(y, y_pred_cv)
    prec = precision_score(y, y_pred_cv, zero_division=0)
    rec = recall_score(y, y_pred_cv, zero_division=0)
    f1 = f1_score(y, y_pred_cv, zero_division=0)
    auc = roc_auc_score(y, y_proba_cv[:, 1])

    print(f"\n  ┌─────────────────────────────────────────┐")
    print(f"  │  Binary Classifier — Cross-Val Results  │")
    print(f"  ├─────────────────────────────────────────┤")
    print(f"  │  Accuracy  : {acc:.4f}                       │")
    print(f"  │  Precision : {prec:.4f}                       │")
    print(f"  │  Recall    : {rec:.4f}                       │")
    print(f"  │  F1 Score  : {f1:.4f}                       │")
    print(f"  │  ROC-AUC   : {auc:.4f}                       │")
    print(f"  └─────────────────────────────────────────┘")

    # Confusion matrix
    cm = confusion_matrix(y, y_pred_cv)
    print(f"\n  Confusion Matrix:")
    print(f"                 Predicted")
    print(f"                 Normal  Attack")
    print(f"  Actual Normal  {cm[0][0]:>6}  {cm[0][1]:>6}")
    print(f"  Actual Attack  {cm[1][0]:>6}  {cm[1][1]:>6}")

    # Train final model on full data
    print(f"\n  Training final model on full dataset...")
    ensemble.fit(X, y)

    # Feature importance (from LightGBM if available)
    importance = None
    if HAS_LGBM and hasattr(ensemble, 'estimators_'):
        lgbm_fitted = ensemble.named_estimators_['lgbm']
        importance = dict(zip(feature_names, lgbm_fitted.feature_importances_))
    elif hasattr(ensemble, 'feature_importances_'):
        importance = dict(zip(feature_names, ensemble.feature_importances_))

    if importance:
        top_20 = sorted(importance.items(), key=lambda x: -x[1])[:20]
        print(f"\n  Top 20 Feature Importances:")
        for i, (feat, imp) in enumerate(top_20, 1):
            bar = '█' * int(imp / max(1, top_20[0][1]) * 30)
            print(f"    {i:2d}. {feat:<35s} {imp:>6.0f}  {bar}")

    metrics = {
        'accuracy': round(acc, 4),
        'precision': round(prec, 4),
        'recall': round(rec, 4),
        'f1_score': round(f1, 4),
        'roc_auc': round(auc, 4),
        'confusion_matrix': cm.tolist(),
    }

    return ensemble, metrics, importance


def train_attack_type_model(X, y_binary, y_attack_type, feature_names):
    """Train multi-class attack type classifier (only on attack rows)."""
    print(f"\n{'='*60}")
    print(f"  Training Attack Type Classifier")
    print(f"{'='*60}")

    # Filter to attack rows only
    attack_mask = y_binary == 1
    X_attack = X[attack_mask]
    y_type = y_attack_type[attack_mask]

    # Encode attack types
    le = LabelEncoder()
    y_encoded = le.fit_transform(y_type)
    n_classes = len(le.classes_)

    print(f"  Attack rows: {len(X_attack)}")
    print(f"  Classes ({n_classes}): {list(le.classes_)}")
    print(f"  Distribution: {dict(Counter(y_type))}")

    if HAS_LGBM:
        model = lgb.LGBMClassifier(
            objective='multiclass',
            num_class=n_classes,
            n_estimators=300,
            max_depth=8,
            learning_rate=0.05,
            num_leaves=63,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
            verbosity=-1,
        )
    else:
        model = RandomForestClassifier(
            n_estimators=300,
            max_depth=10,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
        )

    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    y_pred_cv = cross_val_predict(model, X_attack, y_encoded, cv=cv)

    # Metrics
    report = classification_report(y_encoded, y_pred_cv,
                                    target_names=le.classes_,
                                    output_dict=True)
    print(f"\n  Per-class results:")
    print(f"  {'Class':<25s} {'Precision':>10s} {'Recall':>10s} {'F1':>10s} {'Support':>10s}")
    print(f"  {'-'*65}")
    for cls in le.classes_:
        r = report[cls]
        print(f"  {cls:<25s} {r['precision']:>10.3f} {r['recall']:>10.3f} "
              f"{r['f1-score']:>10.3f} {r['support']:>10.0f}")

    macro_f1 = report['macro avg']['f1-score']
    print(f"\n  Macro F1: {macro_f1:.4f}")

    # Train final model
    model.fit(X_attack, y_encoded)

    return model, le, report


def train_anomaly_detector(X, y_binary):
    """Train Isolation Forest on normal data only (for zero-day detection)."""
    print(f"\n{'='*60}")
    print(f"  Training Anomaly Detector (Isolation Forest)")
    print(f"{'='*60}")

    # Train on normal data only
    X_normal = X[y_binary == 0]
    print(f"  Training on {len(X_normal)} normal samples")

    model = IsolationForest(
        n_estimators=200,
        max_samples='auto',
        contamination=0.05,  # 5% expected anomaly rate
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_normal)

    # Evaluate on full dataset
    scores = model.decision_function(X)
    predictions = model.predict(X)  # 1=normal, -1=anomaly

    # How well does it catch attacks?
    attack_mask = y_binary == 1
    normal_mask = y_binary == 0
    attack_caught = (predictions[attack_mask] == -1).sum()
    attack_total = attack_mask.sum()
    normal_flagged = (predictions[normal_mask] == -1).sum()
    normal_total = normal_mask.sum()

    print(f"\n  Anomaly Detection Results:")
    print(f"    Attacks caught: {attack_caught}/{attack_total} "
          f"({100*attack_caught/max(attack_total,1):.1f}%)")
    print(f"    Normal flagged: {normal_flagged}/{normal_total} "
          f"({100*normal_flagged/max(normal_total,1):.1f}%)")

    return model


# =============================================================================
# Export
# =============================================================================

def save_models(output_dir, binary_model, scaler, feature_names,
                attack_type_model, label_encoder, anomaly_model,
                binary_metrics, attack_report, best_params=None):
    """Save all models and metadata to the output directory."""
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  Saving Models to {output_dir}")
    print(f"{'='*60}")

    # Models
    joblib.dump(binary_model, os.path.join(output_dir, 'binary_model.pkl'))
    joblib.dump(attack_type_model, os.path.join(output_dir, 'attack_type_model.pkl'))
    joblib.dump(anomaly_model, os.path.join(output_dir, 'isolation_forest.pkl'))
    joblib.dump(scaler, os.path.join(output_dir, 'scaler.pkl'))
    joblib.dump(label_encoder, os.path.join(output_dir, 'label_encoder.pkl'))

    # Feature columns
    with open(os.path.join(output_dir, 'feature_columns.json'), 'w') as f:
        json.dump(feature_names, f, indent=2)

    # Training report
    report = {
        'trained_at': datetime.now().isoformat(),
        'model_version': 'v1.0',
        'binary_metrics': binary_metrics,
        'attack_type_report': attack_report,
        'feature_count': len(feature_names),
        'tuning_params': best_params or {},
    }
    with open(os.path.join(output_dir, 'training_report.json'), 'w') as f:
        json.dump(report, f, indent=2, default=str)

    files = os.listdir(output_dir)
    for fname in sorted(files):
        fpath = os.path.join(output_dir, fname)
        size = os.path.getsize(fpath)
        print(f"  ✅ {fname} ({size:,} bytes)")

    print(f"\n  Total files: {len(files)}")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Train ML models for SDN-IPS attack detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--dataset', required=True,
                        help='Path to dataset_final.csv')
    parser.add_argument('--output', default='../ml_models/',
                        help='Output directory for models (default: ../ml_models/)')
    parser.add_argument('--tune', action='store_true',
                        help='Run Optuna hyperparameter tuning')
    parser.add_argument('--tune-trials', type=int, default=50,
                        help='Number of Optuna trials (default: 50)')
    parser.add_argument('--tune-timeout', type=int, default=600,
                        help='Optuna timeout in seconds (default: 600)')
    args = parser.parse_args()

    if not os.path.exists(args.dataset):
        print(f"❌ Dataset not found: {args.dataset}")
        sys.exit(1)

    start_time = time.time()

    print(f"\n{'='*60}")
    print(f"  SDN-IPS ML Training Pipeline")
    print(f"  Dataset: {args.dataset}")
    print(f"  Output:  {args.output}")
    print(f"  Tuning:  {'ON' if args.tune else 'OFF'}")
    print(f"{'='*60}")

    # Step 1: Load and preprocess
    X, y_binary, y_attack_type, feature_names = load_and_preprocess(args.dataset)

    # Step 2: Scale features
    print(f"\n  Scaling features (StandardScaler)...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Step 3: Hyperparameter tuning (optional)
    best_params = {}
    if args.tune:
        best_params = tune_lightgbm(X_scaled, y_binary,
                                     n_trials=args.tune_trials,
                                     timeout=args.tune_timeout)

    # Step 4: Train binary classifier
    binary_model, binary_metrics, importance = train_binary_model(
        X_scaled, y_binary, feature_names, best_params
    )

    # Step 5: Train attack type classifier
    attack_model, label_encoder, attack_report = train_attack_type_model(
        X_scaled, y_binary, y_attack_type, feature_names
    )

    # Step 6: Train anomaly detector
    anomaly_model = train_anomaly_detector(X_scaled, y_binary)

    # Step 7: Save everything
    save_models(
        args.output, binary_model, scaler, feature_names,
        attack_model, label_encoder, anomaly_model,
        binary_metrics, attack_report, best_params
    )

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"  Training Complete!")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Models saved to: {os.path.abspath(args.output)}")

    # Final verdict
    f1 = binary_metrics['f1_score']
    recall = binary_metrics['recall']
    if f1 >= 0.92 and recall >= 0.95:
        print(f"  ✅ PASS — F1={f1:.4f} ≥ 0.92, Recall={recall:.4f} ≥ 0.95")
    else:
        print(f"  ⚠ BELOW TARGET — F1={f1:.4f} (target ≥0.92), Recall={recall:.4f} (target ≥0.95)")
        if recall < 0.85:
            print(f"  💡 Consider supplemental data collection for minority attack classes")

    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
