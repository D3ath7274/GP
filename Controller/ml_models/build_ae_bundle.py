#!/usr/bin/env python3
"""
Build ae_bundle.joblib from the trained Keras AE (.h5) + the v4 training CSV.

Reproduces EXACTLY the preprocessing in Grad_Autoencoder_4.ipynb:
  normal-only rows (label not in {1,2}) -> drop stage1 + stage2 cols ->
  one-hot 'protocol' -> drop label/attack_type -> StandardScaler.fit ->
  load .h5 weights (60-64-16-64-60, relu/relu/relu/linear) ->
  threshold = 99th percentile of validation reconstruction error (split seed 42).
Output bundle matches ae_inference.py's loader (TF-free at runtime).

Prefer the one-cell notebook export if you still have the notebook runtime — it uses
the in-memory scaler/threshold directly (perfect fidelity). Use this when you only have
the .h5 + the CSV.

Usage:
  pip install h5py scikit-learn pandas numpy joblib
  python3 build_ae_bundle.py \
      --csv  /path/to/dataset_v4_master_training.csv \
      --h5   autoencoder_tighter_bottleneck_16units.h5 \
      --out  ae_bundle.joblib
"""
import argparse
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

DROP_STAGE1 = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
               'top_dst_port', 'snort_sid', 'active_snort_alerts', 'distinct_alert_types']
DROP_STAGE2 = ['incomplete_ratio', 'packets_per_second', 'total_bytes',
               'device_pkt_rate_deviation', 'is_broadcast_dst', 'arp_reply_request_ratio',
               'device_byte_rate_deviation', 'arp_gratuitous_count', 'inter_arrival_std',
               'is_registered_iot', 'ip_mac_binding_changes', 'rst_count',
               'arp_unsolicited_count', 'well_known_port_ratio', 'burst_duration_avg',
               'broadcast_ratio', 'arp_reply_rate', 'burst_count', 'psh_count',
               'device_unique_dst_ips', 'mac_ip_binding_changes', 'device_avg_byte_rate',
               'device_age_seconds', 'network_avg_flow_duration', 'inter_arrival_max',
               'dst_port_std', 'inter_arrival_min']
LAYER_ORDER = ['dense', 'dense_1', 'dense_2', 'dense_3']
LAYER_ACTS = ['relu', 'relu', 'relu', 'linear']


def load_weights(h5path):
    import h5py
    layers = []
    with h5py.File(h5path, 'r') as f:
        for name, act in zip(LAYER_ORDER, LAYER_ACTS):
            W = f[f'model_weights/{name}/{name}/kernel'][()]
            b = f[f'model_weights/{name}/{name}/bias'][()]
            layers.append((np.asarray(W, np.float64), np.asarray(b, np.float64), act))
    return layers


def forward(x, layers):
    for W, b, act in layers:
        x = x @ W + b
        if act == 'relu':
            x = np.maximum(0.0, x)
    return x


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', required=True)
    ap.add_argument('--h5', default='autoencoder_tighter_bottleneck_16units.h5')
    ap.add_argument('--out', default='ae_bundle.joblib')
    ap.add_argument('--percentile', type=float, default=99.0)
    a = ap.parse_args()

    df = pd.read_csv(a.csv, low_memory=False)
    df = df[~df['label'].isin([1, 2])].copy()                      # normal only
    df = df.drop(columns=DROP_STAGE1 + DROP_STAGE2, errors='ignore')
    df = pd.get_dummies(df, prefix='protocol')
    x = df.drop(columns=['label', 'attack_type'], errors='ignore')
    y = df['label']

    scaler = StandardScaler()
    x_scaled = pd.DataFrame(scaler.fit_transform(x), columns=x.columns, index=x.index)
    keep = ~(x_scaled.isnull().any(axis=1) | y.isnull())
    x_scaled = x_scaled[keep]

    layers = load_weights(a.h5)
    if layers[0][0].shape[0] != x_scaled.shape[1]:
        raise SystemExit(f"FEATURE MISMATCH: model expects {layers[0][0].shape[0]} inputs "
                         f"but preprocessing produced {x_scaled.shape[1]} columns. "
                         f"Check the CSV is the v4 training file the model was trained on.")

    _, X_val = train_test_split(x_scaled.values, test_size=0.2, random_state=42)
    err = np.mean((X_val - forward(X_val, layers)) ** 2, axis=1)
    threshold = float(np.percentile(err, a.percentile))

    bundle = {
        'features': list(x.columns),
        'mean': np.asarray(scaler.mean_, np.float64),
        'scale': np.asarray(scaler.scale_, np.float64),
        'threshold': threshold,
        'layers': layers,
    }
    joblib.dump(bundle, a.out)
    print(f"Wrote {a.out}")
    print(f"  features : {len(bundle['features'])}")
    print(f"  threshold: {threshold:.6f}  (p{a.percentile:g} of val reconstruction error)")
    print(f"  layers   : {[W.shape for W, _, _ in layers]}")


if __name__ == '__main__':
    main()
