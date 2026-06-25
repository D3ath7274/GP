"""
SDN IPS — Autoencoder Inference Engine (Tier 4, anomaly / zero-day)
===================================================================
Runs the Keras autoencoder from `Untitled5.ipynb` as a **pure-NumPy** forward pass.
No TensorFlow AND no scikit-learn are needed at runtime — standardization uses
plain mean/scale arrays — so this tier is t530-friendly (the RF still needs sklearn).

Trained on NORMAL traffic only; a window that reconstructs badly (high MSE) is flagged
as an anomaly, including attacks no other tier was trained on.

Loads ONE artifact: ml_models/ae_bundle.joblib
    {
      'features':  [final feature column names, in training order]  (60),
      'mean':      np.ndarray  (per-feature mean, from the training StandardScaler),
      'scale':     np.ndarray  (per-feature std; zeros replaced by 1),
      'threshold': float       (p95 of normal reconstruction error, 0.0375),
      'layers':    [(W, b, act), ...]  act in {'relu','linear'}  (60-64-32-64-60),
    }
This bundle was rebuilt from anomaly_detection_autoencoder_model.keras + the training
CSV and validated: p95 reconstruction error reproduced the notebook's 0.0375.

If the bundle is missing or deps are unavailable, the engine disables itself
gracefully (is_loaded=False) and the controller simply runs RF-only.

Interface (mirrors MLInferenceEngine):
    eng = AEInferenceEngine(model_dir, logger=...)
    eng.is_loaded
    eng.score(flow_dict)  -> (is_anomaly: bool, confidence: float, error: float)
    eng.get_stats()

Confidence: conf = error / (error + threshold)  -> 0.5 at the threshold, ->1 as error
grows, ->0 for well-reconstructed (normal) windows. So normal traffic (error < threshold)
stays below 0.5 and is silent under the project bands (silent <0.60, flag 0.60-0.73,
block >=0.73).
"""

import os

try:
    import numpy as np
    import joblib
    import pandas as pd
    _AE_DEPS_OK = True
    _AE_DEPS_ERR = None
except ImportError as _e:  # pragma: no cover
    _AE_DEPS_OK = False
    _AE_DEPS_ERR = _e

AE_BUNDLE_FILENAME = "ae_bundle.joblib"


class AEInferenceEngine:
    """Pure-NumPy autoencoder scorer. Disables gracefully if artifacts are absent."""

    def __init__(self, model_dir, logger=None):
        self._logger = logger
        self.is_loaded = False
        self._features = None
        self._mean = None
        self._scale = None
        self._threshold = None
        self._layers = None          # list of (W, b, activation)
        self._total = 0
        self._anomalies = 0
        self._load(model_dir)

    def _log(self, level, msg, *args):
        if self._logger:
            getattr(self._logger, level)(msg, *args)
        else:
            print(f"[{level.upper()}] {msg % args if args else msg}")

    def _load(self, model_dir):
        if not _AE_DEPS_OK:
            self._log('warning', "AE deps missing (%s) — AE tier disabled.", _AE_DEPS_ERR)
            return
        path = os.path.join(model_dir, AE_BUNDLE_FILENAME)
        if not os.path.exists(path):
            self._log('info',
                      "No AE bundle at %s — AE (Tier 4) disabled; RF still active.", path)
            return
        try:
            b = joblib.load(path)
            self._features = list(b['features'])
            self._mean = np.asarray(b['mean'], dtype=np.float64)
            self._scale = np.asarray(b['scale'], dtype=np.float64)
            self._scale[self._scale == 0] = 1.0
            self._threshold = float(b['threshold'])
            self._layers = [(np.asarray(W, dtype=np.float64),
                             np.asarray(bias, dtype=np.float64),
                             str(act)) for (W, bias, act) in b['layers']]
            self.is_loaded = True
            self._log('info',
                      "AE engine loaded %s (%d features, threshold=%.5f, %d layers)",
                      path, len(self._features), self._threshold, len(self._layers))
        except Exception as e:
            self._log('error', "Failed to load AE bundle %s: %s", path, e)

    def _vectorize(self, flow_dict):
        # Same end-state as the notebook: one-hot protocol, then keep exactly the
        # trained feature columns (reindex drops everything else, fills missing=0),
        # then standardize with the stored mean/scale.
        df = pd.DataFrame([flow_dict])
        df = pd.get_dummies(df, prefix='protocol')
        df = df.reindex(columns=self._features, fill_value=0)
        x = df.apply(pd.to_numeric, errors='coerce').fillna(0.0).astype(np.float64).values
        return (x - self._mean) / self._scale          # (1, n)

    def _forward(self, x):
        for (W, b, act) in self._layers:
            x = x @ W + b
            if act == 'relu':
                x = np.maximum(0.0, x)
            # 'linear' / anything else: identity
        return x

    def score(self, flow_dict):
        """Return (is_anomaly, confidence, error). Exception-safe -> (False, 0.0, 0.0)."""
        if not self.is_loaded:
            return False, 0.0, 0.0
        try:
            x = self._vectorize(flow_dict)
            recon = self._forward(x)
            error = float(np.mean((x - recon) ** 2))
            denom = error + self._threshold
            conf = (error / denom) if denom > 0 else 0.0
            is_anom = error > self._threshold
            self._total += 1
            if is_anom:
                self._anomalies += 1
            return bool(is_anom), float(conf), error
        except Exception as e:
            self._log('error', "AE score error: %s", e)
            return False, 0.0, 0.0

    def get_stats(self):
        return {
            'is_loaded': self.is_loaded,
            'threshold': self._threshold,
            'total_scored': self._total,
            'anomalies_flagged': self._anomalies,
        }
