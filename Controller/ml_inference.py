"""
SDN IPS — ML Inference Engine (pipeline-based)
==============================================
Runtime inference module loaded by Controller.py.

This engine wraps the friend's authoritative end-to-end pipeline
(`full_ml_pipeline.joblib`):

    ColumnDropper -> ColumnTransformer(OneHotEncoder[protocol] + StandardScaler)
                  -> SMOTE (train-only, inert at predict) -> RandomForestClassifier

Because the pipeline is self-contained, this engine just hands it the raw per-flow
row dict (the same 102-column schema traffic_capture.py produces) and maps the
numeric output back to an attack-type name. No manual feature building, no
separate scaler — all preprocessing lives inside the pipeline.

Interface is unchanged from the previous engine so Controller.py / traffic_capture
need no edits:
    engine = MLInferenceEngine(model_dir, logger=...)
    engine.is_loaded                       -> bool
    engine.predict(flow_dict)              -> (label, attack_type, confidence)
    engine.predict_batch([flow_dict, ...]) -> [(label, attack_type, confidence), ...]
    engine.get_stats()                     -> dict

Deployment: place `full_ml_pipeline.joblib` inside the directory passed as
`model_dir` (Controller.py uses <Controller>/ml_models/).

Runtime dependencies on the controller / t530:
    scikit-learn==1.6.1, imbalanced-learn, pandas, numpy, joblib
(imbalanced-learn is needed only to unpickle the bundled SMOTE step.)

All public methods are exception-safe: on any error they return safe defaults
rather than raising, so the controller never crashes due to ML issues.
"""

import os
import time

# All heavy ML deps are optional at import time. On a minimal Controller VM used
# only for dataset collection (ML mode OFF), scikit-learn / pandas / imblearn may
# not be installed. Controller.py imports MLInferenceEngine unconditionally, so
# this module must NEVER fail to import — if deps are missing we just disable
# inference (is_loaded stays False) and the controller runs normally.
try:
    import numpy as np
    import joblib
    import pandas as pd
    from sklearn.base import BaseEstimator, TransformerMixin
    _ML_DEPS_OK = True
    _ML_DEPS_ERR = None
except ImportError as _e:  # pragma: no cover
    _ML_DEPS_OK = False
    _ML_DEPS_ERR = _e
    np = None


# ---------------------------------------------------------------------------
# Custom transformer needed to unpickle full_ml_pipeline.joblib.
# It was pickled from the training notebook's __main__, so pickle resolves it as
# __main__.ColumnDropper. Defining it here and registering it into __main__ makes
# the pipeline loadable inside the controller without any external file.
# (Only defined when sklearn is available; it is only ever used during load.)
# ---------------------------------------------------------------------------
if _ML_DEPS_OK:
    class ColumnDropper(BaseEstimator, TransformerMixin):
        def __init__(self, columns_to_drop=None):
            self.columns_to_drop = columns_to_drop or []

        def fit(self, X, y=None):
            return self

        def transform(self, X):
            return X.drop(columns=[c for c in self.columns_to_drop if c in X.columns])

    import __main__ as _main
    if not hasattr(_main, "ColumnDropper"):
        _main.ColumnDropper = ColumnDropper


# Label mapping fixed at TRAINING time (insertion order of attack_type in
# dataset_final.csv), verified against the pipeline's own predictions. Do NOT
# recompute from live data — order would differ and silently mislabel.
INT_TO_LABEL = {
    0: "normal",
    1: "ICMP Flood",
    2: "SYN Flood",
    3: "ARP Spoofing",
    4: "UDP Flood",
    5: "Port Scan",
    6: "Control Plane Saturation",
}

PIPELINE_FILENAME = "full_ml_pipeline.joblib"


class MLInferenceEngine:
    """Loads full_ml_pipeline.joblib and provides per-flow predictions."""

    def __init__(self, model_dir, logger=None):
        self._logger = logger
        self._model_dir = model_dir
        self.is_loaded = False
        self._pipeline = None

        # Stats
        self._total_predictions = 0
        self._total_attacks = 0
        self._total_inference_time_ms = 0.0

        self._load_pipeline()

    def _log(self, level, msg, *args):
        if self._logger:
            getattr(self._logger, level)(msg, *args)
        else:
            print(f"[{level.upper()}] {msg % args if args else msg}")

    def _load_pipeline(self):
        if not _ML_DEPS_OK:
            self._log("warning", "ML dependencies missing (%s) — ML inference disabled "
                                 "(this is fine for dataset collection). To run ML on this host "
                                 "you need Python >=3.9, then: "
                                 "pip install 'scikit-learn>=1.6' imbalanced-learn pandas numpy",
                      _ML_DEPS_ERR)
            return

        path = os.path.join(self._model_dir, PIPELINE_FILENAME)
        if not os.path.exists(path):
            self._log("warning", "ML pipeline not found: %s — inference disabled. "
                                 "Place %s in this directory to enable it.",
                      path, PIPELINE_FILENAME)
            return

        try:
            self._pipeline = joblib.load(path)
            self.is_loaded = True
            self._log("info", "ML inference engine loaded pipeline: %s", path)
            self._log("info", "Attack classes: %s",
                      [v for v in INT_TO_LABEL.values() if v != "normal"])
        except ModuleNotFoundError as e:
            self._log("error", "Failed to load ML pipeline (%s). "
                               "Install missing dependency: pip install imbalanced-learn", e)
        except Exception as e:
            self._log("error", "Failed to load ML pipeline: %s", e)

    def _interpret(self, num_class, proba_row):
        """Map a numeric class + proba row to (label, attack_type, confidence)."""
        attack_type = INT_TO_LABEL.get(int(num_class), "normal")
        label = 0 if attack_type == "normal" else 1
        confidence = float(np.max(proba_row)) if proba_row is not None else 1.0
        return label, attack_type, confidence

    def predict(self, flow_dict):
        """
        Predict on a single flow row dict.

        Returns (label, attack_type, confidence):
            label (int): 0 = normal, 1 = attack
            attack_type (str): class name or 'normal'
            confidence (float): probability of the predicted class
        On any error, returns (0, 'normal', 0.0).
        """
        if not self.is_loaded:
            return 0, "normal", 0.0
        try:
            start = time.time()
            df = pd.DataFrame([flow_dict])
            num = self._pipeline.predict(df)[0]
            try:
                proba = self._pipeline.predict_proba(df)[0]
            except Exception:
                proba = None

            label, attack_type, confidence = self._interpret(num, proba)

            self._total_predictions += 1
            self._total_inference_time_ms += (time.time() - start) * 1000
            if label > 0:
                self._total_attacks += 1
            return label, attack_type, confidence
        except Exception as e:
            self._log("error", "ML prediction error: %s", e)
            return 0, "normal", 0.0

    def predict_batch(self, flow_dicts):
        """Predict on a list of flow row dicts (one DataFrame, one predict call)."""
        if not self.is_loaded or not flow_dicts:
            return [(0, "normal", 0.0)] * len(flow_dicts)
        try:
            start = time.time()
            df = pd.DataFrame(list(flow_dicts))
            nums = self._pipeline.predict(df)
            try:
                probas = self._pipeline.predict_proba(df)
            except Exception:
                probas = [None] * len(df)

            results = []
            for num, proba in zip(nums, probas):
                results.append(self._interpret(num, proba))

            self._total_predictions += len(results)
            self._total_attacks += sum(1 for r in results if r[0] > 0)
            self._total_inference_time_ms += (time.time() - start) * 1000
            return results
        except Exception as e:
            self._log("error", "ML batch prediction error: %s", e)
            return [(0, "normal", 0.0)] * len(flow_dicts)

    def get_stats(self):
        avg_ms = self._total_inference_time_ms / max(self._total_predictions, 1)
        return {
            "is_loaded": self.is_loaded,
            "total_predictions": self._total_predictions,
            "total_attacks_detected": self._total_attacks,
            "avg_inference_ms": round(avg_ms, 3),
            "total_inference_time_ms": round(self._total_inference_time_ms, 1),
            "attack_classes": [v for v in INT_TO_LABEL.values() if v != "normal"],
        }
