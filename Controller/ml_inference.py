"""
SDN IPS — ML Inference Engine (Random Forest, manual-preprocessing contract)
============================================================================
Loads the Random Forest model trained in `ML model/RF_model_Notebook.ipynb` and
reproduces its EXACT preprocessing chain at inference time, per flow row:

    raw 102-col flow row (dict, as traffic_capture produces)
      -> drop identifiers/leakage (drop-set-1) + meta_* + label/attack_type
      -> pd.get_dummies(protocol)
      -> reindex to the 86 'encoded_columns'   (fixes single-row one-hot, fills 0,
                                                 forces the exact column ORDER)
      -> StandardScaler.transform              (the scaler fit in the notebook)
      -> select the 66 'final_columns'         (x_standrized_v2)
      -> RandomForestClassifier.predict        -> attack-type STRING

Model + scaler + column orders are bundled by the notebook's save cell into
`ml_models/rf_model.joblib`:
    { 'rf', 'scaler', 'encoded_columns', 'final_columns', 'classes', 'sklearn_version' }

Label convention (project scheme): 0 = normal, 2 = attack (the RF shares the
behavioral-attack label 2). `attack_type` names the specific class.

Interface is unchanged so Controller.py / traffic_capture need no signature edits:
    engine = MLInferenceEngine(model_dir, logger=...)
    engine.is_loaded
    engine.predict(flow_dict)              -> (label, attack_type, confidence)
    engine.predict_batch([flow_dict, ...]) -> [(label, attack_type, confidence), ...]
    engine.get_stats()

All public methods are exception-safe: on any error they return safe defaults
(0, 'normal', 0.0) so the controller never crashes due to ML issues.

Runtime deps: scikit-learn (MATCHING the notebook's version — joblib pickles are
version-sensitive), numpy, pandas, joblib. Python >= 3.9. imbalanced-learn is NOT
needed (SMOTE was train-only; the saved object is a plain RandomForestClassifier).
"""

import os
import time

try:
    import numpy as np
    import joblib
    import pandas as pd
    _ML_DEPS_OK = True
    _ML_DEPS_ERR = None
except ImportError as _e:  # pragma: no cover
    _ML_DEPS_OK = False
    _ML_DEPS_ERR = _e
    np = None

MODEL_FILENAME = "rf_model.joblib"

# drop-set-1 from the notebook (CELL 3) + the targets. meta_* are dropped
# dynamically by prefix. Anything not in 'encoded_columns' is dropped anyway by
# the reindex, but we strip the obvious non-features first so get_dummies only
# ever sees the single categorical column ('protocol').
DROP_INITIAL = [
    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'top_dst_port',
    'snort_sid', 'active_snort_alerts', 'distinct_alert_types',
    'label', 'attack_type',
]

ATTACK_LABEL = 2  # project label scheme: 0 normal, 1 Snort, 2 behavioral/RF attack


class MLInferenceEngine:
    """Loads rf_model.joblib and provides per-flow attack-type predictions."""

    def __init__(self, model_dir, logger=None):
        self._logger = logger
        self._model_dir = model_dir
        self.is_loaded = False
        self._rf = None
        self._scaler = None
        self._encoded_columns = None   # 86, scaler input order
        self._final_columns = None     # 66, rf input order
        self._classes = None

        self._total_predictions = 0
        self._total_attacks = 0
        self._total_inference_time_ms = 0.0

        self._load()

    def _log(self, level, msg, *args):
        if self._logger:
            getattr(self._logger, level)(msg, *args)
        else:
            print(f"[{level.upper()}] {msg % args if args else msg}")

    def _load(self):
        if not _ML_DEPS_OK:
            self._log('warning',
                      "ML dependencies missing (%s) — inference disabled (fine for dataset "
                      "collection). To run ML: Python>=3.9 then "
                      "pip install scikit-learn pandas numpy joblib (match the notebook's sklearn).",
                      _ML_DEPS_ERR)
            return

        path = os.path.join(self._model_dir, MODEL_FILENAME)
        if not os.path.exists(path):
            self._log('warning',
                      "ML model not found: %s — inference disabled. Place %s "
                      "(produced by the RF notebook save cell) in this directory.",
                      path, MODEL_FILENAME)
            return

        try:
            art = joblib.load(path)
            self._rf = art['rf']
            self._scaler = art['scaler']
            self._encoded_columns = list(art['encoded_columns'])
            self._final_columns = list(art['final_columns'])
            self._classes = list(art.get('classes', getattr(self._rf, 'classes_', [])))
            self.is_loaded = True
            self._log('info',
                      "ML engine loaded RF: %s (%d encoded -> %d final cols, %d classes)",
                      path, len(self._encoded_columns), len(self._final_columns),
                      len(self._classes))
            self._log('info', "Attack classes: %s",
                      [c for c in self._classes if c != 'normal'])
            saved_ver = art.get('sklearn_version')
            if saved_ver:
                try:
                    import sklearn
                    if saved_ver != sklearn.__version__:
                        self._log('warning',
                                  "sklearn version mismatch: model trained on %s, runtime is %s "
                                  "— pickle load may be unstable / predictions may drift. "
                                  "Pin scikit-learn==%s.",
                                  saved_ver, sklearn.__version__, saved_ver)
                except Exception:
                    pass
        except ModuleNotFoundError as e:
            self._log('error', "Failed to load RF model (%s). Missing dependency.", e)
        except Exception as e:
            self._log('error', "Failed to load RF model: %s", e)

    # -- preprocessing: replicate the notebook chain exactly -----------------
    def _preprocess(self, flow_dicts):
        df = pd.DataFrame(list(flow_dicts))
        drop = [c for c in DROP_INITIAL if c in df.columns]
        drop += [c for c in df.columns if str(c).startswith('meta_')]
        df = df.drop(columns=drop, errors='ignore')
        # one-hot 'protocol' (the only categorical column left), exactly like CELL 11
        df = pd.get_dummies(df, prefix='protocol')
        # align to the EXACT 86 training columns: adds missing protocol dummies as 0,
        # drops anything unexpected, and forces the column ORDER the scaler was fit on
        df = df.reindex(columns=self._encoded_columns, fill_value=0)
        # defensive numeric coercion, then standardize, then pick the 66 final columns
        df = df.apply(pd.to_numeric, errors='coerce').fillna(0.0)
        scaled = self._scaler.transform(df)
        scaled = pd.DataFrame(scaled, columns=self._encoded_columns)
        return scaled[self._final_columns]

    def _result(self, attack_type, proba_row):
        attack_type = str(attack_type)
        label = 0 if attack_type == 'normal' else ATTACK_LABEL
        confidence = float(np.max(proba_row)) if proba_row is not None else 1.0
        return label, attack_type, confidence

    def predict(self, flow_dict):
        """Single flow row -> (label, attack_type, confidence). Safe on error."""
        if not self.is_loaded:
            return 0, 'normal', 0.0
        try:
            start = time.time()
            X = self._preprocess([flow_dict])
            pred = self._rf.predict(X)[0]
            try:
                proba = self._rf.predict_proba(X)[0]
            except Exception:
                proba = None
            label, attack_type, confidence = self._result(pred, proba)

            self._total_predictions += 1
            self._total_inference_time_ms += (time.time() - start) * 1000
            if label > 0:
                self._total_attacks += 1
            return label, attack_type, confidence
        except Exception as e:
            self._log('error', "ML prediction error: %s", e)
            return 0, 'normal', 0.0

    def predict_batch(self, flow_dicts):
        """List of flow rows -> list of (label, attack_type, confidence)."""
        if not self.is_loaded or not flow_dicts:
            return [(0, 'normal', 0.0)] * len(flow_dicts)
        try:
            start = time.time()
            X = self._preprocess(flow_dicts)
            preds = self._rf.predict(X)
            try:
                probas = self._rf.predict_proba(X)
            except Exception:
                probas = [None] * len(preds)
            results = [self._result(p, pr) for p, pr in zip(preds, probas)]

            self._total_predictions += len(results)
            self._total_attacks += sum(1 for r in results if r[0] > 0)
            self._total_inference_time_ms += (time.time() - start) * 1000
            return results
        except Exception as e:
            self._log('error', "ML batch prediction error: %s", e)
            return [(0, 'normal', 0.0)] * len(flow_dicts)

    def get_stats(self):
        avg_ms = self._total_inference_time_ms / max(self._total_predictions, 1)
        return {
            'is_loaded': self.is_loaded,
            'total_predictions': self._total_predictions,
            'total_attacks_detected': self._total_attacks,
            'avg_inference_ms': round(avg_ms, 3),
            'total_inference_time_ms': round(self._total_inference_time_ms, 1),
            'attack_classes': [c for c in (self._classes or []) if c != 'normal'],
        }
