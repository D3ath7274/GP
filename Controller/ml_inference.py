"""
SDN IPS — ML Inference Engine (Random Forest)
=============================================
Loads the Random Forest trained in `ML model/RF_model_Notebook.ipynb` and serves
per-flow predictions to the controller. Supports two model artifacts:

  1. rf_pipeline.joblib  (PREFERRED) — an end-to-end sklearn Pipeline
        [ RFPreprocessor -> RandomForestClassifier ]
     where RFPreprocessor reproduces the notebook's manual chain (drop ids/meta ->
     get_dummies(protocol) -> reindex to 86 encoded cols -> StandardScaler ->
     select the 66 final cols). Inference is just pipeline.predict(raw_row_df).

  2. rf_model.joblib  (FALLBACK) — the earlier bundle
        { rf, scaler, encoded_columns, final_columns, classes, sklearn_version }
     for which this engine replicates the chain manually.

Either way the model predicts the attack-type STRING; label = 0 normal / 2 attack
(project scheme: 0 normal, 1 Snort, 2 behavioral/RF attack). attack_type names the
specific class.

Interface (unchanged — Controller.py / traffic_capture need no edits):
    engine = MLInferenceEngine(model_dir, logger=...)
    engine.is_loaded
    engine.predict(flow_dict)              -> (label, attack_type, confidence)
    engine.predict_batch([flow_dict, ...]) -> [(label, attack_type, confidence), ...]
    engine.get_stats()

All public methods are exception-safe: on any error they return (0, 'normal', 0.0).

Runtime deps: scikit-learn (MATCHING the notebook's version — joblib pickles are
version-sensitive), numpy, pandas, joblib, Python >= 3.9. imbalanced-learn is NOT
needed (SMOTE was train-only).
"""

import os
import time
import warnings

# Silence sklearn's per-predict "X does not have valid feature names" UserWarning.
# It is benign (predictions are identical — verify_inference.py = 100%), but with
# detection OFF the RF scores every flow, so during a flood it fires thousands of
# times and floods the controller log, burying the [ML-OBSERVE] output. The
# RFPreprocessor below also returns a named DataFrame to address the root cause;
# this filter is the belt-and-suspenders guarantee.
warnings.filterwarnings("ignore", message="X does not have valid feature names")

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

PIPELINE_FILENAME = "rf_pipeline.joblib"
BUNDLE_FILENAME = "rf_model.joblib"

# drop-set-1 from the notebook (CELL 3) + the targets. meta_* dropped by prefix.
DROP_INITIAL = [
    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'top_dst_port',
    'snort_sid', 'active_snort_alerts', 'distinct_alert_types',
    'label', 'attack_type',
]

ATTACK_LABEL = 2  # project label scheme: 0 normal, 1 Snort, 2 behavioral/RF attack


# ---------------------------------------------------------------------------
# RFPreprocessor — reproduces the notebook's manual preprocessing as a single
# transformer. It is the first step of rf_pipeline.joblib. Because the pipeline
# was pickled from the notebook's __main__, pickle resolves this class as
# __main__.RFPreprocessor; defining it here and registering it into __main__
# lets the pipeline load inside the controller. (Only when sklearn is available.)
# ---------------------------------------------------------------------------
if _ML_DEPS_OK:
    class RFPreprocessor(BaseEstimator, TransformerMixin):
        def __init__(self, drop_initial=None, encoded_columns=None,
                     final_columns=None, scaler=None):
            self.drop_initial = drop_initial or []
            self.encoded_columns = encoded_columns or []
            self.final_columns = final_columns or []
            self.scaler = scaler

        def fit(self, X, y=None):
            return self

        def transform(self, X):
            df = (X if isinstance(X, pd.DataFrame) else pd.DataFrame(X)).copy()
            drop = [c for c in self.drop_initial if c in df.columns]
            drop += [c for c in df.columns if str(c).startswith('meta_')]
            df = df.drop(columns=drop, errors='ignore')
            df = pd.get_dummies(df, prefix='protocol')
            df = df.reindex(columns=self.encoded_columns, fill_value=0)
            df = df.apply(pd.to_numeric, errors='coerce').fillna(0.0)
            scaled = pd.DataFrame(self.scaler.transform(df), columns=self.encoded_columns)
            # Return a DataFrame (not .values): the RF was fitted on a named DataFrame
            # whose columns are exactly final_columns, so handing it names — instead of a
            # bare array — silences sklearn's "X does not have valid feature names"
            # warning without changing predictions (same columns, same order).
            return scaled[self.final_columns]

    import __main__ as _main
    if not hasattr(_main, "RFPreprocessor"):
        _main.RFPreprocessor = RFPreprocessor


class MLInferenceEngine:
    """Serves RF predictions from rf_pipeline.joblib (preferred) or rf_model.joblib."""

    def __init__(self, model_dir, logger=None):
        self._logger = logger
        self._model_dir = model_dir
        self.is_loaded = False
        self._mode = None              # 'pipeline' | 'bundle'
        self._pipeline = None
        # bundle-mode state
        self._rf = None
        self._scaler = None
        self._encoded_columns = None
        self._final_columns = None
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
                      "ML dependencies missing (%s) — inference disabled (fine for collection). "
                      "Need Python>=3.9 + scikit-learn (match the notebook's version), pandas, numpy, joblib.",
                      _ML_DEPS_ERR)
            return

        pipe_path = os.path.join(self._model_dir, PIPELINE_FILENAME)
        bundle_path = os.path.join(self._model_dir, BUNDLE_FILENAME)

        # 1) preferred: end-to-end pipeline
        if os.path.exists(pipe_path):
            try:
                self._pipeline = joblib.load(pipe_path)
                self._force_single_threaded(self._pipeline)
                self._classes = list(getattr(self._pipeline, 'classes_', []))
                self._mode = 'pipeline'
                self.is_loaded = True
                self._log('info', "ML engine loaded end-to-end pipeline: %s (%d classes)",
                          pipe_path, len(self._classes))
                self._log('info', "Attack classes: %s",
                          [c for c in self._classes if c != 'normal'])
                return
            except Exception as e:
                self._log('error', "Failed to load %s (%s) — trying bundle fallback.",
                          pipe_path, e)

        # 2) fallback: bundle + manual chain
        if os.path.exists(bundle_path):
            try:
                art = joblib.load(bundle_path)
                self._rf = art['rf']
                self._force_single_threaded(self._rf)
                self._scaler = art['scaler']
                self._encoded_columns = list(art['encoded_columns'])
                self._final_columns = list(art['final_columns'])
                self._classes = list(art.get('classes', getattr(self._rf, 'classes_', [])))
                self._mode = 'bundle'
                self.is_loaded = True
                self._log('info', "ML engine loaded bundle: %s (%d->%d cols, %d classes)",
                          bundle_path, len(self._encoded_columns),
                          len(self._final_columns), len(self._classes))
                return
            except Exception as e:
                self._log('error', "Failed to load bundle %s: %s", bundle_path, e)

        self._log('warning',
                  "No ML model found in %s (looked for %s, then %s) — inference disabled.",
                  self._model_dir, PIPELINE_FILENAME, BUNDLE_FILENAME)

    def _force_single_threaded(self, model):
        """Set n_jobs=1 on the loaded estimator (and every pipeline step that has it),
        so RandomForest.predict_proba runs sequentially and never starts a joblib
        multiprocessing pool. See _infer for WHY this is mandatory under eventlet — a
        model pickled with n_jobs=-1 otherwise deadlocks the controller the instant ML
        is armed. This neutralises that at the source; _infer's threading-backend wrap
        is the second line of defence."""
        targets = [model]
        steps = getattr(model, 'steps', None)
        if steps:
            targets += [est for _, est in steps]
        for est in targets:
            if hasattr(est, 'n_jobs'):
                try:
                    est.n_jobs = 1
                    self._log('info', "Forced n_jobs=1 on %s (no multiprocessing pool)",
                              type(est).__name__)
                except Exception:
                    pass

    # bundle-mode preprocessing (pipeline mode does this inside RFPreprocessor)
    def _preprocess_bundle(self, flow_dicts):
        df = pd.DataFrame(list(flow_dicts))
        drop = [c for c in DROP_INITIAL if c in df.columns]
        drop += [c for c in df.columns if str(c).startswith('meta_')]
        df = df.drop(columns=drop, errors='ignore')
        df = pd.get_dummies(df, prefix='protocol')
        df = df.reindex(columns=self._encoded_columns, fill_value=0)
        df = df.apply(pd.to_numeric, errors='coerce').fillna(0.0)
        scaled = pd.DataFrame(self._scaler.transform(df), columns=self._encoded_columns)
        return scaled[self._final_columns]

    def _infer(self, flow_dicts):
        """Return (preds, probas) for a list of flow dicts, using whichever model loaded.

        CRITICAL: wrapped in joblib's THREADING backend (n_jobs=1) so prediction NEVER
        spawns a multiprocessing pool. The controller runs under Ryu's eventlet hub,
        whose monkey-patch leaves multiprocessing semaphores un-greened ("RLock not
        greened" startup warning). A RandomForest saved with n_jobs=-1 then makes
        predict_proba launch a multiprocessing pool from the feature-flush thread, which
        DEADLOCKS on that lock — the flush thread wedges inside predict_proba, the
        controller stops scoring AND stops writing dataset.csv (and appears hung) the
        moment ML is armed. Threading/sequential inference is more than fast enough for a
        single 5s window of flows. (n_jobs is also forced to 1 on load, see _load.)
        """
        with joblib.parallel_backend('threading', n_jobs=1):
            if self._mode == 'pipeline':
                X = pd.DataFrame(list(flow_dicts))
                preds = self._pipeline.predict(X)
                try:
                    probas = self._pipeline.predict_proba(X)
                except Exception:
                    probas = None
            else:
                X = self._preprocess_bundle(flow_dicts)
                preds = self._rf.predict(X)
                try:
                    probas = self._rf.predict_proba(X)
                except Exception:
                    probas = None
        return preds, probas

    def _result(self, attack_type, proba_row):
        attack_type = str(attack_type)
        label = 0 if attack_type == 'normal' else ATTACK_LABEL
        confidence = float(np.max(proba_row)) if proba_row is not None else 1.0
        return label, attack_type, confidence

    def predict(self, flow_dict):
        if not self.is_loaded:
            return 0, 'normal', 0.0
        try:
            start = time.time()
            preds, probas = self._infer([flow_dict])
            proba_row = probas[0] if probas is not None else None
            label, attack_type, confidence = self._result(preds[0], proba_row)

            self._total_predictions += 1
            self._total_inference_time_ms += (time.time() - start) * 1000
            if label > 0:
                self._total_attacks += 1
            return label, attack_type, confidence
        except Exception as e:
            self._log('error', "ML prediction error: %s", e)
            return 0, 'normal', 0.0

    def predict_batch(self, flow_dicts):
        if not self.is_loaded or not flow_dicts:
            return [(0, 'normal', 0.0)] * len(flow_dicts)
        try:
            start = time.time()
            preds, probas = self._infer(flow_dicts)
            results = []
            for i, p in enumerate(preds):
                proba_row = probas[i] if probas is not None else None
                results.append(self._result(p, proba_row))

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
            'mode': self._mode,
            'total_predictions': self._total_predictions,
            'total_attacks_detected': self._total_attacks,
            'avg_inference_ms': round(avg_ms, 3),
            'attack_classes': [c for c in (self._classes or []) if c != 'normal'],
        }
