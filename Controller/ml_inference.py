"""
ML Inference Engine — Real-Time Attack Detection
===================================================
Runtime module loaded by the controller to perform per-flow
ML inference during the _flush_flows() cycle.

Loads pre-trained models from ml_models/ directory and provides
a predict() method that returns (label, attack_type, confidence)
for each flow feature vector.

Architecture:
  1. Binary model (VotingClassifier) → normal vs attack
  2. Attack type model (LightGBM) → 6 attack type classes
  3. Isolation Forest → anomaly score for zero-day detection

Usage:
    from ml_inference import MLInferenceEngine
    engine = MLInferenceEngine('ml_models/')
    label, attack_type, confidence = engine.predict(flow_features_dict)
"""

import os
import json
import time
import numpy as np
import joblib
import threading


class MLInferenceEngine:
    """
    Runtime ML inference engine for real-time attack detection.

    Args:
        model_dir: Directory containing trained model files.
        anomaly_threshold: Isolation Forest decision threshold.
                          Flows with score below this are flagged anomalous.
                          Default -0.1 (conservative, low false positive).
        confidence_threshold: Minimum prediction probability to trigger
                             an attack classification. Default 0.85.
    """

    def __init__(self, model_dir='ml_models/', anomaly_threshold=-0.1,
                 confidence_threshold=0.85):
        self.model_dir = model_dir
        self.anomaly_threshold = anomaly_threshold
        self.confidence_threshold = confidence_threshold
        self._loaded = False
        self._lock = threading.Lock()

        # Stats
        self._total_predictions = 0
        self._total_attacks = 0
        self._total_anomalies = 0
        self._total_time_ms = 0.0

        self._load_models()

    def _load_models(self):
        """Load all models from disk."""
        if not os.path.isdir(self.model_dir):
            print(f"[MLInference] Model directory not found: {self.model_dir}")
            return

        try:
            self.binary_model = joblib.load(
                os.path.join(self.model_dir, 'binary_model.pkl'))
            self.attack_type_model = joblib.load(
                os.path.join(self.model_dir, 'attack_type_model.pkl'))
            self.isolation_forest = joblib.load(
                os.path.join(self.model_dir, 'isolation_forest.pkl'))
            self.scaler = joblib.load(
                os.path.join(self.model_dir, 'scaler.pkl'))
            self.label_encoder = joblib.load(
                os.path.join(self.model_dir, 'label_encoder.pkl'))

            with open(os.path.join(self.model_dir, 'feature_columns.json'), 'r') as f:
                self.feature_columns = json.load(f)

            self._loaded = True
            print(f"[MLInference] Models loaded from {self.model_dir}")
            print(f"[MLInference] Feature columns: {len(self.feature_columns)}")
            print(f"[MLInference] Attack classes: {list(self.label_encoder.classes_)}")

        except FileNotFoundError as e:
            print(f"[MLInference] Missing model file: {e}")
        except Exception as e:
            print(f"[MLInference] Error loading models: {e}")

    @property
    def is_loaded(self):
        return self._loaded

    def _extract_features(self, flow_dict):
        """
        Extract and order features from a flow dictionary to match
        the training feature column order.

        Returns:
            numpy array of shape (1, n_features)
        """
        features = []
        for col in self.feature_columns:
            val = flow_dict.get(col, 0)
            try:
                features.append(float(val))
            except (ValueError, TypeError):
                features.append(0.0)
        return np.array(features, dtype=np.float32).reshape(1, -1)

    def predict(self, flow_features_dict):
        """
        Predict on a single flow feature dictionary.

        Args:
            flow_features_dict: Dict of flow features (from _build_flow_row).

        Returns:
            Tuple of (label, attack_type, confidence) where:
              label: 0 (normal) or 2 (attack)
              attack_type: String attack type or 'normal'
              confidence: Float [0, 1] confidence of the prediction
        """
        if not self._loaded:
            return 0, 'normal', 0.0

        start = time.time()

        try:
            # Extract features
            X = self._extract_features(flow_features_dict)
            X_scaled = self.scaler.transform(X)

            # Binary prediction
            binary_pred = self.binary_model.predict(X_scaled)[0]
            binary_proba = self.binary_model.predict_proba(X_scaled)[0]
            attack_proba = binary_proba[1]  # Probability of attack class

            # Anomaly detection
            anomaly_score = self.isolation_forest.decision_function(X_scaled)[0]
            is_anomaly = anomaly_score < self.anomaly_threshold

            # Decision logic
            label = 0
            attack_type = 'normal'
            confidence = binary_proba[0]  # Normal confidence

            if binary_pred == 1 and attack_proba >= self.confidence_threshold:
                # Binary model says attack with high confidence
                label = 2
                confidence = attack_proba
                # Classify attack type
                type_pred = self.attack_type_model.predict(X_scaled)[0]
                attack_type = self.label_encoder.inverse_transform([type_pred])[0]

            elif is_anomaly and attack_proba >= 0.5:
                # Anomaly detector triggered + binary model leans attack
                label = 2
                confidence = attack_proba
                type_pred = self.attack_type_model.predict(X_scaled)[0]
                attack_type = self.label_encoder.inverse_transform([type_pred])[0]

            # Stats
            with self._lock:
                self._total_predictions += 1
                if label > 0:
                    self._total_attacks += 1
                if is_anomaly:
                    self._total_anomalies += 1
                self._total_time_ms += (time.time() - start) * 1000

            return label, attack_type, round(confidence, 4)

        except Exception as e:
            # Never crash the controller on ML errors
            return 0, 'normal', 0.0

    def predict_batch(self, flow_rows):
        """
        Predict on a batch of flow dictionaries (for _flush_flows).

        Args:
            flow_rows: List of flow feature dicts.

        Returns:
            List of (label, attack_type, confidence) tuples.
        """
        if not self._loaded:
            return [(0, 'normal', 0.0)] * len(flow_rows)

        results = []
        for row in flow_rows:
            results.append(self.predict(row))
        return results

    def get_stats(self):
        """Return inference statistics."""
        with self._lock:
            avg_ms = (self._total_time_ms / max(self._total_predictions, 1))
            return {
                'loaded': self._loaded,
                'total_predictions': self._total_predictions,
                'total_attacks': self._total_attacks,
                'total_anomalies': self._total_anomalies,
                'avg_inference_ms': round(avg_ms, 3),
            }


# =============================================================================
# Self-Test
# =============================================================================

if __name__ == '__main__':
    import sys
    print("=" * 60)
    print("  ML Inference Engine — Self-Test")
    print("=" * 60)

    model_dir = os.path.join(os.path.dirname(__file__), 'ml_models')
    if not os.path.isdir(model_dir):
        # Try parent
        model_dir = os.path.join(os.path.dirname(__file__), '..', 'ml_models')

    engine = MLInferenceEngine(model_dir)

    if not engine.is_loaded:
        print("\n  ⚠ Models not found. Train first with:")
        print("    python3 ml_training/train_model.py --dataset results/dataset_final.csv")
        sys.exit(0)

    # Test with a dummy flow
    dummy_flow = {col: 0.0 for col in engine.feature_columns}
    dummy_flow['packets_per_second'] = 100
    dummy_flow['total_packets'] = 500

    label, attack_type, conf = engine.predict(dummy_flow)
    print(f"\n  Dummy prediction: label={label}, type={attack_type}, conf={conf}")

    stats = engine.get_stats()
    print(f"  Stats: {stats}")

    print(f"\n  ✅ Inference engine operational")
    print("=" * 60)
