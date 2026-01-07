"""
RT-IDPS Hybrid Decision Engine
Combines Random Forest and K-Means for robust detection
"""

import numpy as np
import joblib
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import (RF_MODEL_PATH, KMEANS_MODEL_PATH, MODELS_DIR,
                          DETECTION_CONFIG)
from utils.logger import setup_logger

# Setup logger
logger = setup_logger('HybridDecision', log_file='logs/hybrid_decision.log')


class HybridDetectionEngine:
    """
    Hybrid ML Detection Engine
    Combines Random Forest (supervised) and K-Means (unsupervised)

    Decision Logic:
    1. IF Random Forest predicts ATTACK → MALICIOUS
    2. ELSE IF K-Means detects ANOMALY → SUSPICIOUS
    3. ELSE → NORMAL
    """

    def __init__(self):
        """Initialize hybrid engine"""
        self.rf_model = None
        self.kmeans_model = None
        self.kmeans_metadata = None
        self.rf_metadata = None
        self.loaded = False

    def load_models(self):
        """Load trained ML models"""
        logger.info("Loading trained models...")

        try:
            # Load Random Forest
            if not RF_MODEL_PATH.exists():
                raise FileNotFoundError(f"Random Forest model not found: {RF_MODEL_PATH}")

            self.rf_model = joblib.load(RF_MODEL_PATH)
            rf_metadata_path = MODELS_DIR / 'rf_metadata.joblib'
            self.rf_metadata = joblib.load(rf_metadata_path)
            logger.info("✓ Random Forest loaded")

            # Load K-Means
            if not KMEANS_MODEL_PATH.exists():
                raise FileNotFoundError(f"K-Means model not found: {KMEANS_MODEL_PATH}")

            self.kmeans_model = joblib.load(KMEANS_MODEL_PATH)
            kmeans_metadata_path = MODELS_DIR / 'kmeans_metadata.joblib'
            self.kmeans_metadata = joblib.load(kmeans_metadata_path)
            logger.info("✓ K-Means loaded")

            self.loaded = True
            logger.info("✓ All models loaded successfully")

            # Display model info
            logger.info(f"\nModel Information:")
            logger.info(f"  Random Forest:")
            logger.info(f"    - Estimators: {self.rf_metadata['n_estimators']}")
            logger.info(f"    - Features: {self.rf_metadata['n_features']}")
            logger.info(f"    - Accuracy: {self.rf_metadata['metrics']['accuracy']:.4f}")
            logger.info(f"  K-Means:")
            logger.info(f"    - Clusters: {self.kmeans_metadata['n_clusters']}")
            logger.info(f"    - Threshold: {self.kmeans_metadata['anomaly_threshold']:.4f}")

        except FileNotFoundError as e:
            logger.error(f"Model file not found: {e}")
            logger.info("\nPlease train models first:")
            logger.info("  1. python ml/train_rf.py")
            logger.info("  2. python ml/train_kmeans.py")
            raise

        except Exception as e:
            logger.error(f"Error loading models: {e}")
            raise

    def predict_rf(self, features):
        """
        Random Forest prediction

        Args:
            features: Feature vector or matrix

        Returns:
            prediction (0=normal, 1=attack), confidence
        """
        # Get prediction and probability
        prediction = self.rf_model.predict(features)
        probabilities = self.rf_model.predict_proba(features)

        # Confidence is the probability of the predicted class
        if len(features.shape) == 1:  # Single sample
            confidence = probabilities[0][prediction[0]]
        else:  # Multiple samples
            confidence = np.array([prob[pred] for prob, pred in zip(probabilities, prediction)])

        return prediction, confidence

    def detect_anomaly_kmeans(self, features):
        """
        K-Means anomaly detection

        Args:
            features: Feature vector or matrix

        Returns:
            is_anomaly (True/False), distance from normal cluster
        """
        # Calculate distance from normal cluster center
        normal_center = self.kmeans_metadata['normal_cluster_center']
        threshold = self.kmeans_metadata['anomaly_threshold']

        if len(features.shape) == 1:  # Single sample
            distance = np.linalg.norm(features - normal_center)
            is_anomaly = distance > threshold
        else:  # Multiple samples
            distances = np.linalg.norm(features - normal_center, axis=1)
            is_anomaly = distances > threshold
            distance = distances

        return is_anomaly, distance

    def hybrid_decision(self, features):
        """
        Hybrid decision combining RF and K-Means

        Args:
            features: Feature vector (single sample)

        Returns:
            decision dict with:
                - verdict: 'MALICIOUS', 'SUSPICIOUS', or 'NORMAL'
                - rf_prediction: 0 or 1
                - rf_confidence: probability
                - kmeans_anomaly: True or False
                - kmeans_distance: distance from normal
                - explanation: reasoning
        """
        if not self.loaded:
            raise RuntimeError("Models not loaded. Call load_models() first.")

        # Ensure features is 2D
        if len(features.shape) == 1:
            features = features.reshape(1, -1)

        # Get Random Forest prediction
        rf_pred, rf_conf = self.predict_rf(features)
        rf_pred = rf_pred[0]
        rf_conf = rf_conf[0] if isinstance(rf_conf, np.ndarray) else rf_conf

        # Get K-Means anomaly detection
        kmeans_anomaly, kmeans_dist = self.detect_anomaly_kmeans(features)
        if isinstance(kmeans_anomaly, np.ndarray):
            kmeans_anomaly = kmeans_anomaly[0]
            kmeans_dist = kmeans_dist[0]

        # HYBRID DECISION LOGIC
        if rf_pred == 1:  # Random Forest predicts attack
            verdict = 'MALICIOUS'
            explanation = f"Random Forest detected known attack pattern (confidence: {rf_conf:.2%})"

        elif kmeans_anomaly:  # K-Means detects anomaly
            verdict = 'SUSPICIOUS'
            threshold = self.kmeans_metadata['anomaly_threshold']
            explanation = f"K-Means detected anomaly (distance: {kmeans_dist:.4f}, threshold: {threshold:.4f})"

        else:  # Both models say normal
            verdict = 'NORMAL'
            explanation = "Both models indicate normal traffic"

        # Compile decision
        decision = {
            'verdict': verdict,
            'rf_prediction': int(rf_pred),
            'rf_confidence': float(rf_conf),
            'kmeans_anomaly': bool(kmeans_anomaly),
            'kmeans_distance': float(kmeans_dist),
            'explanation': explanation
        }

        return decision

    def batch_detect(self, features_batch):
        """
        Detect on multiple samples

        Args:
            features_batch: Feature matrix (n_samples x n_features)

        Returns:
            List of decision dicts
        """
        decisions = []

        for i in range(len(features_batch)):
            features = features_batch[i]
            decision = self.hybrid_decision(features)
            decisions.append(decision)

        return decisions

    def get_attack_type(self, features):
        """
        Identify specific attack type (placeholder for future enhancement)

        Args:
            features: Feature vector

        Returns:
            Attack type string
        """
        # This would require multi-class classification
        # For now, return generic "Attack"
        return "Unknown Attack"


def test_hybrid_engine():
    """Test the hybrid detection engine"""

    logger.info("="*70)
    logger.info("TESTING HYBRID DETECTION ENGINE")
    logger.info("="*70 + "\n")

    # Initialize engine
    engine = HybridDetectionEngine()

    # Load models
    engine.load_models()

    # Load test data
    from utils.config import DATA_DIR
    import pandas as pd

    reduced_path = DATA_DIR / "processed_data_reduced.csv"
    df = pd.read_csv(reduced_path)

    # Test on a few samples
    logger.info("\n" + "="*70)
    logger.info("TESTING ON SAMPLE DATA")
    logger.info("="*70 + "\n")

    # Test normal sample
    normal_sample = df[df['binary_label'] == 0].iloc[0]
    X_normal = normal_sample.drop('binary_label').values

    logger.info("Test 1: Normal Traffic Sample")
    logger.info("-" * 70)
    decision = engine.hybrid_decision(X_normal)
    logger.info(f"Verdict: {decision['verdict']}")
    logger.info(f"RF Prediction: {decision['rf_prediction']} (confidence: {decision['rf_confidence']:.4f})")
    logger.info(f"K-Means Anomaly: {decision['kmeans_anomaly']} (distance: {decision['kmeans_distance']:.4f})")
    logger.info(f"Explanation: {decision['explanation']}")
    logger.info("-" * 70 + "\n")

    # Test attack sample
    attack_sample = df[df['binary_label'] == 1].iloc[0]
    X_attack = attack_sample.drop('binary_label').values

    logger.info("Test 2: Attack Traffic Sample")
    logger.info("-" * 70)
    decision = engine.hybrid_decision(X_attack)
    logger.info(f"Verdict: {decision['verdict']}")
    logger.info(f"RF Prediction: {decision['rf_prediction']} (confidence: {decision['rf_confidence']:.4f})")
    logger.info(f"K-Means Anomaly: {decision['kmeans_anomaly']} (distance: {decision['kmeans_distance']:.4f})")
    logger.info(f"Explanation: {decision['explanation']}")
    logger.info("-" * 70 + "\n")

    # Batch test
    logger.info("Test 3: Batch Detection (10 samples)")
    logger.info("-" * 70)

    test_samples = df.sample(10)
    X_test = test_samples.drop('binary_label', axis=1).values
    y_true = test_samples['binary_label'].values

    decisions = engine.batch_detect(X_test)

    correct = 0
    for i, (decision, true_label) in enumerate(zip(decisions, y_true)):
        predicted_attack = 1 if decision['verdict'] in ['MALICIOUS', 'SUSPICIOUS'] else 0
        is_correct = predicted_attack == true_label
        correct += is_correct

        logger.info(f"Sample {i+1}: {decision['verdict']:12s} | True: {'Attack' if true_label else 'Normal':6s} | {'✓' if is_correct else '✗'}")

    accuracy = correct / len(decisions)
    logger.info("-" * 70)
    logger.info(f"Batch Accuracy: {accuracy:.2%} ({correct}/{len(decisions)})")
    logger.info("-" * 70 + "\n")

    logger.info("✅ Hybrid engine testing complete!")


def main():
    """Main function"""

    try:
        test_hybrid_engine()

        logger.info("\n" + "="*70)
        logger.info("HYBRID DECISION ENGINE READY")
        logger.info("="*70)
        logger.info("\nThe hybrid engine successfully combines:")
        logger.info("  ✓ Random Forest (known attacks)")
        logger.info("  ✓ K-Means (unknown anomalies)")
        logger.info("\nNext step: Integrate with real-time packet capture")
        logger.info("="*70 + "\n")

    except Exception as e:
        logger.error(f"Error: {e}")
        raise


if __name__ == "__main__":
    main()