"""
RT-IDPS K-Means Training Module
Trains unsupervised learning model for anomaly detection
"""

import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score, davies_bouldin_score
import joblib
import sys
import os
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import (ML_CONFIG, MODELS_DIR, KMEANS_MODEL_PATH, DATA_DIR)
from utils.logger import setup_logger

# Setup logger
logger = setup_logger('KMeansTraining', log_file='logs/kmeans_training.log')


class KMeansTrainer:
    """Train and evaluate K-Means clustering for anomaly detection"""

    def __init__(self):
        """Initialize trainer"""
        self.model = None
        self.normal_cluster_center = None
        self.anomaly_threshold = None
        self.training_time = 0

    def load_normal_traffic_data(self):
        """
        Load only NORMAL traffic for K-Means training
        K-Means should learn what normal looks like

        Returns:
            X_normal: Normal traffic features
        """
        logger.info("Loading normal traffic data for K-Means...")

        # Load reduced dataset
        reduced_path = DATA_DIR / "processed_data_reduced.csv"

        if not reduced_path.exists():
            logger.error(f"Reduced dataset not found at {reduced_path}")
            logger.info("Please run feature selection first: python ml/feature_selection.py")
            raise FileNotFoundError(f"Dataset not found: {reduced_path}")

        df = pd.read_csv(reduced_path)
        logger.info(f"Loaded {len(df)} total records")

        # Filter only normal traffic (binary_label == 0)
        df_normal = df[df['binary_label'] == 0]
        logger.info(f"Normal traffic records: {len(df_normal)}")

        # Extract features (remove label)
        X_normal = df_normal.drop('binary_label', axis=1)

        logger.info(f"Features: {X_normal.shape[1]}")
        logger.info(f"Training samples: {len(X_normal)}")

        return X_normal

    def find_optimal_clusters(self, X, max_k=10):
        """
        Find optimal number of clusters using elbow method

        Args:
            X: Feature matrix
            max_k: Maximum number of clusters to try

        Returns:
            Optimal k value
        """
        logger.info("\n" + "="*70)
        logger.info("FINDING OPTIMAL NUMBER OF CLUSTERS")
        logger.info("="*70 + "\n")

        inertias = []
        silhouette_scores = []
        k_range = range(2, max_k + 1)

        logger.info("Testing different cluster numbers...")

        for k in k_range:
            logger.info(f"Testing k={k}...")

            kmeans = KMeans(
                n_clusters=k,
                random_state=ML_CONFIG['kmeans_random_state'],
                n_init=10
            )
            kmeans.fit(X)

            inertias.append(kmeans.inertia_)
            silhouette_scores.append(silhouette_score(X, kmeans.labels_))

        # Display results
        logger.info("\nCluster Evaluation Results:")
        logger.info("-" * 70)
        logger.info(f"{'K':>3} | {'Inertia':>15} | {'Silhouette Score':>17}")
        logger.info("-" * 70)

        for k, inertia, silhouette in zip(k_range, inertias, silhouette_scores):
            logger.info(f"{k:3d} | {inertia:15.2f} | {silhouette:17.4f}")

        logger.info("-" * 70)

        # Find best k based on silhouette score
        best_k = k_range[np.argmax(silhouette_scores)]
        logger.info(f"\nOptimal k based on silhouette score: {best_k}")

        return best_k

    def train_model(self, X):
        """
        Train K-Means clustering model

        Args:
            X: Normal traffic features
        """
        logger.info("\n" + "="*70)
        logger.info("TRAINING K-MEANS CLUSTERING")
        logger.info("="*70 + "\n")

        # Use configured number of clusters
        n_clusters = ML_CONFIG['kmeans_n_clusters']

        # Initialize model
        self.model = KMeans(
            n_clusters=n_clusters,
            random_state=ML_CONFIG['kmeans_random_state'],
            n_init=20,
            max_iter=300,
            verbose=1
        )

        logger.info("Model Configuration:")
        logger.info(f"  n_clusters: {n_clusters}")
        logger.info(f"  random_state: {ML_CONFIG['kmeans_random_state']}")
        logger.info(f"  n_init: 20")
        logger.info(f"  max_iter: 300")
        logger.info("")

        # Train model
        logger.info("Training started...")
        start_time = time.time()

        self.model.fit(X)

        self.training_time = time.time() - start_time
        logger.info(f"\nTraining completed in {self.training_time:.2f} seconds")

        # Get cluster assignments
        labels = self.model.labels_

        # Find the largest cluster (assumed to be "normal" cluster)
        unique, counts = np.unique(labels, return_counts=True)
        normal_cluster_idx = unique[np.argmax(counts)]
        self.normal_cluster_center = self.model.cluster_centers_[normal_cluster_idx]

        logger.info(f"\nCluster distribution:")
        for cluster_id, count in zip(unique, counts):
            percentage = (count / len(labels)) * 100
            marker = " <- NORMAL CLUSTER" if cluster_id == normal_cluster_idx else ""
            logger.info(f"  Cluster {cluster_id}: {count:6d} samples ({percentage:5.2f}%){marker}")

    def calculate_anomaly_threshold(self, X):
        """
        Calculate anomaly detection threshold
        Uses 95th percentile of distances from normal cluster center

        Args:
            X: Normal traffic features
        """
        logger.info("\n" + "="*70)
        logger.info("CALCULATING ANOMALY THRESHOLD")
        logger.info("="*70 + "\n")

        # Calculate distances from normal cluster center
        distances = np.linalg.norm(X - self.normal_cluster_center, axis=1)

        # Use 95th percentile as threshold
        self.anomaly_threshold = np.percentile(distances, 95)

        logger.info(f"Distance statistics:")
        logger.info(f"  Min:      {distances.min():.4f}")
        logger.info(f"  Median:   {np.median(distances):.4f}")
        logger.info(f"  Mean:     {distances.mean():.4f}")
        logger.info(f"  95th %:   {self.anomaly_threshold:.4f} <- THRESHOLD")
        logger.info(f"  Max:      {distances.max():.4f}")

        # Count outliers
        outliers = (distances > self.anomaly_threshold).sum()
        outlier_percentage = (outliers / len(distances)) * 100
        logger.info(f"\nOutliers in normal traffic: {outliers} ({outlier_percentage:.2f}%)")

    def evaluate_model(self, X):
        """
        Evaluate clustering quality

        Args:
            X: Normal traffic features
        """
        logger.info("\n" + "="*70)
        logger.info("MODEL EVALUATION")
        logger.info("="*70 + "\n")

        # Get cluster assignments
        labels = self.model.labels_

        # Calculate metrics
        silhouette = silhouette_score(X, labels)
        davies_bouldin = davies_bouldin_score(X, labels)
        inertia = self.model.inertia_

        logger.info("Clustering Quality Metrics:")
        logger.info("-" * 70)
        logger.info(f"Silhouette Score:      {silhouette:.4f} (higher is better, range: -1 to 1)")
        logger.info(f"Davies-Bouldin Index:  {davies_bouldin:.4f} (lower is better)")
        logger.info(f"Inertia:               {inertia:.2f} (sum of squared distances)")
        logger.info("-" * 70)

        # Interpretation
        if silhouette > 0.5:
            logger.info("\n✓ Good clustering structure (Silhouette > 0.5)")
        elif silhouette > 0.25:
            logger.info("\n⚠ Moderate clustering structure (0.25 < Silhouette < 0.5)")
        else:
            logger.info("\n⚠ Weak clustering structure (Silhouette < 0.25)")

    def test_on_attack_data(self):
        """
        Test anomaly detection on actual attack data
        """
        logger.info("\n" + "="*70)
        logger.info("TESTING ON ATTACK DATA")
        logger.info("="*70 + "\n")

        # Load full dataset
        reduced_path = DATA_DIR / "processed_data_reduced.csv"
        df = pd.read_csv(reduced_path)

        # Get attack samples
        df_attack = df[df['binary_label'] == 1]
        X_attack = df_attack.drop('binary_label', axis=1)

        logger.info(f"Testing on {len(X_attack)} attack samples...")

        # Calculate distances from normal cluster
        distances = np.linalg.norm(X_attack.values - self.normal_cluster_center, axis=1)

        # Count anomalies detected
        detected_attacks = (distances > self.anomaly_threshold).sum()
        detection_rate = (detected_attacks / len(X_attack)) * 100

        logger.info(f"\nAnomaly Detection Results:")
        logger.info(f"  Total attacks:     {len(X_attack)}")
        logger.info(f"  Detected:          {detected_attacks}")
        logger.info(f"  Detection rate:    {detection_rate:.2f}%")
        logger.info(f"  Missed:            {len(X_attack) - detected_attacks}")

        # Distance statistics for attacks
        logger.info(f"\nDistance statistics for attacks:")
        logger.info(f"  Min:      {distances.min():.4f}")
        logger.info(f"  Median:   {np.median(distances):.4f}")
        logger.info(f"  Mean:     {distances.mean():.4f}")
        logger.info(f"  Max:      {distances.max():.4f}")
        logger.info(f"  Threshold: {self.anomaly_threshold:.4f}")

    def save_model(self):
        """Save trained model to disk"""
        logger.info("\n" + "="*70)
        logger.info("SAVING MODEL")
        logger.info("="*70 + "\n")

        # Create models directory
        os.makedirs(MODELS_DIR, exist_ok=True)

        # Save model
        logger.info(f"Saving model to {KMEANS_MODEL_PATH}")
        joblib.dump(self.model, KMEANS_MODEL_PATH)

        # Save model metadata
        metadata = {
            'model_type': 'KMeans',
            'n_clusters': ML_CONFIG['kmeans_n_clusters'],
            'normal_cluster_center': self.normal_cluster_center,
            'anomaly_threshold': self.anomaly_threshold,
            'training_time': self.training_time
        }

        metadata_path = MODELS_DIR / 'kmeans_metadata.joblib'
        joblib.dump(metadata, metadata_path)

        logger.info(f"Model saved successfully!")
        logger.info(f"Metadata saved to {metadata_path}")


def main():
    """Main training function"""

    logger.info("="*70)
    logger.info("RT-IDPS K-MEANS TRAINING")
    logger.info("="*70 + "\n")

    # Initialize trainer
    trainer = KMeansTrainer()

    try:
        # Load normal traffic data
        X_normal = trainer.load_normal_traffic_data()

        # Optional: Find optimal clusters
        # optimal_k = trainer.find_optimal_clusters(X_normal, max_k=10)

        # Train model
        trainer.train_model(X_normal)

        # Calculate anomaly threshold
        trainer.calculate_anomaly_threshold(X_normal)

        # Evaluate model
        trainer.evaluate_model(X_normal)

        # Test on attack data
        trainer.test_on_attack_data()

        # Save model
        trainer.save_model()

        # Summary
        logger.info("\n" + "="*70)
        logger.info("TRAINING SUMMARY")
        logger.info("="*70)
        logger.info(f"Training time: {trainer.training_time:.2f} seconds")
        logger.info(f"Number of clusters: {ML_CONFIG['kmeans_n_clusters']}")
        logger.info(f"Anomaly threshold: {trainer.anomaly_threshold:.4f}")
        logger.info(f"Model saved to: {KMEANS_MODEL_PATH}")
        logger.info("="*70 + "\n")

        logger.info("✅ K-Means training complete!")
        logger.info("\nNext step: Create hybrid decision engine (ml/hybrid_decision.py)")

    except Exception as e:
        logger.error(f"Error during training: {e}")
        raise


if __name__ == "__main__":
    main()