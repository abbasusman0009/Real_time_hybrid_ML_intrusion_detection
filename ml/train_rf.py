"""
RT-IDPS Random Forest Training Module
Trains supervised learning model for known attack detection
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix,
                            accuracy_score, precision_score, recall_score,
                            f1_score, roc_auc_score)
import joblib
import sys
import os
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import (ML_CONFIG, MODELS_DIR, RF_MODEL_PATH,
                          FEATURE_NAMES_PATH, DATA_DIR)
from utils.logger import setup_logger

# Setup logger
logger = setup_logger('RandomForestTraining', log_file='logs/rf_training.log')


class RandomForestTrainer:
    """Train and evaluate Random Forest classifier"""

    def __init__(self):
        """Initialize trainer"""
        self.model = None
        self.feature_names = None
        self.training_time = 0
        self.metrics = {}

    def load_data(self):
        """
        Load reduced dataset with selected features

        Returns:
            X_train, X_test, y_train, y_test
        """
        logger.info("Loading reduced dataset...")

        # Load reduced dataset
        reduced_path = DATA_DIR / "processed_data_reduced.csv"

        if not reduced_path.exists():
            logger.error(f"Reduced dataset not found at {reduced_path}")
            logger.info("Please run feature selection first: python ml/feature_selection.py")
            raise FileNotFoundError(f"Dataset not found: {reduced_path}")

        df = pd.read_csv(reduced_path)
        logger.info(f"Loaded {len(df)} records with {df.shape[1]-1} features")

        # Separate features and labels
        X = df.drop('binary_label', axis=1)
        y = df['binary_label']

        # Store feature names
        self.feature_names = X.columns.tolist()

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=ML_CONFIG['test_size'],
            random_state=ML_CONFIG['random_state'],
            stratify=y
        )

        logger.info(f"Train set: {len(X_train)} samples")
        logger.info(f"  Normal: {(y_train == 0).sum()}")
        logger.info(f"  Attack: {(y_train == 1).sum()}")
        logger.info(f"Test set: {len(X_test)} samples")
        logger.info(f"  Normal: {(y_test == 0).sum()}")
        logger.info(f"  Attack: {(y_test == 1).sum()}")

        return X_train, X_test, y_train, y_test

    def train_model(self, X_train, y_train):
        """
        Train Random Forest classifier

        Args:
            X_train: Training features
            y_train: Training labels
        """
        logger.info("\n" + "="*70)
        logger.info("TRAINING RANDOM FOREST CLASSIFIER")
        logger.info("="*70 + "\n")

        # Initialize model
        self.model = RandomForestClassifier(
            n_estimators=ML_CONFIG['rf_n_estimators'],
            max_depth=ML_CONFIG['rf_max_depth'],
            random_state=ML_CONFIG['rf_random_state'],
            n_jobs=-1,
            verbose=2,
            class_weight='balanced'  # Handle class imbalance
        )

        logger.info("Model Configuration:")
        logger.info(f"  n_estimators: {ML_CONFIG['rf_n_estimators']}")
        logger.info(f"  max_depth: {ML_CONFIG['rf_max_depth']}")
        logger.info(f"  random_state: {ML_CONFIG['rf_random_state']}")
        logger.info(f"  class_weight: balanced")
        logger.info("")

        # Train model
        logger.info("Training started...")
        start_time = time.time()

        self.model.fit(X_train, y_train)

        self.training_time = time.time() - start_time
        logger.info(f"\nTraining completed in {self.training_time:.2f} seconds")

    def evaluate_model(self, X_test, y_test):
        """
        Evaluate model performance

        Args:
            X_test: Test features
            y_test: Test labels
        """
        logger.info("\n" + "="*70)
        logger.info("MODEL EVALUATION")
        logger.info("="*70 + "\n")

        # Make predictions
        logger.info("Making predictions on test set...")
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]

        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_pred_proba)

        # Store metrics
        self.metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'roc_auc': roc_auc
        }

        # Display metrics
        logger.info("Performance Metrics:")
        logger.info("-" * 70)
        logger.info(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
        logger.info(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
        logger.info(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
        logger.info(f"F1-Score:  {f1:.4f}")
        logger.info(f"ROC-AUC:   {roc_auc:.4f}")
        logger.info("-" * 70)

        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        logger.info("\nConfusion Matrix:")
        logger.info("-" * 70)
        logger.info(f"                 Predicted")
        logger.info(f"              Normal  Attack")
        logger.info(f"Actual Normal  {cm[0][0]:6d}  {cm[0][1]:6d}")
        logger.info(f"       Attack  {cm[1][0]:6d}  {cm[1][1]:6d}")
        logger.info("-" * 70)

        # Calculate rates
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn)  # False Positive Rate
        fnr = fn / (fn + tp)  # False Negative Rate

        logger.info(f"\nTrue Positives:  {tp:6d} (Correctly detected attacks)")
        logger.info(f"True Negatives:  {tn:6d} (Correctly identified normal)")
        logger.info(f"False Positives: {fp:6d} (Normal flagged as attack)")
        logger.info(f"False Negatives: {fn:6d} (Missed attacks)")
        logger.info(f"\nFalse Positive Rate: {fpr:.4f} ({fpr*100:.2f}%)")
        logger.info(f"False Negative Rate: {fnr:.4f} ({fnr*100:.2f}%)")

        # Classification Report
        logger.info("\nDetailed Classification Report:")
        logger.info("-" * 70)
        report = classification_report(y_test, y_pred,
                                       target_names=['Normal', 'Attack'],
                                       digits=4)
        logger.info(report)
        logger.info("-" * 70)

    def cross_validate(self, X_train, y_train, cv=5):
        """
        Perform cross-validation

        Args:
            X_train: Training features
            y_train: Training labels
            cv: Number of cross-validation folds
        """
        logger.info("\n" + "="*70)
        logger.info(f"CROSS-VALIDATION ({cv}-Fold)")
        logger.info("="*70 + "\n")

        logger.info("Running cross-validation...")

        # Perform cross-validation
        cv_scores = cross_val_score(
            self.model, X_train, y_train,
            cv=cv, scoring='accuracy', n_jobs=-1, verbose=1
        )

        logger.info(f"\nCross-validation scores: {cv_scores}")
        logger.info(f"Mean CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

    def save_model(self):
        """Save trained model to disk"""
        logger.info("\n" + "="*70)
        logger.info("SAVING MODEL")
        logger.info("="*70 + "\n")

        # Create models directory
        os.makedirs(MODELS_DIR, exist_ok=True)

        # Save model
        logger.info(f"Saving model to {RF_MODEL_PATH}")
        joblib.dump(self.model, RF_MODEL_PATH)

        # Save model metadata
        metadata = {
            'model_type': 'RandomForestClassifier',
            'n_estimators': ML_CONFIG['rf_n_estimators'],
            'max_depth': ML_CONFIG['rf_max_depth'],
            'feature_names': self.feature_names,
            'n_features': len(self.feature_names),
            'training_time': self.training_time,
            'metrics': self.metrics
        }

        metadata_path = MODELS_DIR / 'rf_metadata.joblib'
        joblib.dump(metadata, metadata_path)

        logger.info(f"Model saved successfully!")
        logger.info(f"Metadata saved to {metadata_path}")

    def display_feature_importance(self):
        """Display feature importance from trained model"""
        logger.info("\n" + "="*70)
        logger.info("FEATURE IMPORTANCE")
        logger.info("="*70 + "\n")

        # Get feature importances
        importances = self.model.feature_importances_

        # Create DataFrame
        importance_df = pd.DataFrame({
            'feature': self.feature_names,
            'importance': importances
        }).sort_values('importance', ascending=False)

        # Display top 10
        logger.info("Top 10 Most Important Features:")
        logger.info("-" * 70)
        for i, (idx, row) in enumerate(importance_df.head(10).iterrows(), 1):
            logger.info(f"{i:2d}. {row['feature']:25s} | {row['importance']:.6f}")
        logger.info("-" * 70)


def main():
    """Main training function"""

    logger.info("="*70)
    logger.info("RT-IDPS RANDOM FOREST TRAINING")
    logger.info("="*70 + "\n")

    # Initialize trainer
    trainer = RandomForestTrainer()

    try:
        # Load data
        X_train, X_test, y_train, y_test = trainer.load_data()

        # Train model
        trainer.train_model(X_train, y_train)

        # Evaluate model
        trainer.evaluate_model(X_test, y_test)

        # Cross-validation (optional, takes time)
        # trainer.cross_validate(X_train, y_train, cv=5)

        # Display feature importance
        trainer.display_feature_importance()

        # Save model
        trainer.save_model()

        # Summary
        logger.info("\n" + "="*70)
        logger.info("TRAINING SUMMARY")
        logger.info("="*70)
        logger.info(f"Training time: {trainer.training_time:.2f} seconds")
        logger.info(f"Test Accuracy: {trainer.metrics['accuracy']:.4f} ({trainer.metrics['accuracy']*100:.2f}%)")
        logger.info(f"Model saved to: {RF_MODEL_PATH}")
        logger.info("="*70 + "\n")

        logger.info("✅ Random Forest training complete!")
        logger.info("\nNext step: Train K-Means (ml/train_kmeans.py)")

    except Exception as e:
        logger.error(f"Error during training: {e}")
        raise


if __name__ == "__main__":
    main()