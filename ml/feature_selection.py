"""
RT-IDPS Feature Selection Module
Selects most important features for real-time detection
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import (PROCESSED_DATA_PATH, ML_CONFIG, MODELS_DIR,
                          FEATURE_NAMES_PATH)
from utils.logger import setup_logger

# Setup logger
logger = setup_logger('FeatureSelection', log_file='logs/feature_selection.log')


class FeatureSelector:
    """Select most important features using Random Forest"""

    def __init__(self, n_features=20):
        """
        Initialize Feature Selector

        Args:
            n_features: Number of top features to select
        """
        self.n_features = n_features
        self.feature_importances = None
        self.selected_features = None
        self.rf_model = None

    def load_data(self, filepath):
        """
        Load preprocessed data

        Args:
            filepath: Path to processed CSV

        Returns:
            X (features), y (labels)
        """
        logger.info(f"Loading preprocessed data from {filepath}")

        df = pd.read_csv(filepath)
        logger.info(f"Loaded {len(df)} records")

        # Separate features and labels
        exclude_cols = ['attack_type', 'attack_category', 'binary_label', 'difficulty']
        feature_cols = [col for col in df.columns if col not in exclude_cols]

        X = df[feature_cols]
        y = df['binary_label']

        logger.info(f"Features: {X.shape[1]}")
        logger.info(f"Normal samples: {(y == 0).sum()}")
        logger.info(f"Attack samples: {(y == 1).sum()}")

        return X, y, feature_cols

    def split_data(self, X, y):
        """
        Split data into train and test sets

        Args:
            X: Features
            y: Labels

        Returns:
            X_train, X_test, y_train, y_test
        """
        logger.info("Splitting data into train/test sets...")

        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=ML_CONFIG['test_size'],
            random_state=ML_CONFIG['random_state'],
            stratify=y
        )

        logger.info(f"Train set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")

        return X_train, X_test, y_train, y_test

    def train_temporary_rf(self, X_train, y_train):
        """
        Train a temporary Random Forest for feature importance

        Args:
            X_train: Training features
            y_train: Training labels
        """
        logger.info("\n" + "="*70)
        logger.info("TRAINING TEMPORARY RANDOM FOREST FOR FEATURE IMPORTANCE")
        logger.info("="*70 + "\n")

        self.rf_model = RandomForestClassifier(
            n_estimators=50,  # Smaller for faster training
            max_depth=10,
            random_state=ML_CONFIG['random_state'],
            n_jobs=-1,
            verbose=1
        )

        logger.info("Training Random Forest...")
        self.rf_model.fit(X_train, y_train)
        logger.info("Training complete!")

        # Get feature importances
        self.feature_importances = self.rf_model.feature_importances_

    def select_top_features(self, feature_names):
        """
        Select top N most important features

        Args:
            feature_names: List of feature names

        Returns:
            List of selected feature names
        """
        logger.info("\n" + "="*70)
        logger.info(f"SELECTING TOP {self.n_features} FEATURES")
        logger.info("="*70 + "\n")

        # Create DataFrame of feature importances
        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': self.feature_importances
        })

        # Sort by importance
        importance_df = importance_df.sort_values('importance', ascending=False)

        # Select top N features
        self.selected_features = importance_df.head(self.n_features)['feature'].tolist()

        # Display selected features
        logger.info("Selected Features (ranked by importance):")
        logger.info("-" * 70)
        for i, (idx, row) in enumerate(importance_df.head(self.n_features).iterrows(), 1):
            logger.info(f"{i:2d}. {row['feature']:25s} | Importance: {row['importance']:.6f}")
        logger.info("-" * 70)

        # Calculate cumulative importance
        cumulative_importance = importance_df.head(self.n_features)['importance'].sum()
        logger.info(f"\nCumulative importance of top {self.n_features} features: {cumulative_importance:.4f} ({cumulative_importance*100:.2f}%)")

        return self.selected_features

    def plot_feature_importance(self, feature_names, save_path='logs/feature_importance.png'):
        """
        Plot feature importance

        Args:
            feature_names: List of all feature names
            save_path: Path to save plot
        """
        logger.info(f"\nGenerating feature importance plot...")

        # Create figure
        plt.figure(figsize=(12, 8))

        # Create DataFrame for plotting
        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': self.feature_importances
        }).sort_values('importance', ascending=False).head(self.n_features)

        # Create bar plot
        sns.barplot(data=importance_df, x='importance', y='feature', palette='viridis')
        plt.title(f'Top {self.n_features} Most Important Features', fontsize=16, fontweight='bold')
        plt.xlabel('Importance Score', fontsize=12)
        plt.ylabel('Feature', fontsize=12)
        plt.tight_layout()

        # Save plot
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        logger.info(f"Plot saved to: {save_path}")

        plt.close()

    def save_selected_features(self, filepath):
        """
        Save selected feature names

        Args:
            filepath: Path to save feature names
        """
        logger.info(f"\nSaving selected features to {filepath}")

        # Create directory if needed
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # Save using joblib
        joblib.dump(self.selected_features, filepath)
        logger.info(f"Saved {len(self.selected_features)} feature names")

    def create_reduced_dataset(self, X, y, feature_cols, output_path):
        """
        Create dataset with only selected features

        Args:
            X: Full feature set
            y: Labels
            feature_cols: All feature column names
            output_path: Path to save reduced dataset
        """
        logger.info("\nCreating reduced dataset with selected features...")

        # Select only important features
        X_reduced = X[self.selected_features]

        # Combine with labels
        df_reduced = X_reduced.copy()
        df_reduced['binary_label'] = y

        # Save
        df_reduced.to_csv(output_path, index=False)
        logger.info(f"Saved reduced dataset to: {output_path}")
        logger.info(f"Shape: {df_reduced.shape}")


def main():
    """Main feature selection function"""

    logger.info("="*70)
    logger.info("RT-IDPS FEATURE SELECTION")
    logger.info("="*70 + "\n")

    # Check if processed data exists
    if not PROCESSED_DATA_PATH.exists():
        logger.error(f"Processed data not found at {PROCESSED_DATA_PATH}")
        logger.info("\nPlease run preprocessing first: python ml/preprocess.py")
        return

    # Initialize selector
    n_features = ML_CONFIG['n_features']
    selector = FeatureSelector(n_features=n_features)

    # Load data
    X, y, feature_cols = selector.load_data(PROCESSED_DATA_PATH)

    # Split data
    X_train, X_test, y_train, y_test = selector.split_data(X, y)

    # Train temporary RF
    selector.train_temporary_rf(X_train, y_train)

    # Select top features
    selected_features = selector.select_top_features(feature_cols)

    # Plot feature importance
    selector.plot_feature_importance(feature_cols)

    # Save selected features
    selector.save_selected_features(FEATURE_NAMES_PATH)

    # Create reduced dataset
    from utils.config import DATA_DIR
    reduced_path = DATA_DIR / "processed_data_reduced.csv"
    selector.create_reduced_dataset(X, y, feature_cols, reduced_path)

    # Summary
    logger.info("\n" + "="*70)
    logger.info("FEATURE SELECTION SUMMARY")
    logger.info("="*70)
    logger.info(f"Original features: {len(feature_cols)}")
    logger.info(f"Selected features: {len(selected_features)}")
    logger.info(f"Reduction: {(1 - len(selected_features)/len(feature_cols))*100:.1f}%")
    logger.info(f"Feature names saved to: {FEATURE_NAMES_PATH}")
    logger.info(f"Reduced dataset saved to: {reduced_path}")
    logger.info("="*70 + "\n")

    logger.info("✅ Feature selection complete!")
    logger.info("\nNext step: Train Random Forest (ml/train_rf.py)")


if __name__ == "__main__":
    main()