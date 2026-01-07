"""
RT-IDPS Data Preprocessing Module
Prepares NSL-KDD dataset for machine learning
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import NSL_KDD_PATH, PROCESSED_DATA_PATH, ML_CONFIG, NSLKDD_FEATURES
from utils.logger import setup_logger

# Setup logger
logger = setup_logger('DataPreprocessing', log_file='logs/preprocessing.log')

# NSL-KDD Column Names
COLUMN_NAMES = NSLKDD_FEATURES + ['attack_type', 'difficulty']

# Attack category mapping
ATTACK_CATEGORIES = {
    'normal': 'normal',
    # DoS attacks
    'back': 'dos', 'land': 'dos', 'neptune': 'dos', 'pod': 'dos', 'smurf': 'dos',
    'teardrop': 'dos', 'mailbomb': 'dos', 'apache2': 'dos', 'processtable': 'dos',
    'udpstorm': 'dos',
    # Probe attacks
    'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe', 'satan': 'probe',
    'mscan': 'probe', 'saint': 'probe',
    # R2L attacks (Remote to Local)
    'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l', 'multihop': 'r2l',
    'phf': 'r2l', 'spy': 'r2l', 'warezclient': 'r2l', 'warezmaster': 'r2l',
    'sendmail': 'r2l', 'named': 'r2l', 'snmpgetattack': 'r2l', 'snmpguess': 'r2l',
    'xlock': 'r2l', 'xsnoop': 'r2l', 'worm': 'r2l',
    # U2R attacks (User to Root)
    'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r', 'rootkit': 'u2r',
    'httptunnel': 'u2r', 'ps': 'u2r', 'sqlattack': 'u2r', 'xterm': 'u2r'
}


class NSLKDDPreprocessor:
    """Preprocessor for NSL-KDD dataset"""

    def __init__(self):
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.feature_columns = None

    def load_data(self, filepath):
        """
        Load NSL-KDD dataset

        Args:
            filepath: Path to CSV file

        Returns:
            DataFrame with loaded data
        """
        logger.info(f"Loading data from {filepath}")

        try:
            # Load dataset with error handling for inconsistent rows
            df = pd.read_csv(filepath, names=COLUMN_NAMES, on_bad_lines='skip', engine='python')
            logger.info(f"Loaded {len(df)} records")
            logger.info(f"Columns: {df.shape[1]}")

            return df

        except FileNotFoundError:
            logger.error(f"File not found: {filepath}")
            logger.info("\n" + "="*70)
            logger.info("DOWNLOAD NSL-KDD DATASET")
            logger.info("="*70)
            logger.info("\nPlease download the NSL-KDD dataset:")
            logger.info("1. Visit: https://www.unb.ca/cic/datasets/nsl.html")
            logger.info("2. Download KDDTrain+.txt and KDDTest+.txt")
            logger.info("\nOr use this direct link:")
            logger.info("https://github.com/defcom17/NSL_KDD")
            logger.info("="*70 + "\n")
            raise

        except Exception as e:
            logger.error(f"Error loading data: {e}")
            raise
    
    def explore_data(self, df):
        """
        Explore dataset characteristics
        
        Args:
            df: Input DataFrame
        """
        logger.info("\n" + "="*70)
        logger.info("DATASET EXPLORATION")
        logger.info("="*70)
        
        logger.info(f"\nShape: {df.shape}")
        logger.info(f"Memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
        
        # Check for missing values
        missing = df.isnull().sum()
        if missing.sum() > 0:
            logger.warning(f"\nMissing values found:\n{missing[missing > 0]}")
        else:
            logger.info("\nNo missing values found ✓")
        
        # Data types
        logger.info(f"\nData types:\n{df.dtypes.value_counts()}")
        
        # Attack distribution
        logger.info("\nAttack type distribution:")
        attack_dist = df['attack_type'].value_counts()
        for attack, count in attack_dist.head(10).items():
            logger.info(f"  {attack}: {count} ({count/len(df)*100:.2f}%)")
        
        logger.info("="*70 + "\n")
    
    def map_attack_categories(self, df):
        """
        Map specific attack types to broader categories
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with attack_category column
        """
        logger.info("Mapping attack types to categories...")
        
        # Create attack category column
        df['attack_category'] = df['attack_type'].map(ATTACK_CATEGORIES)
        
        # Check for unmapped attacks
        unmapped = df[df['attack_category'].isnull()]['attack_type'].unique()
        if len(unmapped) > 0:
            logger.warning(f"Unmapped attack types: {unmapped}")
            # Default to 'other' for unmapped
            df['attack_category'] = df['attack_category'].fillna('other')
        
        # Distribution of categories
        logger.info("\nAttack category distribution:")
        for category, count in df['attack_category'].value_counts().items():
            logger.info(f"  {category}: {count} ({count/len(df)*100:.2f}%)")
        
        return df
    
    def create_binary_labels(self, df):
        """
        Create binary labels (normal=0, attack=1)
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with binary_label column
        """
        logger.info("Creating binary labels...")
        
        df['binary_label'] = (df['attack_category'] != 'normal').astype(int)
        
        normal_count = (df['binary_label'] == 0).sum()
        attack_count = (df['binary_label'] == 1).sum()
        
        logger.info(f"Normal: {normal_count} ({normal_count/len(df)*100:.2f}%)")
        logger.info(f"Attack: {attack_count} ({attack_count/len(df)*100:.2f}%)")
        
        return df
    
    def encode_categorical_features(self, df):
        """
        Encode categorical features using Label Encoding
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with encoded categorical features
        """
        logger.info("Encoding categorical features...")
        
        categorical_cols = ['protocol_type', 'service', 'flag']
        
        for col in categorical_cols:
            if col in df.columns:
                logger.info(f"  Encoding {col} ({df[col].nunique()} unique values)")
                
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
                self.label_encoders[col] = le
        
        return df
    
    def normalize_features(self, df, fit=True):
        """
        Normalize numerical features using StandardScaler
        
        Args:
            df: Input DataFrame
            fit: Whether to fit the scaler (True for training, False for test)
            
        Returns:
            DataFrame with normalized features
        """
        logger.info("Normalizing numerical features...")
        
        # Identify numerical columns (exclude labels)
        exclude_cols = ['attack_type', 'attack_category', 'binary_label', 'difficulty']
        numerical_cols = [col for col in df.columns if col not in exclude_cols]
        
        self.feature_columns = numerical_cols
        
        if fit:
            df[numerical_cols] = self.scaler.fit_transform(df[numerical_cols])
            logger.info(f"  Fitted scaler on {len(numerical_cols)} features")
        else:
            df[numerical_cols] = self.scaler.transform(df[numerical_cols])
            logger.info(f"  Transformed {len(numerical_cols)} features")
        
        return df
    
    def handle_infinite_values(self, df):
        """
        Replace infinite values with large finite numbers
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with no infinite values
        """
        logger.info("Handling infinite values...")
        
        # Replace inf with large number
        df = df.replace([np.inf, -np.inf], np.nan)
        
        # Check for NaN values
        nan_count = df.isnull().sum().sum()
        if nan_count > 0:
            logger.warning(f"Found {nan_count} NaN values after inf replacement")
            # Fill NaN with 0
            df = df.fillna(0)
            logger.info("Filled NaN values with 0")
        
        return df
    
    def preprocess_pipeline(self, df, fit=True):
        """
        Complete preprocessing pipeline
        
        Args:
            df: Input DataFrame
            fit: Whether to fit transformers (True for training, False for test)
            
        Returns:
            Preprocessed DataFrame
        """
        logger.info("\n" + "="*70)
        logger.info("PREPROCESSING PIPELINE")
        logger.info("="*70 + "\n")
        
        # Step 1: Map attack categories
        df = self.map_attack_categories(df)
        
        # Step 2: Create binary labels
        df = self.create_binary_labels(df)
        
        # Step 3: Encode categorical features
        df = self.encode_categorical_features(df)
        
        # Step 4: Handle infinite values
        df = self.handle_infinite_values(df)
        
        # Step 5: Normalize features
        df = self.normalize_features(df, fit=fit)
        
        logger.info("\n" + "="*70)
        logger.info("PREPROCESSING COMPLETE")
        logger.info("="*70 + "\n")
        
        return df
    
    def save_processed_data(self, df, filepath):
        """
        Save preprocessed data to CSV
        
        Args:
            df: Processed DataFrame
            filepath: Output file path
        """
        logger.info(f"Saving processed data to {filepath}")
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        df.to_csv(filepath, index=False)
        logger.info(f"Saved {len(df)} records")


def main():
    """Main preprocessing function"""
    
    logger.info("="*70)
    logger.info("RT-IDPS DATA PREPROCESSING")
    logger.info("="*70 + "\n")
    
    # Initialize preprocessor
    preprocessor = NSLKDDPreprocessor()
    
    # Check if NSL-KDD file exists
    if not NSL_KDD_PATH.exists():
        logger.error(f"NSL-KDD dataset not found at {NSL_KDD_PATH}")
        logger.info("\nPlease download the dataset and place it in the data/ folder")
        logger.info("See the error message above for download instructions")
        return
    
    # Load data
    df = preprocessor.load_data(NSL_KDD_PATH)
    
    # Explore data
    preprocessor.explore_data(df)
    
    # Preprocess
    df_processed = preprocessor.preprocess_pipeline(df, fit=True)
    
    # Save processed data
    preprocessor.save_processed_data(df_processed, PROCESSED_DATA_PATH)
    
    # Summary statistics
    logger.info("\n" + "="*70)
    logger.info("PREPROCESSING SUMMARY")
    logger.info("="*70)
    logger.info(f"Original records: {len(df)}")
    logger.info(f"Processed records: {len(df_processed)}")
    logger.info(f"Features: {len(preprocessor.feature_columns)}")
    logger.info(f"Processed data saved to: {PROCESSED_DATA_PATH}")
    logger.info("="*70 + "\n")
    
    logger.info("✅ Data preprocessing complete!")
    logger.info("\nNext step: Run feature selection (ml/feature_selection.py)")


if __name__ == "__main__":
    main()
