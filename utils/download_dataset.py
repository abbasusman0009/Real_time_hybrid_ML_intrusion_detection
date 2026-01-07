"""
NSL-KDD Dataset Download Helper
Downloads and prepares NSL-KDD dataset for RT-IDPS
"""

import os
import sys
import urllib.request
import pandas as pd

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import NSL_KDD_PATH, DATA_DIR
from utils.logger import setup_logger

logger = setup_logger('DatasetDownload', log_file='logs/dataset_download.log')

# NSL-KDD URLs (from GitHub mirror)
URLS = {
    'train': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt',
    'test': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt'
}


def download_file(url, destination):
    """
    Download file from URL

    Args:
        url: URL to download from
        destination: Local file path
    """
    logger.info(f"Downloading from {url}")
    logger.info(f"Saving to {destination}")

    try:
        urllib.request.urlretrieve(url, destination)
        logger.info("✓ Download complete")
    except Exception as e:
        logger.error(f"Download failed: {e}")
        raise


def download_nsl_kdd():
    """Download NSL-KDD dataset"""

    logger.info("="*70)
    logger.info("NSL-KDD DATASET DOWNLOAD")
    logger.info("="*70 + "\n")

    # Create data directory
    os.makedirs(DATA_DIR, exist_ok=True)

    # Download training set
    train_path = DATA_DIR / 'nsl_kdd_train.txt'
    if not train_path.exists():
        logger.info("Downloading training set...")
        download_file(URLS['train'], train_path)
    else:
        logger.info("✓ Training set already exists")

    # Download test set
    test_path = DATA_DIR / 'nsl_kdd_test.txt'
    if not test_path.exists():
        logger.info("\nDownloading test set...")
        download_file(URLS['test'], test_path)
    else:
        logger.info("✓ Test set already exists")

    # Combine train and test for this project
    logger.info("\nCombining datasets...")

    # Read both files
    train_df = pd.read_csv(train_path, header=None)
    test_df = pd.read_csv(test_path, header=None)

    # Combine
    combined_df = pd.concat([train_df, test_df], ignore_index=True)

    # Save combined dataset
    combined_df.to_csv(NSL_KDD_PATH, index=False, header=False)

    logger.info(f"✓ Combined dataset saved to {NSL_KDD_PATH}")
    logger.info(f"  Training samples: {len(train_df)}")
    logger.info(f"  Test samples: {len(test_df)}")
    logger.info(f"  Total samples: {len(combined_df)}")

    logger.info("\n" + "="*70)
    logger.info("DOWNLOAD COMPLETE")
    logger.info("="*70)
    logger.info(f"\nDataset ready at: {NSL_KDD_PATH}")
    logger.info("\nNext step: Run preprocessing")
    logger.info("  python ml/preprocess.py")
    logger.info("="*70 + "\n")


def main():
    """Main function"""

    try:
        # Check if dataset already exists
        if NSL_KDD_PATH.exists():
            logger.info(f"Dataset already exists at {NSL_KDD_PATH}")
            response = input("Download again? (y/n): ")
            if response.lower() != 'y':
                logger.info("Skipping download")
                return

        download_nsl_kdd()

    except Exception as e:
        logger.error(f"Error: {e}")
        logger.info("\nManual download instructions:")
        logger.info("1. Visit: https://www.unb.ca/cic/datasets/nsl.html")
        logger.info("2. Download KDDTrain+.txt and KDDTest+.txt")
        logger.info(f"3. Save as {NSL_KDD_PATH}")
        raise


if __name__ == "__main__":
    main()