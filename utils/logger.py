"""
RT-IDPS Logger Utility
Centralized logging for the entire system
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""

    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


def setup_logger(name, log_file=None, level=logging.INFO):
    """
    Setup a logger with both file and console handlers

    Args:
        name: Logger name
        log_file: Path to log file (optional)
        level: Logging level

    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_format = ColoredFormatter(
        '%(levelname)s | %(asctime)s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_format = logging.Formatter(
            '%(levelname)s | %(asctime)s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

    return logger


def log_intrusion(ip_address, attack_type, action, confidence=None, extra_info=None):
    """
    Log intrusion event to CSV file

    Args:
        ip_address: Source IP address
        attack_type: Type of attack detected
        action: Action taken (blocked, flagged, etc.)
        confidence: ML model confidence (optional)
        extra_info: Additional information (optional)
    """
    from utils.config import INTRUSION_LOG_PATH
    import csv

    log_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source_ip': ip_address,
        'attack_type': attack_type,
        'action': action,
        'confidence': confidence if confidence else 'N/A',
        'extra_info': extra_info if extra_info else ''
    }

    # Create log file with headers if it doesn't exist
    if not INTRUSION_LOG_PATH.exists():
        with open(INTRUSION_LOG_PATH, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=log_entry.keys())
            writer.writeheader()

    # Append log entry
    with open(INTRUSION_LOG_PATH, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=log_entry.keys())
        writer.writerow(log_entry)


# Create default system logger
system_logger = setup_logger(
    'RT-IDPS',
    log_file='logs/system.log',
    level=logging.INFO
)
