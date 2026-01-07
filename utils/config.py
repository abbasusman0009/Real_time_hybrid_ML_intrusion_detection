import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.parent

# Paths
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"
INTRUSION_LOG_PATH = LOGS_DIR / "intrusion_logs.csv"
STATIC_DIR = BASE_DIR / "dashboard" / "static"
TEMPLATES_DIR = BASE_DIR / "dashboard" / "templates"

# ML Dataset Paths
NSL_KDD_PATH = DATA_DIR / "nsl_kdd.csv"
PROCESSED_DATA_PATH = DATA_DIR / "processed_data.csv"

# ML Model Paths
RF_MODEL_PATH = MODELS_DIR / "random_forest.pkl"
KMEANS_MODEL_PATH = MODELS_DIR / "kmeans.pkl"
FEATURE_NAMES_PATH = MODELS_DIR / "feature_names.pkl"

# NSL-KDD Feature Names (41 features)
NSLKDD_FEATURES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

# ML Settings
ML_CONFIG = {
    "n_features": 20,           # Number of features to select
    "rf_n_estimators": 100,     # Random Forest trees
    "rf_max_depth": 20,         # Tree depth
    "rf_random_state": 42,      # Random state for reproducibility
    "kmeans_n_clusters": 5,     # Number of clusters for K-Means
    "kmeans_random_state": 42,  # Random state for K-Means
    "test_size": 0.2,           # Test set size
    "random_state": 42,         # General random state
}

# Dashboard Settings
DASHBOARD_CONFIG = {
    "host": "127.0.0.1",
    "port": 5000,
    "debug": True,
    "threaded": True,
    "secret_key": "change-this-in-production",  # Change in production!
    "session_timeout": 3600,    # Session timeout in seconds
}

# Security Settings (CHANGE THESE!)
SECURITY_CONFIG = {
    "admin_username": "admin",
    "admin_password": "admin123",  # Hash in production!
    "max_login_attempts": 5,
    "lockout_duration": 900,     # 15 minutes
    "session_lifetime": 3600,    # Session lifetime in seconds
    "secret_key": "change-this-in-production",  # Change in production!
}

# Logging Settings
LOGGING_CONFIG = {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": LOGS_DIR / "system.log",
    "max_bytes": 10485760,       # 10MB
    "backup_count": 5,
}

# Real-time Settings
REALTIME_CONFIG = {
    "interface": "eth0",         # Network interface to monitor
    "packet_buffer_size": 65536, # Packet buffer size
    "detection_interval": 1.0,   # Detection interval in seconds
    "max_blocked_ips": 1000,     # Maximum blocked IPs
    "block_duration": 3600,      # Block duration in seconds
}

# Detection Settings
DETECTION_CONFIG = {
    "packet_capture_interface": "eth0",  # Network interface for packet capture
    "confidence_threshold": 0.8,         # Minimum confidence for alerts
    "batch_size": 100,                   # Batch processing size
    "timeout": 30.0,                     # Detection timeout in seconds
}

# Prevention Settings
PREVENTION_CONFIG = {
    "enable_blocking": True,      # Enable/disable blocking
    "block_duration": 3600,       # Block duration in seconds
    "use_iptables": False,        # False for simulated blocking (iptables not available)
    "max_blocked_ips": 1000,      # Maximum IPs to block
}

# Create directories if they don't exist
for dir_path in [DATA_DIR, MODELS_DIR, LOGS_DIR]:
    dir_path.mkdir(exist_ok=True)
