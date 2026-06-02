# Real-Time Hybrid ML Intrusion Detection Runbook

This project is a real-time intrusion detection and prevention system (RT-IDPS). It combines a supervised Random Forest classifier with an unsupervised K-Means anomaly detector, then exposes detection status, alerts, traffic, logs, and blocked IP controls through a Flask dashboard.

## Project Overview

The system has five main parts:

- `ml/`: data preprocessing, feature selection, Random Forest training, K-Means training, and hybrid decision logic.
- `realtime/`: packet capture, lightweight feature extraction, detection service, and IP blocking logic.
- `dashboard/`: Flask web application, HTML templates, dashboard pages, and JSON API endpoints.
- `utils/`: shared configuration and logging helpers.
- `tests/`: system-level checks for configuration, logging, model loading, detector service, dashboard routes, and file structure.

The intended flow is:

1. Prepare the NSL-KDD dataset.
2. Preprocess the dataset into model-ready features.
3. Select the best features.
4. Train the Random Forest model for known attack classification.
5. Train the K-Means model to identify anomalous traffic.
6. Start the Flask dashboard.
7. Use the dashboard/API to start or stop the realtime detector service.

## Requirements

Install Python 3.10 or newer if possible, then install the required packages:

```bash
pip install -r requirements.txt
```

The important dependencies are:

- Flask and Flask-CORS for the dashboard.
- pandas, numpy, scipy, scikit-learn, joblib for ML processing and model storage.
- scapy for packet capture.
- psutil and requests for system/runtime support.
- matplotlib and seaborn for feature importance output.

## Dataset Setup

The preprocessing script currently reads the dataset path from `utils/config.py`:

```python
NSL_KDD_PATH = DATA_DIR / "nsl_kdd.csv"
```

The repository currently contains:

```text
data/nsl_kdd_train.txt
data/nsl_kdd_test.txt
```

Before running preprocessing, either copy or rename the training file:

```bash
cp data/nsl_kdd_train.txt data/nsl_kdd.csv
```

Or update `NSL_KDD_PATH` in `utils/config.py` to point directly to `data/nsl_kdd_train.txt`.

## Configuration

Most runtime settings are in `utils/config.py`.

Important values:

- `ML_CONFIG`: number of selected features, Random Forest settings, K-Means cluster count, test split size.
- `DASHBOARD_CONFIG`: dashboard host, port, debug mode, and threading.
- `SECURITY_CONFIG`: dashboard username, password, session lifetime, and secret key.
- `REALTIME_CONFIG`: network interface and realtime detection settings.
- `PREVENTION_CONFIG`: IP blocking settings.

Default dashboard credentials are:

```text
Username: admin
Password: admin123
```

Change these before using the project outside a local development environment.

## Train the ML Pipeline

Run the scripts from the project root.

First preprocess the NSL-KDD data:

```bash
python ml/preprocess.py
```

This creates:

```text
data/processed_data.csv
```

Next run feature selection:

```bash
python ml/feature_selection.py
```

This should create:

```text
data/processed_data_reduced.csv
models/feature_names.pkl
logs/feature_importance.png
```

Train the Random Forest classifier:

```bash
python ml/train_rf.py
```

This creates:

```text
models/random_forest.pkl
models/rf_metadata.joblib
```

Train the K-Means anomaly detector:

```bash
python ml/train_kmeans.py
```

This creates:

```text
models/kmeans.pkl
models/kmeans_metadata.joblib
```

The detector service needs both `models/random_forest.pkl` and `models/kmeans.pkl` before it can start successfully.

## Run the Dashboard

Start the Flask dashboard from the project root:

```bash
python dashboard/app.py
```

Then open:

```text
http://127.0.0.1:5000
```

Login with the credentials configured in `utils/config.py`.

The dashboard pages are:

- `/dashboard`: overview and summary metrics.
- `/alerts`: intrusion alerts.
- `/traffic`: live traffic view.
- `/blocked`: blocked IP management.
- `/logs`: event logs.
- `/status`: system health.

## Start and Stop Detection

The dashboard exposes detector control endpoints. After logging in, the UI can call these endpoints:

```text
POST /api/detector/start
POST /api/detector/stop
POST /api/detector/pause
POST /api/detector/resume
GET  /api/detector/stats
GET  /api/alerts/live
GET  /api/packets/live
```

The detector service loads the trained models, captures packets with Scapy, extracts lightweight features, applies the hybrid ML decision engine, stores recent packets and alerts, and optionally blocks malicious source IPs.

Packet capture may require elevated permissions depending on your operating system and network interface. The configured interface is currently:

```python
REALTIME_CONFIG["interface"] = "eth0"
```

Update this to match your local interface if needed.

## Logs and Outputs

Runtime logs are written under `logs/`.

Common files include:

- `logs/system.log`: general application logs.
- `logs/dashboard.log`: dashboard activity.
- `logs/preprocessing.log`: preprocessing output.
- `logs/rf_training.log`: Random Forest training output.
- `logs/kmeans_training.log`: K-Means training output.
- `logs/detector_service.log`: realtime detector service output.
- `logs/intrusion_logs.csv`: recorded intrusion events.
- `logs/blocked_ips.json`: simulated or tracked blocked IPs.

## Run System Tests

Run:

```bash
python tests/test_system.py
```

The test script checks:

- Configuration loading.
- Logging and intrusion logging.
- Required file and directory structure.
- ML model loading.
- Hybrid detection engine.
- Feature extraction.
- IP blocking.
- Detector service.
- Flask dashboard routes.

Some tests depend on trained models. If model tests fail, run the training pipeline first.

## Troubleshooting

If preprocessing cannot find the dataset, make sure `data/nsl_kdd.csv` exists or update `NSL_KDD_PATH` in `utils/config.py`.

If model loading fails, confirm these files exist:

```text
models/random_forest.pkl
models/kmeans.pkl
```

If packet capture fails, check the configured interface and run with the permissions required by Scapy on your system.

If login fails, confirm `SECURITY_CONFIG["admin_username"]` and `SECURITY_CONFIG["admin_password"]` in `utils/config.py`.

If the dashboard starts but detector statistics stay offline, start the detector from the dashboard controls or call `POST /api/detector/start` after logging in.

## Suggested Development Order

For a fresh setup, use this order:

```bash
pip install -r requirements.txt
cp data/nsl_kdd_train.txt data/nsl_kdd.csv
python ml/preprocess.py
python ml/feature_selection.py
python ml/train_rf.py
python ml/train_kmeans.py
python tests/test_system.py
python dashboard/app.py
```

After that, open `http://127.0.0.1:5000`, log in, and start the detector from the dashboard.
