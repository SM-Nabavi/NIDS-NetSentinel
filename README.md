# NIDS NetSentinel

Real-time network intrusion detection system built on live packet capture, statistical flow feature extraction, and a LightGBM classifier trained on CSE-CIC-IDS2018.

NetSentinel watches a network interface, reconstructs bidirectional traffic flows in real time, extracts the same statistical features used by CICFlowMeter, and classifies each flow as benign or one of eight attack types with sub-second latency. Results are stored in a crash-safe local database and surfaced through a live SOC-style dashboard, with a built-in retraining pipeline to keep the model current with real traffic over time.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Dataset and Model](#dataset-and-model)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the System](#running-the-system)
- [Using the Dashboard](#using-the-dashboard)
- [Command-Line Utilities](#command-line-utilities)
- [Reliability and Error Handling](#reliability-and-error-handling)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Author](#author)

## Overview

Manual, rule-based inspection cannot keep up with modern network attacks (DDoS, botnets, brute-force) that unfold in seconds across thousands of packets. NetSentinel automates this: it captures live traffic, groups packets into bidirectional flows keyed on the standard 5-tuple (source IP, destination IP, source port, destination port, protocol), computes flow-level statistics as each flow evolves, and classifies each finished flow with a gradient-boosted tree model.

Input: raw traffic from a live network interface.
Output: for every completed flow, a label (Benign or one of eight attack types), a confidence score, a severity rating (INFO to CRITICAL), and a persisted, queryable record.

Typical use cases: a lightweight SOC-style monitor for a small or mid-sized network, early DDoS detection at the network edge, and lab/educational environments for studying flow-based intrusion detection. Unlike signature-based IDS/firewalls, NetSentinel classifies traffic based on learned behavioral patterns rather than matching predefined rules.

## Architecture

```
                         [ Network Interface Card ]
                                    | raw packets
                                    v
                 +-----------------------------------+
                 |   flow-capture (C, libpcap/Npcap)   |
                 |   packet -> flow, feature extraction |
                 +-----------------------------------+
                                    | JSON per flow (stdout)
                                    v
                 +-----------------------------------+
                 |          buffer_writer.py           |
                 |   crash-safe SQLite/WAL queue        |
                 +-----------------------------------+
                                    | polling (claim / lease)
                                    v
                 +-----------------------------------+
                 |   main.py  ->  inference.py          |
                 |   feature vector -> model_loader      |
                 |   -> LightGBM prediction              |
                 +-----------------------------------+
                                    | flow + detection result
                                    v
                 +-----------------------------------+
                 |   db_writer.py -> nids.db            |
                 |   flows, detections, alert view       |
                 +-----------------------------------+
                                    |
              +---------------------+--------------------+
              v                                           v
   +----------------------+                  +-------------------------+
   |    soc_server.py       |                  |      retraining.py       |
   |    API + dashboard.html|<-----------------|  semi-supervised learning |
   |    (control, stats,    |   control from UI|  on high-confidence flows |
   |     alerts)            |                  |  -> new model version     |
   +----------------------+                  +-------------------------+
              |
              v
   soc_pipeline_mgr.py
   (start / stop / monitor flow-capture + buffer_writer + main.py)
```

## Project Structure

```
.
├── README.md
├── requirements.in                Direct runtime dependencies (source of truth)
├── requirements.txt               pip-compile-locked, fully pinned lockfile
├── run.bat                        Windows quick-start launcher
│
├── data/                          Created at runtime
│   ├── nids.db                    SQLite database (raw queue, flows, detections)
│   ├── pipeline.pid                PIDs of the running pipeline processes
│   └── *.log                      Per-module log files
│
├── detection-service/
│   ├── models/                    Model artifacts (must be in place before running)
│   │   ├── lightgbm_nids_model.pkl / .txt
│   │   ├── standard_scaler.pkl
│   │   ├── label_mapping.json
│   │   ├── features_spec.json
│   │   └── model_version.json
│   │
│   └── src/
│       ├── buffer_writer.py       Crash-safe SQLite/WAL queue between flow-capture and main.py
│       ├── db_writer.py           Database access layer (schema, insert, claim/reclaim)
│       ├── inference.py           Feature vector construction and LightGBM inference
│       ├── model_loader.py        Loads the model, scaler, and label mappings
│       ├── main.py                Detection service (stdin mode or buffer polling mode)
│       ├── init_db.py             Initial schema and view creation
│       ├── retraining.py          Semi-supervised retraining on live traffic
│       ├── soc_pipeline_mgr.py    Starts / stops / monitors the pipeline processes
│       ├── soc_db_bridge.py       Lightweight CLI/JSON interface for stats and alerts
│       ├── soc_server.py          Dashboard HTTP server (Python standard library only)
│       └── dashboard.html         SOC dashboard interface
│
├── flow-capture/
│   ├── bin/flow-capture.exe       Compiled binary (MinGW-W64 / gcc)
│   ├── include/                   capture.h, flow_table.h, net_compat.h, time_compat.h, types.h
│   ├── src/                       main.c, capture.c, flow_table.c
│   └── build.bat                  Single entry point for building flow-capture.exe
│                                  (MinGW-W64 gcc + Npcap SDK; creates bin\,
│                                   skips rebuild if exe exists, use `force` to override)
│
└── notebooks/
    ├── data_processing.ipynb      Colab-ready CSE-CIC-IDS2018 cleaning and feature selection
    ├── model_training.ipynb       Colab-ready LightGBM training and evaluation
    └── outputs/
        ├── classification_report.txt
        ├── confusion_matrix.png
        ├── feature_importance.png
        ├── pca.png
        ├── tsne.png
        ├── umap.png
        ├── selected_features.json
        └── stage1_cleaning_stats.json
```

## Dataset and Model

The model is trained on the UNSW-Distrinet re-processed release of CSE-CIC-IDS2018 (dhoogla/distrinetcsecicids2018 on Kaggle), a corrected re-export of the original CIC dataset with real network traffic captured under a mix of normal user behavior and executed attack tools. Flow-level features were originally extracted with CICFlowMeter.

Preprocessing (`notebooks/data_processing.ipynb`):
- Removal of flow-identifying columns (Flow ID, IPs, ports, timestamp) to prevent the model from memorizing host identities instead of learning traffic behavior
- Removal of invalid values (Inf/NaN) and duplicate records
- Removal of the Web Attack and Infiltration classes due to insufficient / unreliable samples
- Downsampling of overrepresented classes to control volume and class imbalance
- Hybrid feature selection (variance threshold, correlation pruning, and a union of Random Forest importance, mutual information, and ANOVA F-test) reducing the feature space from 81 to 38 features
- A single StandardScaler fit on a stratified sample and applied consistently at both training and inference time

The final training set contains roughly 15.3 million labeled flows across 9 classes:

| ID | Class          |
|----|----------------|
| 0  | Benign         |
| 1  | Botnet Ares    |
| 2  | DDoS-HOIC      |
| 3  | DDoS-LOIC-HTTP |
| 4  | DDoS-LOIC-UDP  |
| 5  | DoS GoldenEye  |
| 6  | DoS Hulk       |
| 7  | DoS Slowloris  |
| 8  | SSH-BruteForce |

Training (`notebooks/model_training.ipynb`):
- Model: LightGBM, multiclass classification
- Split: stratified 70% train / 15% validation / 15% test, fixed `random_state=42`
- Class imbalance handled via inverse-frequency class weighting rather than oversampling, since the data is tabular rather than image-based
- Result: accuracy and F1-score near 100% on the held-out test set (macro F1 ≈ 99.98%)

Note: high accuracy on this benchmark does not guarantee identical performance on a given organization's live traffic, since traffic distributions differ (domain shift). This is the reason the `retraining.py` module exists — to periodically adapt the model to real traffic collected by this same deployment.

### Model Results

The trained LightGBM model was evaluated on the held-out test split using the same preprocessing and feature set used during training.

* **Model:** LightGBM Multiclass
* **Number of classes:** 9
* **Selected features:** 38
* **Train / Validation / Test split:** 70% / 15% / 15%
* **Random state:** 42
* **Macro F1-score:** ~99.998%
* **Weighted F1-score:** ~99.9997%

These results represent performance on the prepared CSE-CIC-IDS2018 benchmark dataset and should not be interpreted as a direct measure of performance on unseen real-world network traffic.

### Evaluation

The model evaluation includes the following generated outputs:

* Classification report with per-class precision, recall, and F1-score
* Confusion matrix
* Feature importance analysis
* PCA visualization
* t-SNE visualization
* UMAP visualization

These outputs are generated from the training and evaluation notebooks and are intended to provide additional insight into model performance and feature behavior.

### Feature Selection

The preprocessing pipeline reduces the original feature set from **81 features to 38 selected features**.

Feature selection combines:

* Variance thresholding
* Correlation-based feature pruning
* Random Forest feature importance
* Mutual information
* ANOVA F-test

The selected feature set is saved as part of the notebook outputs and is used consistently by the trained model.

### Training environment:
- Training was performed using Google Colab's free tier; the notebooks under `notebooks/` are organized for that environment and include dependency installation, dataset access from Google Drive or Colab storage, and export of the trained artifacts back to Google Drive.
- The notebooks are Colab-oriented; running them in a local Jupyter environment may require path and dependency adjustments.

Trained artifacts are expected at:
```
detection-service/models/
├── lightgbm_nids_model.pkl
├── lightgbm_nids_model.txt
├── standard_scaler.pkl
├── label_mapping.json
├── features_spec.json
└── model_version.json
```

Important: the order and computation of the 38 features must match training exactly, and the saved `StandardScaler` must be used at inference time. Changing the feature set or its order without retraining the model will break compatibility between the capture engine and the detection service.

## Prerequisites

- Windows 10/11. The current build is Windows-only (Npcap, Winsock, interface enumeration via Scapy, process management via `taskkill`)
- Administrator privileges (required for raw packet capture)
- Python 3.9 or later, added to PATH
- Npcap installed on the host (runtime requirement)
- For rebuilding the capture engine: MinGW-W64 (gcc toolchain, 64-bit, with `x86_64-w64-mingw32-gcc` on PATH) and the Npcap SDK extracted to `C:\Npcap-SDK` (or edit `NPCAP_SDK` inside `flow-capture\build.bat`)
### Trained model files

Before first run, the following files must exist under `detection-service/models/` (produced by the notebooks in `notebooks/`):

- `lightgbm_nids_model.pkl` or `lightgbm_nids_model.txt`
- `standard_scaler.pkl`
- `label_mapping.json` (optional — regenerated with the 9 default classes if missing)
- `features_spec.json` (optional — regenerated with the default 38-feature spec if missing)

Without the model and scaler files, the detection service intentionally refuses to start rather than run with an invalid or placeholder model.

The training notebooks are intended for Google Colab's free tier and are not part of the runtime pipeline. They only produce the model artifacts that must be placed under `detection-service/models/`.

## Installation

1. Install Npcap on the host machine (with "Install Npcap in WinPcap API-compatible mode" enabled). The SDK is only required if you plan to rebuild the capture engine.

2. Create and activate a virtual environment. This isolates NetSentinel's dependencies from the system Python and ensures every child process launched by the pipeline manager uses the same interpreter.

   Command Prompt (cmd.exe):
```
python -m venv .venv
.venv\Scripts\activate.bat
```

3. Install Python dependencies:
```
pip install -r requirements.txt
```

`requirements.in` lists the five direct runtime dependencies (numpy, scikit-learn, joblib, lightgbm, scapy) with major-version bounds. `requirements.txt` is the pip-compile-generated lockfile that pins every transitive package with hashes for reproducible installs. To regenerate the lockfile after editing `requirements.in`:
```
pip install pip-tools
pip-compile --output-file=requirements.txt requirements.in
```
Do not edit `requirements.txt` by hand — edit `requirements.in` and re-compile.

4. Place the trained model files (see above) under `detection-service/models/`. These files can be produced by running the Colab notebooks in `notebooks/`.

5. (Optional) Rebuild the capture engine if `flow-capture/bin/flow-capture.exe` is not present. The build uses MinGW-W64 gcc through a single script:
```
cd flow-capture
build.bat
```

The script handles everything automatically:
- Verifies that `x86_64-w64-mingw32-gcc` is on PATH
- Verifies that the Npcap SDK is present at `C:\Npcap-SDK`
- Creates the `bin\` directory if it does not exist
- Skips the build if `bin\flow-capture.exe` already exists (use `build.bat force` to rebuild anyway)
- Prints a clear error message and exits with a non-zero code on failure

If your Npcap SDK is not installed at `C:\Npcap-SDK`, edit the `NPCAP_SDK` variable at the top of `flow-capture\build.bat` before running it. For a 32-bit build, also change `CC` to `i686-w64-mingw32-gcc` and `LIBDIR` to `x86` in the same file.

## Running the System

From the project root, run as Administrator:
```
run.bat
```

This will create the `data/` directory, initialize the database schema, terminate any leftover processes from a previous run, and open the dashboard at:
```
http://127.0.0.1:3000
```

## Using the Dashboard

1. Select a physical network interface from the list (virtual adapters such as VPN, Hyper-V, and loopback are filtered out automatically).
2. Click Start. This launches `flow-capture.exe` on the selected interface, piped into `buffer_writer.py`, alongside `main.py --buffer` for detection.
3. Live statistics, security alerts, and per-module logs appear on the dashboard as traffic is processed.
4. Click Stop to shut the pipeline down cleanly.

Manual equivalent (without the dashboard, for debugging):
```
flow-capture\bin\flow-capture.exe -i "<device>" -t 2 | python detection-service\src\buffer_writer.py
python detection-service\src\main.py --buffer --db-path data\nids.db
```



## Command-Line Utilities

Pipeline control and monitoring:
```
python detection-service\src\soc_pipeline_mgr.py status
python detection-service\src\soc_pipeline_mgr.py start "<device>"
python detection-service\src\soc_pipeline_mgr.py stop
python detection-service\src\soc_pipeline_mgr.py combined-logs 100
```

Model retraining on accumulated high-confidence detections:
```
python detection-service\src\retraining.py --action stats
python detection-service\src\retraining.py --action start --limit 10000 --threshold 0.8
python detection-service\src\retraining.py --action status
```
Retrained models are versioned under `detection-service/models/`; switching the active model can be done from the dashboard or with `set_active_model` in `retraining.py`.

## Reliability and Error Handling

- Crash-safe queue: flows are written to a SQLite/WAL-backed table with an explicit claim/lease mechanism, so a crash or restart of any module never silently drops or duplicates a flow; unprocessed claimed rows are automatically reclaimed after a lease timeout.
- Insert failures during detection are never marked as processed, so a temporary database error leads to a retry on the next cycle instead of a lost detection.
- Malformed JSON lines from the capture engine or queue are skipped and logged, without stopping the pipeline.
- Dual PID tracking (`pipeline.pid`) ensures the pipeline can be stopped reliably from a separate process (e.g. the dashboard), avoiding orphaned background processes.
- Missing model or scaler files cause the detection service to fail fast at startup with a clear error, rather than run in an undefined state.
- Each module writes to its own log file (`flow_capture.log`, `buffer_writer.log`, `main_processor.log`, `pipeline_manager.log`) to simplify troubleshooting.

## Known Limitations

- Windows-only; no Linux or containerized deployment path currently exists.
- Single-server deployment with no redundancy; if the host goes down, detection stops entirely.
- The original design targeted Kafka and TimescaleDB; the current implementation uses a simpler SQLite/WAL queue, suitable for small-to-medium networks rather than very high-throughput or multi-server deployments.
- The model is trained on CSE-CIC-IDS2018 only, not on traffic from a specific deployment; near-100% benchmark accuracy does not guarantee identical real-world accuracy (domain shift).
- Retraining is manual, not scheduled.
- The dashboard has no authentication; anyone with access to the local network can open it.
- Only TCP/UDP flow-level statistics are analyzed; encrypted payloads (TLS) are not inspected.
- The model recognizes exactly 9 classes; an attack type outside this set is likely to be misclassified as one of the known classes or as Benign.

## Roadmap

Priority order:
1. Collect and label real traffic for model fine-tuning (largest expected impact on real-world accuracy)
2. Dashboard authentication (immediate security concern)
3. Automated alerting (email / Slack)
4. Automated response (e.g. IP blocking)
5. Scheduled, automatic retraining
6. Migration to Kafka/TimescaleDB and Linux support, if real-world scale requires it

Other ideas under consideration: anomaly detection for attack types outside the current 9 classes, and HTTPS support for the dashboard.

## Author

Seyed Mahdi Nabavi Mousavi — Team 213, AI Keyboard Competition 1404 (Mashhad, Khorasan Razavi)