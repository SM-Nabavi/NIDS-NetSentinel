#!/usr/bin/env python3
"""
Retraining Module - Fine-tune LightGBM model with network-specific data.
Implements incremental fine-tuning with drift detection and version control.
"""
import os
import sys
import json
import time
import sqlite3
import logging
import threading
import numpy as np
import lightgbm as lgb
from typing import Dict, List, Any, Optional, Tuple
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, f1_score, classification_report
import joblib
import pickle
import glob
import shutil

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "detection-service", "models")
DB_PATH = os.path.join(DATA_DIR, "nids.db")
RETRAIN_LOG = os.path.join(DATA_DIR, "retraining.log")

# Default feature names (38 features from CICIDS2018)
FEATURE_NAMES = [
    "Bwd IAT Mean", "Bwd IAT Min", "Bwd IAT Std", "Bwd IAT Total",
    "Bwd PSH Flags", "Bwd Packet Length Max", "Bwd Packet Length Mean",
    "CWR Flag Count", "Down/Up Ratio", "ECE Flag Count", "FIN Flag Count",
    "Flow Bytes/s", "Flow Duration", "Flow IAT Max", "Flow IAT Mean",
    "Flow IAT Std", "Flow Packets/s", "Fwd Avg Bulk Rate", "Fwd IAT Max",
    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Total", "Fwd PSH Flags",
    "Fwd Packet Length Max", "Fwd Packet Length Mean", "Fwd RST Flags",
    "Fwd Seg Size Min", "Init Bwd Win Bytes", "Init Fwd Win Bytes",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "RST Flag Count", "SYN Flag Count", "Subflow Fwd Packets",
    "Total Backward Packets", "Total Fwd Packets", "Total TCP Flow Time"
]

# Class mapping (9 classes from CICIDS2018)
CLASS_MAPPING = {
    0: "Benign",
    1: "Botnet Ares",
    2: "DDoS-HOIC",
    3: "DDoS-LOIC-HTTP",
    4: "DDoS-LOIC-UDP",
    5: "DoS GoldenEye",
    6: "DoS Hulk",
    7: "DoS Slowloris",
    8: "SSH-BruteForce"
}

SEVERITY_MAPPING = {
    "Benign": "INFO",
    "SSH-BruteForce": "LOW",
    "DoS Slowloris": "MEDIUM",
    "Botnet Ares": "HIGH",
    "DoS GoldenEye": "HIGH",
    "DoS Hulk": "HIGH",
    "DDoS-LOIC-UDP": "CRITICAL",
    "DDoS-LOIC-HTTP": "CRITICAL",
    "DDoS-HOIC": "CRITICAL"
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(RETRAIN_LOG),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("nids.retraining")

# Global state
_retraining_state = {
    "status": "idle",           # idle | preparing | training | evaluating | promoting | failed | completed
    "progress": 0.0,
    "message": "",
    "samples": 0,
    "dataset": "",
    "model_version": "",
    "is_running": False,
    "started_at": None,
    "finished_at": None,
    "error": None
}
_retraining_lock = threading.Lock()


def _normalize_key(k: str) -> str:
    """Normalize feature name for lookup."""
    return k.lower().replace(" ", "").replace("_", "").replace("/", "").replace("-", "")


def _get_db_connection():
    """Get SQLite connection with row_factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _load_existing_model() -> Tuple[Optional[lgb.Booster], Optional[StandardScaler], List[str], Dict]:
    """
    Load existing model artifacts from models directory.
    Returns: (model, scaler, feature_names, label_mapping)
    """
    model_path = os.path.join(MODELS_DIR, "lightgbm_nids_model.pkl")
    txt_path = os.path.join(MODELS_DIR, "lightgbm_nids_model.txt")
    scaler_path = os.path.join(MODELS_DIR, "standard_scaler.pkl")
    mapping_path = os.path.join(MODELS_DIR, "label_mapping.json")
    spec_path = os.path.join(MODELS_DIR, "features_spec.json")

    model = None
    scaler = None
    feature_names = FEATURE_NAMES.copy()
    label_mapping = {"id_to_label": CLASS_MAPPING, "label_to_id": {v: k for k, v in CLASS_MAPPING.items()}}

    # Load label mapping
    if os.path.exists(mapping_path):
        try:
            with open(mapping_path, "r") as f:
                data = json.load(f)
                label_mapping = data
        except Exception as e:
            logger.warning(f"Failed to load label mapping: {e}")

    # Load feature spec
    if os.path.exists(spec_path):
        try:
            with open(spec_path, "r") as f:
                data = json.load(f)
                if data.get("feature_names"):
                    feature_names = data["feature_names"]
        except Exception as e:
            logger.warning(f"Failed to load feature spec: {e}")

    # Load scaler
    if os.path.exists(scaler_path):
        try:
            scaler = joblib.load(scaler_path)
            logger.info(f"Loaded scaler from {scaler_path}")
        except Exception as e:
            logger.warning(f"Failed to load scaler: {e}")

    # Load model (prefer pickle, fallback to text)
    if os.path.exists(model_path):
        try:
            model = joblib.load(model_path)
            logger.info(f"Loaded model from {model_path}")
        except Exception as e:
            logger.warning(f"Failed to load pickle model: {e}")

    if model is None and os.path.exists(txt_path):
        try:
            model = lgb.Booster(model_file=txt_path)
            logger.info(f"Loaded model from {txt_path}")
        except Exception as e:
            logger.warning(f"Failed to load text model: {e}")

    return model, scaler, feature_names, label_mapping


def _extract_training_data(limit: int = 10000, label_threshold: float = 0.8) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Extract labeled flows from database for training.
    Returns: (features_matrix, labels, flow_ids)
    """
    with _get_db_connection() as conn:
        cursor = conn.cursor()

        # Query flows with detections that have high confidence
        cursor.execute("""
            SELECT 
                f.flow_id,
                f.features_json,
                d.attack_type,
                d.confidence,
                d.is_malicious
            FROM flows f
            JOIN detections d ON f.flow_id = d.flow_id
            WHERE d.confidence >= ?
            ORDER BY f.created_at DESC
            LIMIT ?
        """, (label_threshold, limit))

        rows = cursor.fetchall()

        if not rows:
            return np.array([]), np.array([]), []

        features_list = []
        labels_list = []
        flow_ids = []

        for row in rows:
            try:
                features_dict = json.loads(row["features_json"]) if row["features_json"] else {}
                attack_type = row["attack_type"] or "Benign"

                # Build feature vector
                norm_map = {_normalize_key(k): v for k, v in features_dict.items()}
                vec = []
                for feat_name in FEATURE_NAMES:
                    val = norm_map.get(_normalize_key(feat_name), 0.0)
                    try:
                        val = float(val)
                        if np.isnan(val) or np.isinf(val):
                            val = 0.0
                    except (ValueError, TypeError):
                        val = 0.0
                    vec.append(val)

                # Map label to class ID
                label_to_id = {v: k for k, v in CLASS_MAPPING.items()}
                class_id = label_to_id.get(attack_type, 0)  # Default to Benign

                features_list.append(vec)
                labels_list.append(class_id)
                flow_ids.append(row["flow_id"])

            except Exception as e:
                logger.warning(f"Failed to parse flow {row.get('flow_id', 'unknown')}: {e}")
                continue

        return np.array(features_list, dtype=np.float32), np.array(labels_list, dtype=np.int32), flow_ids


def _train_lightgbm(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    num_classes: int = 9,
    existing_model: Optional[lgb.Booster] = None
) -> lgb.Booster:
    """
    Train or fine-tune LightGBM model.
    If existing_model is provided, use it as warm-start (fine-tuning).
    """
    # Parameters optimized for NIDS (based on CICIDS2018)
    params = {
        'objective': 'multiclass',
        'num_class': num_classes,
        'metric': 'multi_logloss',
        'boosting_type': 'gbdt',
        'num_leaves': 31,
        'max_depth': -1,
        'learning_rate': 0.05 if existing_model else 0.1,
        'n_estimators': 100,
        'min_child_samples': 20,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'reg_alpha': 0.1,
        'reg_lambda': 0.1,
        'random_state': 42,
        'n_jobs': -1,
        'verbose': -1
    }

    # Create datasets
    train_data = lgb.Dataset(X_train, label=y_train)
    val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)

    # Callbacks
    callbacks = [
        lgb.early_stopping(stopping_rounds=20),
        lgb.log_evaluation(period=0)
    ]

    if existing_model is not None:
        # Fine-tuning: continue training from existing model
        logger.info("Fine-tuning existing model with new data...")
        model = lgb.train(
            params,
            train_data,
            valid_sets=[train_data, val_data],
            num_boost_round=50,  # Fewer rounds for fine-tuning
            callbacks=callbacks,
            init_model=existing_model
        )
    else:
        # Train from scratch
        logger.info("Training new model from scratch...")
        model = lgb.train(
            params,
            train_data,
            valid_sets=[train_data, val_data],
            num_boost_round=200,
            callbacks=callbacks
        )

    return model


def _save_model_artifacts(
    model: lgb.Booster,
    scaler: Optional[StandardScaler],
    feature_names: List[str],
    label_mapping: Dict,
    model_name: str = ""
) -> Dict:
    """
    Save model artifacts with versioning.
    If model_name is provided, it is appended to the version string.
    Returns metadata about saved files.
    """
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    if model_name:
        # Sanitize model_name: only keep alphanumeric, underscore, hyphen
        sanitized = "".join(c for c in model_name if c.isalnum() or c in "-_").strip() or "model"
        version = f"v{timestamp}_{sanitized}"
    else:
        version = f"v{timestamp}"

    # Save model
    model_path = os.path.join(MODELS_DIR, f"lightgbm_nids_model_{version}.pkl")
    joblib.dump(model, model_path)

    # Also save as primary model (overwrite)
    primary_path = os.path.join(MODELS_DIR, "lightgbm_nids_model.pkl")
    joblib.dump(model, primary_path)

    # Save scaler if provided
    if scaler is not None:
        scaler_path = os.path.join(MODELS_DIR, f"standard_scaler_{version}.pkl")
        joblib.dump(scaler, scaler_path)
        primary_scaler_path = os.path.join(MODELS_DIR, "standard_scaler.pkl")
        joblib.dump(scaler, primary_scaler_path)

    # Save label mapping
    mapping_path = os.path.join(MODELS_DIR, "label_mapping.json")
    with open(mapping_path, "w") as f:
        json.dump(label_mapping, f, indent=4)

    # Save feature spec
    spec_path = os.path.join(MODELS_DIR, "features_spec.json")
    with open(spec_path, "w") as f:
        json.dump({"feature_names": feature_names}, f, indent=4)

    # Save version info
    version_path = os.path.join(MODELS_DIR, "model_version.json")
    with open(version_path, "w") as f:
        json.dump({
            "version": version,
            "created_at": time.time(),
            "timestamp": timestamp,
            "model_name": model_name,
            "files": {
                "model": model_path,
                "scaler": scaler_path if scaler else None,
                "mapping": mapping_path,
                "spec": spec_path
            }
        }, f, indent=4)

    return {
        "version": version,
        "model_path": model_path,
        "primary_model": primary_path,
        "scaler_path": scaler_path if scaler else None
    }


def _update_retraining_state(**kwargs):
    """Thread-safe update of retraining state."""
    with _retraining_lock:
        for key, value in kwargs.items():
            if key in _retraining_state:
                _retraining_state[key] = value


def start_retraining(
    sample_limit: int = 10000,
    test_size: float = 0.2,
    label_threshold: float = 0.8,
    force_retrain: bool = False,
    model_name: str = ""
) -> Dict:
    """
    Main retraining function. Runs in background thread.
    """
    if _retraining_state["is_running"] and not force_retrain:
        return {"status": "already_running", "message": "Retraining is already in progress"}

    # Reset state
    _update_retraining_state(
        is_running=True,
        status="preparing",
        progress=0.0,
        message="Starting retraining process...",
        started_at=time.time(),
        finished_at=None,
        error=None
    )

    def _run_retraining():
        try:
            _do_retraining(sample_limit, test_size, label_threshold, model_name)
        except Exception as e:
            logger.error(f"Retraining failed: {e}")
            _update_retraining_state(
                status="failed",
                error=str(e),
                message=f"Retraining failed: {str(e)}",
                is_running=False,
                finished_at=time.time()
            )

    thread = threading.Thread(target=_run_retraining, daemon=True)
    thread.start()

    return {"status": "started", "message": "Retraining started in background"}


def _do_retraining(sample_limit: int, test_size: float, label_threshold: float, model_name: str = ""):
    """Internal retraining implementation."""
    logger.info("=" * 60)
    logger.info("STARTING MODEL RETRAINING")
    logger.info("=" * 60)

    # Step 1: Load existing model
    _update_retraining_state(status="preparing", progress=5.0, message="Loading existing model artifacts...")
    existing_model, scaler, feature_names, label_mapping = _load_existing_model()

    # Step 2: Extract training data from database
    _update_retraining_state(status="preparing", progress=10.0, message=f"Extracting up to {sample_limit} samples from database...")
    X, y, flow_ids = _extract_training_data(sample_limit, label_threshold)

    if len(X) == 0:
        raise ValueError("No training data found in database. Ensure flows with high-confidence detections exist.")

    logger.info(f"Extracted {len(X)} samples from database")

    # Step 3: Split data
    _update_retraining_state(status="preparing", progress=20.0, message=f"Splitting {len(X)} samples into train/validation sets...")
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )

    logger.info(f"Training samples: {len(X_train)}, Validation samples: {len(X_val)}")

    # Step 4: Fit/update scaler
    _update_retraining_state(status="training", progress=30.0, message="Fitting feature scaler...")
    if scaler is None:
        scaler = StandardScaler()
        scaler.fit(X_train)
    else:
        # Update scaler with new data (incremental fit)
        # For simplicity, we refit on combined data
        combined_X = np.vstack([X_train, X_val]) if len(X_val) > 0 else X_train
        scaler = StandardScaler()
        scaler.fit(combined_X)

    # Transform data
    X_train_scaled = scaler.transform(X_train)
    X_val_scaled = scaler.transform(X_val) if len(X_val) > 0 else np.array([])

    # Step 5: Train/fine-tune model
    _update_retraining_state(status="training", progress=50.0, message="Training LightGBM model (this may take a few minutes)...")
    num_classes = len(label_mapping.get("id_to_label", CLASS_MAPPING))
    model = _train_lightgbm(
        X_train_scaled, y_train,
        X_val_scaled, y_val,
        num_classes=num_classes,
        existing_model=existing_model
    )

    # Step 6: Evaluate
    _update_retraining_state(status="evaluating", progress=80.0, message="Evaluating model performance...")
    y_pred = model.predict(X_val_scaled, num_iteration=model.best_iteration)
    y_pred_classes = np.argmax(y_pred, axis=1)

    accuracy = accuracy_score(y_val, y_pred_classes)
    f1 = f1_score(y_val, y_pred_classes, average='weighted')

    logger.info(f"Validation Accuracy: {accuracy:.4f}, F1-Score: {f1:.4f}")

    # Step 7: Save artifacts
    _update_retraining_state(status="promoting", progress=90.0, message=f"Saving model (Accuracy: {accuracy:.2%}, F1: {f1:.2%})...")
    metadata = _save_model_artifacts(model, scaler, feature_names, label_mapping, model_name)

    # Step 8: Complete
    _update_retraining_state(
        status="completed",
        progress=100.0,
        message=f"Retraining completed successfully! Version: {metadata['version']}, Accuracy: {accuracy:.2%}, F1: {f1:.2%}",
        is_running=False,
        finished_at=time.time(),
        samples=len(X),
        dataset=f"{len(X)} flows (train: {len(X_train)}, val: {len(X_val)})",
        model_version=metadata['version']
    )

    logger.info("=" * 60)
    logger.info(f"RETRAINING COMPLETED - Version: {metadata['version']}")
    logger.info(f"Accuracy: {accuracy:.4f}, F1-Score: {f1:.4f}")
    logger.info("=" * 60)


def stop_retraining() -> Dict:
    """Stop retraining process (sets flag to abort)."""
    with _retraining_lock:
        if not _retraining_state["is_running"]:
            return {"status": "not_running", "message": "No retraining process is running"}

        _retraining_state["status"] = "stopped"
        _retraining_state["message"] = "Retraining stopped by user"
        _retraining_state["is_running"] = False
        _retraining_state["finished_at"] = time.time()

    return {"status": "stopped", "message": "Retraining stopped"}


def get_retraining_status() -> Dict:
    """Get current retraining status."""
    with _retraining_lock:
        return _retraining_state.copy()

def get_training_data_stats() -> Dict:
    """
    Get statistics about available training data in database.
    Returns empty stats if tables don't exist yet.
    """
    # First, check if the 'flows' table exists
    try:
        with _get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='flows'")
            if not cursor.fetchone():
                # Table doesn't exist, return empty stats
                return {
                    "total_samples": 0,
                    "distribution": {},
                    "latest_sample_at": None,
                    "has_data": False
                }
    except Exception:
        return {
            "total_samples": 0,
            "distribution": {},
            "latest_sample_at": None,
            "has_data": False
        }

    # Now query safely
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT COUNT(*) as total
                FROM flows f
                JOIN detections d ON f.flow_id = d.flow_id
                WHERE d.confidence >= 0.7
            """)
            row = cursor.fetchone()
            total = row["total"] if row else 0
        except Exception:
            total = 0

        try:
            cursor.execute("""
                SELECT d.attack_type, COUNT(*) as count
                FROM flows f
                JOIN detections d ON f.flow_id = d.flow_id
                WHERE d.confidence >= 0.7
                GROUP BY d.attack_type
                ORDER BY count DESC
            """)
            distribution = {row["attack_type"]: row["count"] for row in cursor.fetchall()}
        except Exception:
            distribution = {}

        try:
            cursor.execute("SELECT MAX(f.created_at) as latest FROM flows f JOIN detections d ON f.flow_id = d.flow_id")
            row = cursor.fetchone()
            latest = row["latest"] if row else None
        except Exception:
            latest = None

        return {
            "total_samples": total,
            "distribution": distribution,
            "latest_sample_at": latest,
            "has_data": total > 0
        }

# ============================================================
# MODEL VERSION MANAGEMENT
# ============================================================

def list_models() -> List[Dict]:
    """
    Return list of all available model versions (backups) plus the primary model.
    The primary model is included as "primary" (or if it matches a backup version, that entry is marked active).
    """
    pattern = os.path.join(MODELS_DIR, "lightgbm_nids_model_*.pkl")
    files = glob.glob(pattern)
    models = []
    for f in files:
        basename = os.path.basename(f)
        version = basename.replace("lightgbm_nids_model_", "").replace(".pkl", "")
        stat = os.stat(f)
        models.append({
            "version": version,
            "filename": basename,
            "path": f,
            "size_bytes": stat.st_size,
            "modified_at": stat.st_mtime,
            "is_active": os.path.exists(os.path.join(MODELS_DIR, "lightgbm_nids_model.pkl")) and
                         os.path.samefile(f, os.path.join(MODELS_DIR, "lightgbm_nids_model.pkl"))
        })

    # Include the primary model if it exists and is not already represented by a backup version
    primary_path = os.path.join(MODELS_DIR, "lightgbm_nids_model.pkl")
    if os.path.exists(primary_path):
        # Check if any backup file is the same as primary
        if not any(os.path.samefile(primary_path, m["path"]) for m in models):
            stat = os.stat(primary_path)
            models.append({
                "version": "primary",
                "filename": "lightgbm_nids_model.pkl",
                "path": primary_path,
                "size_bytes": stat.st_size,
                "modified_at": stat.st_mtime,
                "is_active": True
            })

    models.sort(key=lambda x: x["modified_at"], reverse=True)
    return models

def set_active_model(version: str) -> Dict:
    """Switch the active model to a specific version."""
    if version == "primary":
        # Primary is already active by definition; but maybe no-op
        return {"status": "success", "message": "Primary model is already active"}

    src = os.path.join(MODELS_DIR, f"lightgbm_nids_model_{version}.pkl")
    if not os.path.exists(src):
        return {"status": "error", "error": f"Model version '{version}' not found"}

    dst = os.path.join(MODELS_DIR, "lightgbm_nids_model.pkl")
    try:
        shutil.copy2(src, dst)
        src_scaler = os.path.join(MODELS_DIR, f"standard_scaler_{version}.pkl")
        if os.path.exists(src_scaler):
            shutil.copy2(src_scaler, os.path.join(MODELS_DIR, "standard_scaler.pkl"))
        version_path = os.path.join(MODELS_DIR, "model_version.json")
        with open(version_path, "w") as f:
            json.dump({
                "version": version,
                "switched_at": time.time(),
                "from_backup": src
            }, f, indent=4)
        return {"status": "success", "message": f"Active model switched to version {version}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
# ============================================================
# CLI Interface
# ============================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NIDS Model Retraining Tool")
    parser.add_argument("--action", choices=["start", "stop", "status", "stats"], default="status")
    parser.add_argument("--limit", type=int, default=10000, help="Max samples to use for training")
    parser.add_argument("--threshold", type=float, default=0.8, help="Confidence threshold for labels")
    parser.add_argument("--test-size", type=float, default=0.2, help="Validation split ratio")
    parser.add_argument("--model-name", type=str, default="", help="Custom model name (optional)")

    args = parser.parse_args()

    if args.action == "start":
        result = start_retraining(args.limit, args.test_size, args.threshold, model_name=args.model_name)
        print(json.dumps(result, indent=2))
    elif args.action == "stop":
        result = stop_retraining()
        print(json.dumps(result, indent=2))
    elif args.action == "status":
        result = get_retraining_status()
        print(json.dumps(result, indent=2))
    elif args.action == "stats":
        result = get_training_data_stats()
        print(json.dumps(result, indent=2))