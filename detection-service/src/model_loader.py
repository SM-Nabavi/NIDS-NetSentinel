import os
import json
import logging
import joblib
import numpy as np
import lightgbm as lgb
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("nids.model_loader")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DEFAULT_MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))

class NIDSModelManager:
    """
    Manages loading, validation, and hot-reloading of the LightGBM NIDS model,
    StandardScaler, and class label mappings.
    """
    def __init__(self, model_dir=DEFAULT_MODEL_DIR):
        self.model_dir = model_dir
        self.model = None
        self.scaler = None
        self.label_to_id = {}
        self.id_to_label = {}
        self.severity_mapping = {}
        self.feature_names = []
        self.model_version = "v1"
        self.load_all()

    def load_all(self):
        """Loads all artifacts, initializing baselines if not present."""
        os.makedirs(self.model_dir, exist_ok=True)
        self._load_label_mapping()
        self._load_feature_spec()
        self._load_scaler()
        self._load_model()
        logger.info(f"[NIDSModelManager] Model and preprocessing pipeline loaded successfully ({len(self.id_to_label)} classes, {len(self.feature_names)} features).")

    def _load_label_mapping(self):
        mapping_path = os.path.join(self.model_dir, "label_mapping.json")
        if os.path.exists(mapping_path):
            with open(mapping_path, "r") as f:
                data = json.load(f)
                self.label_to_id = data.get("label_to_id", {})
                self.id_to_label = {int(k): v for k, v in data.get("id_to_label", {}).items()}
                self.severity_mapping = data.get("severity_mapping", {})
        else:
            # Fallback to the 9 classes defined in the training notebook
            self.id_to_label = {
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
            self.label_to_id = {v: k for k, v in self.id_to_label.items()}
            self.severity_mapping = {
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
            with open(mapping_path, "w") as f:
                json.dump({
                    "label_to_id": self.label_to_id,
                    "id_to_label": self.id_to_label,
                    "severity_mapping": self.severity_mapping
                }, f, indent=4)

    def _load_feature_spec(self):
        spec_path = os.path.join(self.model_dir, "features_spec.json")
        if os.path.exists(spec_path):
            with open(spec_path, "r") as f:
                spec = json.load(f)
                self.feature_names = spec.get("feature_names", [])
        if not self.feature_names:
            self.feature_names = [
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

    def _load_scaler(self):
        scaler_pkl = os.path.join(self.model_dir, "standard_scaler.pkl")
        if os.path.exists(scaler_pkl):
            try:
                self.scaler = joblib.load(scaler_pkl)
                logger.info(f"[NIDSModelManager] Loaded StandardScaler from {scaler_pkl}")
                return
            except Exception as e:
                logger.error(f"Failed to load scaler: {e}")
                raise

        raise FileNotFoundError(
            f"Scaler file not found at {scaler_pkl}. "
            "Please place a valid standard_scaler.pkl in the models directory."
        )

    def _load_model(self):
        pkl_path = os.path.join(self.model_dir, "lightgbm_nids_model.pkl")
        txt_path = os.path.join(self.model_dir, "lightgbm_nids_model.txt")

        if os.path.exists(pkl_path):
            try:
                self.model = joblib.load(pkl_path)
                logger.info(f"[NIDSModelManager] Loaded LightGBM model from {pkl_path}")
                return
            except Exception as e:
                logger.warning(f"[NIDSModelManager] Failed loading pickle {pkl_path}: {e}")

        if os.path.exists(txt_path):
            try:
                self.model = lgb.Booster(model_file=txt_path)
                logger.info(f"[NIDSModelManager] Loaded LightGBM model from text format {txt_path}")
                return
            except Exception as e:
                logger.warning(f"[NIDSModelManager] Failed loading text model {txt_path}: {e}")

        # If user model file has not been copied yet, generate an operational baseline
        raise FileNotFoundError(
            f"LightGBM model not found at {pkl_path} or {txt_path}. "
            "Please place valid model files in the models directory."
        )