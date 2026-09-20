import numpy as np
from typing import Dict, List, Any, Union
from model_loader import NIDSModelManager

class NIDSInferenceEngine:
    """
    Real-time high throughput inference engine for Network Flow classification.
    Conforms strictly to CICIDS2018 38-feature vector and LightGBM model output.
    """
    def __init__(self, manager: NIDSModelManager = None):
        self.manager = manager or NIDSModelManager()

    def _normalize_key(self, k: str) -> str:
        return k.lower().replace(" ", "").replace("_", "").replace("/", "").replace("-", "")

    def extract_feature_vector(self, flow_dict: Dict[str, Any]) -> np.ndarray:
        """
        Extracts a clean, normalized 38-dimensional feature vector from flow dictionary.
        Handles alternate spellings (spaces vs underscores) and replaces NaN/Infs with 0.
        """
        features_input = flow_dict.get("features", flow_dict)
        
        # Build normalized lookup map
        norm_map = {self._normalize_key(k): v for k, v in features_input.items()}

        vec = []
        for feat_name in self.manager.feature_names:
            clean_name = self._normalize_key(feat_name)
            val = norm_map.get(clean_name, 0.0)
            try:
                val = float(val)
                if np.isnan(val) or np.isinf(val):
                    val = 0.0
            except (ValueError, TypeError):
                val = 0.0
            vec.append(val)

        return np.array(vec, dtype=np.float32)

    def predict_single(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """Runs prediction on a single flow dictionary."""
        batch_results = self.predict_batch([flow])
        return batch_results[0]

    def predict_batch(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs micro-batched prediction on multiple flows simultaneously
        to guarantee sub-millisecond per-flow processing under high traffic bursts.
        """
        if not flows:
            return []

        # Build feature matrix
        matrix = np.array([self.extract_feature_vector(f) for f in flows], dtype=np.float32)

        # Apply StandardScaler
        if self.manager.scaler:
            try:
                matrix_scaled = self.manager.scaler.transform(matrix)
            except Exception:
                matrix_scaled = matrix
        else:
            matrix_scaled = matrix

        # Run LightGBM inference
        # model.predict returns class probability matrix of shape (n_samples, 9)
        model = self.manager.model
        if hasattr(model, "predict_proba"):
            raw_preds = model.predict_proba(matrix_scaled)
        else:
            raw_preds = model.predict(matrix_scaled)
        
        # Ensure 2D probability matrix
        if raw_preds.ndim == 1:
            raw_preds = np.expand_dims(raw_preds, axis=0)

        results = []
        for i, flow in enumerate(flows):
            probs = raw_preds[i]
            class_id = int(np.argmax(probs))
            confidence = float(probs[class_id])
            label = self.manager.id_to_label.get(class_id, f"Class_{class_id}")
            is_attack = (class_id != 0)
            severity = self.manager.severity_mapping.get(label, "HIGH" if is_attack else "INFO")

            # Structured prediction payload
            res = {
                "flow_id": flow.get("flow_id", "unknown"),
                "src_ip": flow.get("src_ip", ""),
                "dst_ip": flow.get("dst_ip", ""),
                "src_port": flow.get("src_port", 0),
                "dst_port": flow.get("dst_port", 0),
                "protocol": flow.get("protocol", 0),
                "start_time_us": flow.get("start_time_us", 0),
                "end_time_us": flow.get("end_time_us", 0),
                "features": flow.get("features", {}),
                "interface": flow.get("interface") or flow.get("net_interface"),
                "detection": {
                    "is_malicious": is_attack,
                    "attack_type": label,
                    "class_id": class_id,
                    "confidence": round(confidence, 4),
                    "severity": severity,
                    "probabilities": {
                        self.manager.id_to_label.get(c_id, f"Class_{c_id}"): round(float(probs[c_id]), 4)
                        for c_id in range(len(probs))
                    }
                }
            }
            results.append(res)

        return results
    
