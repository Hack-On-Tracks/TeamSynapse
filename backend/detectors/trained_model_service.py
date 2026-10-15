"""Integration service for pre-trained Isolation Forest and RobustScaler models.

Loads and serves the 32-feature behavioral outlier detection pipeline saved in `models/`.
Extracts network, temporal, volume, and entity baseline features from telemetry and
computes calibrated anomaly scores and explainable deviations.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd


MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "models"
MODEL_PATH = MODEL_DIR / "isolation_forest_model.joblib"
SCALER_PATH = MODEL_DIR / "robust_scaler.joblib"

MODEL_FEATURES: List[str] = [
    "bytes_out",
    "bytes_in",
    "bytes_total",
    "packets_out",
    "packets_in",
    "flow_count",
    "log_bytes_out",
    "log_bytes_in",
    "log_bytes_total",
    "upload_download_ratio",
    "fraction_bytes_out",
    "bytes_out_per_flow",
    "packets_out_per_flow",
    "avg_packet_size_out",
    "avg_packet_size_in",
    "unique_destinations",
    "new_destinations",
    "new_destination_fraction",
    "is_weekend",
    "after_hours_flow_fraction",
    "after_hours_flow_count",
    "rolling_7d_bytes_out",
    "rolling_7d_flow_count",
    "rolling_upload_delta_7d",
    "user_dev_bytes_out",
    "user_dev_flow_count",
    "user_dev_ratio",
    "user_baseline_available",
    "peer_dev_bytes_out",
    "peer_dev_ratio",
    "peer_dev_after_hours",
    "peer_dev_destinations",
]


class TrainedIsolationForestService:
    """Production service for the trained 32-feature Isolation Forest outlier detector."""

    _instance: Optional["TrainedIsolationForestService"] = None

    def __init__(self, model_path: Optional[Path] = None, scaler_path: Optional[Path] = None):
        self.model_path = model_path or MODEL_PATH
        self.scaler_path = scaler_path or SCALER_PATH
        self.model: Any = None
        self.scaler: Any = None
        self.is_loaded = False
        self._load_models()

    @classmethod
    def get_instance(cls) -> "TrainedIsolationForestService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_models(self) -> None:
        """Load serialized RobustScaler and IsolationForest estimator."""
        if self.model_path.exists() and self.scaler_path.exists():
            try:
                self.scaler = joblib.load(self.scaler_path)
                self.model = joblib.load(self.model_path)
                self.is_loaded = True
            except Exception as e:
                self.is_loaded = False
        else:
            self.is_loaded = False

    def get_model_info(self) -> Dict[str, Any]:
        """Return model metadata and configuration details."""
        if not self.is_loaded:
            return {"loaded": False, "error": "Model artifacts not found in models/"}
        return {
            "loaded": True,
            "model_type": "IsolationForest",
            "scaler_type": "RobustScaler",
            "n_features": len(MODEL_FEATURES),
            "features": MODEL_FEATURES,
            "n_estimators": getattr(self.model, "n_estimators", 300),
            "contamination": getattr(self.model, "contamination", 0.02),
            "offset": getattr(self.model, "offset_", -0.55),
        }

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract or derive the 32 behavioral features from raw or aggregated telemetry."""
        if df.empty:
            return pd.DataFrame(columns=MODEL_FEATURES)

        X = pd.DataFrame(index=df.index)
        cols = {c.lower(): c for c in df.columns}

        # Helper to find first matching column
        def _get_col(*names: str, default: float = 0.0) -> pd.Series:
            for n in names:
                if n.lower() in cols:
                    return pd.to_numeric(df[cols[n.lower()]], errors="coerce").fillna(default)
            return pd.Series(default, index=df.index, dtype=float)

        # 1. Byte and Volume metrics
        X["bytes_out"] = _get_col("bytes_out", "bytes_sent", "out_bytes", "bytes", "flow_size")
        X["bytes_in"] = _get_col("bytes_in", "bytes_received", "in_bytes", default=0.0)
        X["bytes_total"] = _get_col("bytes_total", default=0.0)
        mask_bt = X["bytes_total"] <= 0
        X.loc[mask_bt, "bytes_total"] = X.loc[mask_bt, "bytes_out"] + X.loc[mask_bt, "bytes_in"]

        # 2. Packet metrics
        X["packets_out"] = _get_col("packets_out", "packets_sent", "out_pkts", "packets", default=1.0)
        X["packets_in"] = _get_col("packets_in", "packets_received", "in_pkts", default=1.0)
        X["flow_count"] = _get_col("flow_count", "n_conn", "conn_count", default=1.0)

        # 3. Log-scale volumes
        X["log_bytes_out"] = np.log1p(np.maximum(0.0, X["bytes_out"]))
        X["log_bytes_in"] = np.log1p(np.maximum(0.0, X["bytes_in"]))
        X["log_bytes_total"] = np.log1p(np.maximum(0.0, X["bytes_total"]))

        # 4. Traffic Direction Ratios
        X["upload_download_ratio"] = X["bytes_out"] / (X["bytes_in"] + 1.0)
        X["fraction_bytes_out"] = X["bytes_out"] / (X["bytes_total"] + 1.0)

        # 5. Per-flow & Per-packet Averages
        fc = np.maximum(X["flow_count"], 1.0)
        X["bytes_out_per_flow"] = X["bytes_out"] / fc
        X["packets_out_per_flow"] = X["packets_out"] / fc
        X["avg_packet_size_out"] = X["bytes_out"] / np.maximum(X["packets_out"], 1.0)
        X["avg_packet_size_in"] = X["bytes_in"] / np.maximum(X["packets_in"], 1.0)

        # 6. Destination Novelty Metrics
        X["unique_destinations"] = _get_col("unique_destinations", "dest_count", "n_dest", default=1.0)
        X["new_destinations"] = _get_col("new_destinations", "is_new", default=0.0)
        X["new_destination_fraction"] = X["new_destinations"] / np.maximum(X["unique_destinations"], 1.0)

        # 7. Temporal & After-Hours Indicators
        if "timestamp" in cols:
            ts = pd.to_datetime(df[cols["timestamp"]], errors="coerce")
            is_wknd = ts.dt.dayofweek >= 5
            hour = ts.dt.hour
            after_h = (hour < 7) | (hour > 19) | is_wknd
            X["is_weekend"] = is_wknd.astype(float)
            X["after_hours_flow_count"] = after_h.astype(float)
            X["after_hours_flow_fraction"] = X["after_hours_flow_count"] / fc
        elif "hour" in cols:
            hour = pd.to_numeric(df[cols["hour"]], errors="coerce").fillna(12)
            is_wknd = _get_col("is_weekend", default=0.0)
            after_h = ((hour < 7) | (hour > 19) | (is_wknd == 1.0)).astype(float)
            X["is_weekend"] = is_wknd
            X["after_hours_flow_count"] = after_h
            X["after_hours_flow_fraction"] = after_h / fc
        else:
            X["is_weekend"] = _get_col("is_weekend", default=0.0)
            X["after_hours_flow_fraction"] = _get_col("after_hours_flow_fraction", "offhours_share", default=0.0)
            X["after_hours_flow_count"] = _get_col("after_hours_flow_count", default=0.0)

        # 8. Rolling Trailing Window Metrics
        X["rolling_7d_bytes_out"] = _get_col("rolling_7d_bytes_out", "bytes_7d", default=0.0)
        X["rolling_7d_flow_count"] = _get_col("rolling_7d_flow_count", default=0.0)
        X["rolling_upload_delta_7d"] = _get_col("rolling_upload_delta_7d", default=0.0)

        # 9. User Historical Deviation Metrics
        X["user_dev_bytes_out"] = _get_col("user_dev_bytes_out", "z_user_self", default=0.0)
        X["user_dev_flow_count"] = _get_col("user_dev_flow_count", default=0.0)
        X["user_dev_ratio"] = _get_col("user_dev_ratio", default=1.0)
        X["user_baseline_available"] = _get_col("user_baseline_available", default=1.0)

        # 10. Peer Group Deviation Metrics
        X["peer_dev_bytes_out"] = _get_col("peer_dev_bytes_out", "z_user_peer", default=0.0)
        X["peer_dev_ratio"] = _get_col("peer_dev_ratio", "peer_rarity", default=1.0)
        X["peer_dev_after_hours"] = _get_col("peer_dev_after_hours", default=0.0)
        X["peer_dev_destinations"] = _get_col("peer_dev_destinations", default=0.0)

        # Enforce exact column ordering and fill any residual NaNs
        X = X[MODEL_FEATURES].fillna(0.0)
        return X

    def predict(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Run feature extraction, scaling, and Isolation Forest prediction on telemetry.

        Returns:
            Dictionary containing:
                - `anomaly_flags`: binary indicator (1 for outlier, 0 for normal)
                - `anomaly_scores`: 0-100 normalized risk score
                - `raw_scores`: raw IsolationForest decision_function values
                - `top_deviations`: list of key contributing anomaly features per row
        """
        if not self.is_loaded:
            raise RuntimeError("Isolation Forest model is not loaded. Ensure models/ joblib files are present.")

        X = self.extract_features(df)
        if X.empty:
            return {"anomaly_flags": [], "anomaly_scores": [], "raw_scores": [], "top_deviations": []}

        # Apply RobustScaler transform
        X_scaled = self.scaler.transform(X)

        # Predict: 1 for inlier, -1 for outlier
        raw_pred = self.model.predict(X_scaled)
        decisions = self.model.decision_function(X_scaled)

        # Normalize score into [0.0, 100.0]
        # In sklearn, decision_function > 0 is inlier, < 0 is outlier.
        # Typically values span [-0.25, 0.25].
        # Negative decisions map to higher anomaly scores.
        anomaly_scores = np.clip((0.15 - decisions) / 0.35 * 100.0, 0.0, 100.0)
        anomaly_flags = (raw_pred == -1).astype(int)

        # Determine key deviating features for explainability
        top_deviations = []
        feature_names = np.array(MODEL_FEATURES)
        for i in range(len(X)):
            # Look at absolute magnitude of scaled deviation
            row_scaled = np.abs(X_scaled[i])
            top_indices = np.argsort(row_scaled)[::-1][:3]
            top_feats = [
                {
                    "feature": feature_names[idx],
                    "raw_value": float(X.iloc[i, idx]),
                    "scaled_deviation": round(float(row_scaled[idx]), 2),
                }
                for idx in top_indices
                if row_scaled[idx] > 0.5
            ]
            top_deviations.append(top_feats)

        return {
            "anomaly_flags": anomaly_flags.tolist(),
            "anomaly_scores": [round(float(s), 2) for s in anomaly_scores],
            "raw_scores": [round(float(d), 4) for d in decisions],
            "top_deviations": top_deviations,
        }
