"""
CipherSentinelModel - Production-grade, self-healing, self-scaling Isolation Forest model
for encrypted insider threat detection and anomaly scoring.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

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


class CipherSentinelModel:
    """Unified wrapper combining RobustScaler and IsolationForest for behavioral anomaly detection."""

    def __init__(
        self,
        n_estimators: int = 300,
        max_samples: Union[int, float] = 256,
        contamination: float = 0.02,
        random_state: int = 42,
        n_jobs: int = -1,
    ):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self.n_jobs = n_jobs

        self.feature_names = list(MODEL_FEATURES)
        self.feature_medians: Dict[str, float] = {}
        self.decision_threshold: float = -0.05

        self.scaler = RobustScaler()
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
        )
        self._is_fitted = False

    def extract_features(self, data: Union[pd.DataFrame, np.ndarray, dict, list]) -> pd.DataFrame:
        """Extract and format the canonical 32 behavioral features from diverse inputs."""
        if isinstance(data, np.ndarray):
            if data.ndim == 1:
                data = data.reshape(1, -1)
            if data.shape[1] == len(self.feature_names):
                return pd.DataFrame(data, columns=self.feature_names)
            df = pd.DataFrame(data)
        elif isinstance(data, dict):
            df = pd.DataFrame([data])
        elif isinstance(data, list):
            df = pd.DataFrame(data)
        elif isinstance(data, pd.DataFrame):
            df = data.copy()
        else:
            raise ValueError(f"Unsupported data format: {type(data)}")

        if set(self.feature_names).issubset(df.columns):
            return df[self.feature_names].fillna(0.0)

        X = pd.DataFrame(index=df.index)
        cols = {str(c).lower(): c for c in df.columns}

        def _get_col(*names: str, default: float = 0.0) -> pd.Series:
            for n in names:
                if n.lower() in cols:
                    return pd.to_numeric(df[cols[n.lower()]], errors="coerce").fillna(default)
            return pd.Series(default, index=df.index, dtype=float)

        # Byte and Volume metrics (including CSE-CIC-IDS2018 fwd/bwd columns)
        X["bytes_out"] = _get_col("bytes_out", "fwd_bytes", "bytes_sent", "out_bytes", "bytes", "flow_size")
        X["bytes_in"] = _get_col("bytes_in", "bwd_bytes", "bytes_received", "in_bytes", default=0.0)
        X["bytes_total"] = _get_col("bytes_total", default=0.0)
        mask_bt = X["bytes_total"] <= 0
        X.loc[mask_bt, "bytes_total"] = X.loc[mask_bt, "bytes_out"] + X.loc[mask_bt, "bytes_in"]

        # Packet metrics
        X["packets_out"] = _get_col("packets_out", "fwd_pkts", "packets_sent", "out_pkts", "packets", default=1.0)
        X["packets_in"] = _get_col("packets_in", "bwd_pkts", "packets_received", "in_pkts", default=1.0)
        X["flow_count"] = _get_col("flow_count", "n_conn", "conn_count", default=1.0)

        # Log scale volumes
        X["log_bytes_out"] = np.log1p(np.maximum(0.0, X["bytes_out"]))
        X["log_bytes_in"] = np.log1p(np.maximum(0.0, X["bytes_in"]))
        X["log_bytes_total"] = np.log1p(np.maximum(0.0, X["bytes_total"]))

        # Traffic Direction Ratios
        X["upload_download_ratio"] = X["bytes_out"] / (X["bytes_in"] + 1.0)
        X["fraction_bytes_out"] = X["bytes_out"] / (X["bytes_total"] + 1.0)

        # Per-flow & Per-packet Averages
        fc = np.maximum(X["flow_count"], 1.0)
        X["bytes_out_per_flow"] = X["bytes_out"] / fc
        X["packets_out_per_flow"] = X["packets_out"] / fc
        X["avg_packet_size_out"] = X["bytes_out"] / np.maximum(X["packets_out"], 1.0)
        X["avg_packet_size_in"] = X["bytes_in"] / np.maximum(X["packets_in"], 1.0)

        # Destination Novelty Metrics
        X["unique_destinations"] = _get_col("unique_destinations", "dest_count", "n_dest", default=1.0)
        X["new_destinations"] = _get_col("new_destinations", "is_new", default=0.0)
        X["new_destination_fraction"] = X["new_destinations"] / np.maximum(X["unique_destinations"], 1.0)

        # Temporal indicators
        X["is_weekend"] = _get_col("is_weekend", default=0.0)
        X["after_hours_flow_fraction"] = _get_col("after_hours_flow_fraction", "offhours_share", default=0.0)
        X["after_hours_flow_count"] = _get_col("after_hours_flow_count", default=0.0)

        # Rolling Trailing Window Metrics
        X["rolling_7d_bytes_out"] = _get_col("rolling_7d_bytes_out", "bytes_7d", default=0.0)
        X["rolling_7d_flow_count"] = _get_col("rolling_7d_flow_count", default=0.0)
        X["rolling_upload_delta_7d"] = _get_col("rolling_upload_delta_7d", default=0.0)

        # User Historical Deviation Metrics
        X["user_dev_bytes_out"] = _get_col("user_dev_bytes_out", "z_user_self", default=0.0)
        X["user_dev_flow_count"] = _get_col("user_dev_flow_count", default=0.0)
        X["user_dev_ratio"] = _get_col("user_dev_ratio", default=1.0)
        X["user_baseline_available"] = _get_col("user_baseline_available", default=1.0)

        # Peer Group Deviation Metrics
        X["peer_dev_bytes_out"] = _get_col("peer_dev_bytes_out", "z_user_peer", default=0.0)
        X["peer_dev_ratio"] = _get_col("peer_dev_ratio", "peer_rarity", default=1.0)
        X["peer_dev_after_hours"] = _get_col("peer_dev_after_hours", default=0.0)
        X["peer_dev_destinations"] = _get_col("peer_dev_destinations", default=0.0)

        # Fallback to feature medians if present
        for col in self.feature_names:
            if col not in X.columns:
                X[col] = self.feature_medians.get(col, 0.0)

        return X[self.feature_names].fillna(0.0)

    def fit(self, X: Union[pd.DataFrame, np.ndarray]) -> "CipherSentinelModel":
        """Fit RobustScaler and IsolationForest on feature matrix."""
        df_feat = self.extract_features(X)
        self.feature_medians = {col: float(df_feat[col].median()) for col in self.feature_names}

        X_scaled = self.scaler.fit_transform(df_feat)
        self.model.fit(X_scaled)

        # Calibrate decision threshold using contamination
        decisions = self.model.decision_function(X_scaled)
        self.decision_threshold = float(np.percentile(decisions, self.contamination * 100))
        self._is_fitted = True
        return self

    def predict(self, X: Union[pd.DataFrame, np.ndarray, dict, list]) -> np.ndarray:
        """Predict anomaly labels: -1 for anomaly / threat, 1 for normal."""
        df_feat = self.extract_features(X)
        X_scaled = self.scaler.transform(df_feat)
        raw_pred = self.model.predict(X_scaled)
        # Also enforce calibrated threshold
        decisions = self.model.decision_function(X_scaled)
        calibrated_pred = np.where(decisions <= self.decision_threshold, -1, raw_pred)
        return calibrated_pred

    def anomaly_score(self, X: Union[pd.DataFrame, np.ndarray, dict, list]) -> np.ndarray:
        """Compute raw IsolationForest decision scores (lower = more anomalous)."""
        df_feat = self.extract_features(X)
        X_scaled = self.scaler.transform(df_feat)
        return self.model.decision_function(X_scaled)

    def predict_risk(self, X: Union[pd.DataFrame, np.ndarray, dict, list]) -> np.ndarray:
        """Compute normalized 0.0 to 100.0 risk score (higher = higher threat)."""
        decisions = self.anomaly_score(X)
        # Map decision function [-0.25, 0.20] to [0.0, 100.0]
        # Anomaly decision function is centered near 0. Outliers < 0.
        risk = np.clip((0.15 - decisions) / 0.35 * 100.0, 0.0, 100.0)
        return np.round(risk, 1)
