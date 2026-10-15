"""M2 Isolation Forest with percentile-based sub-score (NOT a calibrated probability)."""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


class IFDetector:
    def __init__(self, cfg: dict):
        c = cfg["weights"]["isolation_forest"]
        self.features = list(c["features"])
        self.floor = c["percentile_floor"]
        self.params = dict(n_estimators=c["n_estimators"], max_samples=c["max_samples"],
                           contamination=c["contamination"], random_state=c["random_state"])
        self.model: IsolationForest | None = None
        self.medians: pd.Series | None = None
        self.train_scores: np.ndarray | None = None

    def _X(self, df: pd.DataFrame) -> np.ndarray:
        X = df[self.features].astype(float)
        return X.fillna(self.medians).values   # imputer statistics fit on the TRAINING period only

    def fit(self, train: pd.DataFrame) -> "IFDetector":
        assert len(train) > 0, "empty training period"
        X0 = train[self.features].astype(float)
        self.medians = X0.median().fillna(0.0)
        self.model = IsolationForest(**self.params, n_jobs=1).fit(self._X(train))
        self.train_scores = np.sort(self.anomaly_score(train))
        return self

    def anomaly_score(self, df: pd.DataFrame) -> np.ndarray:
        """Higher = more anomalous (negated sklearn score_samples, where higher = more normal)."""
        return -self.model.score_samples(self._X(df))

    def percentile(self, df: pd.DataFrame) -> np.ndarray:
        a = self.anomaly_score(df)
        return np.searchsorted(self.train_scores, a, side="right") / len(self.train_scores)

    def subscore(self, df: pd.DataFrame) -> np.ndarray:
        """clip((p - 0.90) / 0.10, 0, 1) where p is the percentile among training anomaly scores."""
        p = self.percentile(df)
        return np.clip((p - self.floor) / (1 - self.floor), 0, 1)

    def save(self, path: str | Path) -> None:
        joblib.dump({"features": self.features, "model": self.model, "medians": self.medians,
                     "train_scores": self.train_scores, "floor": self.floor, "params": self.params}, path)

    @classmethod
    def load(cls, path: str | Path, cfg: dict) -> "IFDetector":
        d = joblib.load(path)
        o = cls(cfg)
        o.features, o.model, o.medians, o.train_scores, o.floor = d["features"], d["model"], d["medians"], d["train_scores"], d["floor"]
        return o
