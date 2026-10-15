import pandas as pd
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    def __init__(self, contamination: float = 0.01):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.is_fitted = False

    def fit(self, df: pd.DataFrame, feature_cols: list):
        if not feature_cols:
            raise ValueError("feature_cols must contain at least one column name")
        self.model.fit(df[feature_cols])
        self.is_fitted = True
        return self

    def predict(self, df: pd.DataFrame, feature_cols: list) -> pd.Series:
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before prediction")
        scores = self.model.decision_function(df[feature_cols])
        anomalies = self.model.predict(df[feature_cols])  # -1 for anomaly, 1 for normal
        return pd.Series(anomalies, index=df.index, name="anomaly_flag")

    def score_samples(self, df: pd.DataFrame, feature_cols: list) -> pd.Series:
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before scoring")
        return pd.Series(self.model.decision_function(df[feature_cols]), index=df.index, name="anomaly_score")
