# backend/features/feature_engineering.py
import pandas as pd

def add_time_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add simple time‑based features.

    * ``hour`` – hour of the timestamp (assuming a column ``timestamp`` exists)
    * ``day_of_week`` – day of week (0=Monday)
    """
    if 'timestamp' not in df.columns:
        return df
    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    return df
