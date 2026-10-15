import os
import pandas as pd
from pathlib import Path

DATA_DIR = Path(os.getenv('DATA_DIR', './data'))
RAW_DIR = DATA_DIR / 'raw'
PROCESSED_DIR = DATA_DIR / 'processed'

def ingest_csv(file_name: str) -> pd.DataFrame:
    """Read a CSV file from the raw data directory.

    Args:
        file_name: Name of the CSV file located in ``data/raw``.
    Returns:
        pandas.DataFrame containing the loaded data.
    """
    file_path = RAW_DIR / file_name
    if not file_path.exists():
        raise FileNotFoundError(f"Ingestion source not found: {file_path}")
    df = pd.read_csv(file_path)
    # Ensure processed directory exists for downstream steps
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    return df

def save_processed(df: pd.DataFrame, table_name: str):
    """Save a processed DataFrame as Parquet for later stages.

    Args:
        df: DataFrame to store.
        table_name: Logical name used for the file (e.g. ``events``).
    """
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = PROCESSED_DIR / f"{table_name}.parquet"
    df.to_parquet(out_path, index=False)
    return out_path
