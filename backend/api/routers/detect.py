import os
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
import pandas as pd

from ...auth.auth import decode_access_token
from ...storage.storage import DuckDBStorage
from ...detectors.detector import AnomalyDetector
from ...features.feature_engineering import add_time_features

router = APIRouter()

class DetectRequest(BaseModel):
    table_name: str
    feature_columns: list = []  # optional list of columns to use; if empty use all
    contamination: float = 0.01

class DetectResponse(BaseModel):
    anomalies: dict  # mapping row index to anomaly flag
    scores: dict      # mapping row index to anomaly score

@router.post("/detect", response_model=DetectResponse)
def detect_anomalies(req: DetectRequest, token: dict = Depends(decode_access_token)):
    storage = DuckDBStorage()
    # Load data from DuckDB table
    try:
        df = storage.query(f"SELECT * FROM {req.table_name}")
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Table not found: {req.table_name}")
    finally:
        storage.close()

    if df.empty:
        raise HTTPException(status_code=400, detail="No data to analyze")

    # Feature engineering
    df = add_time_features(df)

    # Determine feature columns
    feature_cols = req.feature_columns or [c for c in df.select_dtypes(include='number').columns]
    if not feature_cols:
        raise HTTPException(status_code=400, detail="No numeric feature columns available for detection")

    detector = AnomalyDetector(contamination=req.contamination)
    detector.fit(df, feature_cols)
    anomalies = detector.predict(df, feature_cols)
    scores = detector.score_samples(df, feature_cols)

    # Persist detected flags and scores back to DuckDB table for downstream scoring and UI
    df["anomaly_flag"] = anomalies
    df["anomaly_score"] = scores
    storage = DuckDBStorage()
    try:
        storage.insert_dataframe(df, req.table_name)
    finally:
        storage.close()

    return DetectResponse(
        anomalies=anomalies.to_dict(),
        scores=scores.to_dict()
    )


@router.get("/tables")
def list_available_tables(token: dict = Depends(decode_access_token)):
    """List tables currently available in DuckDB for detection."""
    storage = DuckDBStorage()
    try:
        tables_df = storage.query("SHOW TABLES")
        table_names = tables_df["name"].tolist() if not tables_df.empty else []
        # Filter internal tables
        public_tables = [t for t in table_names if t not in ["users", "audit_logs"]]
        return {"tables": public_tables}
    finally:
        storage.close()

