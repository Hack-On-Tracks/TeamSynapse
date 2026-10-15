import os
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
import pandas as pd

from ...auth.auth import decode_access_token
from ...storage.storage import DuckDBStorage
from ...detectors.detector import AnomalyDetector
from ...detectors.trained_model_service import TrainedIsolationForestService
from ...features.feature_engineering import add_time_features

router = APIRouter()

class DetectRequest(BaseModel):
    table_name: str
    feature_columns: list = []  # optional list of columns to use; if empty uses trained 32-feature model
    contamination: float = 0.01

class DetectResponse(BaseModel):
    anomalies: dict  # mapping row index to anomaly flag
    scores: dict      # mapping row index to anomaly score
    model_used: str = "TrainedIsolationForest"


class ModelPredictRequest(BaseModel):
    table_name: Optional[str] = None
    records: Optional[list] = None  # optional list of telemetry row dictionaries
    limit: int = 500


@router.get("/model/info")
def get_trained_model_info(token: dict = Depends(decode_access_token)):
    """Retrieve metadata, feature list, and configuration of the trained Isolation Forest model."""
    service = TrainedIsolationForestService.get_instance()
    return service.get_model_info()


@router.post("/model/predict")
def predict_with_trained_model(req: ModelPredictRequest, token: dict = Depends(decode_access_token)):
    """Run inference using the trained 32-feature Isolation Forest model on DuckDB tables or records."""
    service = TrainedIsolationForestService.get_instance()
    if not service.is_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Trained Isolation Forest model artifacts not loaded from models/",
        )

    df = pd.DataFrame()
    if req.records:
        df = pd.DataFrame(req.records)
    elif req.table_name:
        storage = DuckDBStorage()
        try:
            df = storage.query(f"SELECT * FROM {req.table_name} LIMIT {req.limit}")
        except Exception as e:
            raise HTTPException(status_code=404, detail=f"Table not found: {req.table_name}")
        finally:
            storage.close()
    else:
        raise HTTPException(status_code=400, detail="Must provide either table_name or records")

    if df.empty:
        return {"predictions": [], "summary": {"total": 0, "anomalies": 0, "anomaly_rate": 0.0}}

    results = service.predict(df)
    total = len(results["anomaly_flags"])
    anom_count = sum(results["anomaly_flags"])
    rate = round(anom_count / max(total, 1) * 100.0, 2)

    predictions = []
    for i in range(total):
        predictions.append({
            "index": i,
            "is_anomaly": bool(results["anomaly_flags"][i]),
            "anomaly_score": results["anomaly_scores"][i],
            "raw_decision": results["raw_scores"][i],
            "top_deviations": results["top_deviations"][i] if i < len(results["top_deviations"]) else [],
        })

    return {
        "model_type": "IsolationForest (32 features)",
        "summary": {
            "total_evaluated": total,
            "anomalies_detected": anom_count,
            "anomaly_rate_percent": rate,
        },
        "predictions": predictions,
    }


@router.post("/detect", response_model=DetectResponse)
def detect_anomalies(req: DetectRequest, token: dict = Depends(decode_access_token)):
    storage = DuckDBStorage()
    try:
        df = storage.query(f"SELECT * FROM {req.table_name}")
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Table not found: {req.table_name}")
    finally:
        storage.close()

    if df.empty:
        raise HTTPException(status_code=400, detail="No data to analyze")

    # If trained model is available and user didn't request custom columns, use trained pipeline
    service = TrainedIsolationForestService.get_instance()
    if service.is_loaded and not req.feature_columns:
        results = service.predict(df)
        anomalies_series = pd.Series(results["anomaly_flags"], index=df.index, name="anomaly_flag")
        scores_series = pd.Series(results["anomaly_scores"], index=df.index, name="anomaly_score")
        model_name = "TrainedIsolationForest (32 features)"
    else:
        # Fallback to dynamic detector
        df = add_time_features(df)
        feature_cols = req.feature_columns or [c for c in df.select_dtypes(include='number').columns]
        if not feature_cols:
            raise HTTPException(status_code=400, detail="No numeric feature columns available for detection")

        detector = AnomalyDetector(contamination=req.contamination)
        detector.fit(df, feature_cols)
        anomalies_series = detector.predict(df, feature_cols)
        scores_series = detector.score_samples(df, feature_cols)
        model_name = "DynamicAnomalyDetector"

    # Persist detected flags and scores back to DuckDB table for downstream scoring and UI
    df["anomaly_flag"] = anomalies_series
    df["anomaly_score"] = scores_series
    storage = DuckDBStorage()
    try:
        storage.insert_dataframe(df, req.table_name)
    finally:
        storage.close()

    return DetectResponse(
        anomalies=anomalies_series.to_dict(),
        scores=scores_series.to_dict(),
        model_used=model_name,
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

