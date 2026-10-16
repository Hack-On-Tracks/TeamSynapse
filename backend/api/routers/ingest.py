import io
import os
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from typing import List, Optional
from pydantic import BaseModel
import pandas as pd

from ...auth.auth import decode_access_token
from ...ingestion.ingest import ingest_csv, save_processed
from ...storage.storage import DuckDBStorage

router = APIRouter()

class IngestResponse(BaseModel):
    message: str
    table_name: str
    rows: int
    columns: List[str]

@router.post("/ingest/{file_name}", response_model=IngestResponse)
async def ingest_file(file_name: str, token: dict = Depends(decode_access_token)):
    """Ingest a CSV file pre-existing in data/raw."""
    try:
        df = ingest_csv(file_name)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    rows = len(df)
    tbl = file_name.rsplit(".", 1)[0]
    save_processed(df, table_name=tbl)
    storage = DuckDBStorage()
    try:
        storage.insert_dataframe(df, table_name=tbl)
    finally:
        storage.close()
    return {
        "message": f"Ingested {file_name}",
        "table_name": tbl,
        "rows": rows,
        "columns": df.columns.tolist(),
    }

@router.post("/upload", response_model=IngestResponse)
async def upload_file(file: UploadFile = File(...), token: dict = Depends(decode_access_token)):
    """Upload a CSV file directly from browser/client into DuckDB and Parquet."""
    content = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(content))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {e}")

    table_name = file.filename.rsplit(".", 1)[0] if file.filename else "uploaded_data"
    storage = DuckDBStorage()
    try:
        from ...ingestion.ingestion_service import TelemetryIngestionService
        service = TelemetryIngestionService(storage=storage)
        ingest_report = service.ingest_dataframe(df, table_name=table_name, source_type="browser_upload")
        return {
            "message": f"Successfully uploaded {file.filename} (accepted: {ingest_report['accepted_records']}, quarantined: {ingest_report['quarantined_records']})",
            "table_name": table_name,
            "rows": ingest_report["accepted_records"],
            "columns": ingest_report["columns"],
        }
    finally:
        storage.close()

from collections import deque
from datetime import datetime, timezone
import uuid

# In-memory buffer for ultra-fast live visualization of incoming streaming logs from n8n
_LIVE_STREAM_BUFFER = deque(maxlen=250)

class WebLogItem(BaseModel):
    timestamp: Optional[str] = None
    user_id: Optional[str] = "USR-001"
    source_ip: Optional[str] = "10.0.0.1"
    destination_ip: Optional[str] = "198.51.100.1"
    source_port: Optional[int] = 50000
    destination_port: Optional[int] = 443
    protocol: Optional[str] = "TCP"
    method: Optional[str] = "GET"
    url: Optional[str] = "/"
    hostname: Optional[str] = "api.internal.corp"
    user_agent: Optional[str] = "Mozilla/5.0"
    status_code: Optional[int] = 200
    bytes_sent: Optional[int] = 1200
    bytes_received: Optional[int] = 8400
    duration: Optional[float] = 0.5
    application: Optional[str] = "Web Browser"
    category: Optional[str] = "General"

@router.post("/stream-log")
async def ingest_stream_log(
    log: WebLogItem,
    token: dict = Depends(decode_access_token),
):
    """Receive a single streaming web/network log (e.g. from n8n every 2 seconds).
    
    Evaluates real-time anomaly heuristics, persists into DuckDB, and caches in live buffer.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    log_id = f"LOG-{uuid.uuid4().hex[:8].upper()}"
    
    log_dict = log.dict()
    log_dict["log_id"] = log_id
    if not log_dict.get("timestamp"):
        log_dict["timestamp"] = now_iso

    # Heuristic real-time risk scoring
    bytes_out = log_dict.get("bytes_sent") or 0
    cat = (log_dict.get("category") or "").lower()
    host = (log_dict.get("hostname") or "").lower()
    user = log_dict.get("user_id") or "USR-ANON"
    status = log_dict.get("status_code") or 200

    is_anomaly = False
    threat_score = 15.0
    risk_level = "LOW"
    alert_reason = "Standard baseline enterprise traffic"

    if bytes_out > 25_000_000 or "mega" in host or "dropbox" in host or "personal cloud" in cat:
        is_anomaly = True
        threat_score = 92.5 if bytes_out > 20_000_000 else 78.0
        risk_level = "CRITICAL" if threat_score >= 80 else "HIGH"
        alert_reason = f"Unusual volumetric egress ({bytes_out / 1024 / 1024:.1f} MB) to external destination {host}"
    elif "tunnel" in host or "tor" in host or status in [401, 403] and bytes_out > 500_000:
        is_anomaly = True
        threat_score = 84.0
        risk_level = "HIGH"
        alert_reason = f"Suspicious outbound handshake or repeated access failures on {host}"
    elif bytes_out > 5_000_000:
        is_anomaly = True
        threat_score = 65.0
        risk_level = "MEDIUM"
        alert_reason = f"Elevated outbound byte volume ({bytes_out / 1024 / 1024:.1f} MB)"

    log_dict["is_anomaly"] = is_anomaly
    log_dict["threat_score"] = threat_score
    log_dict["risk_level"] = risk_level
    log_dict["alert_reason"] = alert_reason

    # Add to in-memory live stream deque
    _LIVE_STREAM_BUFFER.appendleft(log_dict)

    # Persist into DuckDB web_logs table asynchronously / safely
    try:
        storage = DuckDBStorage()
        df = pd.DataFrame([log_dict])
        storage.append_dataframe(df, table_name="live_web_logs")
    except Exception as e:
        # Don't break stream if duckdb lock retry occurs
        pass

    return {
        "status": "success",
        "log_id": log_id,
        "timestamp": log_dict["timestamp"],
        "entity_id": user,
        "is_anomaly": is_anomaly,
        "threat_score": threat_score,
        "risk_level": risk_level,
        "alert_reason": alert_reason,
        "total_streamed": len(_LIVE_STREAM_BUFFER),
    }

@router.get("/stream-logs")
def get_stream_logs(limit: int = 50, token: dict = Depends(decode_access_token)):
    """Retrieve the latest live logs ingested from n8n streaming simulation."""
    logs = list(_LIVE_STREAM_BUFFER)[:limit]
    return {
        "count": len(logs),
        "total_buffered": len(_LIVE_STREAM_BUFFER),
        "logs": logs,
    }

@router.delete("/stream-logs")
def clear_stream_logs(token: dict = Depends(decode_access_token)):
    """Clear the in-memory live simulation buffer."""
    _LIVE_STREAM_BUFFER.clear()
    return {"status": "cleared", "total_buffered": 0}

@router.get("/table/{table_name}")
def get_table_data(
    table_name: str,
    limit: int = 500,
    offset: int = 0,
    token: dict = Depends(decode_access_token),
):
    """Retrieve tabular data from DuckDB for dashboard visualization."""
    storage = DuckDBStorage()
    try:
        df = storage.query(f"SELECT * FROM {table_name} LIMIT {int(limit)} OFFSET {int(offset)}")
        return {
            "table_name": table_name,
            "count": len(df),
            "columns": df.columns.tolist(),
            "data": df.to_dict(orient="records"),
        }
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Table '{table_name}' error: {e}")
    finally:
        storage.close()

