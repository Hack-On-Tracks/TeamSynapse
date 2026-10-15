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
    save_processed(df, table_name=table_name)
    storage = DuckDBStorage()
    try:
        storage.insert_dataframe(df, table_name=table_name)
    finally:
        storage.close()

    return {
        "message": f"Successfully uploaded {file.filename}",
        "table_name": table_name,
        "rows": len(df),
        "columns": df.columns.tolist(),
    }

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

