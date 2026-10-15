"""Comprehensive ingestion service with schema validation, normalization, and quarantine.

Handles CSV, JSON, Parquet, and Zeek logs. Normalizes column aliases (SRC_IP -> src_ip),
enforces UTC timestamps, filters duplicates, quarantines malformed rows, and generates
ingestion quality audit events.
"""
from __future__ import annotations

import datetime
import io
import json
import os
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import pandas as pd
from ..storage.storage import DuckDBStorage

DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
PROCESSED_DIR = DATA_DIR / "processed"
QUARANTINE_DIR = DATA_DIR / "quarantine"

# Column alias dictionary to support uppercase, lowercase, and Zeek metadata conventions
COLUMN_ALIASES = {
    "id": "flow_id",
    "flow_id": "flow_id",
    "src_ip": "src_ip",
    "id.orig_h": "src_ip",
    "dst_ip": "dst_ip",
    "id.resp_h": "dst_ip",
    "src_port": "src_port",
    "id.orig_p": "src_port",
    "dst_port": "dst_port",
    "id.resp_p": "dst_port",
    "protocol": "proto",
    "proto": "proto",
    "time_first": "timestamp",
    "time_last": "time_last",
    "ts": "timestamp",
    "timestamp": "timestamp",
    "duration": "duration",
    "bytes": "bytes_sent",
    "bytes_sent": "bytes_sent",
    "orig_bytes": "bytes_sent",
    "bytes_rev": "bytes_rev",
    "resp_bytes": "bytes_rev",
    "packets": "packets",
    "orig_pkts": "packets",
    "packets_rev": "packets_rev",
    "resp_pkts": "packets_rev",
    "app": "app",
    "category": "dst_category",
    "dst_category": "dst_category",
    "user_id": "user_id",
    "user": "user_id",
    "asset_tier": "asset_tier",
    "scenario": "scenario",
    "allowlisted": "allowlisted",
}


class TelemetryIngestionService:
    """Enterprise ingestion and data quality controller."""

    def __init__(self, storage: Optional[DuckDBStorage] = None):
        self.storage = storage or DuckDBStorage()
        PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    def normalize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Map heterogeneous column names to standard lowercase canonical schema."""
        rename_map = {}
        for col in df.columns:
            clean_col = str(col).strip().lower()
            if clean_col in COLUMN_ALIASES:
                rename_map[col] = COLUMN_ALIASES[clean_col]
            else:
                rename_map[col] = clean_col
        return df.rename(columns=rename_map)

    def validate_and_quarantine(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, int]]:
        """Validate records and isolate invalid rows into quarantine."""
        df = self.normalize_columns(df)
        reasons: Dict[str, int] = {}
        quarantine_indices = set()

        # 1. Check for negative bytes or durations
        for num_col in ["bytes_sent", "bytes_rev", "duration", "packets", "packets_rev"]:
            if num_col in df.columns:
                df[num_col] = pd.to_numeric(df[num_col], errors="coerce")
                bad_mask = df[num_col] < 0
                count = int(bad_mask.sum())
                if count > 0:
                    reasons[f"negative_{num_col}"] = reasons.get(f"negative_{num_col}", 0) + count
                    quarantine_indices.update(df[bad_mask].index.tolist())

        # 2. Check for missing mandatory endpoints
        if "src_ip" in df.columns:
            bad_src = df["src_ip"].isna() | (df["src_ip"].astype(str).str.strip() == "")
            c = int(bad_src.sum())
            if c > 0:
                reasons["missing_src_ip"] = reasons.get("missing_src_ip", 0) + c
                quarantine_indices.update(df[bad_src].index.tolist())

        if "dst_ip" in df.columns:
            bad_dst = df["dst_ip"].isna() | (df["dst_ip"].astype(str).str.strip() == "")
            c = int(bad_dst.sum())
            if c > 0:
                reasons["missing_dst_ip"] = reasons.get("missing_dst_ip", 0) + c
                quarantine_indices.update(df[bad_dst].index.tolist())

        # 3. Normalize timestamp to UTC
        if "timestamp" in df.columns:
            ts_parsed = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
            bad_ts = ts_parsed.isna()
            c = int(bad_ts.sum())
            if c > 0:
                reasons["invalid_timestamp"] = reasons.get("invalid_timestamp", 0) + c
                quarantine_indices.update(df[bad_ts].index.tolist())
            else:
                df["timestamp"] = ts_parsed.dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        quarantine_df = df.loc[list(quarantine_indices)].copy()
        clean_df = df.drop(index=list(quarantine_indices)).copy()

        return clean_df, quarantine_df, reasons

    def ingest_dataframe(
        self,
        df: pd.DataFrame,
        table_name: str,
        source_type: str = "csv_upload",
        deduplicate: bool = True,
    ) -> Dict[str, Any]:
        """Ingest a DataFrame into DuckDB and Parquet with validation, deduplication, and quarantine."""
        total_in = len(df)
        batch_id = f"BATCH-{uuid.uuid4().hex[:8].upper()}"

        clean_df, quarantine_df, quarantine_reasons = self.validate_and_quarantine(df)
        quarantined_count = len(quarantine_df)

        # Handle duplicates
        duplicate_count = 0
        if deduplicate and not clean_df.empty:
            subset_cols = [c for c in ["flow_id", "src_ip", "dst_ip", "timestamp", "bytes_sent"] if c in clean_df.columns]
            if len(subset_cols) >= 2:
                initial_count = len(clean_df)
                clean_df = clean_df.drop_duplicates(subset=subset_cols)
                duplicate_count = initial_count - len(clean_df)

        accepted_count = len(clean_df)

        # Save clean records to DuckDB and Parquet
        if accepted_count > 0:
            parquet_path = PROCESSED_DIR / f"{table_name}.parquet"
            clean_df.to_parquet(parquet_path, index=False)
            self.storage.insert_dataframe(clean_df, table_name)

        # Save quarantined records if any
        if quarantined_count > 0:
            q_path = QUARANTINE_DIR / f"{table_name}_{batch_id}_quarantined.parquet"
            quarantine_df.to_parquet(q_path, index=False)

        # Record audit log
        try:
            self.storage.execute(
                """
                INSERT INTO audit_logs (id, timestamp, event_type, username, status, details, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"aud_{uuid.uuid4().hex[:8]}",
                    datetime.datetime.now(datetime.timezone.utc),
                    "DATA_INGESTION",
                    "system",
                    "SUCCESS" if accepted_count > 0 else "WARNING",
                    f"Batch {batch_id}: table={table_name}, accepted={accepted_count}, quarantined={quarantined_count}, duplicates={duplicate_count}",
                    "127.0.0.1",
                ),
            )
        except Exception:
            pass

        return {
            "batch_id": batch_id,
            "table_name": table_name,
            "source_type": source_type,
            "total_input_records": total_in,
            "accepted_records": accepted_count,
            "quarantined_records": quarantined_count,
            "duplicate_records": duplicate_count,
            "quarantine_reasons": quarantine_reasons,
            "columns": clean_df.columns.tolist() if not clean_df.empty else [],
            "ingested_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
