"""FastAPI router for synthetic telemetry generation and scenario management."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ...auth.auth import decode_access_token
from ...sim.synthetic_generator import SyntheticTelemetryGenerator, SyntheticConfig, SCENARIO_CATALOGUE
from ...ingestion.ingestion_service import TelemetryIngestionService
from ...storage.storage import DuckDBStorage

router = APIRouter()


class GenerateRequest(BaseModel):
    n_employees: int = 30
    n_days: int = 14
    min_flows: int = 5000
    random_seed: int = 42


@router.get("/scenarios")
def list_scenarios(token: dict = Depends(decode_access_token)):
    """List the 15 enterprise attack and benign lookalike scenarios."""
    return {"scenarios": SCENARIO_CATALOGUE, "count": len(SCENARIO_CATALOGUE)}


@router.post("/generate")
def generate_synthetic_data(
    req: Optional[GenerateRequest] = None,
    token: dict = Depends(decode_access_token),
):
    """Generate synthetic telemetry files (CSV, JSON, Parquet) with dataset manifest."""
    try:
        r = req or GenerateRequest()
        cfg = SyntheticConfig(
            n_employees=r.n_employees,
            n_days=r.n_days,
            min_flows=r.min_flows,
            random_seed=r.random_seed,
        )
        gen = SyntheticTelemetryGenerator(cfg)
        saved = gen.save_dataset()
        return {
            "message": f"Successfully generated {saved['total_records']} synthetic flows",
            "files": saved,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate synthetic telemetry: {str(e)}",
        )


@router.get("/manifest")
def get_dataset_manifest(token: dict = Depends(decode_access_token)):
    """Retrieve manifest metadata for the generated synthetic dataset."""
    manifest_path = Path("./data/synthetic/manifest.json")
    if not manifest_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No synthetic dataset manifest found")
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read manifest: {e}")


@router.post("/ingest-synthetic")
def ingest_synthetic_dataset(
    req: Optional[GenerateRequest] = None,
    table_name: str = "network_flows",
    token: dict = Depends(decode_access_token),
):
    """Generate and directly ingest synthetic flows into DuckDB analytical storage."""
    cfg = SyntheticConfig(
        n_employees=req.n_employees if req else 30,
        n_days=req.n_days if req else 14,
        min_flows=req.min_flows if req else 5000,
        random_seed=req.random_seed if req else 42,
    )
    gen = SyntheticTelemetryGenerator(cfg)
    flows_df, auth_df, gt_df, manifest = gen.generate()

    storage = DuckDBStorage()
    try:
        service = TelemetryIngestionService(storage=storage)
        ingest_res = service.ingest_dataframe(flows_df, table_name=table_name, source_type="synthetic_generator")
        # Also ingest auth logs
        service.ingest_dataframe(auth_df, table_name="auth_logs", source_type="synthetic_generator")
        return {
            "ingestion": ingest_res,
            "manifest": manifest,
        }
    finally:
        storage.close()
