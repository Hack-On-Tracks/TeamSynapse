"""FastAPI router for cross-table threat scoring and investigation cases."""
from __future__ import annotations

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ...auth.auth import decode_access_token
from ...storage.storage import DuckDBStorage
from ...scoring.aggregator import CrossTableScoringEngine

router = APIRouter()


class AggregateRequest(BaseModel):
    table_names: Optional[List[str]] = None
    weights: Optional[Dict[str, float]] = None


class CaseStatusUpdate(BaseModel):
    status: str  # OPEN, INVESTIGATING, CONFIRMED, DISMISSED, MITIGATED, FALSE_POSITIVE
    analyst_note: Optional[str] = None


@router.post("/aggregate")
def aggregate_threat_scores(
    req: AggregateRequest,
    token: dict = Depends(decode_access_token),
):
    """Aggregate multi-table telemetry, compute composite risk scores, and generate cases."""
    storage = DuckDBStorage()
    try:
        engine = CrossTableScoringEngine(storage=storage)
        results = engine.aggregate_tables(table_names=req.table_names, weights=req.weights)
        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scoring aggregation failed: {str(e)}",
        )
    finally:
        storage.close()


@router.get("/scores")
def get_threat_scores(
    min_score: float = 0.0,
    severity: Optional[str] = "ALL",
    limit: int = 100,
    token: dict = Depends(decode_access_token),
):
    """Retrieve scored entities with optional severity and threshold filtering."""
    storage = DuckDBStorage()
    try:
        engine = CrossTableScoringEngine(storage=storage)
        scores = engine.get_threat_scores(min_score=min_score, severity=severity, limit=limit)
        return scores
    finally:
        storage.close()


@router.get("/cases")
def get_cases(
    case_status: Optional[str] = "ALL",
    limit: int = 50,
    token: dict = Depends(decode_access_token),
):
    """Retrieve prioritized SOC investigation cases."""
    storage = DuckDBStorage()
    try:
        engine = CrossTableScoringEngine(storage=storage)
        cases = engine.get_cases(status=case_status, limit=limit)
        return cases
    finally:
        storage.close()


@router.get("/entity/{entity_id}")
def get_entity_detail(
    entity_id: str,
    token: dict = Depends(decode_access_token),
):
    """Retrieve detailed threat score profile and historical cases for a specific entity."""
    storage = DuckDBStorage()
    try:
        engine = CrossTableScoringEngine(storage=storage)
        detail = engine.get_entity_detail(entity_id)
        if not detail:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Entity {entity_id} not found")
        return detail
    finally:
        storage.close()


@router.post("/case/{case_id}/status")
def update_case_status(
    case_id: str,
    update: CaseStatusUpdate,
    token: dict = Depends(decode_access_token),
):
    """Update case status (e.g. INVESTIGATING, CONFIRMED, DISMISSED, MITIGATED, FALSE_POSITIVE)."""
    valid_statuses = ["OPEN", "INVESTIGATING", "CONFIRMED", "DISMISSED", "MITIGATED", "FALSE_POSITIVE"]
    if update.status.upper() not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Choose from: {valid_statuses}",
        )
    storage = DuckDBStorage()
    try:
        # Check if analyst_note column exists, add if needed
        try:
            storage.execute("ALTER TABLE threat_cases ADD COLUMN IF NOT EXISTS analyst_note VARCHAR")
        except Exception:
            pass

        storage.execute(
            "UPDATE threat_cases SET status = ?, analyst_note = ? WHERE case_id = ?",
            (update.status.upper(), update.analyst_note or "", case_id),
        )

        # Record audit event in user database
        try:
            from ...auth.auth import UsersDatabase
            db = UsersDatabase(storage=storage)
            username = token.get("sub", "analyst")
            note_text = f" (Note: {update.analyst_note})" if update.analyst_note else ""
            db.log_audit_event(
                event_type="CASE_REVIEW",
                username=username,
                status="SUCCESS",
                details=f"Case {case_id} status updated to {update.status.upper()}{note_text}",
            )
        except Exception:
            pass

        return {
            "case_id": case_id,
            "status": update.status.upper(),
            "analyst_note": update.analyst_note or "",
            "message": "Status and audit event updated successfully",
        }
    finally:
        storage.close()


@router.get("/consensus")
def get_consensus_scores(limit: int = 50, live_ollama: bool = False, token: dict = Depends(decode_access_token)):
    """Retrieve full 4-stage consensus scores reconciling Rules, Scratch ML, and Ollama LLM."""
    storage = DuckDBStorage()
    try:
        from ...scoring.consensus import ConsensusEngine
        engine = ConsensusEngine(storage=storage)
        return engine.run_all_consensus(limit=limit, live_ollama=live_ollama)
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Consensus error: {type(e).__name__}: {str(e)}")
    finally:
        storage.close()


@router.get("/consensus/entity/{entity_id}")
def get_entity_consensus(entity_id: str, live_ollama: bool = False, token: dict = Depends(decode_access_token)):
    """Run real-time multi-layer consensus evaluation on a specific entity."""
    storage = DuckDBStorage()
    try:
        from ...scoring.consensus import ConsensusEngine
        engine = ConsensusEngine(storage=storage)
        rows = storage.query("SELECT * FROM threat_scores WHERE entity_id = ?", (entity_id,))
        if rows.empty:
            raise HTTPException(status_code=404, detail=f"Entity {entity_id} not found")
        return engine.evaluate_consensus(entity_id, rows.iloc[0].to_dict(), live_ollama=live_ollama)
    finally:
        storage.close()

