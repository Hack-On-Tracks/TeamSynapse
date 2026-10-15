"""FastAPI router for Cytoscape temporal network graph and traffic replay."""
from __future__ import annotations

import uuid
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ...auth.auth import decode_access_token
from ...graph.graph_service import TemporalGraphService
from ...storage.storage import DuckDBStorage
from ...sim.synthetic_generator import SCENARIO_CATALOGUE

router = APIRouter()

# In-memory replay cache for deterministic simulation playback
_REPLAY_SESSIONS: Dict[str, Dict[str, Any]] = {}


class ReplayRequest(BaseModel):
    scenario: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    speed: float = 1.0
    playback_step_seconds: int = 3600


@router.get("/summary")
def get_graph_summary(
    table_name: Optional[str] = None,
    min_risk: float = 0.0,
    token: dict = Depends(decode_access_token),
):
    """Retrieve network graph summary metrics (nodes, edges, flows, volume)."""
    storage = DuckDBStorage()
    try:
        service = TemporalGraphService(storage=storage)
        return service.get_summary(table_name=table_name, min_risk=min_risk)
    finally:
        storage.close()


@router.get("/nodes")
def get_graph_nodes(
    table_name: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    entity_id: Optional[str] = None,
    protocol: Optional[str] = None,
    category: Optional[str] = None,
    min_risk: float = 0.0,
    token: dict = Depends(decode_access_token),
):
    """Retrieve network graph nodes for Cytoscape.js rendering."""
    storage = DuckDBStorage()
    try:
        service = TemporalGraphService(storage=storage)
        elements = service.get_graph_elements(
            table_name=table_name,
            start_time=start_time,
            end_time=end_time,
            entity_id=entity_id,
            protocol=protocol,
            category=category,
            min_risk=min_risk,
        )
        return {"nodes": elements["nodes"], "count": len(elements["nodes"])}
    finally:
        storage.close()


@router.get("/edges")
def get_graph_edges(
    table_name: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    entity_id: Optional[str] = None,
    protocol: Optional[str] = None,
    category: Optional[str] = None,
    min_risk: float = 0.0,
    limit: int = 250,
    token: dict = Depends(decode_access_token),
):
    """Retrieve aggregated network graph edges for Cytoscape.js rendering."""
    storage = DuckDBStorage()
    try:
        service = TemporalGraphService(storage=storage)
        elements = service.get_graph_elements(
            table_name=table_name,
            start_time=start_time,
            end_time=end_time,
            entity_id=entity_id,
            protocol=protocol,
            category=category,
            min_risk=min_risk,
            limit_edges=limit,
        )
        return {"edges": elements["edges"], "count": len(elements["edges"])}
    finally:
        storage.close()


@router.get("/elements")
def get_all_graph_elements(
    table_name: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    entity_id: Optional[str] = None,
    protocol: Optional[str] = None,
    category: Optional[str] = None,
    min_risk: float = 0.0,
    scenario: Optional[str] = None,
    limit: int = 250,
    token: dict = Depends(decode_access_token),
):
    """Combined endpoint returning Cytoscape.js compatible nodes and edges in one call."""
    storage = DuckDBStorage()
    try:
        service = TemporalGraphService(storage=storage)
        return service.get_graph_elements(
            table_name=table_name,
            start_time=start_time,
            end_time=end_time,
            entity_id=entity_id,
            protocol=protocol,
            category=category,
            min_risk=min_risk,
            scenario=scenario,
            limit_edges=limit,
        )
    finally:
        storage.close()


@router.get("/timeline")
def get_graph_timeline(
    table_name: Optional[str] = None,
    bucket: str = "hour",
    token: dict = Depends(decode_access_token),
):
    """Retrieve time-binned telemetry for the scrubber timeline."""
    storage = DuckDBStorage()
    try:
        service = TemporalGraphService(storage=storage)
        return service.get_timeline(table_name=table_name, bucket=bucket)
    finally:
        storage.close()


@router.get("/entity/{entity_id}")
def get_entity_profile(
    entity_id: str,
    token: dict = Depends(decode_access_token),
):
    """Inspect entity risk profile, baseline comparison, and related cases."""
    storage = DuckDBStorage()
    try:
        from ...scoring.aggregator import CrossTableScoringEngine
        engine = CrossTableScoringEngine(storage=storage)
        detail = engine.get_entity_detail(entity_id)
        if not detail:
            return {"entity_id": entity_id, "status": "No explicit threat profile recorded", "risk_score": 10.0}
        return detail
    finally:
        storage.close()


@router.get("/entity/{entity_id}/connections")
def get_entity_connections(
    entity_id: str,
    table_name: Optional[str] = None,
    token: dict = Depends(decode_access_token),
):
    """Retrieve detailed connections and protocol distribution for a specific entity."""
    storage = DuckDBStorage()
    try:
        service = TemporalGraphService(storage=storage)
        return service.get_entity_connections(entity_id=entity_id, table_name=table_name)
    finally:
        storage.close()


@router.get("/scenarios")
def get_graph_scenarios(token: dict = Depends(decode_access_token)):
    """List simulation scenarios available for graph replay filtering."""
    return {"scenarios": SCENARIO_CATALOGUE}


@router.post("/replay")
def create_replay_session(
    req: ReplayRequest,
    token: dict = Depends(decode_access_token),
):
    """Initialize a deterministic temporal replay session."""
    replay_id = f"RPL-{uuid.uuid4().hex[:8].upper()}"
    storage = DuckDBStorage()
    try:
        service = TemporalGraphService(storage=storage)
        timeline = service.get_timeline()
        session = {
            "replay_id": replay_id,
            "scenario": req.scenario or "ALL",
            "speed": req.speed,
            "step_seconds": req.playback_step_seconds,
            "total_frames": len(timeline),
            "timeline": timeline,
            "frames": timeline,
        }
        _REPLAY_SESSIONS[replay_id] = session
        return session
    finally:
        storage.close()


@router.get("/replay/{replay_id}")
def get_replay_session(
    replay_id: str,
    frame: int = 0,
    token: dict = Depends(decode_access_token),
):
    """Fetch frame snapshot for a deterministic replay session."""
    if replay_id not in _REPLAY_SESSIONS:
        raise HTTPException(status_code=404, detail="Replay session not found")
    session = _REPLAY_SESSIONS[replay_id]
    timeline = session.get("timeline", [])
    current_time_bucket = timeline[frame]["time_bucket"] if 0 <= frame < len(timeline) else None

    # Load graph elements for this specific time bucket
    storage = DuckDBStorage()
    try:
        service = TemporalGraphService(storage=storage)
        elements = service.get_graph_elements(
            start_time=f"{current_time_bucket}:00:00Z" if current_time_bucket else None,
            end_time=f"{current_time_bucket}:59:59Z" if current_time_bucket else None,
            scenario=session["scenario"] if session["scenario"] != "ALL" else None,
        )
        return {
            "replay_id": replay_id,
            "frame": frame,
            "time_bucket": current_time_bucket,
            "elements": elements,
            "total_frames": len(timeline),
        }
    finally:
        storage.close()
