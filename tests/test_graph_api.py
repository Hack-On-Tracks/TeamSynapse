import os
import pytest
from fastapi.testclient import TestClient
from backend.api.main import app


@pytest.fixture(scope="module")
def api_client():
    os.environ["DUCKDB_PATH"] = "./data/test_graph_api.db"
    with TestClient(app) as client:
        yield client
    try:
        if os.path.exists("./data/test_graph_api.db"):
            os.remove("./data/test_graph_api.db")
    except Exception:
        pass


@pytest.fixture(scope="module")
def auth_headers(api_client):
    login_res = api_client.post("/auth/token", json={"username": "admin", "password": "admin123"})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_graph_endpoints_available(api_client, auth_headers):
    # 0. Ingest initial synthetic flows to populate database
    gen_res = api_client.post(
        "/sim/ingest-synthetic",
        json={"min_flows": 150, "n_employees": 10, "n_days": 2},
        headers=auth_headers,
    )
    assert gen_res.status_code == 200

    # 1. /graph/summary
    res = api_client.get("/graph/summary", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "node_count" in data
    assert "edge_count" in data
    assert "critical_entities" in data

    # 2. /graph/elements (Cytoscape format)
    res = api_client.get("/graph/elements", headers=auth_headers)
    assert res.status_code == 200
    elements = res.json()
    assert "nodes" in elements
    assert "edges" in elements
    assert len(elements["nodes"]) > 0

    # 3. /graph/nodes & /graph/edges
    res_nodes = api_client.get("/graph/nodes", headers=auth_headers)
    assert res_nodes.status_code == 200
    nodes_data = res_nodes.json()
    assert "nodes" in nodes_data or isinstance(nodes_data, list)

    res_edges = api_client.get("/graph/edges", headers=auth_headers)
    assert res_edges.status_code == 200
    edges_data = res_edges.json()
    assert "edges" in edges_data or isinstance(edges_data, list)

    # 4. /graph/timeline
    res_timeline = api_client.get("/graph/timeline?buckets=8", headers=auth_headers)
    assert res_timeline.status_code == 200
    timeline_data = res_timeline.json()
    assert isinstance(timeline_data, list) or "timeline" in timeline_data

    # 5. /graph/scenarios & /sim/scenarios
    res_scenarios = api_client.get("/graph/scenarios", headers=auth_headers)
    assert res_scenarios.status_code == 200
    sc_data = res_scenarios.json()
    sc_list = sc_data.get("scenarios", sc_data) if isinstance(sc_data, dict) else sc_data
    assert len(sc_list) >= 15

    res_sim_scenarios = api_client.get("/sim/scenarios", headers=auth_headers)
    assert res_sim_scenarios.status_code == 200
    sim_sc_data = res_sim_scenarios.json()
    sim_sc_list = sim_sc_data.get("scenarios", sim_sc_data) if isinstance(sim_sc_data, dict) else sim_sc_data
    assert len(sim_sc_list) >= 15

    # 6. /graph/replay
    res_replay = api_client.post(
        "/graph/replay",
        json={"scenario": "ALL_SCENARIOS", "step_size_minutes": 30, "min_risk": 0.0},
        headers=auth_headers,
    )
    assert res_replay.status_code == 200
    replay_data = res_replay.json()
    assert "replay_id" in replay_data
    assert "total_frames" in replay_data
    assert "frames" in replay_data
