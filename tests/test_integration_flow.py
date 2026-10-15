import io
import os
import pytest
import pandas as pd
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.storage.storage import DuckDBStorage


@pytest.fixture(scope="module")
def client():
    # Use temporary test database for integration testing
    os.environ["DUCKDB_PATH"] = "./data/test_integration.db"
    with TestClient(app) as test_client:
        yield test_client
    # Cleanup test db
    try:
        if os.path.exists("./data/test_integration.db"):
            os.remove("./data/test_integration.db")
    except Exception:
        pass


def test_end_to_end_pipeline(client):
    # 1. Health check
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}

    # 2. Authenticate
    login_res = client.post("/auth/token", json={"username": "admin", "password": "admin123"})
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert "access_token" in token_data
    token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Ingest / Upload telemetry CSV
    sample_csv = io.StringIO(
        "user_id,timestamp,bytes_sent,flow_duration,is_new,asset_tier\n"
        "U101,2026-10-15T02:30:00,55000000,120,True,3\n"
        "U102,2026-10-15T14:15:00,12000,30,False,1\n"
        "U103,2026-10-15T11:00:00,25000,45,False,1\n"
        "U104,2026-10-15T16:20:00,18000,25,False,1\n"
    )
    files = {"file": ("test_flows.csv", sample_csv.getvalue().encode("utf-8"), "text/csv")}
    upload_res = client.post("/data/upload", files=files, headers=headers)
    assert upload_res.status_code == 200
    up_data = upload_res.json()
    assert up_data["rows"] == 4
    assert up_data["table_name"] == "test_flows"

    # 4. Run Anomaly Detection
    det_res = client.post(
        "/detect/detect",
        json={"table_name": "test_flows", "contamination": 0.25},
        headers=headers,
    )
    assert det_res.status_code == 200
    det_data = det_res.json()
    assert "anomalies" in det_data
    assert "scores" in det_data

    # 5. Run Cross-Table Scoring Aggregation
    score_res = client.post(
        "/score/aggregate",
        json={"table_names": ["test_flows"]},
        headers=headers,
    )
    assert score_res.status_code == 200
    agg_data = score_res.json()
    assert agg_data["entities_scored"] >= 1

    # 6. Retrieve Scored Entities for Visualization
    scores_res = client.get("/score/scores", headers=headers)
    assert scores_res.status_code == 200
    scores_list = scores_res.json()
    assert len(scores_list) >= 1
    # U101 has off-hours, 55MB volume, tier 3, is_new -> should rank top
    assert scores_list[0]["entity_id"] == "U101"

    # 7. Retrieve Data for Plotly Visualizations
    table_view_res = client.get("/data/table/test_flows", headers=headers)
    assert table_view_res.status_code == 200
    table_view = table_view_res.json()
    assert table_view["count"] == 4

    # 8. Retrieve Threat Cases and Update Status
    cases_res = client.get("/score/cases", headers=headers)
    assert cases_res.status_code == 200
    cases_list = cases_res.json()
    if cases_list:
        case_id = cases_list[0]["case_id"]
        status_res = client.post(
            f"/score/case/{case_id}/status",
            json={"status": "INVESTIGATING"},
            headers=headers,
        )
        assert status_res.status_code == 200
        assert status_res.json()["status"] == "INVESTIGATING"
