import pytest
import pandas as pd
from backend.storage.storage import DuckDBStorage
from backend.scoring.aggregator import CrossTableScoringEngine, score_to_severity


@pytest.fixture
def temp_scoring_storage(tmp_path):
    db_file = str(tmp_path / "test_scoring.db")
    storage = DuckDBStorage(db_path=db_file)
    yield storage
    storage.close()


def test_severity_mapping():
    assert score_to_severity(95.0) == "CRITICAL"
    assert score_to_severity(70.0) == "HIGH"
    assert score_to_severity(45.0) == "MEDIUM"
    assert score_to_severity(15.0) == "LOW"


def test_cross_table_scoring_aggregation(temp_scoring_storage):
    # Setup sample network telemetry table
    net_df = pd.DataFrame([
        {"user_id": "U101", "bytes_sent": 50_000_000, "is_new": True, "asset_tier": 3},
        {"user_id": "U102", "bytes_sent": 200_000, "is_new": False, "asset_tier": 1},
    ])
    temp_scoring_storage.insert_dataframe(net_df, "network_flows")

    # Setup sample authentication telemetry table
    auth_df = pd.DataFrame([
        {"user_id": "U101", "failed_logins": 5, "hour": 2},  # 2 AM off-hours
        {"user_id": "U102", "failed_logins": 0, "hour": 14},
    ])
    temp_scoring_storage.insert_dataframe(auth_df, "auth_logs")

    engine = CrossTableScoringEngine(storage=temp_scoring_storage)
    res = engine.aggregate_tables(table_names=["network_flows", "auth_logs"])

    assert res["entities_scored"] == 2
    # U101 has high volume, off-hours, failed logins, asset tier 3 -> should have higher score than U102
    scores = engine.get_threat_scores()
    assert len(scores) == 2
    top_entity = scores[0]
    assert top_entity["entity_id"] == "U101"
    assert top_entity["composite_score"] > scores[1]["composite_score"]
    assert top_entity["severity"] in ["CRITICAL", "HIGH"]

    # Cases should be opened for entities with score >= 35
    cases = engine.get_cases()
    assert len(cases) >= 1
    assert cases[0]["entity_id"] == "U101"
