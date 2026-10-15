import pytest
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from backend.detectors.trained_model_service import TrainedIsolationForestService, MODEL_FEATURES
from backend.api.main import app


@pytest.fixture
def model_service():
    service = TrainedIsolationForestService.get_instance()
    assert service.is_loaded is True, "Trained Isolation Forest model should be loaded from models/"
    return service


def test_model_loading_and_metadata(model_service):
    info = model_service.get_model_info()
    assert info["loaded"] is True
    assert info["model_type"] == "IsolationForest"
    assert info["n_features"] == 32
    assert len(info["features"]) == 32
    assert "bytes_out" in info["features"]
    assert "upload_download_ratio" in info["features"]
    assert "user_dev_bytes_out" in info["features"]


def test_feature_extraction(model_service):
    # Test mapping from typical network flow telemetry
    sample_flows = pd.DataFrame([
        {
            "src_ip": "10.0.1.15",
            "dst_ip": "203.0.113.5",
            "bytes_sent": 500_000_000,
            "bytes_received": 10_000,
            "packets_sent": 350_000,
            "packets_received": 5_000,
            "timestamp": "2026-10-15 02:30:00",  # off-hours
            "is_new": 1,
        },
        {
            "src_ip": "10.0.1.20",
            "dst_ip": "198.51.100.10",
            "bytes_sent": 25_000,
            "bytes_received": 50_000,
            "packets_sent": 20,
            "packets_received": 40,
            "timestamp": "2026-10-15 11:30:00",  # normal hours
            "is_new": 0,
        }
    ])

    X = model_service.extract_features(sample_flows)
    assert X.shape == (2, 32)
    assert list(X.columns) == MODEL_FEATURES

    # Verify mathematical derivations
    assert X["bytes_out"].iloc[0] == 500_000_000
    assert X["upload_download_ratio"].iloc[0] > 1000.0
    assert X["after_hours_flow_count"].iloc[0] == 1.0
    assert X["is_weekend"].iloc[0] == 0.0


def test_model_inference_discrimination(model_service):
    # Construct normal vs exfiltration profile
    telemetry = pd.DataFrame([
        # Routine normal activity
        {
            "bytes_out": 30_000,
            "bytes_in": 120_000,
            "packets_out": 25,
            "packets_in": 80,
            "flow_count": 5,
            "unique_destinations": 2,
            "new_destinations": 0,
            "hour": 14,
            "is_weekend": 0,
        },
        # Extreme exfiltration outlier: 1 GB upload, high ratio, off-hours, new destinations
        {
            "bytes_out": 1_200_000_000,
            "bytes_in": 50_000,
            "packets_out": 900_000,
            "packets_in": 2_000,
            "flow_count": 450,
            "unique_destinations": 18,
            "new_destinations": 15,
            "hour": 3,
            "is_weekend": 1,
            "user_dev_bytes_out": 10.5,
            "peer_dev_ratio": 8.0,
        }
    ])

    results = model_service.predict(telemetry)
    assert len(results["anomaly_flags"]) == 2
    assert len(results["anomaly_scores"]) == 2

    # The exfiltration profile must score substantially higher than the routine activity
    normal_score = results["anomaly_scores"][0]
    exfil_score = results["anomaly_scores"][1]
    assert exfil_score > normal_score
    assert exfil_score >= 50.0  # Significant anomaly score
    assert len(results["top_deviations"][1]) > 0


def test_detect_api_model_endpoints():
    client = TestClient(app)

    # 1. Test model info endpoint
    info_resp = client.get("/detect/model/info")
    assert info_resp.status_code == 200
    info_data = info_resp.json()
    assert info_data["loaded"] is True
    assert info_data["n_features"] == 32

    # 2. Test model predict endpoint with record list
    predict_resp = client.post(
        "/detect/model/predict",
        json={
            "records": [
                {"bytes_sent": 50_000, "bytes_received": 100_000, "hour": 10},
                {"bytes_sent": 850_000_000, "bytes_received": 20_000, "hour": 2},
            ]
        }
    )
    assert predict_resp.status_code == 200
    pred_data = predict_resp.json()
    assert "summary" in pred_data
    assert pred_data["summary"]["total_evaluated"] == 2
    assert len(pred_data["predictions"]) == 2
