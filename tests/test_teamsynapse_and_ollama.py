import os
from pathlib import Path
import pytest
import pandas as pd
import numpy as np

from models.ciphersentinel_model import CipherSentinelModel, MODEL_FEATURES
from models.load_model import load_model, get_models_dir
from backend.genai.ollama_client import OllamaClient


def test_models_dir_discovery():
    md = get_models_dir()
    assert md.exists()
    assert (md / "isolation_forest_model.joblib").exists()
    assert (md / "robust_scaler.joblib").exists()


def test_ciphersentinel_model_loading():
    model = load_model()
    assert model is not None
    assert len(model.feature_names) == 32
    assert hasattr(model, "predict")
    assert hasattr(model, "predict_risk")
    assert hasattr(model, "anomaly_score")


def test_ciphersentinel_model_inference():
    model = load_model()

    flows = pd.DataFrame([
        {
            "src_ip": "172.31.64.111",
            "dst_ip": "205.174.165.73",
            "fwd_bytes": 45_000_000,
            "bwd_bytes": 120_000,
            "fwd_pkts": 32_000,
            "bwd_pkts": 400,
        },
        {
            "src_ip": "172.31.64.111",
            "dst_ip": "104.16.1.1",
            "fwd_bytes": 2000,
            "bwd_bytes": 50000,
            "fwd_pkts": 10,
            "bwd_pkts": 50,
        }
    ])

    preds = model.predict(flows)
    risks = model.predict_risk(flows)

    assert len(preds) == 2
    assert len(risks) == 2
    # Exfiltration flow should receive elevated risk
    assert risks[0] > risks[1]


def test_ollama_client_models_path():
    client = OllamaClient(models_dir=r"D:\ollama_models")
    assert str(client.models_dir) == r"D:\ollama_models"
    assert client.models_dir.exists()

    status = client.status()
    assert status["models_dir"] == r"D:\ollama_models"
    assert status["models_dir_exists"] is True
    # If service is running, verify model present
    if status["running"]:
        assert "qwen3:4b" in status["models"]
        assert status["model_present"] is True
