"""
load_model.py - Model Loader Utility for CipherSentinel.

Loads the production-grade CipherSentinelModel from `models/` artifacts.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import joblib
from .ciphersentinel_model import CipherSentinelModel, MODEL_FEATURES


def get_models_dir() -> Path:
    """Find the models directory across possible run environments."""
    # 1. Check relative to this file
    here = Path(__file__).resolve().parent
    if (here / "isolation_forest_model.joblib").exists():
        return here

    # 2. Check workspace root / models
    root = here.parent
    if (root / "models" / "isolation_forest_model.joblib").exists():
        return root / "models"

    # 3. Check current working directory
    cwd = Path(os.getcwd())
    if (cwd / "models" / "isolation_forest_model.joblib").exists():
        return cwd / "models"
    if (cwd.parent / "models" / "isolation_forest_model.joblib").exists():
        return cwd.parent / "models"

    return here


def load_model(
    model_path: Optional[str | Path] = None,
    scaler_path: Optional[str | Path] = None,
) -> CipherSentinelModel:
    """Load and return an instantiated, calibrated CipherSentinelModel."""
    models_dir = get_models_dir()

    primary_path = Path(model_path) if model_path else (models_dir / "isolation_forest_model.joblib")
    unified_path = models_dir / "ciphersentinel_model.joblib"
    scaler_p = Path(scaler_path) if scaler_path else (models_dir / "robust_scaler.joblib")

    # 1. If unified CipherSentinelModel joblib exists, load directly
    if unified_path.exists():
        try:
            m = joblib.load(unified_path)
            if isinstance(m, CipherSentinelModel):
                return m
        except Exception:
            pass

    # 2. If primary isolation forest and scaler exist, instantiate and wrap
    if primary_path.exists():
        raw_iforest = joblib.load(primary_path)

        # Check if already a CipherSentinelModel
        if isinstance(raw_iforest, CipherSentinelModel):
            return raw_iforest

        scaler = joblib.load(scaler_p) if scaler_p.exists() else None

        sentinel = CipherSentinelModel(
            n_estimators=getattr(raw_iforest, "n_estimators", 300),
            max_samples=getattr(raw_iforest, "max_samples", 256),
            contamination=getattr(raw_iforest, "contamination", 0.02),
            random_state=getattr(raw_iforest, "random_state", 42),
        )
        sentinel.model = raw_iforest
        if scaler is not None:
            sentinel.scaler = scaler
        sentinel.decision_threshold = getattr(raw_iforest, "offset_", -0.05)
        sentinel._is_fitted = True
        return sentinel

    raise FileNotFoundError(
        f"CipherSentinel model artifacts not found. Looked in {models_dir}."
    )
