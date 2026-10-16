"""
train_model.py - Manual training script for CipherSentinel Isolation Forest.
Trains the production-grade, self-healing, self-scaling model and exports
all artifacts to models/ for seamless integration in external projects.
"""

import os
import sys
import json
import time
import joblib
import pandas as pd
import numpy as np

# Ensure project root in sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
from models.ciphersentinel_model import CipherSentinelModel


def main():
    print("=" * 70)
    print("CIPHERSENTINEL: ISOLATION FOREST MODEL TRAINING & ARTIFACT EXPORT")
    print("=" * 70)

    # 1. Load configuration
    config_path = os.path.join(ROOT_DIR, "config", "training_config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "config", "training_config.json")
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r") as f:
        cfg = json.load(f)

    feature_cols = cfg["feature_columns_ordered"]
    hparams = cfg["hyperparameters_recommended"]
    train_path = cfg["data_paths"]["train_features"]
    val_path = cfg["data_paths"]["validation_features"]
    test_path = cfg["data_paths"]["test_features"]
    gt_path = cfg["data_paths"]["ground_truth_incidents"]

    print(f"[*] Configuration loaded from: {config_path}")
    print(f"[*] Total feature columns: {len(feature_cols)}")

    # 2. Load model-ready training data
    print(f"\n[*] Loading training split from: {train_path}")
    train_df = pd.read_parquet(train_path)
    X_train = train_df[feature_cols].fillna(0)
    print(f"[+] Loaded {len(X_train)} training records ({X_train.shape[1]} features).")

    # 3. Initialize and fit unified CipherSentinelModel
    print("\n[*] Initializing CipherSentinelModel with parameters:")
    for k, v in hparams.items():
        print(f"    - {k}: {v}")

    t0 = time.time()
    model = CipherSentinelModel(
        n_estimators=hparams.get("n_estimators", 300),
        max_samples=hparams.get("max_samples", 256),
        contamination=hparams.get("contamination", 0.02),
        random_state=hparams.get("random_state", 42),
        n_jobs=cfg["hardware_notes"].get("intended_n_jobs", -1)
    )
    model.fit(X_train)
    fit_duration = round(time.time() - t0, 3)

    print(f"[+] Model fitting complete in {fit_duration}s!")
    print(f"[+] Calibrated Anomaly Threshold: {model.decision_threshold:.4f}")

    # 4. Predict on training data
    train_preds = model.predict(X_train)  # -1 for anomaly, 1 for normal
    train_scores = model.anomaly_score(X_train)
    train_anomalies = int((train_preds == -1).sum())
    print(f"[+] Training set: {train_anomalies} anomalies flagged ({train_anomalies / len(train_preds) * 100:.2f}%)")

    # 5. Evaluate on Validation & Test splits if present
    for split_name, split_path in [("Validation", val_path), ("Test", test_path)]:
        if os.path.exists(split_path):
            df_eval = pd.read_parquet(split_path)
            X_eval = df_eval[feature_cols].fillna(0)

            preds = model.predict(X_eval)
            scores = model.anomaly_score(X_eval)
            risks = model.predict_risk(X_eval)
            n_anom = int((preds == -1).sum())
            print(f"\n[*] {split_name} Split ({len(df_eval)} rows):")
            print(f"    - Anomalies flagged: {n_anom} ({n_anom / len(preds) * 100:.2f}%)")
            print(f"    - Score range: min={scores.min():.4f}, median={float(np.median(scores)):.4f}, max={scores.max():.4f}")
            print(f"    - Risk score (0-100) range: min={risks.min():.1f}, median={float(np.median(risks)):.1f}, max={risks.max():.1f}")

    # 6. Check detection against ground truth incident labels
    if os.path.exists(gt_path):
        gt_df = pd.read_parquet(gt_path)
        print(f"\n[*] Ground truth incident table loaded ({len(gt_df)} incidents).")
        print("    Sample incidents detected:")
        test_merged = pd.read_parquet(test_path).merge(gt_df, on=["user_id", "day_index"], how="left")
        test_insiders = test_merged[test_merged["is_insider_threat"] == 1]
        for _, row in test_insiders.head(5).iterrows():
            sc = float(model.anomaly_score(pd.DataFrame([row[feature_cols]]))[0])
            rk = float(model.predict_risk(pd.DataFrame([row[feature_cols]]))[0])
            print(f"    - [{row['incident_id']}] User: {row['user_id']}, Day: {row['day_index']} | Anomaly Score: {sc:.4f} | Risk: {rk:.1f}/100 | {row['scenario_name']}")

    # 7. Save trained model artifacts into models/
    models_dir = os.path.join(ROOT_DIR, "models")
    os.makedirs(models_dir, exist_ok=True)

    primary_model_path = os.path.join(models_dir, "isolation_forest_model.joblib")
    unified_model_path = os.path.join(models_dir, "ciphersentinel_model.joblib")
    scaler_artifact_path = os.path.join(models_dir, "robust_scaler.joblib")
    metadata_path = os.path.join(models_dir, "model_metadata.json")

    # Export unified model as primary isolation_forest_model.joblib (drop-in compatibility)
    joblib.dump(model, primary_model_path)
    joblib.dump(model, unified_model_path)
    joblib.dump(model.scaler, scaler_artifact_path)

    # Export metadata JSON
    metadata = {
        "model_name": "CipherSentinelModel",
        "description": "Production-grade, self-healing, self-scaling Isolation Forest model for encrypted insider threat detection",
        "trained_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "training_records": len(X_train),
        "feature_count": len(feature_cols),
        "feature_columns_ordered": feature_cols,
        "feature_medians": model.feature_medians,
        "calibrated_decision_threshold": model.decision_threshold,
        "hyperparameters": {
            "n_estimators": model.n_estimators,
            "max_samples": model.max_samples,
            "contamination": model.contamination,
            "random_state": model.random_state,
        },
        "supported_input_formats": [
            "pandas.DataFrame (any column order, missing columns automatically imputed)",
            "numpy.ndarray (shape [N, 32], raw unscaled or pre-scaled)",
            "dict (single observation key-value)",
            "list of dicts"
        ]
    }
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\n[+] Saved primary model to: {primary_model_path}")
    print(f"[+] Saved unified model to: {unified_model_path}")
    print(f"[+] Saved standalone scaler to: {scaler_artifact_path}")
    print(f"[+] Saved model metadata to: {metadata_path}")

    print("\n" + "=" * 70)
    print("MODEL TRAINING & EXPORT COMPLETE SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()
