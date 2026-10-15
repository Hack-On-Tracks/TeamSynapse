import pytest
import pandas as pd
from backend.sim.synthetic_generator import SyntheticTelemetryGenerator, GENERATOR_SCENARIOS


def test_generator_scenarios_completeness():
    # Verify all 15 required scenarios are registered
    assert len(GENERATOR_SCENARIOS) >= 15
    assert "normal_employee_traffic" in GENERATOR_SCENARIOS
    assert "approved_nightly_backups" in GENERATOR_SCENARIOS
    assert "high_volume_outbound" in GENERATOR_SCENARIOS
    assert "low_and_slow_exfil" in GENERATOR_SCENARIOS
    assert "first_seen_destination" in GENERATOR_SCENARIOS
    assert "unusual_after_hours" in GENERATOR_SCENARIOS
    assert "dns_entropy_frequency" in GENERATOR_SCENARIOS
    assert "approved_cloud_upload_lookalike" in GENERATOR_SCENARIOS
    assert "suspicious_auth_then_network" in GENERATOR_SCENARIOS
    assert "multi_user_unusual_shared_destination" in GENERATOR_SCENARIOS


def test_generator_reproducibility():
    gen1 = SyntheticTelemetryGenerator(seed=42, num_employees=5, days=1)
    df1, _, _, _ = gen1.generate(num_records=50)

    gen2 = SyntheticTelemetryGenerator(seed=42, num_employees=5, days=1)
    df2, _, _, _ = gen2.generate(num_records=50)

    # Identical seed must yield exact same rows
    pd.testing.assert_frame_equal(df1, df2)


def test_data_quality_constraints():
    gen = SyntheticTelemetryGenerator(seed=123, num_employees=10, days=2)
    df, _, _, manifest = gen.generate(num_records=200)

    # 1. Non-negative bytes, packets, duration
    assert (df["BYTES"] >= 0).all()
    assert (df["BYTES_REV"] >= 0).all()
    assert (df["PACKETS"] >= 0).all()
    assert (df["DURATION"] >= 0).all()

    # 2. Temporal consistency: TIME_LAST >= TIME_FIRST
    time_first = pd.to_datetime(df["TIME_FIRST"], format="ISO8601")
    time_last = pd.to_datetime(df["TIME_LAST"], format="ISO8601")
    assert (time_last >= time_first).all()

    # 3. Valid port ranges (1 to 65535)
    assert ((df["SRC_PORT"] >= 1) & (df["SRC_PORT"] <= 65535)).all()
    assert ((df["DST_PORT"] >= 1) & (df["DST_PORT"] <= 65535)).all()

    # 4. Manifest properties
    assert manifest["record_count"] >= 1
    assert manifest["random_seed"] == 123
    assert "sha256_hash" in manifest
    assert "scenario_counts" in manifest
    assert len(manifest["scenario_counts"]) >= 1


def test_ground_truth_isolation():
    gen = SyntheticTelemetryGenerator(seed=999)
    df, _, _, manifest = gen.generate(num_records=100)

    # Ground truth fields exist in raw generator output
    assert "SCENARIO" in df.columns
    assert "IS_SUSPICIOUS" in df.columns

    # Model training feature set must EXCLUDE ground truth columns
    feature_cols = [c for c in df.columns if c not in ["SCENARIO", "IS_SUSPICIOUS", "ID", "DATA_QUALITY_FLAGS"]]
    assert "SCENARIO" not in feature_cols
    assert "IS_SUSPICIOUS" not in feature_cols
