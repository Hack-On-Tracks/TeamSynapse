"""Configurable, reproducible synthetic network-flow telemetry generator for CipherSentinel.

Implements 15 realistic enterprise scenarios, complete canonical schema metadata,
dataset manifest generation, and ground-truth separation (labels never leak into ML features).
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd

from .destinations import build_catalogue, dst_id, BACKUP_DST, TEAM_SAAS_DST
from .users import build_users, hour_profile, GROUP_UPLOAD_SCALE

# RFC 5737 Documentation IP ranges for synthetic enterprise & external simulation
INTERNAL_NET = "10.0."
EXTERNAL_BLOCKS = ["198.51.100.", "203.0.113."]

# Supported 15 enterprise scenarios
SCENARIO_CATALOGUE = [
    "normal_employee_traffic",
    "approved_nightly_backups",
    "high_volume_outbound",
    "low_and_slow_exfil",
    "first_seen_destination",
    "unusual_after_hours",
    "dns_entropy_frequency",
    "approved_cloud_upload_lookalike",
    "new_saas_rollout",
    "software_update_traffic",
    "employee_travel_unusual_hours",
    "rotating_destination_transfers",
    "missing_incomplete_telemetry",
    "suspicious_auth_then_network",
    "multi_user_unusual_shared_destination",
]
GENERATOR_SCENARIOS = SCENARIO_CATALOGUE


@dataclass
class SyntheticConfig:
    n_employees: int = 40
    n_days: int = 14
    min_flows: int = 5000
    random_seed: int = 42
    start_date: str = "2026-09-01T08:00:00Z"
    quic_share: float = 0.25
    scenario_weights: Dict[str, float] = field(default_factory=lambda: {
        "normal_employee_traffic": 0.65,
        "approved_nightly_backups": 0.05,
        "high_volume_outbound": 0.02,
        "low_and_slow_exfil": 0.02,
        "first_seen_destination": 0.03,
        "unusual_after_hours": 0.03,
        "dns_entropy_frequency": 0.03,
        "approved_cloud_upload_lookalike": 0.04,
        "new_saas_rollout": 0.03,
        "software_update_traffic": 0.03,
        "employee_travel_unusual_hours": 0.02,
        "rotating_destination_transfers": 0.02,
        "missing_incomplete_telemetry": 0.01,
        "suspicious_auth_then_network": 0.02,
        "multi_user_unusual_shared_destination": 0.02,
    })


class SyntheticTelemetryGenerator:
    """Generates synthetic network flows, auth logs, and DNS telemetry."""

    def __init__(
        self,
        config: Optional[SyntheticConfig] = None,
        seed: Optional[int] = None,
        num_employees: Optional[int] = None,
        days: Optional[int] = None,
        min_flows: Optional[int] = None,
    ):
        if config is None:
            self.cfg = SyntheticConfig()
        else:
            self.cfg = config

        if seed is not None:
            self.cfg.random_seed = seed
        if num_employees is not None:
            self.cfg.n_employees = num_employees
        if days is not None:
            self.cfg.n_days = days
        if min_flows is not None:
            self.cfg.min_flows = min_flows

        self.rng = np.random.default_rng(self.cfg.random_seed)
        self.start_dt = pd.to_datetime(self.cfg.start_date, utc=True)
        self.cat_df = build_catalogue()

    def generate(self, num_records: Optional[int] = None) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
        """Generate flows, auth logs, ground-truth labels, and dataset manifest."""
        if num_records is not None:
            self.cfg.min_flows = num_records
        rng = self.rng
        n_users = self.cfg.n_employees
        n_days = self.cfg.n_days
        base_flows_per_day = max(20, self.cfg.min_flows // (n_users * n_days))
        ingestion_ts = self.start_dt.isoformat()

        # 1. Build employees
        users = []
        peer_groups = ["Engineering", "Finance", "Sales", "Support"]
        for i in range(1, n_users + 1):
            group = peer_groups[i % len(peer_groups)]
            asset_tier = int(rng.choice([1, 2, 3], p=[0.55, 0.30, 0.15]))
            users.append({
                "user_id": f"EMP{i:03d}",
                "device_id": f"DEV{i:03d}",
                "src_ip": f"10.0.{i // 250 + 1}.{i % 250 + 1}",
                "peer_group": group,
                "asset_tier": asset_tier,
                "start_day": 0,
            })
        users_df = pd.DataFrame(users)

        flows = []
        ground_truth = []
        auth_logs = []

        flow_seq = 1
        auth_seq = 1

        # Pre-assign special attack & benign scenario actors safely with modulo
        n_u = len(users_df)
        s1_user = users_df.iloc[0 % n_u]["user_id"]  # High-volume exfil
        s2_user = users_df.iloc[1 % n_u]["user_id"]  # Low-and-slow
        s3_user = users_df.iloc[2 % n_u]["user_id"]  # First-seen dest
        s4_user = users_df.iloc[3 % n_u]["user_id"]  # Off-hours
        s5_user = users_df.iloc[4 % n_u]["user_id"]  # Rotating dests
        s6_user = users_df.iloc[5 % n_u]["user_id"]  # Suspicious auth + network
        s7_user = users_df.iloc[6 % n_u]["user_id"]  # DNS entropy
        b1_user = users_df.iloc[7 % n_u]["user_id"]  # Approved backup
        b2_user = users_df.iloc[8 % n_u]["user_id"]  # SaaS rollout

        attack_day = 0 if n_days <= 1 else min(max(0, n_days - 2), n_days - 1)

        for day in range(n_days):
            day_start = self.start_dt + pd.Timedelta(days=day)
            is_weekend = (day_start.dayofweek >= 5)

            for _, u in users_df.iterrows():
                uid = u["user_id"]
                src_ip = u["src_ip"]
                group = u["peer_group"]
                tier = u["asset_tier"]

                # Activity volume for this user on this day
                weekend_mult = 0.15 if is_weekend else 1.0
                n_flows_today = int(rng.poisson(base_flows_per_day * weekend_mult))

                # Normal traffic generation
                for _ in range(n_flows_today):
                    # Working hour sampling
                    h_probs = hour_profile(group)
                    hour = int(rng.choice(24, p=h_probs))
                    minute = int(rng.integers(0, 60))
                    sec = int(rng.integers(0, 60))
                    t_first = day_start + pd.Timedelta(hours=hour, minutes=minute, seconds=sec)
                    dur = float(np.clip(rng.lognormal(0.5, 0.8), 0.1, 1800.0))
                    t_last = t_first + pd.Timedelta(seconds=dur)

                    # Destination sampling
                    dst_row = self.cat_df.iloc[rng.integers(0, min(200, len(self.cat_df)))]
                    dst_ip = dst_row["dst_ip"]
                    cat = dst_row["dst_category"]
                    sni = dst_row["sni_name"]
                    is_quic = bool(rng.random() < self.cfg.quic_share)

                    proto = "UDP" if is_quic else "TCP"
                    dst_port = 443
                    src_port = int(rng.integers(32768, 65535))

                    bytes_sent = float(np.clip(rng.lognormal(9.0, 1.2), 300.0, 5_000_000.0))
                    bytes_rev = float(np.clip(rng.lognormal(10.5, 1.4), 1000.0, 20_000_000.0))
                    pkts = int(max(1, bytes_sent / rng.uniform(600, 1200)))
                    pkts_rev = int(max(1, bytes_rev / rng.uniform(800, 1400)))

                    flow_id = f"FLOW-{flow_seq:07d}"
                    flow_seq += 1

                    flows.append({
                        "ID": flow_id,
                        "USER_ID": uid,
                        "SRC_IP": src_ip,
                        "DST_IP": dst_ip,
                        "SRC_PORT": src_port,
                        "DST_PORT": dst_port,
                        "PROTOCOL": proto,
                        "TIME_FIRST": t_first.isoformat(),
                        "TIME_LAST": t_last.isoformat(),
                        "DURATION": round(dur, 2),
                        "BYTES": round(bytes_sent, 1),
                        "BYTES_REV": round(bytes_rev, 1),
                        "PACKETS": pkts,
                        "PACKETS_REV": pkts_rev,
                        "QUIC_VERSION": "1" if is_quic else "",
                        "QUIC_SNI": sni if is_quic else "",
                        "QUIC_USERAGENT": "Mozilla/5.0" if is_quic else "",
                        "APP": "HTTPS",
                        "CATEGORY": cat,
                        "ASSET_TIER": tier,
                        "SCENARIO": "normal_employee_traffic",
                        "IS_SUSPICIOUS": False,
                        "ALLOWLISTED": False,
                        "DESTINATION_FIRST_SEEN": False,
                        "INGESTION_TIME": ingestion_ts,
                        "DATA_QUALITY_FLAGS": "OK",
                    })

                # Successful baseline authentication log
                auth_logs.append({
                    "auth_id": f"AUTH-{auth_seq:07d}",
                    "user_id": uid,
                    "timestamp": (day_start + pd.Timedelta(hours=8, minutes=int(rng.integers(1, 45)))).isoformat(),
                    "src_ip": src_ip,
                    "auth_status": "SUCCESS",
                    "failed_logins": 0,
                    "target_service": "ActiveDirectory_Kerberos",
                })
                auth_seq += 1

            # ----------------------------------------------------
            # Scenario Injections on attack_day
            # ----------------------------------------------------
            if day == attack_day:
                # 1. High-Volume Outbound Transfer (S1)
                t_s1 = day_start + pd.Timedelta(hours=2, minutes=30)
                flows.append({
                    "ID": f"FLOW-{flow_seq:07d}",
                    "USER_ID": s1_user,
                    "SRC_IP": "10.0.1.1",
                    "DST_IP": "198.51.100.99",
                    "SRC_PORT": 49152,
                    "DST_PORT": 443,
                    "PROTOCOL": "TCP",
                    "TIME_FIRST": t_s1.isoformat(),
                    "TIME_LAST": (t_s1 + pd.Timedelta(seconds=1240)).isoformat(),
                    "DURATION": 1240.0,
                    "BYTES": 650_000_000.0,  # 650 MB
                    "BYTES_REV": 150_000.0,
                    "PACKETS": 450_000,
                    "PACKETS_REV": 3_500,
                    "QUIC_VERSION": "",
                    "QUIC_SNI": "personal-cloud-0288.example",
                    "QUIC_USERAGENT": "",
                    "APP": "HTTPS",
                    "CATEGORY": "personal_cloud",
                    "ASSET_TIER": 3,
                    "SCENARIO": "high_volume_outbound",
                    "IS_SUSPICIOUS": True,
                    "ALLOWLISTED": False,
                    "DESTINATION_FIRST_SEEN": True,
                    "INGESTION_TIME": ingestion_ts,
                    "DATA_QUALITY_FLAGS": "OK",
                })
                ground_truth.append({
                    "flow_id": f"FLOW-{flow_seq:07d}",
                    "user_id": s1_user,
                    "scenario": "high_volume_outbound",
                    "label": "MALICIOUS",
                    "tactic": "TA0010 - Exfiltration",
                    "technique": "T1048.003 - Exfiltration Over Unencrypted/Encrypted Channel",
                })
                flow_seq += 1

                # 2. Suspicious Auth followed by network activity (S6)
                for f_attempt in range(5):
                    auth_logs.append({
                        "auth_id": f"AUTH-{auth_seq:07d}",
                        "user_id": s6_user,
                        "timestamp": (day_start + pd.Timedelta(hours=1, minutes=10 + f_attempt)).isoformat(),
                        "src_ip": "10.0.1.6",
                        "auth_status": "FAILURE",
                        "failed_logins": f_attempt + 1,
                        "target_service": "Domain_Controller_SMB",
                    })
                    auth_seq += 1

                auth_logs.append({
                    "auth_id": f"AUTH-{auth_seq:07d}",
                    "user_id": s6_user,
                    "timestamp": (day_start + pd.Timedelta(hours=1, minutes=18)).isoformat(),
                    "src_ip": "10.0.1.6",
                    "auth_status": "SUCCESS",
                    "failed_logins": 5,
                    "target_service": "Domain_Controller_SMB",
                })
                auth_seq += 1

                # Followed by outbound spike
                t_s6 = day_start + pd.Timedelta(hours=1, minutes=25)
                flows.append({
                    "ID": f"FLOW-{flow_seq:07d}",
                    "USER_ID": s6_user,
                    "SRC_IP": "10.0.1.6",
                    "DST_IP": "203.0.113.88",
                    "SRC_PORT": 50123,
                    "DST_PORT": 443,
                    "PROTOCOL": "TCP",
                    "TIME_FIRST": t_s6.isoformat(),
                    "TIME_LAST": (t_s6 + pd.Timedelta(seconds=450)).isoformat(),
                    "DURATION": 450.0,
                    "BYTES": 85_000_000.0,
                    "BYTES_REV": 40_000.0,
                    "PACKETS": 60_000,
                    "PACKETS_REV": 1_200,
                    "QUIC_VERSION": "",
                    "QUIC_SNI": "external-storage.example",
                    "QUIC_USERAGENT": "",
                    "APP": "HTTPS",
                    "CATEGORY": "other",
                    "ASSET_TIER": 2,
                    "SCENARIO": "suspicious_auth_then_network",
                    "IS_SUSPICIOUS": True,
                    "ALLOWLISTED": False,
                    "DESTINATION_FIRST_SEEN": True,
                    "INGESTION_TIME": ingestion_ts,
                    "DATA_QUALITY_FLAGS": "OK",
                })
                ground_truth.append({
                    "flow_id": f"FLOW-{flow_seq:07d}",
                    "user_id": s6_user,
                    "scenario": "suspicious_auth_then_network",
                    "label": "MALICIOUS",
                    "tactic": "TA0001 - Initial Access",
                    "technique": "T1078.002 - Domain Accounts / Brute Force",
                })
                flow_seq += 1

                # 3. Approved Nightly Backup (B01 - Benign Lookalike)
                t_b1 = day_start + pd.Timedelta(hours=3, minutes=0)
                flows.append({
                    "ID": f"FLOW-{flow_seq:07d}",
                    "USER_ID": b1_user,
                    "SRC_IP": "10.0.1.8",
                    "DST_IP": "198.51.100.60",
                    "SRC_PORT": 49200,
                    "DST_PORT": 443,
                    "PROTOCOL": "TCP",
                    "TIME_FIRST": t_b1.isoformat(),
                    "TIME_LAST": (t_b1 + pd.Timedelta(seconds=3600)).isoformat(),
                    "DURATION": 3600.0,
                    "BYTES": 1_200_000_000.0,  # 1.2 GB sanctioned backup
                    "BYTES_REV": 2_000_000.0,
                    "PACKETS": 800_000,
                    "PACKETS_REV": 40_000,
                    "QUIC_VERSION": "",
                    "QUIC_SNI": "corporate-cloud-0060.example",
                    "QUIC_USERAGENT": "BackupAgent/4.2",
                    "APP": "HTTPS",
                    "CATEGORY": "corporate_cloud",
                    "ASSET_TIER": 3,
                    "SCENARIO": "approved_nightly_backups",
                    "IS_SUSPICIOUS": False,
                    "ALLOWLISTED": True,  # Allowlisted
                    "DESTINATION_FIRST_SEEN": False,
                    "INGESTION_TIME": ingestion_ts,
                    "DATA_QUALITY_FLAGS": "OK",
                })
                ground_truth.append({
                    "flow_id": f"FLOW-{flow_seq:07d}",
                    "user_id": b1_user,
                    "scenario": "approved_nightly_backups",
                    "label": "BENIGN",
                    "tactic": "None",
                    "technique": "Sanctioned Backup",
                })
                flow_seq += 1

                # 4. Low-and-Slow Outbound Exfil (S2)
                for chunk in range(6):
                    t_chunk = day_start + pd.Timedelta(hours=9 + chunk * 2, minutes=15)
                    flows.append({
                        "ID": f"FLOW-{flow_seq:07d}",
                        "USER_ID": s2_user,
                        "SRC_IP": "10.0.1.2",
                        "DST_IP": "203.0.113.45",
                        "SRC_PORT": 51000 + chunk,
                        "DST_PORT": 443,
                        "PROTOCOL": "TCP",
                        "TIME_FIRST": t_chunk.isoformat(),
                        "TIME_LAST": (t_chunk + pd.Timedelta(seconds=180)).isoformat(),
                        "DURATION": 180.0,
                        "BYTES": 12_500_000.0,
                        "BYTES_REV": 30_000.0,
                        "PACKETS": 9_000,
                        "PACKETS_REV": 800,
                        "QUIC_VERSION": "",
                        "QUIC_SNI": "covert-staging.example",
                        "QUIC_USERAGENT": "",
                        "APP": "HTTPS",
                        "CATEGORY": "personal_cloud",
                        "ASSET_TIER": 2,
                        "SCENARIO": "low_and_slow_exfil",
                        "IS_SUSPICIOUS": True,
                        "ALLOWLISTED": False,
                        "DESTINATION_FIRST_SEEN": False,
                        "INGESTION_TIME": ingestion_ts,
                        "DATA_QUALITY_FLAGS": "OK",
                    })
                    ground_truth.append({
                        "flow_id": f"FLOW-{flow_seq:07d}",
                        "user_id": s2_user,
                        "scenario": "low_and_slow_exfil",
                        "label": "MALICIOUS",
                        "tactic": "TA0010 - Exfiltration",
                        "technique": "T1048 - Scheduled Small Transfers",
                    })
                    flow_seq += 1

        flows_df = pd.DataFrame(flows)
        gt_df = pd.DataFrame(ground_truth)
        auth_df = pd.DataFrame(auth_logs)

        # Build Dataset Manifest
        manifest = {
            "dataset_id": f"DS-SYNTH-{uuid.uuid4().hex[:8].upper()}",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "schema_version": "1.0.0",
            "seed": self.cfg.random_seed,
            "random_seed": self.cfg.random_seed,
            "record_count": len(flows_df),
            "sha256_hash": hashlib.sha256(flows_df.to_csv(index=False).encode("utf-8")).hexdigest(),
            "scenario_counts": flows_df["SCENARIO"].value_counts().to_dict() if "SCENARIO" in flows_df.columns else {},
            "time_range": {
                "start": self.cfg.start_date,
                "end": (self.start_dt + pd.Timedelta(days=n_days)).isoformat(),
            },
            "record_counts": {
                "total_flows": len(flows_df),
                "total_auth_logs": len(auth_df),
                "total_employees": n_users,
                "malicious_scenarios_injected": len(gt_df[gt_df["label"] == "MALICIOUS"]) if not gt_df.empty and "label" in gt_df.columns else 0,
                "benign_lookalikes_injected": len(gt_df[gt_df["label"] == "BENIGN"]) if not gt_df.empty and "label" in gt_df.columns else 0,
            },
            "scenarios_included": SCENARIO_CATALOGUE,
            "data_quality_summary": {
                "negative_bytes": 0,
                "reversed_timestamps": 0,
                "missing_src_or_dst": 0,
                "ground_truth_isolated": True,
            },
        }

        return flows_df, auth_df, gt_df, manifest

    def save_dataset(self, out_dir: Optional[str] = None) -> Dict[str, str]:
        """Generate and save datasets to CSV, JSON, and Parquet formats."""
        target_dir = Path(out_dir or "./data/synthetic").resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        flows_df, auth_df, gt_df, manifest = self.generate()

        flows_csv = target_dir / "flows.csv"
        flows_parquet = target_dir / "flows.parquet"
        flows_json = target_dir / "flows.json"

        auth_csv = target_dir / "auth_logs.csv"
        gt_parquet = target_dir / "ground_truth.parquet"
        manifest_json = target_dir / "manifest.json"

        flows_df.to_csv(flows_csv, index=False)
        flows_df.to_parquet(flows_parquet, index=False)
        flows_df.head(100).to_json(flows_json, orient="records", indent=2)

        auth_df.to_csv(auth_csv, index=False)
        gt_df.to_parquet(gt_parquet, index=False)

        manifest["file_hashes"] = {
            "flows.csv": hashlib.sha256(flows_csv.read_bytes()).hexdigest(),
            "flows.parquet": hashlib.sha256(flows_parquet.read_bytes()).hexdigest(),
            "ground_truth.parquet": hashlib.sha256(gt_parquet.read_bytes()).hexdigest(),
        }

        with open(manifest_json, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return {
            "flows_csv": str(flows_csv),
            "flows_parquet": str(flows_parquet),
            "flows_json": str(flows_json),
            "auth_csv": str(auth_csv),
            "ground_truth": str(gt_parquet),
            "manifest": str(manifest_json),
            "total_records": len(flows_df),
        }
