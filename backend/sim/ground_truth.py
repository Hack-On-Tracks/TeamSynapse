"""Ground-truth handling. ONLY the evaluation module may read these labels."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

GT_COLUMNS = [
    "scenario_id", "scenario_type", "label", "user", "peer_group",
    "dst_ids", "start_day", "end_day", "params", "description",
]

DESCRIPTIONS = {
    "S1": "Burst exfiltration to a previously unseen personal-cloud-like destination",
    "S2": "Low-and-slow exfiltration to one new cloud-like destination",
    "S3": "Scheduled exfiltration: six nightly transfers at ~60 minute intervals",
    "S4": "Blended exfiltration: gradual ramp to a known corporate-cloud destination",
    "S5": "Destination rotation: many new destinations per day",
    "S6": "Slow-ramp poisoning test: +10%/day upload growth to a known destination",
    "S7": "Synthetic DNS tunnelling statistics (no real DNS traffic)",
    "B01": "Nightly backup (allowlisted, scheduled)",
    "B02": "Team-wide adoption of a new SaaS service",
    "B03": "Employee travelling (shifted hours, new destinations)",
    "B04": "One-off allowlisted upload",
    "B05": "Video-call-heavy week",
    "B06": "Organisation-wide software-update day",
    "B07": "Legitimate large engineering transfer to corporate cloud",
    "B08": "Finance reporting period",
    "B09": "New approved application (allowlisted)",
    "B10": "Burst of normal collaboration activity",
    "B11": "Routine scheduled automation",
    "B12": "Device with little historical baseline",
}


def gt_frame(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    for c in GT_COLUMNS:
        if c not in df.columns:
            df[c] = None
    return df[GT_COLUMNS]


def make_row(plan: dict, user: str, group: str) -> dict:
    return {
        "scenario_id": plan["scenario_id"],
        "scenario_type": plan["type"],
        "label": plan["label"],
        "user": user,
        "peer_group": group,
        "dst_ids": json.dumps(plan.get("dst_ids", [])),
        "start_day": int(plan["start_day"]),
        "end_day": int(plan["end_day"]),
        "params": json.dumps(plan.get("params", {}), default=float),
        "description": DESCRIPTIONS[plan["type"]],
    }


def save_ground_truth(df: pd.DataFrame, path: Path) -> None:
    df.to_parquet(path, index=False)


def load_ground_truth(path: Path) -> pd.DataFrame:
    return pd.read_parquet(path)
