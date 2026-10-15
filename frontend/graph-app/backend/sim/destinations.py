"""Synthetic destination catalogue (~300 stable synthetic destination identifiers).

Layout is FIXED (independent of the seed) so policies (allowlist, scheduled windows)
can refer to stable IDs. Only user sampling depends on the seed. No real hosts are used:
SNI names end in the reserved ``.example`` TLD and IPs come from documentation ranges.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

# (category, first_id, last_id) inclusive
LAYOUT = [
    ("saas", 0, 59),
    ("corporate_cloud", 60, 71),
    ("cdn", 72, 111),
    ("video", 112, 131),
    ("social", 132, 156),
    ("update", 157, 171),
    ("web", 172, 231),
    ("other", 232, 259),
    ("personal_cloud", 260, 299),
]

# Destinations reserved for scenarios: never used by baseline traffic.
RESERVED = {60} | set(range(50, 60)) | set(range(68, 72)) | set(range(260, 300))

BACKUP_DST = "dst0060"            # allowlisted + scheduled nightly backup target
ONEOFF_ALLOWLISTED_DST = "dst0068"
NEW_APPROVED_APP_DST = "dst0069"
AUTOMATION_DST = "dst0070"        # allowlisted + scheduled automation target
TEAM_SAAS_DST = "dst0050"         # team-wide SaaS adoption (not allowlisted)
ORG_SAAS_DST = "dst0051"          # org-wide SaaS switch (robustness test)
TRAVEL_POOL = [f"dst{i:04d}" for i in range(232, 242)]


def dst_id(i: int) -> str:
    return f"dst{i:04d}"


def build_catalogue() -> pd.DataFrame:
    rows = []
    for cat, lo, hi in LAYOUT:
        for i in range(lo, hi + 1):
            # Documentation ranges only (RFC 5737): 198.51.100.0/24 and 203.0.113.0/24
            block = "198.51.100" if i % 2 == 0 else "203.0.113"
            rows.append(
                {
                    "dst_id": dst_id(i),
                    "dst_category": cat,
                    "sni_name": f"{cat.replace('_', '-')}-{i:04d}.example",
                    "dst_ip": f"{block}.{(i // 2) % 254 + 1}",
                    "asn": f"AS{64512 + i}",
                    "reserved": i in RESERVED,
                }
            )
    return pd.DataFrame(rows)


def zipf_weights(n: int, s: float = 1.1) -> np.ndarray:
    w = 1.0 / np.arange(1, n + 1) ** s
    return w / w.sum()


def baseline_pool(cat_df: pd.DataFrame) -> pd.DataFrame:
    return cat_df[~cat_df["reserved"]].reset_index(drop=True)
