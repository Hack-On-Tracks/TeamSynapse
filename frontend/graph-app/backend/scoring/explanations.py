"""Reason codes, MITRE tags and cautious human-readable explanations (deterministic)."""
from __future__ import annotations

import numpy as np
import pandas as pd


def _g(row, k, default=np.nan):
    v = row.get(k, default)
    return default if v is None else v


def reasons_for_row(row: pd.Series) -> list[str]:
    r = []
    isnew = bool(_g(row, "is_new", False))
    if row.get("dst_id") == "*rotation*":
        return ["DEST_ROTATION", "NEW_DESTINATION"]
    if row.get("dst_id") == "*dns*":
        return ["DNS_ANOMALY"]
    if isnew and (_g(row, "sub_novelty", 0) or 0) > 0.15:
        r.append("NEW_DESTINATION")
    if isnew and (_g(row, "peer_rarity", 0) or 0) >= 0.8 and (_g(row, "volume_gate", 0) or 0) > 0.1:
        r.append("RARE_AMONG_PEERS")
    if (_g(row, "z_user_self") or 0) >= 3 and not np.isnan(_g(row, "z_user_self")):
        r.append("SELF_BASELINE_DEVIATION")
    if (_g(row, "z_user_peer") or 0) >= 3 and not np.isnan(_g(row, "z_user_peer")):
        r.append("PEER_BASELINE_DEVIATION")
    if (_g(row, "sub_direction", 0) or 0) >= 0.5:
        r.append("UPLOAD_DOMINANT")
    if (_g(row, "offhours_share", 0) or 0) >= 0.6 and (_g(row, "volume_gate", 0) or 0) > 0.3:
        r.append("OFF_HOURS_TRANSFER")
    if (_g(row, "periodicity", 0) or 0) >= 0.5 and (_g(row, "offhours_share", 0) or 0) >= 0.5:
        r.append("PERIODIC_TRANSFER")
    if bool(_g(row, "cusum_alarm", False)):
        r.append("CUSUM_ALARM")
    if (_g(row, "sub_isolation_forest", 0) or 0) >= 0.5:
        r.append("ISOLATION_FOREST_OUTLIER")
    if (_g(row, "sub_dns", 0) or 0) >= 0.3:
        r.append("DNS_ANOMALY")
    if (_g(row, "ja3_novel_share", 0) or 0) >= 0.5:
        r.append("TLS_FINGERPRINT_NOVEL")
    return r


def mitre_for(reasons: list[str], cfg: dict) -> list[dict]:
    m = cfg["policies"]["mitre_attack"]; names = cfg["policies"]["mitre_names"]
    seen: dict[str, dict] = {}
    for r in reasons:
        for t in m.get(r, []):
            seen[t] = {"technique_id": t, "name": names.get(t, t), "note": "Tag indicating a related technique; not a conclusion."}
    return list(seen.values())


def tier_for(score: float, cfg: dict) -> str:
    t = cfg["weights"]["case"]["tiers"]
    s = float(score)
    return "High" if s >= t["high"] else "Medium" if s >= t["medium"] else "Low" if s >= t["low"] else "Monitor"


def fmt_bytes(b: float) -> str:
    if b is None or (isinstance(b, float) and np.isnan(b)):
        return "n/a"
    for unit, div in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if abs(b) >= div:
            return f"{b / div:.1f} {unit}"
    return f"{b:.0f} B"
