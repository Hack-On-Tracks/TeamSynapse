"""Daily risk fusion: weighted, availability-renormalised sub-scores with contextual multipliers.

Risk is a PRIORITY INDEX in [0, 100], not a probability. Confidence is computed separately.

daily_risk = 100 * context_multiplier * sum(w_i * s_i) / sum(w_i over AVAILABLE signals)

A missing signal (NaN) is excluded from both numerator and denominator; it is never treated as
zero evidence. Context multiplier (policy-configurable): allowlisted 0.3, scheduled 0.5, both 0.15
(replacing, not multiplying, the two), tier-3 asset x1.2; result clamped to [0, 100].
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from detectors.destination_novelty import novelty_score
from detectors.dns_detector import dns_subscore, timing_subscore
from detectors.graph_detector import graph_subscore
from detectors.robust_baseline import direction_subscore, volume_subscore
from features.user_destination_day import volume_gate

COMPONENTS = ["volume", "direction", "novelty", "timing", "graph", "isolation_forest", "dns"]

# Evaluation system presets (B3..B5 are pair-level; B5 is the full system).
SYSTEMS = {
    "B3": dict(components=["volume", "novelty"], use_peer=True, use_pair=False, context=False, temporal=False),
    "B4": dict(components=COMPONENTS, use_peer=True, use_pair=False, context=False, temporal=False),
    "B5": dict(components=COMPONENTS, use_peer=True, use_pair=True, context=True, temporal=True),
}


def context_multiplier(allowlisted, scheduled, tier, cfg: dict) -> np.ndarray:
    m = cfg["weights"]["context_multipliers"]
    al = np.asarray(allowlisted, dtype=bool); sc = np.asarray(scheduled, dtype=bool)
    mult = np.where(al & sc, m["allowlisted_and_scheduled"],
                    np.where(al, m["allowlisted"], np.where(sc, m["scheduled"], 1.0)))
    return mult * np.where(np.asarray(tier) == 3, m["tier3_asset"], 1.0)


def compute_subscores(pair: pd.DataFrame, if_model, cfg: dict, use_peer=True, use_pair=True) -> pd.DataFrame:
    df = pair.copy()
    df["sub_volume"] = volume_subscore(df, cfg, use_peer, use_pair)
    df["sub_direction"] = direction_subscore(df, cfg)
    df["sub_novelty"] = novelty_score(df["is_new"], df["peer_rarity"], df["cat_prior"], df["volume_gate"])
    df["sub_timing"] = timing_subscore(df, cfg)
    df["sub_graph"] = graph_subscore(df)
    df["sub_isolation_forest"] = if_model.subscore(df) if if_model is not None else np.nan
    dns = dns_subscore(df["dns_max_hourly_queries"].fillna(0), df["dns_mean_entropy"], cfg)
    df["sub_dns"] = np.where(df["dns_available"].fillna(False).astype(bool), dns, np.nan)
    return df


def fuse(df: pd.DataFrame, cfg: dict, components=COMPONENTS, context=True, temporal=True) -> pd.DataFrame:
    """Add ``weighted`` and ``daily_risk`` columns (plus ``weight_used`` for transparency)."""
    w = cfg["weights"]["weights"]
    W = np.array([w[c] for c in components], dtype=float)
    S = df[[f"sub_{c}" for c in components]].values.astype(float)
    avail = ~np.isnan(S)
    wsum = (avail * W).sum(1)
    weighted = np.where(wsum > 0, (np.nan_to_num(S) * W).sum(1) / np.where(wsum > 0, wsum, 1), 0.0)
    out = df.copy()
    out["weight_available"] = wsum / W.sum()
    bonus = np.zeros(len(df))
    if temporal and "cusum_alarm" in df:
        tmax = cfg["weights"]["case"]["temporal_bonus_max"] / 100.0
        h = cfg["weights"]["temporal"]["cusum_h"]
        bonus = np.where(df["cusum_alarm"].fillna(False).astype(bool) & df["is_new"].fillna(False).astype(bool),
                         tmax * np.clip(df["cusum"].fillna(0) / (2 * h), 0, 1), 0.0)
    out["temporal_bonus"] = bonus * 100
    mult = context_multiplier(df["allowlisted"].fillna(False), df["scheduled"].fillna(False), df["asset_tier"], cfg) if context else 1.0
    out["context_mult"] = mult
    out["daily_risk"] = np.clip(100.0 * mult * np.clip(weighted + bonus, 0, 1), 0, 100)
    return out


def special_entries(ud: pd.DataFrame, cfg: dict, dns_visible: bool) -> pd.DataFrame:
    """User-level entries: destination rotation (F11/F15) and DNS tunnelling statistics (F34)."""
    f = cfg["settings"]["features"]; w = cfg["weights"]["weights"]
    rows = []
    rot = ud[(ud["n_new_dests"] >= f["rotation_min_new_dests"]) & (ud["bytes_first_today"] >= f["rotation_min_bytes"])]
    if len(rot):
        gate = volume_gate(rot["bytes_first_today"], cfg)
        nov = np.clip(rot["n_new_dests"].values / 15.0, 0, 1) * gate
        risk = 100 * (w["volume"] * gate + w["novelty"] * nov) / (w["volume"] + w["novelty"])
        r = rot[["user_id", "day", "peer_group", "asset_tier", "bytes_first_today", "n_new_dests", "identity_confidence",
                 "capture_quality", "hidden_sni_share", "ja3_missing_share", "n_clean_days", "dns_available"]].copy()
        r["dst_id"] = "*rotation*"; r["dst_category"] = "multiple"
        r["out_bytes"] = r["bytes_first_today"]; r["sub_volume"] = gate; r["sub_novelty"] = nov
        r["daily_risk"] = np.clip(risk, 0, 100); r["is_new"] = True; r["allowlisted"] = False; r["scheduled"] = False
        r["peer_rarity"] = 1.0; r["cusum_alarm"] = False; r["cusum"] = 0.0
        rows.append(r)
    if dns_visible:
        d = ud[ud["dns_max_hourly_queries"].fillna(0) > 0].copy()
        s = dns_subscore(d["dns_max_hourly_queries"], d["dns_mean_entropy"], cfg)
        d = d[s >= 0.3].copy(); s = s[s >= 0.3]
        if len(d):
            r = d[["user_id", "day", "peer_group", "asset_tier", "dns_max_hourly_queries", "dns_mean_entropy", "identity_confidence",
                   "capture_quality", "hidden_sni_share", "ja3_missing_share", "n_clean_days", "dns_available"]].copy()
            r["dst_id"] = "*dns*"; r["dst_category"] = "dns"; r["sub_dns"] = s
            r["daily_risk"] = np.clip(100 * s, 0, 100); r["out_bytes"] = np.nan
            r["is_new"] = False; r["allowlisted"] = False; r["scheduled"] = False; r["peer_rarity"] = np.nan
            r["cusum_alarm"] = False; r["cusum"] = 0.0
            rows.append(r)
    if not rows:
        return pd.DataFrame()
    out = pd.concat(rows, ignore_index=True)
    out["special"] = True
    return out
