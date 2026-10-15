"""Confidence (kept separate from risk). Starts at 1.0 and degrades with visibility/data-quality gaps."""
from __future__ import annotations

import numpy as np
import pandas as pd


def confidence_for_rows(df: pd.DataFrame, cfg: dict) -> tuple[np.ndarray, list[list[str]]]:
    c = cfg["weights"]["confidence"]
    n = len(df)
    conf = np.full(n, float(c["start"]))
    reasons: list[list[str]] = [[] for _ in range(n)]

    def apply(mask, amount, text):
        m = np.asarray(mask, dtype=bool)
        conf[m] -= amount
        for i in np.where(m)[0]:
            reasons[i].append(text)

    nc = df["n_clean_days"].fillna(0).values
    apply(nc < 7, c["very_few_clean_days_lt7"], "Fewer than 7 clean baseline days (cold start): peer baseline used")
    apply((nc >= 7) & (nc < 14), c["few_clean_days_lt14"], "Fewer than 14 clean baseline days")
    apply(df["hidden_sni_share"].fillna(0).values > 0.5, c["hidden_sni_share_gt50"], "Destination hostname (SNI) hidden for most flows (QUIC/ECH/loss)")
    apply(~df["dns_available"].fillna(False).astype(bool).values, c["dns_unavailable"], "DNS visibility unavailable")
    apply(df["capture_quality"].fillna(1).values < 0.90, c["poor_capture_lt090"], "Poor capture quality / possible packet loss")
    apply(df["identity_confidence"].fillna(1).values < 0.80, c["identity_uncertain_lt080"], "Identity attribution uncertain (shared device / ambiguous mapping)")
    apply(df["ja3_missing_share"].fillna(0).values > 0.5, c["tls_fp_missing"], "TLS client fingerprint mostly unavailable")
    conf = np.clip(conf, 0.0, 1.0)
    return conf, reasons


def confidence_level(conf: float, cfg: dict) -> str:
    lv = cfg["weights"]["confidence"]["levels"]
    return "high" if conf >= lv["high"] else ("medium" if conf >= lv["medium"] else "low")
