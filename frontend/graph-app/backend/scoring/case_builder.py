"""Cumulative case engine and evidence bundles.

C(t) = 0.8 * C(t-1) + max(0, daily_risk(t) - 20)
Open a case when ANY of: C >= 40; CUSUM alarm on a (recently) first-seen destination with
supporting rarity/volume; a single day reaches daily risk 70.
Case score (for tier/ranking) = clamp(max(C, daily_risk), 0, 100). One case per user-destination pair.
Nothing is blocked automatically: cases are analyst decision-support only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from scoring.confidence import confidence_for_rows, confidence_level
from scoring.explanations import mitre_for, reasons_for_row, tier_for


@dataclass
class CaseResult:
    cases: dict
    track: pd.DataFrame          # per user-destination-day state (daily risk, cumulative, score, open)
    queue: pd.DataFrame          # per-day ranked queue (rank 1..N); priority = rank <= 5
    entries: pd.DataFrame
    meta: dict = field(default_factory=dict)


def annotate_entries(entries: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    e = entries.copy().reset_index(drop=True)
    conf, why = confidence_for_rows(e, cfg)
    e["confidence"] = conf
    e["conf_reasons"] = why
    e["reasons"] = [reasons_for_row(r) for _, r in e.iterrows()]
    return e


def _cid(user_id: str, dst: str, day: int) -> str:
    d = re.sub(r"[^A-Za-z0-9]", "", dst)
    return f"CS-{user_id[2:8]}-{d}-D{day:02d}"


def run_case_engine(entries: pd.DataFrame, cfg: dict, n_days: int, first_scored_day: int = 14) -> CaseResult:
    c = cfg["weights"]["case"]
    decay, floor = c["decay"], c["daily_floor"]
    by_day = {d: g for d, g in entries[entries["day"] >= first_scored_day].groupby("day")}
    state: dict = {}
    track, queue = [], []
    maxq = cfg["settings"]["queue"]["max_priority_cases_per_day"]
    for t in range(first_scored_day, n_days):
        g = by_day.get(t)
        today, rot_users = {}, set()
        if g is not None:
            rot_users = set(g.loc[g["dst_id"] == "*rotation*", "user_id"])
            for row in g.to_dict("records"):
                today[(row["user_id"], row["dst_id"])] = row
        keys = set(today) | {k for k, s in state.items() if s["C"] > 0.01 or s["open"]}
        scores = []
        for k in keys:
            st = state.setdefault(k, dict(C=0.0, open=False, case_id=None, opened_day=None, low=0, triggers=set(), reopen=0))
            row = today.get(k)
            r = float(row["daily_risk"]) if row is not None else 0.0
            C = decay * st["C"] + max(0.0, r - floor)
            alarm = bool(row is not None and row.get("cusum_alarm") and row.get("is_new")
                         and (row.get("peer_rarity") if row.get("peer_rarity") == row.get("peer_rarity") else 1.0) >= c["cusum_open_min_rarity"]
                         and (row.get("out_bytes") or 0) >= c["cusum_open_min_bytes"])
            if alarm:
                C = max(C, c["open_cumulative"])
            suppressed = bool(row is not None and k[1] not in ("*rotation*", "*dns*") and k[0] in rot_users
                              and row.get("dest_age_days") == 0)
            trig = set()
            if C >= c["open_cumulative"] and not alarm:
                trig.add("CUMULATIVE_ACCUMULATION")
            if alarm:
                trig.add("CUSUM_ALARM")
            if r >= c["open_single_day"]:
                trig.add("HIGH_DAILY_RISK")
            st["C"] = C
            if trig and not suppressed:
                if not st["open"]:
                    if st["case_id"] is None:
                        st["case_id"] = _cid(k[0], k[1], t); st["opened_day"] = t
                    else:
                        st["reopen"] += 1
                    st["open"] = True; st["low"] = 0
                st["triggers"] |= trig
            score = float(np.clip(max(C, r), 0, 100))
            if st["open"]:
                st["low"] = st["low"] + 1 if score < c["close_below"] else 0
                if st["low"] >= c["close_after_days"]:
                    st["open"] = False
            if row is not None or C > 0.01 or st["open"]:
                track.append({"user_id": k[0], "dst_id": k[1], "day": t, "daily_risk": r, "cumulative": C,
                              "case_score": score, "is_open": st["open"], "case_id": st["case_id"],
                              "has_entry": row is not None, "alarm": alarm})
            if st["open"] and score >= c["tiers"]["low"]:
                scores.append((score, k, st["case_id"]))
        scores.sort(key=lambda x: -x[0])
        for rank, (s, k, cid) in enumerate(scores, 1):
            queue.append({"day": t, "rank": rank, "case_id": cid, "user_id": k[0], "dst_id": k[1],
                          "case_score": s, "priority": rank <= maxq})
    tr = pd.DataFrame(track)
    q = pd.DataFrame(queue)
    cases = {}
    for k, st in state.items():
        if st["case_id"] is None:
            continue
        cases[st["case_id"]] = {"case_id": st["case_id"], "user_id": k[0], "dst_id": k[1], "opened_day": st["opened_day"],
                                "triggers": sorted(st["triggers"]), "status": "open" if st["open"] else "dormant",
                                "reopened": st["reopen"]}
    return CaseResult(cases=cases, track=tr, queue=q, entries=entries)


def exclusion_from_cases(res: CaseResult) -> pd.DataFrame:
    """User-days that belong to an already-open case: removed from clean baselines on later days."""
    rows = []
    if not len(res.track):
        return pd.DataFrame(columns=["user_id", "day", "known_at"])
    for cid, c in res.cases.items():
        tr = res.track[(res.track["user_id"] == c["user_id"]) & (res.track["dst_id"] == c["dst_id"]) & res.track["has_entry"]]
        for r in tr.itertuples():
            if r.day >= c["opened_day"] or r.daily_risk > 20:
                rows.append({"user_id": r.user_id, "day": int(r.day), "known_at": int(max(r.day, c["opened_day"]) + 1)})
    return pd.DataFrame(rows).drop_duplicates(["user_id", "day"]) if rows else pd.DataFrame(columns=["user_id", "day", "known_at"])


# ----------------------------------------------------------------------------- bundles
FLOW_FIELDS = ["flow_id", "day", "hour", "dst_id", "dst_port", "proto", "orig_bytes", "resp_bytes", "duration", "tls_version"]


def build_bundle(case: dict, res: CaseResult, fs, cfg: dict, catalogue: pd.DataFrame | None = None,
                 device_map: dict | None = None) -> dict:
    u, dst = case["user_id"], case["dst_id"]
    app = cfg["settings"]["app"]; t0 = fs.t0
    tr = res.track[(res.track["user_id"] == u) & (res.track["dst_id"] == dst)].sort_values("day")
    ent = res.entries[(res.entries["user_id"] == u) & (res.entries["dst_id"] == dst)].sort_values("day")
    ent_d = ent.set_index("day")
    date = lambda d: (t0 + pd.Timedelta(days=int(d))).strftime("%Y-%m-%d")
    hist = []
    for r in tr.itertuples():
        e = ent_d.loc[r.day] if r.day in ent_d.index else None
        h = {"day": int(r.day), "date": date(r.day), "daily_risk": round(float(r.daily_risk), 2),
             "cumulative_score": round(float(r.cumulative), 2), "case_score": round(float(r.case_score), 2),
             "has_traffic": bool(r.has_entry)}
        if e is not None:
            for kcol in ["out_bytes", "in_bytes", "n_conn", "z_user_self", "z_user_peer", "cusum", "ewma_z", "peer_rarity",
                         "offhours_share", "confidence", "sub_volume", "sub_novelty", "sub_isolation_forest", "sub_timing", "sub_graph", "sub_direction", "sub_dns"]:
                v = e.get(kcol)
                h[kcol] = None if v is None or (isinstance(v, float) and np.isnan(v)) else (round(float(v), 4) if not isinstance(v, (bool, np.bool_)) else bool(v))
            h["is_new"] = bool(e.get("is_new")) if e.get("is_new") == e.get("is_new") else False
            h["reasons"] = list(e["reasons"])
        hist.append(h)
    last_e = ent.iloc[-1] if len(ent) else None
    first_day = int(ent["day"].min()) if len(ent) else case["opened_day"]
    last_day = int(ent["day"].max()) if len(ent) else case["opened_day"]
    cur = tr.iloc[-1]
    codes = {}
    for r in ent.itertuples():
        for code in r.reasons:
            codes.setdefault(code, int(r.day))
    for trg in case["triggers"]:
        codes.setdefault(trg, case["opened_day"])
    rc = cfg["policies"]["reason_codes"]
    reasons = [{"code": c_, "description": rc.get(c_, c_), "first_day": d_, "first_date": date(d_)} for c_, d_ in sorted(codes.items(), key=lambda x: x[1])]
    # baseline comparison (trailing window BEFORE the first day of the pair's activity)
    ud = fs.user_day
    lo = max(0, first_day - 14)
    uw = ud[(ud["user_id"] == u) & (ud["day"] >= lo) & (ud["day"] < first_day)]
    grp = ud.loc[ud["user_id"] == u, "peer_group"].iloc[0] if (ud["user_id"] == u).any() else None
    pw = ud[(ud["peer_group"] == grp) & (ud["user_id"] != u) & (ud["day"] >= lo) & (ud["day"] < first_day)]
    out_b = ent["out_bytes"].dropna()
    base = {"window_days": f"{lo}-{max(first_day - 1, lo)}",
            "user_median_daily_out_bytes": None if uw.empty else round(float(uw["out_bytes"].median()), 1),
            "peer_median_daily_out_bytes": None if pw.empty else round(float(pw["out_bytes"].median()), 1),
            "destination_total_out_bytes": round(float(out_b.sum()), 1),
            "destination_mean_daily_out_bytes": None if out_b.empty else round(float(out_b.mean()), 1),
            "destination_peak_daily_out_bytes": None if out_b.empty else round(float(out_b.max()), 1)}
    if base["user_median_daily_out_bytes"]:
        base["destination_mean_vs_user_median_ratio"] = None if out_b.empty else round(float(out_b.mean()) / base["user_median_daily_out_bytes"], 3)
    # destination metadata
    dmeta = {"dst_id": dst, "category": None, "sni_name": None, "first_seen_day": None}
    if last_e is not None:
        dmeta["category"] = last_e.get("dst_category")
        if last_e.get("first_seen_day") == last_e.get("first_seen_day"):
            dmeta["first_seen_day"] = int(last_e["first_seen_day"])
            dmeta["first_seen_date"] = date(dmeta["first_seen_day"])
    if catalogue is not None and dst in set(catalogue["dst_id"]):
        dmeta["sni_name"] = catalogue.set_index("dst_id").loc[dst, "sni_name"]
    # confidence
    conf = float(last_e["confidence"]) if last_e is not None else 1.0
    reasons_c = list(last_e["conf_reasons"]) if last_e is not None else []
    gaps = []
    if last_e is not None:
        if (last_e.get("hidden_sni_share") or 0) > 0.5: gaps.append("Hostname (SNI) not visible for most flows.")
        if not bool(last_e.get("dns_available", True)): gaps.append("DNS statistics unavailable.")
        if (last_e.get("ja3_missing_share") or 0) > 0.5: gaps.append("TLS client fingerprint mostly unavailable.")
        if (last_e.get("capture_quality") or 1) < 0.9: gaps.append("Capture quality below 0.90.")
        if (last_e.get("identity_confidence") or 1) < 0.8: gaps.append("Identity attribution uncertain.")
        if (last_e.get("n_clean_days") or 0) < 7: gaps.append("Fewer than 7 clean baseline days.")
    # related flows (pseudonymised, payload-free whitelisted columns only)
    fl = fs.flows
    sub = fl[(fl["user_id"] == u)] if dst.startswith("*") else fl[(fl["user_id"] == u) & (fl["dst_id"] == dst)]
    if dst == "*rotation*":
        days = set(ent["day"]); sub = sub[sub["day"].isin(days) & (sub["day"] == sub["day"])]
    if dst == "*dns*":
        sub = sub.iloc[0:0]
    sub = sub[(sub["day"] >= first_day) & (sub["day"] <= last_day)].nlargest(25, "orig_bytes")
    related = [{**{k: (None if pd.isna(v) else (v.item() if hasattr(v, "item") else v)) for k, v in r.items()},
                "ts": (t0 + pd.Timedelta(days=int(r["day"]), hours=int(r["hour"]))).strftime("%Y-%m-%dT%H:00Z")}
               for r in sub[[c_ for c_ in FLOW_FIELDS if c_ in sub.columns]].to_dict("records")]
    hs = [h["case_score"] for h in hist]
    peak = max(hs) if hs else 0.0
    tot_mb = float(out_b.sum()) / 1e6
    derived = {"n_days_with_traffic": int(len(ent)), "n_days_tracked": len(hist),
               "total_out_mb_to_destination": round(tot_mb, 2),
               "mean_daily_out_mb_to_destination": round(tot_mb / max(len(ent), 1), 2),
               "peak_daily_out_mb_to_destination": round(float(out_b.max()) / 1e6, 2) if len(out_b) else 0.0,
               "current_case_score": round(float(cur["case_score"]), 2), "peak_case_score": round(float(peak), 2),
               "n_related_flows_listed": len(related)}
    return {
        "case_id": case["case_id"], "bundle_version": "1.0", "feature_schema_version": app["feature_schema_version"],
        "model_version": app["model_version"], "data_origin": "simulated",
        "user_id": u, "device_id": (device_map or {}).get(u), "peer_group": grp,
        "asset_tier": int(last_e["asset_tier"]) if last_e is not None and last_e.get("asset_tier") == last_e.get("asset_tier") else None,
        "destination": dmeta, "opened_day": case["opened_day"], "opened_date": date(case["opened_day"]),
        "first_day": first_day, "last_day": last_day, "first_seen": date(first_day), "last_seen": date(last_day),
        "status": case["status"], "tier": tier_for(cur["case_score"], cfg), "peak_tier": tier_for(peak, cfg),
        "risk": {"current_score": round(float(cur["case_score"]), 2), "peak_score": round(float(peak), 2),
                 "latest_daily_risk": round(float(cur["daily_risk"]), 2),
                 "note": "Priority index 0-100, not a probability."},
        "confidence": {"score": round(conf, 3), "level": confidence_level(conf, cfg), "reasons": reasons_c},
        "triggers": case["triggers"], "reason_codes": reasons, "daily_history": hist,
        "baseline_comparison": base, "related_flows": related, "visibility_gaps": gaps,
        "mitre_attack": mitre_for([r["code"] for r in reasons], cfg),
        "derived": derived,
        "disposition": {"status": "new", "feedback": []},
        "disclaimer": "Potential exfiltration pattern requiring human investigation. Not evidence of intent or guilt.",
    }


def truncate_bundle(bundle: dict, as_of_day: int, cfg: dict) -> dict:
    """Replay view: only evidence available up to ``as_of_day`` (no future leakage)."""
    b = dict(bundle)
    hist = [h for h in bundle["daily_history"] if h["day"] <= as_of_day]
    b["daily_history"] = hist
    b["as_of_day"] = as_of_day
    if not hist:
        b["status"] = "not_yet_observed"; return b
    traffic = [h for h in hist if h.get("has_traffic")]
    b["last_day"] = traffic[-1]["day"] if traffic else hist[-1]["day"]
    b["last_seen"] = traffic[-1]["date"] if traffic else hist[-1]["date"]
    b["first_day"] = min(bundle["first_day"], b["last_day"])
    b["status"] = "open" if as_of_day >= bundle["opened_day"] else "pre-open (monitoring)"
    cur = hist[-1]["case_score"]; peak = max(h["case_score"] for h in hist)
    b["tier"] = tier_for(cur, cfg); b["peak_tier"] = tier_for(peak, cfg)
    b["risk"] = {**bundle["risk"], "current_score": cur, "peak_score": peak, "latest_daily_risk": hist[-1]["daily_risk"]}
    b["reason_codes"] = [r for r in bundle["reason_codes"] if r["first_day"] <= as_of_day]
    b["related_flows"] = [f for f in bundle["related_flows"] if f["day"] <= as_of_day]
    outs = [h["out_bytes"] for h in traffic if h.get("out_bytes") is not None]
    tot = sum(outs) / 1e6
    b["derived"] = {**bundle["derived"], "n_days_with_traffic": len(traffic), "n_days_tracked": len(hist),
                    "total_out_mb_to_destination": round(tot, 2),
                    "mean_daily_out_mb_to_destination": round(tot / max(len(traffic), 1), 2),
                    "peak_daily_out_mb_to_destination": round(max(outs) / 1e6, 2) if outs else 0.0,
                    "current_case_score": cur, "peak_case_score": peak, "n_related_flows_listed": len(b["related_flows"])}
    bc = dict(bundle["baseline_comparison"])
    bc["destination_total_out_bytes"] = round(sum(outs), 1)
    bc["destination_mean_daily_out_bytes"] = round(sum(outs) / len(outs), 1) if outs else None
    bc["destination_peak_daily_out_bytes"] = round(max(outs), 1) if outs else None
    bc.pop("destination_mean_vs_user_median_ratio", None)
    if bc.get("user_median_daily_out_bytes") and outs:
        bc["destination_mean_vs_user_median_ratio"] = round((sum(outs) / len(outs)) / bc["user_median_daily_out_bytes"], 3)
    b["baseline_comparison"] = bc
    return b
