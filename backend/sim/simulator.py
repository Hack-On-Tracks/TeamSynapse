"""Core flow synthesis: normal enterprise traffic and the FlowBuilder used by scenarios."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from sim import destinations as D
from sim.users import GROUP_WEEKEND_FACTOR, build_users, hour_profile

# category -> (orig_median, orig_sigma, resp_median, resp_sigma)  [bytes, lognormal]
CAT_BYTES = {
    "saas": (60e3, 1.9, 400e3, 1.5),
    "corporate_cloud": (400e3, 2.0, 800e3, 1.5),
    "cdn": (3e3, 1.0, 600e3, 1.6),
    "video": (2e6, 1.2, 6e6, 1.2),
    "social": (20e3, 1.3, 500e3, 1.4),
    "update": (5e3, 1.0, 20e6, 1.5),
    "web": (8e3, 1.2, 300e3, 1.5),
    "other": (15e3, 1.5, 200e3, 1.5),
    "personal_cloud": (300e3, 1.5, 100e3, 1.2),
}
CAT_POPULARITY = {"saas": 3.0, "cdn": 2.0, "web": 2.0, "social": 1.0, "video": 0.5,
                  "update": 0.3, "other": 0.3, "corporate_cloud": 1.0}


@dataclass
class SimResult:
    flows: pd.DataFrame
    users: pd.DataFrame
    dns: pd.DataFrame
    destinations: pd.DataFrame
    ground_truth: pd.DataFrame
    manifest: dict
    plan: list = field(default_factory=list)


class FlowBuilder:
    """Builds canonical flow rows (payload-free metadata only)."""

    def __init__(self, cfg: dict, cat_df: pd.DataFrame, users: pd.DataFrame, rng: np.random.Generator):
        sim = cfg["settings"]["simulation"]
        self.start = pd.Timestamp(sim["start_date"])
        self.rng = rng
        self.cat = cat_df.set_index("dst_id")
        self.users = users.set_index("user")
        self.quic_share = sim["quic_share"]
        self.p_vis_quic = 0.60
        self.p_vis_nonquic = float(np.clip((sim["sni_visible_share"] - self.quic_share * 0.60) / (1 - self.quic_share), 0, 1))

    def ts_from(self, day, hour, jitter=3600.0):
        day = np.asarray(day); hour = np.asarray(hour, dtype=float)
        secs = day * 86400.0 + hour * 3600.0 + self.rng.uniform(0, jitter, size=np.broadcast(day, hour).shape)
        return self.start + pd.to_timedelta(secs, unit="s")

    def make(self, user: str, ts, dst_ids, orig, resp, tool_share: float = 0.0, tool_tag: str = "") -> pd.DataFrame:
        rng = self.rng
        ts = pd.DatetimeIndex(ts)
        n = len(ts)
        if n == 0:
            return pd.DataFrame()
        u = self.users.loc[user]
        dst_ids = np.asarray(dst_ids, dtype=object)
        if dst_ids.ndim == 0:
            dst_ids = np.repeat(dst_ids, n)
        orig = np.maximum(np.asarray(orig, dtype=float), 40.0)
        resp = np.maximum(np.asarray(resp, dtype=float), 40.0)
        quic = rng.random(n) < self.quic_share
        vis = rng.random(n) < np.where(quic, self.p_vis_quic, self.p_vis_nonquic)
        cat = self.cat.loc[dst_ids]
        sni = np.where(vis, cat["sni_name"].values, None)
        # synthetic TLS fingerprints: per-device browser/agent/cli + optional "tool" fingerprint
        base = [hashlib.md5(f"{u['device']}-fp{k}".encode()).hexdigest() for k in range(3)]
        ja3 = rng.choice(base, size=n, p=[0.8, 0.15, 0.05]).astype(object)
        if tool_share > 0:
            tool_fp = hashlib.md5(f"tool-{tool_tag}".encode()).hexdigest()
            ja3 = np.where(rng.random(n) < tool_share, tool_fp, ja3)
        ja3 = np.where(quic, None, ja3)
        dur = 0.2 + rng.lognormal(0, 1.0, n) * (1 + (orig + resp) / 1.5e6)
        return pd.DataFrame(
            {
                "ts": ts,
                "user": user,
                "device": u["device"],
                "src_ip": u["src_ip"],
                "dst_id": dst_ids,
                "dst_ip": cat["dst_ip"].values,
                "dst_port": 443,
                "proto": np.where(quic, "udp", "tcp"),
                "dst_category": cat["dst_category"].values,
                "orig_bytes": orig,
                "resp_bytes": resp,
                "orig_pkts": np.ceil(orig / rng.uniform(500, 1300, n)),
                "resp_pkts": np.ceil(resp / rng.uniform(800, 1400, n)),
                "duration": dur,
                "tls_version": np.where(quic, "QUIC", rng.choice(["TLSv13", "TLSv12"], size=n, p=[0.9, 0.1])),
                "sni": sni,
                "ja3": ja3,
                "is_quic": quic,
            }
        )


def _ordered_choice(rng, pool: pd.DataFrame, k: int) -> list[str]:
    w = pool["dst_category"].map(CAT_POPULARITY).values.astype(float)
    idx = rng.choice(len(pool), size=k, replace=False, p=w / w.sum())
    return pool["dst_id"].values[idx].tolist()


def normal_traffic(cfg, rng, builder: FlowBuilder, users: pd.DataFrame, cat_df: pd.DataFrame) -> pd.DataFrame:
    sim = cfg["settings"]["simulation"]
    n_days = sim["n_days"]
    pool = D.baseline_pool(cat_df)
    tail = pool[pool["dst_category"].isin(["web", "other"])]["dst_id"].values
    corp = pool[pool["dst_category"] == "corporate_cloud"]["dst_id"].values
    shared_sets = {}
    for g in users["peer_group"].unique():
        shared_sets[g] = _ordered_choice(rng, pool, 30)
    zw = lambda n: D.zipf_weights(n)
    out = []
    dow = np.arange(n_days) % 7
    for _, u in users.iterrows():
        gset = shared_sets[u["peer_group"]]
        own_corp = rng.choice(corp, size=2, replace=False).tolist()
        gl = own_corp + [d for d in _ordered_choice(rng, pool, 15) if d not in own_corp]
        base_rate = sim["flows_per_user_day"] * u["activity_scale"]
        weekend = np.where(dow >= 5, GROUP_WEEKEND_FACTOR[u["peer_group"]], 1.0)
        rate = base_rate * weekend * (np.arange(n_days) >= u["start_day"])
        n_per_day = rng.poisson(rate)
        T = int(n_per_day.sum())
        if T == 0:
            continue
        day = np.repeat(np.arange(n_days), n_per_day)
        hours = rng.choice(24, size=T, p=hour_profile(u["peer_group"]))
        shared = rng.random(T) < sim["shared_pool_share"]
        dst = np.where(shared, rng.choice(gset, size=T, p=zw(len(gset))), rng.choice(gl, size=T, p=zw(len(gl))))
        explore = rng.random(T) < 0.02
        dst = np.where(explore, rng.choice(tail, size=T), dst)
        cat = builder.cat.loc[dst, "dst_category"].values
        om = np.array([CAT_BYTES[c][0] for c in cat]); osg = np.array([CAT_BYTES[c][1] for c in cat])
        rm = np.array([CAT_BYTES[c][2] for c in cat]); rsg = np.array([CAT_BYTES[c][3] for c in cat])
        day_mult = rng.lognormal(0, 0.35, n_days)[day]
        orig = rng.lognormal(np.log(om), osg) * u["upload_scale"] * day_mult
        resp = rng.lognormal(np.log(rm), rsg) * day_mult
        out.append(builder.make(u["user"], builder.ts_from(day, hours), dst, orig, resp))
    return pd.concat(out, ignore_index=True)


def add_quality_columns(cfg, rng, flows: pd.DataFrame, users: pd.DataFrame) -> pd.DataFrame:
    sim = cfg["settings"]["simulation"]
    day = ((flows["ts"] - pd.Timestamp(sim["start_date"])).dt.total_seconds() // 86400).astype(int)
    key = flows["user"] + "|" + day.astype(str)
    uniq, inv = np.unique(key.values, return_inverse=True)
    q = np.clip(1 - np.abs(rng.normal(0, 0.02, len(uniq))), 0.5, 1.0)
    bad = rng.random(len(uniq)) < 0.01
    q[bad] = rng.uniform(0.6, 0.85, bad.sum())
    flows["capture_quality"] = q[inv].round(3)
    base = users.set_index("user")["base_identity_conf"]
    ic = flows["user"].map(base).values.copy()
    unc = rng.random(len(flows)) < sim["identity_uncertainty"]
    ic[unc] = 0.6
    flows["identity_confidence"] = ic
    return flows


def dns_stats(cfg, rng, flows: pd.DataFrame, s7_plan: list[dict], users: pd.DataFrame) -> pd.DataFrame:
    """Synthetic hourly DNS statistics (counts/entropy only; never real queries)."""
    start = pd.Timestamp(cfg["settings"]["simulation"]["start_date"])
    h = flows["ts"].dt.floor("h")
    g = flows.groupby([flows["user"], h]).size().reset_index(name="n")
    g.columns = ["user", "ts_hour", "n"]
    q = rng.poisson(g["n"].values * 3 + 2)
    dns = pd.DataFrame(
        {
            "user": g["user"], "ts_hour": g["ts_hour"], "query_count": q,
            "unique_domains": np.maximum(1, (q * rng.uniform(0.4, 0.8, len(g))).astype(int)),
            "mean_label_len": np.clip(rng.normal(9, 2, len(g)), 3, 20).round(2),
            "mean_label_entropy": np.clip(rng.normal(2.9, 0.25, len(g)), 1.5, 4.0).round(3),
        }
    )
    extra = []
    for p in s7_plan:
        for d in range(p["start_day"], p["end_day"] + 1):
            for hr in range(24):
                qc = int(rng.integers(200, 2001))
                extra.append({"user": p["user"], "ts_hour": start + pd.Timedelta(days=d, hours=hr),
                              "query_count": qc, "unique_domains": int(qc * rng.uniform(0.8, 0.98)),
                              "mean_label_len": float(np.clip(rng.normal(32, 3), 20, 50)),
                              "mean_label_entropy": float(np.clip(rng.normal(4.2, 0.15), 3.8, 4.8))})
    if extra:
        e = pd.DataFrame(extra)
        dns = pd.concat([dns[~dns.set_index(["user", "ts_hour"]).index.isin(e.set_index(["user", "ts_hour"]).index)], e], ignore_index=True)
    return dns.sort_values(["ts_hour", "user"]).reset_index(drop=True)


def generate(cfg: dict, seed: int | None = None, overrides: dict | None = None) -> SimResult:
    """Generate the full dataset deterministically for ``seed``."""
    from sim import scenarios as S
    from sim.ground_truth import gt_frame, make_row

    cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in cfg.items()}
    cfg["settings"] = json.loads(json.dumps(cfg["settings"]))
    if overrides:
        cfg["settings"]["simulation"].update(overrides)
    sim = cfg["settings"]["simulation"]
    seed = sim["seed"] if seed is None else seed
    rng = np.random.default_rng(seed)
    cat_df = D.build_catalogue()
    users = build_users(cfg, rng)
    plan = S.plan_scenarios(cfg, rng, users)
    for p in plan:                       # e.g. B12: user with a short history
        if p["type"] == "B12":
            users.loc[users["user"] == p["users"][0], "start_day"] = p["params"]["start_day"]
    builder = FlowBuilder(cfg, cat_df, users, rng)
    normal = normal_traffic(cfg, rng, builder, users, cat_df)
    extra = S.inject(cfg, rng, builder, users, cat_df, normal, plan)
    flows = pd.concat([normal] + extra, ignore_index=True)
    if sim["capture_loss"] > 0:
        flows = flows[rng.random(len(flows)) >= sim["capture_loss"]]
    flows = flows.sort_values(["ts", "user"], kind="stable").reset_index(drop=True)
    flows = add_quality_columns(cfg, rng, flows, users)
    s7 = [{"user": p["users"][0], "start_day": p["start_day"], "end_day": p["end_day"]} for p in plan if p["type"] == "S7"]
    dns = dns_stats(cfg, rng, flows, s7, users)
    gt_rows = []
    grp = users.set_index("user")["peer_group"]
    for p in plan:
        for u in p["users"]:
            gt_rows.append(make_row(p, u, grp[u]))
    gt = gt_frame(gt_rows)
    manifest = {
        "seed": seed,
        "schema_version": cfg["settings"]["app"]["schema_version"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_flows": int(len(flows)),
        "n_users": int(len(users)),
        "n_days": sim["n_days"],
        "n_destinations": int(len(cat_df)),
        "n_dns_rows": int(len(dns)),
        "simulation_config": sim,
        "scenarios": [{k: v for k, v in p.items() if k != "users"} | {"users": len(p["users"])} for p in plan],
        "note": "SIMULATED data. Ground truth is stored separately and read only by evaluation.",
    }
    users_out = users[["user", "device", "peer_group", "asset_tier", "src_ip"]].copy()
    return SimResult(flows=flows, users=users_out, dns=dns, destinations=cat_df, ground_truth=gt, manifest=manifest, plan=plan)
