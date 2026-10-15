"""Keyed-HMAC pseudonymisation. The key lives in an env var or a protected secret file,
never in the database or source control."""
from __future__ import annotations

import hashlib
import hmac
import os

import pandas as pd

from common.settings import get_config, get_secret


def load_hmac_key() -> bytes:
    return get_secret("CIPHER_HMAC_KEY", "hmac.key", lambda: os.urandom(32).hex().encode())


class Pseudonymizer:
    def __init__(self, key: bytes | str | None = None, hex_len: int | None = None):
        cfg = get_config()["settings"]["privacy"]
        self.key = key.encode() if isinstance(key, str) else (key or load_hmac_key())
        self.hex_len = hex_len or cfg["pseudonym_hex_len"]
        self.pu = cfg["pseudonym_prefix_user"]
        self.pd_ = cfg["pseudonym_prefix_device"]

    def _h(self, kind: str, value: str) -> str:
        return hmac.new(self.key, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()[: self.hex_len]

    def user_id(self, raw: str) -> str:
        return f"{self.pu}{self._h('user', str(raw))}"

    def device_id(self, raw: str) -> str:
        return f"{self.pd_}{self._h('device', str(raw))}"

    def apply_flows(self, flows: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
        """Replace raw identities; drop src_ip. Returns (pseudonymised, mapping)."""
        f = flows.copy()
        users = f["user"].unique()
        devs = f["device"].unique()
        umap = {u: self.user_id(u) for u in users}
        dmap = {d: self.device_id(d) for d in devs}
        f["user_id"] = f["user"].map(umap)
        f["device_id"] = f["device"].map(dmap)
        mapping = {umap[u]: {"kind": "user", "identity": u} for u in users}
        mapping.update({dmap[d]: {"kind": "device", "identity": d} for d in devs})
        f = f.drop(columns=["user", "device", "src_ip"])
        return f, mapping

    def apply_users(self, users: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
        u = users.copy()
        u["user_id"] = u["user"].map(self.user_id)
        u["device_id"] = u["device"].map(self.device_id)
        mapping = {r.user_id: {"kind": "user", "identity": r.user, "device": r.device} for r in u.itertuples()}
        return u[["user_id", "device_id", "peer_group", "asset_tier"]], mapping

    def apply_dns(self, dns: pd.DataFrame) -> pd.DataFrame:
        d = dns.copy()
        d["user_id"] = d["user"].map(self.user_id)
        return d.drop(columns=["user"])
