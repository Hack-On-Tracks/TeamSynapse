"""Configuration loading, paths and shared constants."""
from __future__ import annotations

import copy
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

BACKEND_DIR = Path(__file__).resolve().parents[1]
CONFIG_DIR = BACKEND_DIR / "config"


def _load_yaml(name: str) -> dict:
    with open(CONFIG_DIR / name, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@lru_cache(maxsize=1)
def _cached() -> dict:
    return {
        "settings": _load_yaml("settings.yaml"),
        "weights": _load_yaml("detector_weights.yaml"),
        "policies": _load_yaml("policies.yaml"),
        "feature_schema": _load_yaml("feature_schema.yaml"),
    }


def get_config() -> dict:
    """Return a deep copy so callers (tests, ablations) may mutate safely."""
    return copy.deepcopy(_cached())


def data_root() -> Path:
    """Root of data/model/report directories. Override with CIPHER_DATA_DIR."""
    override = os.environ.get("CIPHER_DATA_DIR")
    return Path(override) if override else BACKEND_DIR


def path_for(key: str, root: Path | None = None) -> Path:
    cfg = _cached()["settings"]["paths"]
    p = (root or data_root()) / cfg[key]
    p.mkdir(parents=True, exist_ok=True)
    return p


def secrets_dir() -> Path:
    p = (data_root() / ".secrets")
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_secret(env_name: str, filename: str, generator) -> bytes:
    """Read a secret from the environment, else from a gitignored dev file, else
    generate it once. Secrets are never stored in the database or source tree."""
    val = os.environ.get(env_name)
    if val:
        return val.encode()
    f = secrets_dir() / filename
    if f.exists():
        return f.read_bytes().strip()
    val = generator()
    f.write_bytes(val)
    return val


# Canonical (payload-free) flow schema -- the single source of truth for ingestion.
FLOW_COLUMNS: dict[str, dict[str, Any]] = {
    "ts": {"dtype": "datetime", "required": True},
    "user": {"dtype": "str", "required": True},          # raw identity (pseudonymised on ingest)
    "device": {"dtype": "str", "required": True},        # raw device (pseudonymised on ingest)
    "src_ip": {"dtype": "str", "required": False},       # dropped after identity mapping
    "dst_id": {"dtype": "str", "required": True},
    "dst_ip": {"dtype": "str", "required": False},
    "dst_port": {"dtype": "int", "required": True},
    "proto": {"dtype": "str", "required": True},
    "dst_category": {"dtype": "str", "required": False},
    "orig_bytes": {"dtype": "float", "required": True},
    "resp_bytes": {"dtype": "float", "required": True},
    "orig_pkts": {"dtype": "float", "required": False},
    "resp_pkts": {"dtype": "float", "required": False},
    "duration": {"dtype": "float", "required": False},
    "tls_version": {"dtype": "str", "required": False},
    "sni": {"dtype": "str", "required": False},
    "ja3": {"dtype": "str", "required": False},
    "is_quic": {"dtype": "bool", "required": False},
    "capture_quality": {"dtype": "float", "required": False},
    "identity_confidence": {"dtype": "float", "required": False},
}

USER_COLUMNS = ["user", "device", "peer_group", "asset_tier"]
DNS_COLUMNS = ["user", "ts_hour", "query_count", "unique_domains", "mean_label_len", "mean_label_entropy"]

# Fields that must never be accepted, even if a source provides them.
FORBIDDEN_FIELDS = {
    "payload", "data", "body", "http_body", "request_body", "response_body", "content",
    "raw", "raw_bytes", "pcap", "packet", "packets", "plaintext", "decrypted", "uri", "url",
    "cookie", "cookies", "password", "username", "email", "label", "is_malicious",
    "scenario", "scenario_id", "ground_truth", "attack", "query", "dns_query", "http_user_agent",
}
