"""Fernet-encrypted identity vault: pseudonym -> real identity. Stored apart from the analytical DB.
The demo works without ever decrypting it."""
from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from common.settings import get_secret, path_for


def load_vault_key() -> bytes:
    return get_secret("CIPHER_VAULT_KEY", "vault.key", Fernet.generate_key)


def vault_path() -> Path:
    p = path_for("processed").parent / "vault"
    p.mkdir(parents=True, exist_ok=True)
    return p / "identity_map.enc"


class IdentityVault:
    def __init__(self, path: Path | None = None, key: bytes | None = None):
        self.path = path or vault_path()
        self.fernet = Fernet(key or load_vault_key())

    def save(self, mapping: dict) -> None:
        self.path.write_bytes(self.fernet.encrypt(json.dumps(mapping).encode()))

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> dict:
        try:
            return json.loads(self.fernet.decrypt(self.path.read_bytes()))
        except (InvalidToken, FileNotFoundError) as e:
            raise PermissionError("Identity vault unavailable or key mismatch") from e

    def lookup(self, pseudonym: str) -> dict | None:
        """Used ONLY by the approved two-person reveal workflow."""
        return self.load().get(pseudonym)

    def status(self) -> dict:
        return {"present": self.exists(), "encrypted": True, "algorithm": "Fernet (AES-128-CBC + HMAC-SHA256)"}
