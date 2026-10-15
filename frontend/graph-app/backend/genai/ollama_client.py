"""Local-only Ollama client. The GenAI layer is OPTIONAL: callers must handle OllamaUnavailable."""
from __future__ import annotations

import time
from urllib.parse import urlparse

import requests

from common.settings import get_config


class OllamaUnavailable(RuntimeError):
    pass


class OllamaClient:
    def __init__(self, cfg: dict | None = None, model: str | None = None, base_url: str | None = None):
        g = (cfg or get_config())["settings"]["genai"]
        self.base_url = (base_url or g["ollama_url"]).rstrip("/")
        self.model = model or g["model"]
        self.timeout = g["timeout_s"]
        self.max_tokens = g["max_tokens"]
        self.temperature = g["temperature"]
        host = urlparse(self.base_url).hostname
        if g.get("local_only", True) and host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("Local-only mode: Ollama URL must be a loopback address")

    def status(self) -> dict:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=2)
            r.raise_for_status()
            models = [m["name"] for m in r.json().get("models", [])]
            present = any(m == self.model or m.startswith(self.model.split(":")[0] + ":") and self.model in m for m in models) or self.model in models
            return {"running": True, "model": self.model, "model_present": present, "models": models, "local_only": True}
        except Exception as e:  # noqa: BLE001
            return {"running": False, "model": self.model, "model_present": False, "models": [], "local_only": True, "error": type(e).__name__}

    def available(self) -> bool:
        s = self.status()
        return bool(s["running"] and s["model_present"])

    def chat(self, system: str, user: str, json_mode: bool = False, max_tokens: int | None = None) -> dict:
        body = {"model": self.model, "stream": False, "think": False,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "options": {"temperature": self.temperature, "num_predict": max_tokens or self.max_tokens}}
        if json_mode:
            body["format"] = "json"
        t = time.time()
        try:
            r = requests.post(f"{self.base_url}/api/chat", json=body, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except Exception as e:  # noqa: BLE001
            raise OllamaUnavailable(f"{type(e).__name__}: {e}") from e
        return {"text": data.get("message", {}).get("content", ""), "latency_s": time.time() - t, "model": self.model,
                "eval_count": data.get("eval_count")}
