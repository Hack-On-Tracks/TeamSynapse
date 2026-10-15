"""Local-only Ollama client. The GenAI layer is OPTIONAL: callers must handle OllamaUnavailable."""
from __future__ import annotations

import time
from urllib.parse import urlparse

import requests

try:
    from common.settings import get_config
except ImportError:
    from ..common.settings import get_config



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
        body = {
            "model": self.model,
            "stream": False,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": self.temperature, "num_predict": max_tokens or self.max_tokens},
        }
        if json_mode:
            body["format"] = "json"
        t = time.time()
        try:
            r = requests.post(f"{self.base_url}/api/chat", json=body, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except Exception as e:  # noqa: BLE001
            raise OllamaUnavailable(f"{type(e).__name__}: {e}") from e
        
        msg = data.get("message", {})
        content = msg.get("content", "").strip()
        thinking = msg.get("thinking", "").strip()
        text = content if content else thinking

        return {
            "text": text,
            "content": content,
            "thinking": thinking,
            "latency_s": round(time.time() - t, 2),
            "model": self.model,
            "eval_count": data.get("eval_count"),
        }

    def verify_threat(self, entity_id: str, indicators: dict) -> dict:
        """Use Qwen3:4b to verify whether an alert from Base Layers is a genuine threat or false positive."""
        system_prompt = (
            "You are a Tier-3 Cybersecurity SOC Analyst verifying insider threats. "
            "Analyze the base detection signals and determine if the activity is a CONFIRMED_THREAT, "
            "a SUSPICIOUS_ANOMALY, or a LIKELY_FALSE_POSITIVE (e.g. routine backup, scheduled update). "
            "Provide a concise verdict, confidence percentage (0-100%), and a 2-sentence rationale."
        )
        user_prompt = (
            f"Entity: {entity_id}\n"
            f"Signals:\n"
            f"- Volume Score: {indicators.get('sub_volume', 0.0)}\n"
            f"- Novelty Score: {indicators.get('sub_novelty', 0.0)}\n"
            f"- Timing / Off-Hours: {indicators.get('sub_timing', 0.0)}\n"
            f"- Scratch Model (Isolation Forest) Anomaly: {indicators.get('sub_ml_isolation_forest', 0.0)}\n"
            f"- Auth Failures: {indicators.get('sub_auth', 0.0)}\n"
            f"- Primary Indicator: {indicators.get('primary_indicator', 'N/A')}\n"
            f"- Context / Department: {indicators.get('department', 'Enterprise User')}\n\n"
            "Assess whether this represents true malicious egress or legitimate operational work."
        )
        try:
            res = self.chat(system=system_prompt, user=user_prompt, max_tokens=400)
            text = res.get("text", "")
            thinking = res.get("thinking", "")

            # Heuristic classification fallback based on LLM output
            combined_text = (text + " " + thinking).upper()
            if "CONFIRMED_THREAT" in combined_text or "HIGH RISK" in combined_text or "MALICIOUS" in combined_text:
                verdict = "CONFIRMED_THREAT"
                confidence = 88.0
            elif "FALSE_POSITIVE" in combined_text or "BENIGN" in combined_text or "ROUTINE" in combined_text:
                verdict = "LIKELY_FALSE_POSITIVE"
                confidence = 85.0
            else:
                verdict = "SUSPICIOUS_ANOMALY"
                confidence = 72.0

            return {
                "entity_id": entity_id,
                "model": self.model,
                "verdict": verdict,
                "confidence": confidence,
                "analysis": text or thinking[:300] + "...",
                "thinking": thinking,
                "latency_s": res.get("latency_s", 0.0),
                "verified_by_ollama": True,
            }
        except Exception as e:
            return {
                "entity_id": entity_id,
                "model": self.model,
                "verdict": "UNVERIFIED_OFFLINE",
                "confidence": 50.0,
                "analysis": f"Ollama verification unavailable: {e}",
                "thinking": "",
                "latency_s": 0.0,
                "verified_by_ollama": False,
            }

