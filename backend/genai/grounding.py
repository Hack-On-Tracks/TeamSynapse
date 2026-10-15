"""Number grounding and minimal LLM-safe evidence views.

verify_numbers: every number in an LLM response must be supported by the evidence (directly,
via unit conversion/rounding, or an explicitly permitted derived value).
"""
from __future__ import annotations

import copy
import re

from genai.prompt_safety import sanitize_text

_NUM = re.compile(r"(?<![A-Za-z_])(\d[\d,]*\.?\d*|\.\d+)")
_LIST_MARKER = re.compile(r"(?m)^\s*(\d{1,2}[.)]|step\s+\d{1,2}[:.)]?)\s+", re.I)


def llm_view(bundle: dict) -> dict:
    """Minimal, pseudonymised, sanitised evidence for the LLM.

    Removes: raw related flows, analyst free-text notes, device ids, anything not needed to explain.
    Destination names (untrusted) are sanitised. Real identities are never present in bundles.
    """
    b = copy.deepcopy(bundle)
    b.pop("related_flows", None)
    b.pop("device_id", None)
    b["disposition"] = {"status": b.get("disposition", {}).get("status")}
    d = b.get("destination", {})
    if d.get("sni_name") is not None:
        d["sni_name"] = sanitize_text(d["sni_name"], 64)
    d["category"] = sanitize_text(d.get("category"), 32)
    b["daily_history"] = [
        {k: v for k, v in h.items() if k not in ("reasons",)} for h in b.get("daily_history", [])[-30:]
    ]
    for key in ("visibility_gaps",):
        b[key] = [sanitize_text(x, 160) for x in b.get(key, [])]
    b["confidence"]["reasons"] = [sanitize_text(x, 160) for x in b["confidence"].get("reasons", [])]
    b["n_related_flows_available"] = len(bundle.get("related_flows", []))
    return b


def extract_numbers(text: str) -> list[tuple[str, float]]:
    text = _LIST_MARKER.sub("", text)
    out = []
    for m in _NUM.finditer(text):
        raw = m.group(1).rstrip(".").replace(",", "")
        if not raw or raw == ".":
            continue
        try:
            out.append((raw, float(raw)))
        except ValueError:
            pass
    return out


def _walk(obj, acc: list[float]):
    if isinstance(obj, bool) or obj is None:
        return
    if isinstance(obj, (int, float)):
        acc.append(float(obj))
    elif isinstance(obj, str):
        for _, v in extract_numbers(obj):
            acc.append(v)
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk(v, acc)
    elif isinstance(obj, (list, tuple)):
        acc.append(float(len(obj)))
        for v in obj:
            _walk(v, acc)


def allowed_numbers(evidence, extra=()) -> set[float]:
    base: list[float] = []
    _walk(evidence, base)
    base += [float(x) for x in extra]
    s: set[float] = set()
    for v in base:
        s.add(v)
        for div in (1e3, 1e6, 1e9, 1024.0, 1024.0 ** 2):
            s.add(v / div)
        if abs(v) <= 1.5:
            s.add(v * 100)
        s.add(abs(v))
    return s


def _supported(raw: str, x: float, allowed: set[float]) -> bool:
    dec = len(raw.split(".")[1]) if "." in raw else 0
    tol = max(0.51 * 10 ** (-dec), 0.01 * abs(x) if dec == 0 and abs(x) >= 100 else 0)
    return any(abs(a - x) <= tol for a in allowed)


def verify_numbers(text: str, evidence, extra_allowed=()) -> tuple[bool, list[str]]:
    """Return (ok, unsupported_numbers). Dates/ids in the text are fine if present in the evidence."""
    allowed = allowed_numbers(evidence, extra_allowed)
    bad = [raw for raw, x in extract_numbers(text) if not _supported(raw, x, allowed)]
    return (len(bad) == 0), bad
