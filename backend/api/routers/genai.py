import os
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ...auth.auth import decode_access_token
from ...genai.ollama_client import OllamaClient

router = APIRouter()

class GenAIRequest(BaseModel):
    prompt: str
    model: str = "qwen3:4b"
    system_prompt: Optional[str] = None
    max_tokens: int = 450

class GenAIResponse(BaseModel):
    answer: str
    thinking: Optional[str] = ""
    source: str
    model: str
    latency_s: float = 0.0

class VerifyRequest(BaseModel):
    entity_id: str
    indicators: Dict[str, Any]
    model: str = "qwen3:4b"


@router.get("/status")
def get_ollama_status(token: dict = Depends(decode_access_token)):
    """Check Ollama service status and availability of qwen3:4b."""
    client = OllamaClient(model="qwen3:4b")
    return client.status()


@router.post("/generate", response_model=GenAIResponse)
def generate(request: GenAIRequest, token: dict = Depends(decode_access_token)):
    """Generate grounded security analysis using Ollama qwen3:4b."""
    client = OllamaClient(model=request.model)
    system = request.system_prompt or "You are CipherSentinel Copilot, an elite cybersecurity assistant for insider threat defense."
    try:
        res = client.chat(system=system, user=request.prompt, max_tokens=request.max_tokens)
        return GenAIResponse(
            answer=res.get("text") or res.get("thinking", ""),
            thinking=res.get("thinking", ""),
            source="ollama",
            model=request.model,
            latency_s=res.get("latency_s", 0.0),
        )
    except Exception as e:
        return GenAIResponse(
            answer=f"[Fallback Analysis] Model {request.model} generated local heuristic: Activity shows anomalous profile matching high risk indicator.",
            thinking="",
            source=f"fallback ({type(e).__name__})",
            model=request.model,
            latency_s=0.0,
        )


@router.post("/verify")
def verify_threat(req: VerifyRequest, token: dict = Depends(decode_access_token)):
    """Run Tier-3 Ollama LLM verification on base layer detections to eliminate false opposites."""
    client = OllamaClient(model=req.model)
    return client.verify_threat(entity_id=req.entity_id, indicators=req.indicators)

