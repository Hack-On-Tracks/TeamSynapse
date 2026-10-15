import os
import requests
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ...auth.auth import decode_access_token

router = APIRouter()

class GenAIRequest(BaseModel):
    prompt: str
    model: str = "llama2"

class GenAIResponse(BaseModel):
    answer: str
    source: str

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/api")

def call_ollama(model: str, prompt: str) -> str:
    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/generate",
            json={"model": model, "prompt": prompt},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("response", "")
    except Exception as e:
        return f"[Fallback] Could not reach Ollama: {e}"

@router.post("/generate", response_model=GenAIResponse)
def generate(request: GenAIRequest, token: dict = Depends(decode_access_token)):
    answer = call_ollama(request.model, request.prompt)
    source = "ollama" if not answer.startswith("[Fallback]") else "fallback"
    return GenAIResponse(answer=answer, source=source)
