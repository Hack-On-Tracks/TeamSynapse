# backend/api/main.py

"""FastAPI entry point for CipherSentinel.

Provides minimal health endpoint and placeholder routes.
"""

from fastapi import FastAPI

app = FastAPI(title="CipherSentinel API", version="0.1.0")

# Include routers
from .routers import auth, ingest, detect, genai, score
app.include_router(auth.router, prefix="/auth")
app.include_router(ingest.router, prefix="/data")
app.include_router(detect.router, prefix="/detect")
app.include_router(score.router, prefix="/score")
app.include_router(genai.router, prefix="/genai")

@app.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {"status": "ok"}

# Additional routes will be added under backend/api/ as the project evolves.
