# backend/api/main.py

"""FastAPI entry point for CipherSentinel.

Provides minimal health endpoint and placeholder routes.
"""

from fastapi import FastAPI

app = FastAPI(title="CipherSentinel API", version="0.1.0")

from fastapi.middleware.cors import CORSMiddleware

# Enable CORS for React frontend (port 5173) and Streamlit (port 8501)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8501", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
from .routers import auth, ingest, detect, genai, score, sim, graph
app.include_router(auth.router, prefix="/auth")
app.include_router(ingest.router, prefix="/data")
app.include_router(detect.router, prefix="/detect")
app.include_router(score.router, prefix="/score")
app.include_router(sim.router, prefix="/sim")
app.include_router(graph.router, prefix="/graph")
app.include_router(genai.router, prefix="/genai")

@app.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {"status": "ok"}

# Additional routes will be added under backend/api/ as the project evolves.
