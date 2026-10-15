"""CipherSentinel One-Click Unified Launcher.

Starts both the FastAPI REST backend (port 8000) and the Streamlit SOC Dashboard (port 8501)
with a single command:
    python run.py
"""
import os
import sys
import time
import signal
import urllib.request
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent

# Locate Python executable inside virtual environment if present
VENV_PYTHON = ROOT_DIR / ".venv" / "Scripts" / "python.exe"
if not VENV_PYTHON.exists():
    VENV_PYTHON = ROOT_DIR / ".venv" / "bin" / "python"
if not VENV_PYTHON.exists():
    PYTHON_EXE = sys.executable
else:
    PYTHON_EXE = str(VENV_PYTHON)


def check_api_ready(timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def main():
    print("=" * 65)
    print("🛡️  CIPHERSENTINEL — AI-Powered Insider Threat Detection Platform")
    print("=" * 65)
    print(f"[*] Workspace Root: {ROOT_DIR}")
    print(f"[*] Python Binary:  {PYTHON_EXE}")

    # Set environment variables
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT_DIR)

    # 1. Start FastAPI Backend Server
    print("\n[1/2] Starting FastAPI Backend on http://127.0.0.1:8000 ...")
    backend_proc = subprocess.Popen(
        [
            PYTHON_EXE,
            "-m",
            "uvicorn",
            "backend.api.main:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
        ],
        cwd=str(ROOT_DIR),
        env=env,
    )

    if check_api_ready(timeout=15):
        print("  -> Backend is healthy and listening on http://127.0.0.1:8000 (Docs: /docs)")
    else:
        print("  -> Warning: Backend health check took longer than expected; proceeding...")

    # 2. Start Streamlit SOC Dashboard
    print("\n[2/2] Launching Streamlit SOC Dashboard on http://localhost:8501 ...")
    frontend_script = str(ROOT_DIR / "frontend" / "dashboard" / "app.py")
    frontend_proc = subprocess.Popen(
        [
            PYTHON_EXE,
            "-m",
            "streamlit",
            "run",
            frontend_script,
            "--server.port",
            "8501",
            "--server.headless",
            "false",
        ],
        cwd=str(ROOT_DIR),
        env=env,
    )

    # 3. Start React Cytoscape Graph Simulator (port 5173)
    graph_proc = None
    graph_dir = ROOT_DIR / "frontend" / "graph-app"
    if (graph_dir / "package.json").exists():
        print("\n[3/3] Launching React Graph Simulator on http://localhost:5173 ...")
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        try:
            graph_proc = subprocess.Popen(
                [npm_cmd, "run", "dev"],
                cwd=str(graph_dir),
                shell=(sys.platform == "win32"),
            )
            print("  -> React Graph Simulator is starting on http://localhost:5173")
        except Exception as e:
            print(f"  -> React Graph skipped ({e}); launch manually via 'npm run dev' in frontend/graph-app")

    print("\n" + "=" * 65)
    print("🚀 CIPHERSENTINEL IS LIVE!")
    print("   • Graph Simulator: http://localhost:5173")
    print("   • SOC Dashboard:   http://localhost:8501")
    print("   • REST API:        http://127.0.0.1:8000")
    print("   • API Docs:        http://127.0.0.1:8000/docs")
    print("   • Default Login:   admin / admin123")
    print("=" * 65)
    print("Press Ctrl+C to stop all servers.\n")

    try:
        # Keep launcher alive and monitor processes
        while True:
            if backend_proc.poll() is not None:
                print("[-] Backend process terminated unexpectedly.")
                break
            if frontend_proc.poll() is not None:
                print("[-] Frontend dashboard closed.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down CipherSentinel services...")
    finally:
        procs = [p for p in [backend_proc, frontend_proc, graph_proc] if p is not None]
        for proc in procs:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        print("[*] All services stopped.")


if __name__ == "__main__":
    main()
