# Virtual environment detection
ifeq ($(OS),Windows_NT)
    VENV_PYTHON = .\.venv\Scripts\python.exe
    PYTHON ?= $(if $(wildcard $(VENV_PYTHON)),$(VENV_PYTHON),python)
else
    VENV_PYTHON = ./.venv/bin/python
    PYTHON ?= $(if $(wildcard $(VENV_PYTHON)),$(VENV_PYTHON),python3)
endif

PIP = $(PYTHON) -m pip

# Install dependencies
install:
	$(PIP) install -r requirements.txt

# Run backend (FastAPI) server on port 8000
run-backend:
	$(PYTHON) -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload

# Run frontend (Streamlit) dashboard on port 8501
run-frontend:
	$(PYTHON) -m streamlit run frontend/dashboard/app.py

# Run all test suites
test:
	$(PYTHON) -m pytest tests -v
