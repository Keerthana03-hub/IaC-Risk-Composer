"""
IaC Risk Composer – Backend Entry Point
----------------------------------------
Runs with:  uvicorn main:app --reload --port 8000

Architecture is intentionally modular so future parsers, threat-detection
engines, and ML models can be wired in as separate sub-packages without
touching this file.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import init_db
from routers.analysis import router as api_router
from routers.auth import router as auth_router
from routers.projects import router as projects_router
from routers.reports import router as reports_router

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

# Initialize persistent SQLite database tables on startup
init_db()

app = FastAPI(
    title="IaC Risk Composer API",
    description="Cybersecurity platform for analysing Infrastructure-as-Code.",
    version="1.0.0",
)

# Allow the Vite dev server (port 5173) to reach the API during development.
# In production, tighten this to the actual frontend origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(auth_router, prefix="/api")
app.include_router(projects_router, prefix="/api")
app.include_router(api_router, prefix="/api")
app.include_router(reports_router, prefix="/api")


# ---------------------------------------------------------------------------
# Dev convenience – run directly with `python main.py`
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
