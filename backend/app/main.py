from typing import Dict

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.routes.auth import router as auth_router
from app.core.database import get_db

app = FastAPI(
    title="Project Sentinel API",
    version="0.1.0",
    description="Backend API for Project Sentinel",
)

app.include_router(auth_router, prefix="/api/v1")


@app.get("/", tags=["General"])
def read_root() -> Dict[str, str]:
    """Root endpoint returning a welcome message."""
    return {"message": "Welcome to Project Sentinel API"}


@app.get("/health", tags=["Health"])
def health_check() -> Dict[str, str]:
    """Health check endpoint returning application status."""
    return {
        "status": "healthy",
        "project": "Project Sentinel",
    }


@app.get("/health/database", tags=["Health"])
def health_database(db: Session = Depends(get_db)) -> Dict[str, str]:
    """Health check endpoint to verify database connectivity."""
    try:
        db.execute(text("SELECT 1"))
        return {
            "status": "healthy",
            "database": "connected",
        }
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable",
        )
