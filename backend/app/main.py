from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router

app = FastAPI(
    title="AllTools-CyberSec Workbench API",
    description="Practical Defensive Security Workbench API with Scope Guard enforcement.",
    version="0.1.0",
)

# Configure CORS for local development and frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/health", tags=["System"])
def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "service": "alltools-cybersec-backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "0.1.0",
    }


@app.get("/", tags=["System"])
def root():
    """Root info endpoint."""
    return {
        "name": "AllTools-CyberSec",
        "role": "Practical Defensive Security Workbench",
        "scopeGuard": "Active (Default-Deny)",
        "docsUrl": "/docs",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
