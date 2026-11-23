from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.api.routes import repository, discovery, sbom, graph
from app.core.config import BASE_DIR
from app.core.logging import logger

app = FastAPI(
    title="Software Supply Chain Guardian API",
    description="Deterministic, evidence-first supply chain discovery, mapping, SBOM & security platform for BGSW Hackathon",
    version="1.0.0"
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(repository.router)
app.include_router(discovery.router)
app.include_router(sbom.router)
app.include_router(graph.router)


@app.get("/health")
def health():
    return {"status": "healthy"}


# Mount production frontend build if available
frontend_dist = BASE_DIR / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
    logger.info(f"Mounted frontend static dashboard from {frontend_dist}")
