"""
LOCATION: threatshield-ai/backend/app/main.py

ThreatShield AI - FastAPI Application Entry Point
"""
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.database import init_db, close_db
from app.api.auth import router as auth_router
from app.api.emails import router as emails_router
from app.api.threats import router as threats_router
from app.api.alerts import router as alerts_router
from app.api.reports import router as reports_router
from app.api.dashboard import router as dashboard_router
from app.api.cases import router as cases_router
from app.api.gmail import router as gmail_router
from app.api.trusted_senders import router as trusted_senders_router
from app.api.users import router as users_router
from app.api.feedback import router as feedback_router
from app.api.search import router as search_router
from app.api.graph import router as graph_router          # #18 Graph Analysis
from app.api.siem import router as siem_router            # #21 SIEM/ELK

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.APP_NAME}...")
    await init_db()
    logger.info("Database initialized.")

    # Bootstrap Elasticsearch indices (no-op if ES is disabled or unreachable)
    from app.services.siem import siem_client
    await siem_client.ensure_indices()

    yield

    logger.info("Shutting down...")
    from app.services.siem import siem_client as _siem
    await _siem.close()
    await close_db()


app = FastAPI(
    title=settings.APP_NAME,
    description="AI-powered email threat detection and analysis platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(emails_router)
app.include_router(threats_router)
app.include_router(alerts_router)
app.include_router(reports_router)
app.include_router(dashboard_router)
app.include_router(cases_router)
app.include_router(gmail_router)
app.include_router(trusted_senders_router)
app.include_router(users_router)
app.include_router(feedback_router)
app.include_router(search_router)
app.include_router(graph_router)                          # #18 Graph Analysis
app.include_router(siem_router)                           # #21 SIEM/ELK


@app.get("/")
async def root():
    return {"message": f"{settings.APP_NAME} API is running", "version": "1.0.0"}


@app.get("/health")
async def health():
    return {"status": "healthy", "app": settings.APP_NAME}


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})