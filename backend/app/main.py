"""AI Security Operations Center — FastAPI application entry point."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from app.core.config import settings
from app.core.logging import setup_logging
from app.core.database import init_db
from app.api.routes import router

setup_logging(settings.log_level)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    init_db()
    logger.info("AI Security Ops Center ready — demo_mode=%s", settings.demo_mode)
    yield
    # Shutdown: add cleanup here if needed


def create_app() -> FastAPI:
    """Application factory used by Docker, uvicorn, and tests."""
    settings.validate_demo_mode()

    application = FastAPI(
        title="AI Security Operations Center",
        version="1.0.0",
        description=(
            "AI-powered security operations platform: real-time threat detection, "
            "LLM-driven incident correlation, natural language security queries, "
            "and deterministic asset risk scoring."
        ),
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(router)

    # Serve compiled frontend if present
    if os.path.isdir("frontend/dist"):
        application.mount("/", StaticFiles(directory="frontend/dist", html=True), name="frontend")

    return application


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=False)
