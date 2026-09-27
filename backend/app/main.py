import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.deps import new_http_client
from app.api.errors import install_error_handlers
from app.api.protection import (
    BodySizeLimitMiddleware,
    ProxyHeadersMiddleware,
    RateLimiter,
    SecurityHeadersMiddleware,
)
from app.api.routes import analyze, health, report
from app.core.config import Settings, get_settings
from app.core.logging import RequestIDMiddleware, setup_logging
from app.db.session import create_engine, create_sessionmaker
from app.services.agent.graph import get_graph
from app.services.agent.llm import GroqReasoner, LRUTTLCache
from app.services.embeddings import FastEmbedder

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings  # set by create_app
    setup_logging(settings.LOG_LEVEL)
    engine = create_engine(settings.DATABASE_URL)
    app.state.engine = engine
    app.state.sessionmaker = create_sessionmaker(engine)
    app.state.http_client = new_http_client(settings.HTTP_TIMEOUT_S)
    # Loads in a worker thread; until it's ready the pattern signal reports "unavailable".
    # Off (PATTERN_SIGNAL_ENABLED=false): fastembed is never imported, saving ~560 MB.
    app.state.embedder = None
    if settings.PATTERN_SIGNAL_ENABLED:
        app.state.embedder = FastEmbedder(
            settings.EMBEDDING_MODEL, settings.EMBEDDING_CACHE_DIR, settings.EMBEDDING_DIM
        )
        app.state.embedder.start_loading()
    app.state.graph = get_graph()  # compiled once, shared by every request
    app.state.reasoner = (
        GroqReasoner(
            api_key=settings.GROQ_API_KEY,
            model=settings.GROQ_MODEL,
            fallback_model=settings.GROQ_FALLBACK_MODEL,
            timeout_s=settings.LLM_TIMEOUT_S,
            reasoning_effort=settings.GROQ_REASONING_EFFORT,
            cache=LRUTTLCache(settings.LLM_CACHE_SIZE, settings.LLM_CACHE_TTL_S),
        )
        if settings.GROQ_API_KEY
        else None
    )
    logger.info(
        "startup complete",
        extra={
            "extra_fields": {
                "env": settings.ENV,
                "pattern_signal": settings.PATTERN_SIGNAL_ENABLED,
                "llm": app.state.reasoner is not None,
            }
        },
    )
    try:
        yield
    finally:
        await app.state.http_client.aclose()
        await engine.dispose()
        logger.info("shutdown complete")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    docs = settings.docs_enabled
    app = FastAPI(
        title="Kavach",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.settings = settings
    app.state.rate_limiter = RateLimiter()
    install_error_handlers(app, settings)
    # Last added = outermost. Outermost first: real client IP, security headers on every
    # response, request id + access log, CORS (so errors below are readable by browsers),
    # body size limit.
    app.add_middleware(
        BodySizeLimitMiddleware,
        json_limit=settings.MAX_JSON_BODY_BYTES,
        upload_limit=settings.MAX_UPLOAD_BODY_BYTES,
    )
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "X-Request-ID"],
            expose_headers=["X-Request-ID", "Retry-After"],
            max_age=600,
        )
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(ProxyHeadersMiddleware, trusted_hops=settings.TRUSTED_PROXY_HOPS)
    app.include_router(health.router)
    app.include_router(analyze.router)
    app.include_router(report.router)
    return app


app = create_app()
