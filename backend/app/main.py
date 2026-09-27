import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.deps import new_http_client
from app.api.routes import analyze, health, report
from app.core.config import get_settings
from app.core.logging import RequestIDMiddleware, setup_logging
from app.db.session import create_engine, create_sessionmaker
from app.services.agent.graph import get_graph
from app.services.agent.llm import GroqReasoner, LRUTTLCache
from app.services.embeddings import FastEmbedder

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    setup_logging(settings.LOG_LEVEL)
    engine = create_engine(settings.DATABASE_URL)
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessionmaker = create_sessionmaker(engine)
    app.state.http_client = new_http_client(settings.HTTP_TIMEOUT_S)
    # Loads in a worker thread; until it's ready the pattern signal reports "unavailable".
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
            cache=LRUTTLCache(settings.LLM_CACHE_SIZE, settings.LLM_CACHE_TTL_S),
        )
        if settings.GROQ_API_KEY
        else None
    )
    logger.info("startup complete", extra={"extra_fields": {"env": settings.ENV}})
    try:
        yield
    finally:
        await app.state.http_client.aclose()
        await engine.dispose()
        logger.info("shutdown complete")


def create_app() -> FastAPI:
    app = FastAPI(title="Kavach", version="0.1.0", lifespan=lifespan)
    app.add_middleware(RequestIDMiddleware)
    app.include_router(health.router)
    app.include_router(analyze.router)
    app.include_router(report.router)
    return app


app = create_app()
