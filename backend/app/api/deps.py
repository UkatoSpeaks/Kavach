from collections.abc import AsyncIterator
from typing import Annotated

import httpx
from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.session import SessionFactory
from app.services import rag
from app.services.agent.llm import Reasoner


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.sessionmaker() as session:
        yield session


def get_session_factory(request: Request) -> SessionFactory | None:
    """Short-lived sessions for concurrent checks (cache, reputation). None if the app
    started without a database."""
    return getattr(request.app.state, "sessionmaker", None)


def new_http_client(timeout_s: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout_s,
        follow_redirects=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; KavachLinkCheck/0.1)"},
    )


async def get_http_client(
    request: Request, settings: Annotated[Settings, Depends(get_settings)]
) -> AsyncIterator[httpx.AsyncClient]:
    """The app-wide client from the lifespan, or a per-request one if there is none."""
    client = getattr(request.app.state, "http_client", None)
    if client is not None:
        yield client
        return
    async with new_http_client(settings.HTTP_TIMEOUT_S) as client:
        yield client


def get_pattern_search(
    request: Request, settings: Annotated[Settings, Depends(get_settings)]
) -> rag.PatternSearch | None:
    """Embedder (loaded at startup) + pgvector retrieval. None if the app started without
    an embedder or a database."""
    embedder = getattr(request.app.state, "embedder", None)
    session_factory = get_session_factory(request)
    if embedder is None or session_factory is None:
        return None
    return rag.PatternSearch(
        embedder, rag.retriever_in(session_factory), rag.PatternParams.from_settings(settings)
    )


def get_reasoner(request: Request) -> Reasoner | None:
    """The Groq reasoner created at startup, or None (no GROQ_API_KEY): then the LLM
    signal is reported unavailable and template explanations are used."""
    return getattr(request.app.state, "reasoner", None)
