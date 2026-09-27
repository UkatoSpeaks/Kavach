import asyncio
import socket
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Annotated, Any

import httpx
import pytest
from fastapi import Depends, FastAPI
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_http_client, get_reasoner, get_session, get_session_factory
from app.api.routes.analyze import get_checks
from app.core.config import Settings, get_settings
from app.db.models import UrlCache
from app.db.session import create_engine
from app.main import create_app
from app.services import url_intel
from app.services.agent.llm import Reasoner
from app.services.cache import LookupCache
from app.services.pipeline import Checks
from tests.fakes import FakeSession, InMemoryReputation, fake_pattern_search, session_factory

# What every hostname resolves to unless a test says otherwise (see fake_dns).
PUBLIC_IP = "93.184.215.14"


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    """No test resolves real hostnames. Returns host -> addresses; unlisted hosts resolve
    to PUBLIC_IP, and a host mapped to [] doesn't resolve at all."""
    answers: dict[str, list[str]] = {}

    async def getaddrinfo(host: str) -> list[tuple[Any, ...]]:
        ips = answers.get(host, [PUBLIC_IP])
        if not ips:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, 0, 0, 0))
            if ":" in ip
            else (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
            for ip in ips
        ]

    monkeypatch.setattr(url_intel, "_getaddrinfo", getaddrinfo)
    return answers


ClientFactory = Callable[..., httpx.AsyncClient]


def _client(app: FastAPI, session: object, **settings_overrides: Any) -> httpx.AsyncClient:
    async def session_override() -> AsyncIterator[object]:
        yield session

    app.dependency_overrides[get_session] = session_override
    # Independent of the local .env: Safe Browsing is off unless a test turns it on.
    settings_overrides.setdefault("SAFE_BROWSING_API_KEY", "")
    settings = get_settings().model_copy(update=settings_overrides)
    app.dependency_overrides[get_settings] = lambda: settings
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


# ----------------------------------------------------------------------------- fast (no DB)


@pytest.fixture
def fake_session() -> FakeSession:
    return FakeSession()


@pytest.fixture
def reputation_store() -> InMemoryReputation:
    return InMemoryReputation()


@pytest.fixture
def make_client(fake_session: FakeSession, reputation_store: InMemoryReputation) -> ClientFactory:
    """make_client(**settings_overrides) -> API client with no database behind it.

    Analyses are saved to fake_session (by the background save, which the test client
    runs before it returns the response), reputation comes from reputation_store, the
    url_cache is in-memory (per request) and pattern retrieval runs in memory over the real
    knowledge-base docs with FakeEmbedder. The LLM step is off (reported unavailable) unless
    a test passes reasoner=, e.g. a tests.fakes.FakeReasoner; the real Groq API is never
    called here. Outbound HTTP is not mocked here; tests wrap
    calls in respx.mock.
    """

    def build(reasoner: Reasoner | None = None, **settings_overrides: Any) -> httpx.AsyncClient:
        app = create_app()
        patterns = fake_pattern_search()
        app.dependency_overrides[get_reasoner] = lambda: reasoner
        factory = session_factory(fake_session)
        app.dependency_overrides[get_session_factory] = lambda: factory

        async def checks_override(
            client: Annotated[httpx.AsyncClient, Depends(get_http_client)],
            settings: Annotated[Settings, Depends(get_settings)],
        ) -> Checks:
            ttl = timedelta(hours=settings.URL_CACHE_TTL_HOURS)
            return Checks(client, LookupCache(None, ttl), reputation_store, patterns)

        app.dependency_overrides[get_checks] = checks_override
        return _client(app, fake_session, **settings_overrides)

    return build


# ----------------------------------------------------------------------------- real DB


@pytest.fixture
async def db_session(request: pytest.FixtureRequest) -> AsyncIterator[AsyncSession]:
    """A session inside an outer transaction that is always rolled back.

    Nothing a test writes is ever committed to the (Supabase) database. Code under test
    may call session.commit(); with join_transaction_mode="create_savepoint" that only
    releases a SAVEPOINT inside the outer transaction.
    """
    if request.node.get_closest_marker("db") is None:
        pytest.fail("tests that use the database must be marked @pytest.mark.db")
    engine = create_engine(get_settings().DATABASE_URL)
    try:
        async with engine.connect() as conn:
            outer = await conn.begin()
            session = AsyncSession(
                bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
            )
            try:
                yield session
            finally:
                await session.close()
                await outer.rollback()
    finally:
        await engine.dispose()


class SharedSessionFactory:
    """Stands in for the app's sessionmaker: hands out the test's rolled-back session to
    the concurrent checks (cache, reputation) one at a time, since an AsyncSession can't
    run queries in parallel."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def __call__(self) -> AsyncIterator[AsyncSession]:
        async with self._lock:
            yield self._session


@pytest.fixture
async def make_db_client(db_session: AsyncSession) -> ClientFactory:
    """make_db_client(**settings_overrides) -> API client whose DB writes are rolled back.

    The session factory used by the url_cache and reputation lookups is the same
    rolled-back session. url_cache starts empty (inside that transaction), so lookups
    cached by real use of the app don't leak into tests.
    """
    await db_session.execute(delete(UrlCache))

    def build(**settings_overrides: Any) -> httpx.AsyncClient:
        app = create_app()
        factory = SharedSessionFactory(db_session)
        app.dependency_overrides[get_session_factory] = lambda: factory
        return _client(app, db_session, **settings_overrides)

    return build
