import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_session, get_session_factory
from app.core.config import get_settings
from app.db.models import UrlCache
from app.db.session import create_engine
from app.main import create_app


@pytest.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """A session inside an outer transaction that is always rolled back.

    Nothing a test writes is ever committed to the (Supabase) database. Code under test
    may call session.commit(); with join_transaction_mode="create_savepoint" that only
    releases a SAVEPOINT inside the outer transaction.
    """
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


ClientFactory = Callable[..., httpx.AsyncClient]


@pytest.fixture
async def make_client(db_session: AsyncSession) -> ClientFactory:
    """make_client(**settings_overrides) -> API client whose DB writes are rolled back.

    The session factory used by the url_cache and reputation lookups is the same
    rolled-back session. url_cache starts empty (inside that transaction), so lookups
    cached by real use of the app don't leak into tests.

    Outbound HTTP from the app is not mocked here; tests wrap calls in respx.mock.
    """
    await db_session.execute(delete(UrlCache))

    def build(**settings_overrides: Any) -> httpx.AsyncClient:
        app = create_app()
        factory = SharedSessionFactory(db_session)

        async def session_override() -> AsyncIterator[AsyncSession]:
            yield db_session

        app.dependency_overrides[get_session] = session_override
        app.dependency_overrides[get_session_factory] = lambda: factory
        # Independent of the local .env: Safe Browsing is off unless a test turns it on.
        settings_overrides.setdefault("SAFE_BROWSING_API_KEY", "")
        settings = get_settings().model_copy(update=settings_overrides)
        app.dependency_overrides[get_settings] = lambda: settings
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    return build
