from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import create_engine


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
