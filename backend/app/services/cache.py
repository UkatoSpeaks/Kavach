"""24h cache for network lookups (link expansion, RDAP, Safe Browsing) in the url_cache table.

Keys are namespaced, e.g. "rdap:example.com" or "expand:https://bit.ly/x". Only successful
lookups are cached, so a timeout is retried on the next request. The cache fails soft: if
the database is slow or down, a lookup is simply a miss and results are kept in memory for
the rest of the request.
"""

import asyncio
import logging
import time
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError

from app.db.models import UrlCache
from app.db.session import SessionFactory

logger = logging.getLogger(__name__)

DB_TIMEOUT_S = 2


class LookupCache:
    def __init__(self, session_factory: SessionFactory | None, ttl: timedelta) -> None:
        self._sessions = session_factory
        self._ttl = ttl
        self._memory: dict[str, tuple[float, dict[str, Any]]] = {}

    async def get(self, key: str) -> dict[str, Any] | None:
        hit = self._memory.get(key)
        if hit and time.monotonic() - hit[0] < self._ttl.total_seconds():
            return hit[1]
        if self._sessions is None:
            return None
        try:
            async with asyncio.timeout(DB_TIMEOUT_S), self._sessions() as session:
                stmt = select(UrlCache.result).where(
                    UrlCache.url == key, UrlCache.checked_at > func.now() - self._ttl
                )
                result = (await session.execute(stmt)).scalar_one_or_none()
        except (SQLAlchemyError, OSError, TimeoutError) as exc:
            logger.warning("url_cache read failed: %s: %s", type(exc).__name__, exc)
            return None
        if result is not None:
            self._memory[key] = (time.monotonic(), result)
        return result

    async def set(self, key: str, value: dict[str, Any]) -> None:
        self._memory[key] = (time.monotonic(), value)
        if self._sessions is None:
            return
        stmt = (
            insert(UrlCache)
            .values(url=key, result=value, checked_at=func.now())
            .on_conflict_do_update(
                index_elements=[UrlCache.url], set_={"result": value, "checked_at": func.now()}
            )
        )
        try:
            async with asyncio.timeout(DB_TIMEOUT_S), self._sessions() as session:
                await session.execute(stmt)
                await session.commit()
        except (SQLAlchemyError, OSError, TimeoutError) as exc:
            logger.warning("url_cache write failed: %s: %s", type(exc).__name__, exc)
