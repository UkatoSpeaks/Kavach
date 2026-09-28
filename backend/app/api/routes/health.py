import asyncio
import logging
import os
import time
from collections.abc import Awaitable, Callable
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text

from app.api.deps import get_reasoner
from app.api.protection import rate_limit
from app.core.config import Settings, get_settings
from app.services.agent.llm import PingResult, Reasoner

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)

DB_CHECK_TIMEOUT_S = 5
LLM_CHECK_TTL_S = 60
# Environment variables httpx reads (trust_env) that change how Groq is reached.
_NETWORK_ENV = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "GROQ_BASE_URL", "GROQ_CUSTOM_HEADERS",
)  # fmt: skip


@router.get("/health")
async def health(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, str]:
    """Liveness only: no database, no network. The platform polls it (Render's health
    check), so it must stay instant and must not fail because Supabase or Groq is down:
    the API fails soft without them."""
    return {"status": "ok", "env": settings.ENV}


@router.get("/health/db")
async def health_db(
    request: Request, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, str]:
    """Round trip to the database. Always 200; `db` is "ok" or the error (type only in
    prod)."""
    engine = request.app.state.engine
    try:
        async with asyncio.timeout(DB_CHECK_TIMEOUT_S):
            async with engine.connect() as conn:
                await conn.execute(text("select 1"))
        db_status = "ok"
    except Exception as exc:  # fail soft: report the error instead of a 500
        logger.warning("db health check failed: %s: %s", type(exc).__name__, exc)
        db_status = (
            f"error: {type(exc).__name__}"
            if settings.is_prod
            else f"error: {type(exc).__name__}: {exc}"
        )
    return {"status": "ok", "db": db_status, "env": settings.ENV}


class CachedCheck:
    """The last result of an expensive check, reused for `ttl_s`. Concurrent callers wait
    for the one check in flight instead of starting their own."""

    def __init__(self, ttl_s: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl_s, self._clock = ttl_s, clock
        self._lock = asyncio.Lock()
        self._last: tuple[float, PingResult] | None = None

    async def get(
        self, check: Callable[[], Awaitable[PingResult]]
    ) -> tuple[PingResult, float | None]:
        """(result, its age in seconds, or None if it was just checked)."""
        async with self._lock:
            now = self._clock()
            if self._last is not None and now - self._last[0] < self.ttl_s:
                return self._last[1], now - self._last[0]
            result = await check()
            self._last = (self._clock(), result)
            return result, None


def _llm_config(settings: Settings) -> dict[str, Any]:
    """What differs between machines, without values that could be secret."""
    key = settings.GROQ_API_KEY
    raw_key = os.environ.get("GROQ_API_KEY")
    return {
        "base_url_host": urlsplit(settings.GROQ_BASE_URL).hostname,
        "timeout_s": settings.LLM_TIMEOUT_S,
        "key_set": bool(key),
        "key_looks_valid": key.startswith("gsk_") and key.isascii() and key.isprintable(),
        # Stripped at startup: before this fix, this broke every call with APIConnectionError.
        "key_had_surrounding_whitespace": raw_key is not None and raw_key != raw_key.strip(),
        "network_env_set": [name for name in _NETWORK_ENV if os.environ.get(name)],
    }


@router.get("/health/llm", dependencies=[rate_limit("health_llm", "RATE_LIMIT_HEALTH_LLM")])
async def health_llm(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    reasoner: Annotated[Reasoner | None, Depends(get_reasoner)],
) -> dict[str, Any]:
    """One tiny Groq call through the app's own client (at most one per LLM_CHECK_TTL_S per
    process; later calls get the cached result). Always 200; `llm` is "ok", "error" or
    "disabled" (no GROQ_API_KEY). Errors come as class, cause chain and a sanitized
    message; the key and request details are never included."""
    body: dict[str, Any] = {"status": "ok", "env": settings.ENV, "config": _llm_config(settings)}
    ping = getattr(reasoner, "ping", None)
    if ping is None:
        return body | {"llm": "disabled"}
    cache: CachedCheck = request.app.state.llm_health
    result, age = await cache.get(ping)
    if not result.ok and age is None:
        logger.warning("llm health check failed: %s", result.error)
    err = result.error
    return body | {
        "llm": "ok" if result.ok else "error",
        "model": result.model,
        "reachable": result.reachable,
        "status_code": result.status_code,
        "elapsed_ms": result.elapsed_ms,
        "error_class": err.error_class if err else None,
        "error_causes": list(err.causes) if err else [],
        "error_message": err.message if err else None,
        "cached": age is not None,
        "checked_seconds_ago": round(age or 0),
    }
