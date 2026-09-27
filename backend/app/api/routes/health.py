import asyncio
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text

from app.core.config import Settings, get_settings

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)

DB_CHECK_TIMEOUT_S = 5


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
