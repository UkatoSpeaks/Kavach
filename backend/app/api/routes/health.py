import asyncio
import logging

from fastapi import APIRouter, Request
from sqlalchemy import text

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)

DB_CHECK_TIMEOUT_S = 5


@router.get("/health")
async def health(request: Request) -> dict[str, str]:
    engine = request.app.state.engine
    try:
        async with asyncio.timeout(DB_CHECK_TIMEOUT_S):
            async with engine.connect() as conn:
                await conn.execute(text("select 1"))
        db_status = "ok"
    except Exception as exc:  # fail soft: report the error instead of a 500
        logger.warning("db health check failed: %s", exc)
        db_status = f"error: {type(exc).__name__}: {exc}"
    return {"status": "ok", "db": db_status, "env": request.app.state.settings.ENV}
