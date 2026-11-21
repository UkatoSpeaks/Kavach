"""Scan cache: whole analysis results, so a repeated scan of the same input skips Groq.

Keys are "<scan_type>:<sha256>" over the normalized input (see the key_* functions), e.g.
"upi:3f2a...". Two layers:

- L1: in-process cachetools.TTLCache (SCAN_CACHE_L1_SIZE items, SCAN_CACHE_L1_TTL_S).
- L2: the scan_cache table, with a per-type TTL (SCAN_CACHE_TTL_*_HOURS).

Lookups go L1 -> L2 -> a real analysis. The caller stores only results whose LLM step
succeeded (never template fallbacks after a timeout, a 429 or bad output). Like LookupCache,
the database side fails soft: a slow or failing database is just a miss, and writes are
best-effort.

CACHE_VERSION is hashed into every key: bump it when a change to scoring, rules or prompts
should invalidate results cached before it.

Invalidation on new reports: every entry is tagged with entity_tag() of each reportable
entity the result was checked against (reputation.entity_keys of the scan's extracted
entities: UPI IDs, including the payee of a upi:// link, phones, URLs and their domains).
POST /report calls invalidate() with the value it just normalized, which deletes every L1
and L2 entry carrying that tag, whatever its scan type or language_hint. L1 is per process:
with several workers, the others' L1 copies live on until their L1 TTL.
"""

import asyncio
import hashlib
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from cachetools import TTLCache
from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import Settings
from app.core.enums import EntityType
from app.db.models import ScanCache as ScanCacheRow
from app.db.session import SessionFactory
from app.schemas.entities import ExtractedEntities
from app.services.reputation import entity_keys

logger = logging.getLogger(__name__)

CACHE_VERSION = "2"  # 2: entries carry entity_tags
DB_TIMEOUT_S = 2
CLEANUP_TIMEOUT_S = 30

ScanType = Literal["upi", "url", "message", "screenshot", "qr"]
_TRACKING_PARAMS = frozenset({"fbclid", "gclid"})


# --------------------------------------------------------------------------- keys


def _key(scan_type: ScanType, material: bytes | str, *variant: str | None) -> str:
    h = hashlib.sha256(f"v{CACHE_VERSION}\x00{scan_type}\x00".encode())
    h.update(material.encode() if isinstance(material, str) else material)
    for v in variant:  # request options that change the result (e.g. the advice language)
        h.update(f"\x00{v or ''}".encode())
    return f"{scan_type}:{h.hexdigest()}"


def normalize_upi(value: str) -> str:
    return value.strip().lower()


def normalize_url(url: str) -> str:
    """Lowercase scheme and host, drop utm_*/fbclid/gclid and trailing slashes. Pure."""
    url = url.strip()
    has_scheme = "://" in url
    parts = urlsplit(url if has_scheme else "//" + url)
    query = urlencode(
        [
            (k, v)
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if not (k.lower().startswith("utm_") or k.lower() in _TRACKING_PARAMS)
        ]
    )
    rebuilt = urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/"), query, parts.fragment)
    )
    return rebuilt if has_scheme else rebuilt.removeprefix("//")


def normalize_message(text: str) -> str:
    return " ".join(text.split()).lower()


def key_upi(upi_id: str | None, upi_uri: str | None) -> str:
    if upi_id is not None:
        return _key("upi", normalize_upi(upi_id))
    # A upi:// link carries more than the ID (amount, payee name...), all of which is analyzed.
    return _key("upi", "uri\x00" + (upi_uri or "").strip())


def key_url(url: str) -> str:
    return _key("url", normalize_url(url))


def key_message(text: str, language_hint: str | None) -> str:
    return _key("message", normalize_message(text), language_hint)


def key_image(scan_type: Literal["screenshot", "qr"], data: bytes, *variant: str | None) -> str:
    return _key(scan_type, data, *variant)


def entity_tag(entity_type: EntityType | str, value: str) -> str:
    """Tag for a reported entity. `value` must be normalized like reputation.normalize()
    (POST /report already does; entity_keys() yields values in that form)."""
    t = EntityType(entity_type).value
    digest = hashlib.sha256(f"{t}\x00{value}".encode()).hexdigest()
    return f"{t}:{digest}"


def entity_tags(entities: ExtractedEntities) -> list[str]:
    """Tags of everything a scan's reputation check looked up."""
    return [entity_tag(t, v) for t, v in entity_keys(entities)]


def scan_type_of(key: str) -> ScanType:
    return key.split(":", 1)[0]  # type: ignore[return-value]


# --------------------------------------------------------------------------- cache


@dataclass(frozen=True)
class CacheHit:
    payload: dict[str, Any]
    layer: Literal["l1", "l2"]


class ScanCache:
    def __init__(self, session_factory: SessionFactory | None, settings: Settings) -> None:
        self._sessions = session_factory
        # key -> (expiry timestamp, payload, entity tags)
        self._memory: TTLCache[str, tuple[float, dict[str, Any], frozenset[str]]] = TTLCache(
            maxsize=settings.SCAN_CACHE_L1_SIZE, ttl=settings.SCAN_CACHE_L1_TTL_S
        )
        image = timedelta(hours=settings.SCAN_CACHE_TTL_IMAGE_HOURS)
        self.ttls: dict[ScanType, timedelta] = {
            "upi": timedelta(hours=settings.SCAN_CACHE_TTL_UPI_HOURS),
            "url": timedelta(hours=settings.SCAN_CACHE_TTL_URL_HOURS),
            "message": timedelta(hours=settings.SCAN_CACHE_TTL_MESSAGE_HOURS),
            "screenshot": image,
            "qr": image,
        }

    def _remember(
        self, key: str, payload: dict[str, Any], expires_at: datetime, tags: Sequence[str]
    ) -> None:
        # Kept with the L2 expiry too, so L1 never outlives the entry's own TTL.
        self._memory[key] = (expires_at.timestamp(), payload, frozenset(tags))

    async def get(self, key: str) -> CacheHit | None:
        if (item := self._memory.get(key)) is not None:
            if time.time() < item[0]:
                return CacheHit(item[1], "l1")
            self._memory.pop(key, None)
        if self._sessions is None:
            return None
        try:
            async with asyncio.timeout(DB_TIMEOUT_S), self._sessions() as session:
                stmt = select(
                    ScanCacheRow.result, ScanCacheRow.expires_at, ScanCacheRow.entity_tags
                ).where(ScanCacheRow.cache_key == key, ScanCacheRow.expires_at > datetime.now(UTC))
                row = (await session.execute(stmt)).one_or_none()
        except (SQLAlchemyError, OSError, TimeoutError) as exc:
            logger.warning("scan_cache read failed: %s: %s", type(exc).__name__, exc)
            return None
        if row is None:
            return None
        self._remember(key, row.result, row.expires_at, row.entity_tags)
        return CacheHit(row.result, "l2")

    def put(self, key: str, payload: dict[str, Any], tags: Sequence[str] = ()) -> datetime:
        """Store in L1 now; returns the expiry to pass to persist(). `tags`: entity_tags()
        of the scan, so a report on any of those entities invalidates it."""
        expires_at = datetime.now(UTC) + self.ttls[scan_type_of(key)]
        self._remember(key, payload, expires_at, tags)
        return expires_at

    async def persist(
        self,
        key: str,
        payload: dict[str, Any],
        expires_at: datetime,
        tags: Sequence[str] = (),
    ) -> None:
        """Write to L2. Background task: never raises."""
        if self._sessions is None:
            return
        values = {
            "result": payload,
            "expires_at": expires_at,
            "created_at": datetime.now(UTC),
            "entity_tags": list(tags),
        }
        stmt = (
            insert(ScanCacheRow)
            .values(cache_key=key, scan_type=scan_type_of(key), hit_count=0, **values)
            .on_conflict_do_update(
                index_elements=[ScanCacheRow.cache_key], set_={**values, "hit_count": 0}
            )
        )
        try:
            async with asyncio.timeout(DB_TIMEOUT_S), self._sessions() as session:
                await session.execute(stmt)
                await session.commit()
        except Exception as exc:
            logger.warning("scan_cache write failed: %s: %s", type(exc).__name__, exc)

    async def record_hit(self, key: str) -> None:
        """hit_count += 1 for an L2 hit. Background task: never raises."""
        if self._sessions is None:
            return
        stmt = (
            update(ScanCacheRow)
            .where(ScanCacheRow.cache_key == key)
            .values(hit_count=ScanCacheRow.hit_count + 1)
        )
        try:
            async with asyncio.timeout(DB_TIMEOUT_S), self._sessions() as session:
                await session.execute(stmt)
                await session.commit()
        except Exception as exc:
            logger.warning("scan_cache hit_count update failed: %s: %s", type(exc).__name__, exc)

    async def invalidate(self, entity_type: EntityType | str, value: str) -> int:
        """Drop every cached scan that looked up this entity (normalized like
        reputation.normalize), from L1 and L2, so the next scan sees the new report.
        Returns how many entries went. Never raises: a failed L2 delete is logged and the
        entry ages out with its TTL."""
        tag = entity_tag(entity_type, value)
        stale = [k for k, (_, _, tags) in list(self._memory.items()) if tag in tags]
        for k in stale:
            self._memory.pop(k, None)
        deleted = len(stale)
        if self._sessions is not None:
            stmt = delete(ScanCacheRow).where(ScanCacheRow.entity_tags.contains([tag]))
            try:
                async with asyncio.timeout(DB_TIMEOUT_S), self._sessions() as session:
                    result = await session.execute(stmt)
                    await session.commit()
                deleted = max(deleted, result.rowcount or 0)  # type: ignore[attr-defined]
            except Exception as exc:
                logger.warning("scan_cache invalidation failed: %s: %s", type(exc).__name__, exc)
        logger.info(
            "scan_cache invalidated",
            extra={"extra_fields": {"entity_type": str(entity_type), "deleted": deleted}},
        )
        return deleted


async def purge_expired(session_factory: SessionFactory | None) -> int:
    """Delete expired scan_cache rows; returns how many. Run at startup (in the background);
    safe to call any time. Never raises."""
    if session_factory is None:
        return 0
    try:
        async with asyncio.timeout(CLEANUP_TIMEOUT_S), session_factory() as session:
            result = await session.execute(
                delete(ScanCacheRow).where(ScanCacheRow.expires_at <= datetime.now(UTC))
            )
            await session.commit()
    except Exception as exc:
        logger.warning("scan_cache cleanup failed: %s: %s", type(exc).__name__, exc)
        return 0
    deleted = result.rowcount or 0  # type: ignore[attr-defined]
    logger.info("scan_cache cleanup", extra={"extra_fields": {"deleted": deleted}})
    return deleted
