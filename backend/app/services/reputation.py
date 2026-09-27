"""Community-reported entities (UPI IDs, phones, URLs, domains) -> the "reputation" signal."""

import re
from collections.abc import Awaitable, Callable, Sequence
from urllib.parse import urlsplit

from sqlalchemy import func, select, tuple_
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import EntityType, Severity
from app.db.models import ReportedEntity
from app.db.session import SessionFactory
from app.schemas.analysis import RedFlag
from app.schemas.entities import ExtractedEntities
from app.services.extractors import extract_phones, extract_urls
from app.services.scoring import SignalOutcome

# Score per entity by community reports.
ONE_REPORT_SCORE = 40
TWO_REPORTS_SCORE = 60
MANY_REPORTS = 3
MANY_REPORTS_SCORE = 80
VERIFIED_SCORE = 100
# Final-score floors. Unverified reports only make a result "suspicious", so a handful of
# false reports can't brand an innocent number a scam.
VERIFIED_FLOOR = 90
MANY_REPORTS_FLOOR = 50

_UPI_RE = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}@[a-z][a-z0-9-]+")
_HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}")


# --------------------------------------------------------------------------- normalizing


def normalize(entity_type: EntityType, value: str) -> str:
    """Canonical stored form. Raises ValueError if `value` isn't a valid entity."""
    value = value.strip()
    match entity_type:
        case EntityType.UPI:
            v = value.lower()
            if not _UPI_RE.fullmatch(v):
                raise ValueError("not a valid UPI ID (expected name@handle)")
            return v
        case EntityType.PHONE:
            phones = extract_phones(value)
            if len(phones) != 1:
                raise ValueError("not a valid Indian phone number")
            return phones[0].number
        case EntityType.URL:
            urls = extract_urls(value)
            if len(urls) != 1:
                raise ValueError("not a valid URL")
            return urls[0].url
        case EntityType.DOMAIN:
            host = urlsplit(value if "://" in value else f"http://{value}").hostname or ""
            host = host.lower().rstrip(".").removeprefix("www.")
            if not _HOST_RE.fullmatch(host):
                raise ValueError("not a valid domain")
            return host
    raise ValueError(f"unsupported entity type {entity_type}")


def entity_keys(entities: ExtractedEntities) -> list[tuple[EntityType, str]]:
    """Every (type, normalized value) worth looking up for a message."""
    keys: list[tuple[EntityType, str]] = []
    keys += [(EntityType.UPI, u.value) for u in entities.upi_ids]
    keys += [(EntityType.PHONE, p.number) for p in entities.phones]
    for u in entities.urls:
        keys.append((EntityType.URL, u.url))
        keys.append((EntityType.DOMAIN, u.host.removeprefix("www.")))
        keys.append((EntityType.DOMAIN, u.registered_domain))
    return list(dict.fromkeys(keys))


# --------------------------------------------------------------------------- DB


async def upsert_reported_entity(
    session: AsyncSession, entity_type: EntityType, value: str
) -> ReportedEntity:
    """Insert the entity with report_count=1, or bump report_count and last_seen.

    Atomic (single INSERT ... ON CONFLICT), so concurrent reports don't lose counts.
    `value` must already be normalized by the caller.
    """
    stmt = (
        insert(ReportedEntity)
        .values(entity_type=entity_type.value, value=value)
        .on_conflict_do_update(
            constraint="uq_reported_entities_entity_type_value",
            set_={
                "report_count": ReportedEntity.report_count + 1,
                "last_seen": func.now(),
            },
        )
        .returning(ReportedEntity)
        .execution_options(populate_existing=True)
    )
    return (await session.execute(stmt)).scalar_one()


async def find_reported(
    session: AsyncSession, keys: Sequence[tuple[EntityType, str]]
) -> list[ReportedEntity]:
    if not keys:
        return []
    stmt = select(ReportedEntity).where(
        tuple_(ReportedEntity.entity_type, ReportedEntity.value).in_(
            [(t.value, v) for t, v in keys]
        )
    )
    return list((await session.execute(stmt)).scalars())


# Looks up reported entities by (type, normalized value). The app uses the database
# (find_reported_in); tests can pass an in-memory stand-in.
FindReported = Callable[[Sequence[tuple[EntityType, str]]], Awaitable[Sequence[ReportedEntity]]]


def find_reported_in(session_factory: SessionFactory) -> FindReported:
    """find_reported on a short-lived session of its own."""

    async def lookup(keys: Sequence[tuple[EntityType, str]]) -> Sequence[ReportedEntity]:
        async with session_factory() as session:
            return await find_reported(session, keys)

    return lookup


# --------------------------------------------------------------------------- signal


def entity_score(entity: ReportedEntity) -> int:
    if entity.is_verified_scam:
        return VERIFIED_SCORE
    if entity.report_count >= MANY_REPORTS:
        return MANY_REPORTS_SCORE
    if entity.report_count == 2:
        return TWO_REPORTS_SCORE
    return ONE_REPORT_SCORE if entity.report_count >= 1 else 0


def _describe(e: ReportedEntity) -> str:
    verified = ", verified scam" if e.is_verified_scam else ""
    return f"{e.entity_type} {e.value}: {e.report_count} report(s){verified}"


def reputation_signal(
    keys: Sequence[tuple[EntityType, str]], found: Sequence[ReportedEntity]
) -> SignalOutcome | None:
    """Pure. None if there was nothing to look up."""
    if not keys:
        return None
    reported = sorted((e for e in found if entity_score(e) > 0), key=entity_score, reverse=True)
    if not reported:
        # No reports is not evidence of safety, so this doesn't dilute other signals.
        checked = ", ".join(v for _, v in keys[:3]) + (
            f" (+{len(keys) - 3} more)" if len(keys) > 3 else ""
        )
        return SignalOutcome(
            "reputation", 0, f"no community reports for {checked}", informative=False
        )
    top = reported[0]
    floor = None
    if top.is_verified_scam:
        floor = VERIFIED_FLOOR
    elif top.report_count >= MANY_REPORTS:
        floor = MANY_REPORTS_FLOOR
    flags = tuple(
        RedFlag(
            code="reported_entity",
            message=(
                "Confirmed scam: this has been verified as used by scammers"
                if e.is_verified_scam
                else f"Reported as a scam by other users ({e.report_count} report(s))"
            ),
            message_hi=(
                "पुष्टि हो चुकी है कि इसका इस्तेमाल ठग करते हैं"
                if e.is_verified_scam
                else f"दूसरे लोगों ने इसकी धोखाधड़ी के रूप में शिकायत की है ({e.report_count} शिकायत)"
            ),
            severity=Severity.HIGH if entity_score(e) >= MANY_REPORTS_SCORE else Severity.MEDIUM,
            evidence=e.value,
        )
        for e in reported
    )
    return SignalOutcome(
        "reputation",
        entity_score(top),
        "; ".join(_describe(e) for e in reported),
        floor=floor,
        red_flags=flags,
    )
