"""Community-reported entities (UPI IDs, phones, URLs, domains)."""

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import EntityType
from app.db.models import ReportedEntity


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
