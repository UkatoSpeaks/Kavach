"""Seed demo reported entities so the reputation signal can be demoed.

All values are obviously fake ("demo-" prefixes, 99999 000xx numbers). Idempotent:
re-running resets these rows to the counts below and never touches other rows.

    uv run python -m scripts.seed_reported
"""

import asyncio

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.enums import EntityType
from app.db.models import ReportedEntity
from app.db.session import create_engine, create_sessionmaker
from app.services.reputation import normalize

U, P, D, L = EntityType.UPI, EntityType.PHONE, EntityType.DOMAIN, EntityType.URL

# (type, value, report_count, is_verified_scam, notes)
DEMO_ENTITIES: list[tuple[EntityType, str, int, bool, str]] = [
    (U, "demo-kyc-help@ybl", 7, True, "demo: fake SBI KYC helpdesk"),
    (U, "demo-refund-desk@axl", 4, False, "demo: fake refund desk"),
    (U, "demo-cashback-win@ibl", 3, False, "demo: cashback prize bait"),
    (U, "demo-electricity-bill@paytm", 2, False, "demo: fake electricity officer"),
    (U, "demo-olx-buyer@okaxis", 1, False, "demo: OLX QR advance scam"),
    (U, "demo-task-hr@apl", 5, True, "demo: task job deposit collector"),
    (U, "demo-mistake-sender@ybl", 1, False, "demo: sent-by-mistake refund"),
    (P, "+919999900001", 9, True, "demo: fake bank officer"),
    (P, "+919999900002", 3, False, "demo: fake electricity officer"),
    (P, "+919999900003", 2, False, "demo: fake courier support"),
    (P, "+919999900004", 1, False, "demo: part-time job recruiter"),
    (P, "+919999900005", 4, False, "demo: fake customer care"),
    (D, "demo-sbi-kyc.xyz", 12, True, "demo: SBI KYC phishing"),
    (D, "demo-parivahan-challan.top", 6, True, "demo: fake e-challan"),
    (D, "demo-indiapost-redeliver.shop", 3, False, "demo: parcel redelivery fee"),
    (D, "demo-amazon-rewards.click", 2, False, "demo: fake rewards"),
    (D, "demo-bijli-bill.online", 1, False, "demo: electricity bill phishing"),
    (D, "demo-flipkart-sale.site", 1, False, "demo: fake sale"),
    (L, "https://demo-task-earn.xyz/join", 3, False, "demo: task job signup"),
    (L, "http://demo-hdfc-rewards.top/app.apk", 2, True, "demo: malicious APK"),
]


async def seed(session: AsyncSession) -> int:
    """Upsert the demo entities. Returns how many rows were written."""
    for entity_type, value, count, verified, notes in DEMO_ENTITIES:
        values = {
            "entity_type": entity_type.value,
            "value": normalize(entity_type, value),
            "report_count": count,
            "is_verified_scam": verified,
            "notes": notes,
        }
        stmt = insert(ReportedEntity).values(**values)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_reported_entities_entity_type_value",
            set_={k: stmt.excluded[k] for k in ("report_count", "is_verified_scam", "notes")},
        )
        await session.execute(stmt)
    await session.commit()
    return len(DEMO_ENTITIES)


async def main() -> None:
    engine = create_engine(get_settings().DATABASE_URL)
    try:
        async with create_sessionmaker(engine)() as session:
            n = await seed(session)
        print(f"seeded {n} demo reported entities")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
