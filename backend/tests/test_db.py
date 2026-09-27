"""DB round-trip tests against the real database. All writes are rolled back."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import EntityType, InputType, Verdict
from app.db.models import Analysis
from app.schemas.analysis import AnalysisResult, RedFlag, Signal
from app.services.reputation import upsert_reported_entity


async def test_insert_and_read_analysis(db_session: AsyncSession) -> None:
    result = AnalysisResult(
        risk_score=87,
        verdict=Verdict.SCAM,
        scam_type="kyc_update",
        red_flags=[RedFlag(code="otp_request", message="Asks you to share an OTP")],
        signal_breakdown=[Signal(source="rules", score=90, weight=0.4, detail="3 rules hit")],
        explanation_en="Banks never ask for your OTP.",
        explanation_hi="बैंक कभी भी आपका OTP नहीं मांगते।",
    )
    analysis = Analysis(
        input_type=InputType.TEXT,
        raw_input="Your SBI KYC expires today, share OTP to 98XXXXXX10",
        normalized_text="your sbi kyc expires today share otp",
        extracted_entities={"phones": ["+9198XXXXXX10"], "otp_mentioned": True},
        latency_ms={"rules": 2, "classifier": 35},
        **result.model_dump(
            mode="json",
            include={
                "risk_score",
                "verdict",
                "scam_type",
                "red_flags",
                "signal_breakdown",
                "explanation_en",
                "explanation_hi",
            },
        ),
    )
    db_session.add(analysis)
    await db_session.flush()
    db_session.expunge_all()  # force a real read from the DB below

    row = (
        await db_session.execute(select(Analysis).where(Analysis.id == analysis.id))
    ).scalar_one()

    assert isinstance(row.id, uuid.UUID)
    assert row.created_at.tzinfo is not None
    assert row.verdict == "scam"
    assert row.extracted_entities["otp_mentioned"] is True
    assert row.latency_ms == {"rules": 2, "classifier": 35}
    assert row.explanation_hi == "बैंक कभी भी आपका OTP नहीं मांगते।"
    # JSONB columns round-trip back into the API schema.
    restored = AnalysisResult.model_validate(row)
    assert restored.red_flags[0].code == "otp_request"
    assert restored.signal_breakdown[0].weight == 0.4


async def test_upsert_reported_entity_increments_count(db_session: AsyncSession) -> None:
    value = f"test-{uuid.uuid4().hex[:12]}@okaxis"  # unique, never collides with real data

    first = await upsert_reported_entity(db_session, EntityType.UPI, value)
    # Both calls return the same identity-mapped object, so snapshot before the 2nd call.
    first_id, first_seen = first.id, first.first_seen
    assert first.report_count == 1
    assert first.is_verified_scam is False

    second = await upsert_reported_entity(db_session, EntityType.UPI, value)
    assert second.id == first_id
    assert second.report_count == 2
    assert second.first_seen == first_seen
