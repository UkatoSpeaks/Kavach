import uuid

import pytest
import respx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import EntityType
from app.db.models import Report, ReportedEntity
from app.services.extractors import extract_entities
from app.services.reputation import (
    MANY_REPORTS_FLOOR,
    VERIFIED_FLOOR,
    entity_keys,
    normalize,
    reputation_signal,
)
from scripts.seed_reported import DEMO_ENTITIES, seed
from tests.conftest import ClientFactory

U, P, D, L = EntityType.UPI, EntityType.PHONE, EntityType.DOMAIN, EntityType.URL


@pytest.mark.parametrize(
    ("entity_type", "raw", "normalized"),
    [
        (U, "  Demo-KYC-Help@YBL ", "demo-kyc-help@ybl"),
        (P, "+91 99999 00001", "+919999900001"),
        (P, "09999900001", "+919999900001"),
        (D, "https://WWW.Demo-SBI-KYC.xyz/login?x=1", "demo-sbi-kyc.xyz"),
        (D, "demo-sbi-kyc.xyz.", "demo-sbi-kyc.xyz"),
        (L, "HTTPS://Demo-Task-Earn.xyz/join", "https://demo-task-earn.xyz/join"),
    ],
)
def test_normalize(entity_type: EntityType, raw: str, normalized: str) -> None:
    assert normalize(entity_type, raw) == normalized


@pytest.mark.parametrize(
    ("entity_type", "raw"),
    [(U, "no-at-sign"), (U, "me@gmail.com"), (P, "12345"), (D, "not a domain"), (L, "hello")],
)
def test_normalize_rejects(entity_type: EntityType, raw: str) -> None:
    with pytest.raises(ValueError):
        normalize(entity_type, raw)


def test_entity_keys_cover_upi_phone_url_and_domains() -> None:
    e = extract_entities(
        "Pay demo-kyc-help@ybl or call 9999900001, see https://login.demo-sbi-kyc.xyz/a"
    )
    assert set(entity_keys(e)) == {
        (U, "demo-kyc-help@ybl"),
        (P, "+919999900001"),
        (L, "https://login.demo-sbi-kyc.xyz/a"),
        (D, "login.demo-sbi-kyc.xyz"),
        (D, "demo-sbi-kyc.xyz"),
    }


def _entity(count: int, verified: bool = False) -> ReportedEntity:
    return ReportedEntity(
        entity_type="upi", value="x@ybl", report_count=count, is_verified_scam=verified
    )


@pytest.mark.parametrize(
    ("count", "verified", "score", "floor"),
    [(1, False, 40, None), (2, False, 60, None), (3, False, 80, MANY_REPORTS_FLOOR),
     (1, True, 100, VERIFIED_FLOOR)],
)  # fmt: skip
def test_reputation_scores(count: int, verified: bool, score: int, floor: int | None) -> None:
    out = reputation_signal([(U, "x@ybl")], [_entity(count, verified)])
    assert out is not None
    assert (out.score, out.floor, out.informative) == (score, floor, True)
    assert out.red_flags[0].code == "reported_entity"


def test_no_reports_is_not_informative() -> None:
    out = reputation_signal([(U, "x@ybl")], [])
    assert out is not None and not out.informative
    assert reputation_signal([], []) is None


# ----------------------------------------------------------------------------- DB + API


async def test_seed_is_idempotent(db_session: AsyncSession) -> None:
    await seed(db_session)
    await seed(db_session)
    values = [normalize(t, v) for t, v, *_ in DEMO_ENTITIES]
    rows = (
        await db_session.execute(select(ReportedEntity).where(ReportedEntity.value.in_(values)))
    ).scalars()
    by_value = {r.value: r for r in rows}
    assert len(by_value) == len(DEMO_ENTITIES) >= 20
    assert by_value["demo-kyc-help@ybl"].report_count == 7
    assert all(v.startswith(("demo-", "+9199999", "http")) for v in values)


async def test_seeded_upi_id_raises_the_score(
    make_client: ClientFactory, db_session: AsyncSession
) -> None:
    # Same message shape; one UPI ID is seeded (3 reports), the other never reported.
    text = "Please send the ₹499 KYC processing fee to {} today."
    unreported = f"x{uuid.uuid4().hex[:8]}-cashback-win@ibl"
    await seed(db_session)
    async with make_client() as client:
        before = await client.post("/analyze/text", json={"text": text.format(unreported)})
        after = await client.post(
            "/analyze/text", json={"text": text.format("demo-cashback-win@ibl")}
        )
        before, after = before.json(), after.json()

    rep_before = next(s for s in before["signal_breakdown"] if s["source"] == "reputation")
    rep_after = next(s for s in after["signal_breakdown"] if s["source"] == "reputation")
    assert rep_before["weight"] == 0 and "no community reports" in rep_before["detail"]
    assert rep_after["score"] == 80 and rep_after["weight"] > 0
    assert "3 report(s)" in rep_after["detail"]
    assert after["risk_score"] > before["risk_score"]
    assert "reported_entity" in {f["code"] for f in after["red_flags"]}


async def test_verified_scam_domain_is_decisive(
    make_client: ClientFactory, db_session: AsyncSession
) -> None:
    await seed(db_session)
    async with make_client() as client:
        # A subdomain of a verified-scam domain; RDAP is not mocked, so url_intel fails soft.
        with respx.mock:
            body = (
                await client.post("/analyze/url", json={"url": "https://secure.demo-sbi-kyc.xyz"})
            ).json()
    assert body["risk_score"] >= VERIFIED_FLOOR
    assert body["verdict"] == "scam"


async def test_report_endpoint_upserts_and_logs(
    make_client: ClientFactory, db_session: AsyncSession
) -> None:
    value = f"test-{uuid.uuid4().hex[:10]}@ybl"
    async with make_client() as client:
        analysis = (await client.post("/analyze/upi", json={"upi_id": value})).json()
        first = await client.post(
            "/report",
            json={"entity_type": "upi", "value": value.upper(), "reason": "asked for UPI PIN",
                  "analysis_id": analysis["id"]},
        )  # fmt: skip
        second = await client.post("/report", json={"entity_type": "upi", "value": value})

    assert first.status_code == 201
    assert first.json()["value"] == value
    assert (first.json()["report_count"], second.json()["report_count"]) == (1, 2)
    assert first.json()["id"] == second.json()["id"]
    reports = (
        (
            await db_session.execute(
                select(Report).where(Report.entity_id == uuid.UUID(first.json()["id"]))
            )
        )
        .scalars()
        .all()
    )
    assert len(reports) == 2
    linked = next(r for r in reports if r.analysis_id is not None)
    assert (str(linked.analysis_id), linked.reason) == (analysis["id"], "asked for UPI PIN")


@pytest.mark.parametrize(
    "payload",
    [{"entity_type": "upi", "value": "nope"}, {"entity_type": "email", "value": "a@b.com"},
     {"entity_type": "phone", "value": "12"}, {"entity_type": "domain"}],
)  # fmt: skip
async def test_report_rejects_bad_input(make_client: ClientFactory, payload: dict) -> None:
    async with make_client() as client:
        assert (await client.post("/report", json=payload)).status_code == 422


async def test_report_unknown_analysis_404(
    make_client: ClientFactory, db_session: AsyncSession
) -> None:
    before = (await db_session.execute(select(func.count()).select_from(Report))).scalar_one()
    async with make_client() as client:
        resp = await client.post(
            "/report",
            json={"entity_type": "phone", "value": "9999900009", "analysis_id": str(uuid.uuid4())},
        )
    assert resp.status_code == 404
    after = (await db_session.execute(select(func.count()).select_from(Report))).scalar_one()
    assert after == before
