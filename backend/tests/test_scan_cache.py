"""app/services/scan_cache.py: key normalization, the L1/L2 layers, and the analyze routes'
use of it (a repeated scan returns cached=true without calling the LLM again)."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import groq
import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import EntityType
from app.db.models import Analysis, ReportedEntity
from app.db.models import ScanCache as ScanCacheRow
from app.services import scan_cache as sc
from app.services.agent.llm import rate_limit_delay
from app.services.ocr import GroqVisionOCR, ScreenshotReader
from app.services.scan_cache import ScanCache, purge_expired
from tests.conftest import ClientFactory, SharedSessionFactory, settings_for_tests
from tests.examples import SCAM_EXAMPLES
from tests.fakes import FakeReasoner, FakeSession, InMemoryReputation, assessment, scripted_groq
from tests.screenshots import render_sms
from tests.test_api_screenshot import post, reader, upload, vision_reply
from tests.test_llm import error

SCAM = SCAM_EXAMPLES[0][1]


def memory_cache(**overrides: Any) -> ScanCache:
    return ScanCache(None, settings_for_tests(**overrides))


# ----------------------------------------------------------------------------- keys


def test_key_format() -> None:
    key = sc.key_upi("someone@ybl", None)
    prefix, digest = key.split(":")
    assert prefix == "upi" and len(digest) == 64


def test_upi_ids_ignore_case_and_spaces() -> None:
    assert sc.key_upi("  SomeOne@YBL ", None) == sc.key_upi("someone@ybl", None)
    assert sc.key_upi("someone@ybl", None) != sc.key_upi(None, "upi://pay?pa=someone@ybl")


@pytest.mark.parametrize(
    "variant",
    [
        "https://EXAMPLE.com/login/",
        "HTTPS://example.com/login",
        "https://example.com/login?utm_source=sms&utm_medium=x",
        "https://example.com/login/?fbclid=abc&gclid=def",
    ],
)
def test_url_normalization(variant: str) -> None:
    assert sc.key_url(variant) == sc.key_url("https://example.com/login")


def test_url_keeps_meaningful_parts() -> None:
    base = sc.key_url("https://example.com/login")
    assert sc.key_url("https://example.com/login?id=7") != base
    assert sc.key_url("https://example.com/Login") != base  # paths are case-sensitive
    assert sc.key_url("http://example.com/login") != base
    assert sc.normalize_url("Example.COM/a/?utm_x=1&b=2") == "example.com/a?b=2"


def test_messages_ignore_case_and_whitespace_but_not_language() -> None:
    a = sc.key_message("  Your  KYC\nhas expired ", None)
    assert a == sc.key_message("your kyc has expired", None)
    assert a != sc.key_message("your kyc has expired", "hi")


def test_images_hash_bytes_per_type() -> None:
    assert sc.key_image("qr", b"abc") == sc.key_image("qr", b"abc")
    assert sc.key_image("qr", b"abc") != sc.key_image("qr", b"abd")
    assert sc.key_image("qr", b"abc") != sc.key_image("screenshot", b"abc")


# ----------------------------------------------------------------------------- L1


async def test_l1_round_trip_and_ttl_by_type() -> None:
    cache = memory_cache()
    key = sc.key_url("https://example.com")
    assert await cache.get(key) is None
    expires = cache.put(key, {"x": 1})
    assert timedelta(hours=11.9) < expires - datetime.now(UTC) <= timedelta(hours=12)
    hit = await cache.get(key)
    assert hit is not None and hit.payload == {"x": 1} and hit.layer == "l1"


async def test_l1_respects_entry_expiry() -> None:
    cache = memory_cache(SCAN_CACHE_TTL_UPI_HOURS=0)
    key = sc.key_upi("a@ybl", None)
    cache.put(key, {"x": 1})
    assert await cache.get(key) is None


# ----------------------------------------------------------------------------- API


async def test_repeated_text_scan_is_cached(
    make_client: ClientFactory, fake_session: FakeSession
) -> None:
    llm = FakeReasoner(assessment(90, "upi_receive_money"))
    async with make_client(reasoner=llm, scan_cache=memory_cache()) as client:
        first = (await client.post("/analyze/text", json={"text": SCAM})).json()
        again = (await client.post("/analyze/text", json={"text": f"  {SCAM.upper()} "})).json()
    assert first["cached"] is False and again["cached"] is True
    assert len(llm.calls) == 1
    assert again["id"] != first["id"]  # each scan is its own saved analysis
    strip = {"id", "created_at", "cached"}
    assert {k: v for k, v in again.items() if k not in strip} == {
        k: v for k, v in first.items() if k not in strip
    }
    saved = fake_session.rows[(Analysis, UUID(again["id"]))]
    assert "cache" in saved.latency_ms and saved.risk_score == again["risk_score"]


async def test_template_fallbacks_are_not_cached(make_client: ClientFactory) -> None:
    llm = FakeReasoner(None)  # e.g. Groq rate limited: template explanations
    async with make_client(reasoner=llm, scan_cache=memory_cache()) as client:
        for _ in range(2):
            body = (await client.post("/analyze/text", json={"text": SCAM})).json()
            assert body["cached"] is False
    assert len(llm.calls) == 2


async def test_explain_false_bypasses_the_cache(make_client: ClientFactory) -> None:
    llm = FakeReasoner(assessment(90))
    async with make_client(reasoner=llm, scan_cache=memory_cache()) as client:
        await client.post("/analyze/text", json={"text": SCAM})
        body = (await client.post("/analyze/text?explain=false", json={"text": SCAM})).json()
    assert body["cached"] is False and body["confidence"] is None


@pytest.mark.parametrize(
    ("path", "first", "second"),
    [
        ("/analyze/upi", {"upi_id": "Refund.Help@ybl"}, {"upi_id": " refund.help@YBL"}),
        (
            "/analyze/url",
            {"url": "https://sbi-kyc-update.xyz/login/?utm_source=sms"},
            {"url": "https://SBI-KYC-UPDATE.xyz/login"},
        ),
    ],
)
async def test_upi_and_url_scans_are_cached(
    make_client: ClientFactory, path: str, first: dict, second: dict
) -> None:
    llm = FakeReasoner(assessment(80))
    with respx_offline():
        async with make_client(reasoner=llm, scan_cache=memory_cache()) as client:
            a = (await client.post(path, json=first)).json()
            b = (await client.post(path, json=second)).json()
    assert (a["cached"], b["cached"]) == (False, True)
    assert len(llm.calls) == 1


def respx_offline():  # noqa: ANN201
    """Every outbound HTTP call (link expansion, RDAP...) fails fast, as if offline."""
    import respx

    router = respx.mock(assert_all_called=False)
    router.route().mock(side_effect=httpx.ConnectError("offline"))
    return router


async def test_screenshot_is_cached_by_image_bytes(make_client: ClientFactory) -> None:
    phishing = SCAM_EXAMPLES[9][1]
    ocr = reader(vision_reply(phishing, "VM-SBIINB"))
    llm = FakeReasoner(assessment(90))
    image = upload(render_sms("VM-SBIINB", phishing))
    async with make_client(ocr=ocr, reasoner=llm, scan_cache=memory_cache()) as client:
        a = (await post(client, image)).json()
        b = (await post(client, image)).json()
    assert (a["cached"], b["cached"]) == (False, True)
    assert b["extracted_text"] == a["extracted_text"] and b["sender"] == a["sender"]
    assert len(llm.calls) == 1


async def test_screenshot_rate_limited_returns_high_traffic(make_client: ClientFactory) -> None:
    client_, requests = scripted_groq(error(429, "rate_limit_exceeded"))
    vision = GroqVisionOCR("test-key", "vision-test-model", timeout_s=5, client=client_)
    ocr = ScreenshotReader(vision, None, rate_limit_backoff_s=0)
    async with make_client(ocr=ocr) as client:
        resp = await post(client, upload(render_sms("x", SCAM)))
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "high_traffic"
    assert "try again in a minute" in resp.json()["error"]["message"]
    assert resp.headers["retry-after"] == "60"
    assert len(requests) == 2  # retried once after the backoff


# ----------------------------------------------------------------------------- 429 backoff


def rate_limit_error(headers: dict[str, str]) -> groq.RateLimitError:
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    response = httpx.Response(429, headers=headers, request=request)
    return groq.RateLimitError("rate limited", response=response, body=None)


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({}, 1.0),
        ({"retry-after": "2"}, 2.0),
        ({"retry-after": "30"}, 3.0),
        ({"retry-after": "x"}, 1.0),
    ],
)
def test_rate_limit_delay(headers: dict[str, str], expected: float) -> None:
    assert rate_limit_delay(rate_limit_error(headers), 1.0, 3.0) == expected


# ----------------------------------------------------------------------------- L2 (Supabase)


@pytest.mark.db
async def test_l2_round_trip_hit_count_and_cleanup(db_session: AsyncSession) -> None:
    """Needs the scan_cache migration (alembic upgrade head). Rolled back afterwards."""
    sessions = SharedSessionFactory(db_session)
    settings = settings_for_tests()
    key = sc.key_upi("l2-test@ybl", None)
    writer = ScanCache(sessions, settings)
    await writer.persist(key, {"x": 1}, writer.put(key, {"x": 1}))

    reader_ = ScanCache(sessions, settings)  # fresh L1: must come from the table
    hit = await reader_.get(key)
    assert hit is not None and hit.layer == "l2" and hit.payload == {"x": 1}
    await reader_.record_hit(key)
    row = (
        await db_session.execute(select(ScanCacheRow).where(ScanCacheRow.cache_key == key))
    ).scalar_one()
    assert row.hit_count == 1 and row.scan_type == "upi"

    expired = sc.key_upi("expired-test@ybl", None)
    await writer.persist(expired, {"x": 2}, datetime.now(UTC) - timedelta(seconds=1))
    assert await ScanCache(sessions, settings).get(expired) is None
    assert await purge_expired(sessions) >= 1
    assert await db_session.get(ScanCacheRow, expired) is None


# ----------------------------------------------------------------------------- invalidation


def test_entity_tags_match_what_report_normalizes() -> None:
    """A scan's tags and POST /report's value meet on reputation.normalize()."""
    from app.services.extractors import extract_entities
    from app.services.reputation import normalize

    entities = extract_entities("pay at upi://pay?pa=Refund.Help@ybl or call 98765 43210")
    tags = sc.entity_tags(entities)
    assert sc.entity_tag(EntityType.UPI, normalize(EntityType.UPI, " REFUND.help@YBL")) in tags
    assert sc.entity_tag(EntityType.PHONE, normalize(EntityType.PHONE, "9876543210")) in tags
    assert sc.entity_tag(EntityType.UPI, "someone-else@ybl") not in tags


async def test_invalidate_drops_only_tagged_l1_entries() -> None:

    cache = memory_cache()
    tag = sc.entity_tag(EntityType.UPI, "a@ybl")
    cache.put(sc.key_upi("a@ybl", None), {"x": 1}, [tag])
    cache.put(sc.key_message("pay a@ybl", "hi"), {"x": 2}, [tag])
    other = sc.key_upi("b@ybl", None)
    cache.put(other, {"x": 3}, [sc.entity_tag(EntityType.UPI, "b@ybl")])

    assert await cache.invalidate(EntityType.UPI, "a@ybl") == 2
    assert await cache.get(sc.key_upi("a@ybl", None)) is None
    assert await cache.get(sc.key_message("pay a@ybl", "hi")) is None
    assert await cache.get(other) is not None


@pytest.fixture
def reports_feed_reputation(
    monkeypatch: pytest.MonkeyPatch, reputation_store: InMemoryReputation
) -> None:
    """POST /report writes into the in-memory reputation store the scans read, as the real
    reported_entities table would (no database in these tests)."""
    from app.api.routes import report

    async def upsert(session: object, entity_type: EntityType, value: str) -> ReportedEntity:
        prev = reputation_store.entities.get((entity_type.value, value))
        reputation_store.add(entity_type, value, (prev.report_count if prev else 0) + 1, False)
        return reputation_store.entities[(entity_type.value, value)]

    monkeypatch.setattr(report, "upsert_reported_entity", upsert)


PHONE_SCAM = "Your electricity will be cut tonight. Call officer 98765 43210 to update the bill"


@pytest.mark.usefixtures("reports_feed_reputation")
@pytest.mark.parametrize(
    ("scans", "reported", "evidence"),
    [
        pytest.param(
            [("/analyze/upi", {"upi_id": "Refund.Help@ybl"})],
            {"entity_type": "upi", "value": " REFUND.help@YBL"},
            "refund.help@ybl",
            id="upi",
        ),
        pytest.param(
            [("/analyze/url", {"url": "https://sbi-kyc-update.xyz/login"})],
            {"entity_type": "url", "value": "https://SBI-KYC-UPDATE.xyz/login"},
            "https://sbi-kyc-update.xyz/login",
            id="url",
        ),
        pytest.param(
            # every language_hint variant of the same input is invalidated
            [
                ("/analyze/text", {"text": PHONE_SCAM}),
                ("/analyze/text", {"text": PHONE_SCAM, "language_hint": "hi"}),
                ("/analyze/text", {"text": PHONE_SCAM, "language_hint": "hinglish"}),
            ],
            {"entity_type": "phone", "value": "9876543210"},
            "+919876543210",
            id="phone-all-language-hints",
        ),
    ],
)
async def test_report_invalidates_cached_scans(
    make_client: ClientFactory,
    scans: list[tuple[str, dict]],
    reported: dict,
    evidence: str,
) -> None:
    def reported_flags(body: dict) -> list[dict]:
        return [f for f in body["red_flags"] if f["code"] == "reported_entity"]

    llm = FakeReasoner(assessment(80))
    with respx_offline():
        async with make_client(reasoner=llm, scan_cache=memory_cache()) as client:
            for path, body in scans:
                first = (await client.post(path, json=body)).json()
                again = (await client.post(path, json=body)).json()
                assert (first["cached"], again["cached"]) == (False, True)
                assert reported_flags(again) == []

            resp = await client.post("/report", json=reported)
            assert resp.status_code == 201

            calls = len(llm.calls)
            for path, body in scans:
                after = (await client.post(path, json=body)).json()
                assert after["cached"] is False
                assert [f["evidence"] for f in reported_flags(after)] == [evidence]
            assert len(llm.calls) == calls + len(scans)  # really re-analyzed


@pytest.mark.usefixtures("reports_feed_reputation")
async def test_report_leaves_unrelated_cached_scans(make_client: ClientFactory) -> None:
    llm = FakeReasoner(assessment(80))
    async with make_client(reasoner=llm, scan_cache=memory_cache()) as client:
        await client.post("/analyze/upi", json={"upi_id": "keep.me@ybl"})
        await client.post("/report", json={"entity_type": "upi", "value": "other@ybl"})
        body = (await client.post("/analyze/upi", json={"upi_id": "keep.me@ybl"})).json()
    assert body["cached"] is True


@pytest.mark.db
async def test_l2_invalidation_by_entity_tag(db_session: AsyncSession) -> None:
    """Needs the entity_tags migration (alembic upgrade head). Rolled back afterwards."""

    sessions = SharedSessionFactory(db_session)
    settings = settings_for_tests()
    value = "l2-invalidate-test@ybl"
    tag = sc.entity_tag(EntityType.UPI, value)
    writer = ScanCache(sessions, settings)
    keys = [sc.key_upi(value, None), sc.key_message(f"pay {value}", None),
            sc.key_message(f"pay {value}", "hi")]  # fmt: skip
    for key in keys:
        await writer.persist(key, {"x": 1}, writer.put(key, {"x": 1}, [tag]), [tag])
    other = sc.key_upi("l2-keep-test@ybl", None)
    other_tags = [sc.entity_tag(EntityType.UPI, "l2-keep-test@ybl")]
    await writer.persist(other, {"x": 2}, writer.put(other, {"x": 2}, other_tags), other_tags)

    # A fresh instance (another worker): nothing in its L1, so only L2 can match.
    assert await ScanCache(sessions, settings).invalidate(EntityType.UPI, value) == 3
    for key in keys:
        assert await db_session.get(ScanCacheRow, key) is None
        assert await writer.get(key) is not None  # the writer's own L1 is separate...
    assert await writer.invalidate(EntityType.UPI, value) == 3  # ...and cleared by its own call
    assert await ScanCache(sessions, settings).get(other) is not None
