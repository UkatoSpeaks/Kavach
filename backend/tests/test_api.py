"""API tests. Analyses are saved to an in-memory FakeSession; one @pytest.mark.db test
covers the real save and read-back."""

import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_session
from app.db.models import Analysis
from app.main import create_app
from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES
from tests.fakes import FakeSession


def _client_with(session: object) -> httpx.AsyncClient:
    app = create_app()

    async def override() -> AsyncIterator[object]:
        yield session

    app.dependency_overrides[get_session] = override
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


@pytest.fixture
async def client(fake_session: FakeSession) -> AsyncIterator[httpx.AsyncClient]:
    async with _client_with(fake_session) as c:
        yield c


async def test_analyze_scam_saves_and_reads_back(
    client: httpx.AsyncClient, fake_session: FakeSession
) -> None:
    text = SCAM_EXAMPLES[0][1]
    resp = await client.post("/analyze/text", json={"text": text})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "scam"
    assert body["scam_type"] == "upi_receive_money"
    assert body["risk_score"] >= 70
    assert body["red_flags"] and body["signal_breakdown"][0]["source"] == "rules"
    assert body["created_at"] is not None

    [row] = fake_session.all(Analysis)
    assert str(row.id) == body["id"]
    assert row.raw_input == text
    assert row.input_type == "text"
    assert set(row.latency_ms) == {"extract", "rules", "pattern_similarity", "scoring", "explain"}
    assert row.extracted_entities["sensitive_info"] == ["upi_pin"]

    got = await client.get(f"/analysis/{body['id']}")
    assert got.status_code == 200
    assert got.json() == body


@pytest.mark.db
async def test_saved_analysis_round_trips_through_db(db_session: AsyncSession) -> None:
    async with _client_with(db_session) as client:
        body = (await client.post("/analyze/text", json={"text": SCAM_EXAMPLES[0][1]})).json()
        got = await client.get(f"/analysis/{body['id']}")
    row = (
        await db_session.execute(select(Analysis).where(Analysis.id == uuid.UUID(body["id"])))
    ).scalar_one()
    assert row.created_at is not None and row.extracted_entities["sensitive_info"] == ["upi_pin"]
    assert got.status_code == 200
    assert got.json() == body


async def test_analyze_genuine_is_safe(client: httpx.AsyncClient) -> None:
    resp = await client.post("/analyze/text", json={"text": GENUINE_EXAMPLES[0][1]})
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "safe"
    assert resp.json()["risk_score"] < 35


async def test_hindi_advice_with_language_hint(client: httpx.AsyncClient) -> None:
    resp = await client.post(
        "/analyze/text", json={"text": SCAM_EXAMPLES[2][1], "language_hint": "hi"}
    )
    assert "1930" in resp.json()["advice"][-1]
    assert "शिकायत" in resp.json()["advice"][-1]


async def test_get_missing_analysis_404(client: httpx.AsyncClient) -> None:
    resp = await client.get(f"/analysis/{uuid.uuid4()}")
    assert resp.status_code == 404


async def test_get_bad_uuid_422(client: httpx.AsyncClient) -> None:
    assert (await client.get("/analysis/not-a-uuid")).status_code == 422


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"text": ""},
        {"text": "   "},
        {"text": "x" * 5001},
        {"text": "hi", "language_hint": "fr"},
    ],
)
async def test_invalid_requests_422(client: httpx.AsyncClient, payload: dict) -> None:
    assert (await client.post("/analyze/text", json=payload)).status_code == 422


class _BrokenSession:
    """Stands in for a session whose database is unreachable."""

    def add(self, _: object) -> None:
        pass

    async def commit(self) -> None:
        raise OperationalError("INSERT", {}, ConnectionRefusedError("db down"))

    async def rollback(self) -> None:
        pass


async def test_db_down_still_returns_verdict() -> None:
    async with _client_with(_BrokenSession()) as client:
        resp = await client.post("/analyze/text", json={"text": SCAM_EXAMPLES[0][1]})
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "scam"
    assert resp.json()["id"] is None
