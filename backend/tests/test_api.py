"""API tests. Analyses are saved to an in-memory FakeSession; one @pytest.mark.db test
covers the real save and read-back.

The save is a background task. httpx's ASGITransport returns the response only after the
app has finished, background tasks included, so a test can read the row right after."""

import asyncio
import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import BackgroundTasks
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_session, get_session_factory
from app.api.routes import analyze
from app.core.config import get_settings
from app.db.models import Analysis
from app.main import create_app
from tests.conftest import settings_for_tests
from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES
from tests.fakes import FakeSession, session_factory


def _client_with(session: object) -> httpx.AsyncClient:
    settings = settings_for_tests()
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings

    async def override() -> AsyncIterator[object]:
        yield session

    factory = session_factory(session)
    app.dependency_overrides[get_session] = override
    app.dependency_overrides[get_session_factory] = lambda: factory
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
    assert set(row.latency_ms) == {
        "extract", "rules", "pattern_similarity", "llm", "scoring", "explain", "total",
        "node.extract", "node.run_checks", "node.reason", "node.finalize",
    }  # fmt: skip
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

    async def get(self, *_: object) -> None:
        return None  # nothing was ever stored


class _HangingSession(_BrokenSession):
    async def commit(self) -> None:
        await asyncio.sleep(3600)


@pytest.mark.parametrize("session", [_BrokenSession(), _HangingSession()], ids=["down", "slow"])
async def test_failed_save_still_returns_verdict_and_logs(
    session: object, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(analyze, "DB_SAVE_TIMEOUT_S", 0.05)
    async with _client_with(session) as client:
        resp = await client.post("/analyze/text", json={"text": SCAM_EXAMPLES[0][1]})
        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] == "scam"
        assert body["id"] is not None and body["created_at"] is not None  # generated up front
        assert f"could not save analysis {body['id']}" in caplog.text
        assert (await client.get(f"/analysis/{body['id']}")).status_code == 404


async def test_save_is_a_background_task(
    fake_session: FakeSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing is written before the response; the id returned is the one saved later."""
    tasks: list[tuple[object, tuple[object, ...]]] = []
    monkeypatch.setattr(
        BackgroundTasks, "add_task", lambda self, func, *args: tasks.append((func, args))
    )
    async with _client_with(fake_session) as client:
        body = (await client.post("/analyze/text", json={"text": SCAM_EXAMPLES[0][1]})).json()
    assert fake_session.all(Analysis) == []  # not saved inline
    [(func, args)] = tasks
    assert func is analyze.save_analysis
    await analyze.save_analysis(*args)  # type: ignore[arg-type]
    [row] = fake_session.all(Analysis)
    assert str(row.id) == body["id"]
    assert row.created_at.isoformat().replace("+00:00", "Z") == body["created_at"]
