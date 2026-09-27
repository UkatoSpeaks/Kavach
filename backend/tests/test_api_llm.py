"""The LLM step through the API: ?explain=false, stored confidence. LLM is FakeReasoner."""

import httpx
import pytest
import respx

from app.db.models import Analysis
from tests.conftest import ClientFactory
from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES
from tests.fakes import FakeReasoner, FakeSession, assessment


@pytest.fixture(autouse=True)
def offline() -> respx.MockRouter:
    with respx.mock(assert_all_called=False) as router:
        router.route().mock(side_effect=httpx.ConnectError("offline"))
        yield router


def llm_signal(body: dict) -> dict:
    return next(s for s in body["signal_breakdown"] if s["source"] == "llm")


async def test_text_goes_through_the_llm(
    make_client: ClientFactory, fake_session: FakeSession
) -> None:
    llm = FakeReasoner(assessment(90, "upi_receive_money", confidence="medium"))
    async with make_client(reasoner=llm) as client:
        body = (await client.post("/analyze/text", json={"text": SCAM_EXAMPLES[0][1]})).json()
    assert len(llm.calls) == 1
    assert body["confidence"] == "medium" and body["explanation_en"].startswith("LLM")
    assert llm_signal(body)["weight"] > 0
    [row] = fake_session.all(Analysis)
    assert row.confidence == "medium" and row.explanation_en == body["explanation_en"]
    assert "node.reason" in row.latency_ms and "total" in row.latency_ms


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/analyze/text", {"text": SCAM_EXAMPLES[0][1]}),
        ("/analyze/url", {"url": "https://sbi-kyc-update.xyz/login"}),
        ("/analyze/upi", {"upi_id": "someone@ybl"}),
    ],
)
async def test_explain_false_skips_the_llm(
    make_client: ClientFactory, path: str, payload: dict
) -> None:
    llm = FakeReasoner(assessment(90))
    async with make_client(reasoner=llm) as client:
        body = (await client.post(f"{path}?explain=false", json=payload)).json()
        assert llm.calls == []
        assert llm_signal(body)["detail"] == "unavailable: skipped (explain=false)"
        assert body["confidence"] is None
        await client.post(path, json=payload)
        assert len(llm.calls) == 1  # default: explain=true


async def test_overruled_llm_reports_low_confidence(make_client: ClientFactory) -> None:
    async with make_client(reasoner=FakeReasoner(assessment(100, "phishing_link"))) as client:
        body = (await client.post("/analyze/text", json={"text": GENUINE_EXAMPLES[3][1]})).json()
    assert body["verdict"] == "safe" and body["confidence"] == "low"
