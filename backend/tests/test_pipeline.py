"""The async pipeline with every network signal, on the labelled examples.

Network scenarios are mocked with respx: nothing leaves the machine.
"""

from collections.abc import AsyncIterator, Callable
from datetime import timedelta

import httpx
import pytest
import respx

from app.core.config import get_settings
from app.core.enums import ScamType, Verdict
from app.services.cache import LookupCache
from app.services.pipeline import Checks, analyze, analyze_text
from app.services.scoring import SignalOutcome, Thresholds, combine_signals, score
from app.services.url_intel import SAFE_BROWSING_URL
from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES
from tests.test_scoring import WEIGHTS, rule_result


def _network_down(router: respx.MockRouter) -> None:
    router.route().mock(side_effect=httpx.ConnectError("network unreachable"))


def _normal_internet(router: respx.MockRouter) -> None:
    """Old, established domains; no redirects; nothing on Safe Browsing."""
    router.post(SAFE_BROWSING_URL).mock(return_value=httpx.Response(200, json={}))
    router.get(url__regex=r"^https://rdap\.org/domain/").mock(
        return_value=httpx.Response(
            200,
            json={"events": [{"eventAction": "registration", "eventDate": "2012-03-04T00:00Z"}]},
        )
    )
    router.head(url__regex=r".*").mock(return_value=httpx.Response(200))


SCENARIOS: dict[str, Callable[[respx.MockRouter], None]] = {
    "network-down": _network_down,
    "normal-internet": _normal_internet,
}


@pytest.fixture(params=list(SCENARIOS))
async def checks(request: pytest.FixtureRequest) -> AsyncIterator[Checks]:
    with respx.mock(assert_all_called=False) as router:
        SCENARIOS[request.param](router)
        async with httpx.AsyncClient() as client:
            # No database: reputation reports "unavailable", the cache lives in memory.
            yield Checks(client, LookupCache(None, timedelta(hours=24)), session_factory=None)


SETTINGS = get_settings().model_copy(update={"SAFE_BROWSING_API_KEY": "test-key"})


@pytest.mark.parametrize(
    ("expected_type", "text"),
    SCAM_EXAMPLES,
    ids=[f"{t}-{i}" for i, (t, _) in enumerate(SCAM_EXAMPLES)],
)
async def test_scam_examples_keep_verdict(
    checks: Checks, expected_type: ScamType, text: str
) -> None:
    result = (await analyze(text, SETTINGS, checks=checks)).result
    assert result.verdict is Verdict.SCAM, result.signal_breakdown
    assert result.risk_score >= 70
    assert result.scam_type == expected_type


@pytest.mark.parametrize(("label", "text"), GENUINE_EXAMPLES, ids=[g[0] for g in GENUINE_EXAMPLES])
async def test_genuine_examples_stay_safe(checks: Checks, label: str, text: str) -> None:
    result = (await analyze(text, SETTINGS, checks=checks)).result
    assert result.verdict is Verdict.SAFE, result.signal_breakdown
    assert result.risk_score < 35
    assert result.scam_type is None


def test_all_36_examples_are_covered() -> None:
    assert len(SCAM_EXAMPLES) + len(GENUINE_EXAMPLES) == 36


async def test_network_down_marks_signals_unavailable() -> None:
    text = "Win cashback, claim at https://sbi-rewards.top/claim or call 9123456780"
    with respx.mock as router:
        _network_down(router)
        async with httpx.AsyncClient() as client:
            checks = Checks(client, LookupCache(None, timedelta(hours=24)), None)
            out = await analyze(text, SETTINGS, checks=checks)
    by_source = {s.source: s for s in out.result.signal_breakdown}
    # url_intel still has the static lookalike findings, with the lookups noted as missing.
    assert by_source["url_intel"].weight > 0
    assert "domain age (RDAP): ConnectError" in by_source["url_intel"].detail
    assert "Safe Browsing: ConnectError" in by_source["url_intel"].detail
    assert by_source["reputation"].detail == "unavailable: database not configured"
    assert {"extract", "rules", "url_intel", "reputation", "scoring"} <= set(out.latency_ms)


def test_pure_analysis_makes_no_network_calls() -> None:
    with respx.mock as router:
        result = analyze_text(SCAM_EXAMPLES[9][1], get_settings()).result
    assert router.calls.call_count == 0
    assert {s.source for s in result.signal_breakdown} == {"rules"}


# ----------------------------------------------------------------------------- scoring


def test_uninformative_signal_does_not_dilute() -> None:
    risk, breakdown = combine_signals(
        [SignalOutcome("rules", 80), SignalOutcome("url_intel", 0, "clean", informative=False)],
        WEIGHTS,
    )
    assert risk == 80
    assert [(s.source, s.weight, s.detail) for s in breakdown] == [
        ("rules", 1.0, ""),
        ("url_intel", 0, "clean"),
    ]


def test_evidence_floor_lifts_score_and_is_explained() -> None:
    result = score(
        rule_result(),
        WEIGHTS,
        Thresholds(),
        extra=[SignalOutcome("url_intel", 100, "SB", floor=90)],
    )
    assert (result.risk_score, result.verdict, result.floor_source) == (
        90,
        Verdict.SCAM,
        "url_intel",
    )
    intel = next(s for s in result.signal_breakdown if s.source == "url_intel")
    assert intel.detail == "SB; sets the minimum score to 90"


def test_floor_never_lowers_score() -> None:
    result = score(
        rule_result("pin_to_receive", "credential_request"),
        WEIGHTS,
        Thresholds(),
        extra=[SignalOutcome("reputation", 80, "3 reports", floor=50)],
    )
    assert result.risk_score > 50 and result.floor_source is None


def test_empty_rules_count_only_for_message_text() -> None:
    intel = SignalOutcome("url_intel", 60, "lookalike")
    as_text = score(rule_result(), WEIGHTS, Thresholds(), extra=[intel])
    bare = score(
        rule_result(), WEIGHTS, Thresholds(), extra=[intel], rules_informative_if_empty=False
    )
    assert as_text.risk_score == 20  # (0.3*0 + 0.15*60) / 0.45
    assert bare.risk_score == 60
    rules = next(s for s in bare.signal_breakdown if s.source == "rules")
    assert (rules.weight, "no message text" in rules.detail) == (0, True)
