"""The pattern_similarity signal: retrieval, the margin rule, and how it may affect scores."""

from datetime import timedelta

import httpx
import pytest
import respx

from app.core.config import get_settings
from app.core.enums import PatternKind, ScamType, Verdict
from app.services import rag
from app.services.cache import LookupCache
from app.services.pipeline import Checks, analyze
from app.services.scoring import SignalOutcome, Thresholds, score
from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES
from tests.fakes import FakeEmbedder, UnavailableEmbedder, fake_pattern_search
from tests.test_knowledge_base import GOOD, parse_doc
from tests.test_scoring import WEIGHTS, rule_result

PARAMS = rag.PatternParams(top_k=3, min_margin=0.05, full_margin=0.20, min_similarity=0.35)


def match(slug: str, similarity: float, kind: PatternKind = PatternKind.SCAM) -> rag.PatternMatch:
    category = "genuine" if kind is PatternKind.GENUINE else ScamType.PHISHING_LINK.value
    return rag.PatternMatch(slug, slug.title(), category, kind, similarity)


def retrieval(scam: list[float], genuine: float | None) -> rag.Retrieval:
    return rag.Retrieval(
        scam=[match(f"scam-{i}", s) for i, s in enumerate(scam)],
        genuine=None if genuine is None else match("bank-alert", genuine, PatternKind.GENUINE),
    )


# ----------------------------------------------------------------------------- the signal


@pytest.mark.parametrize(
    ("scam", "genuine", "expected"),
    [
        (0.70, 0.66, None),  # margin 0.04: below min_margin
        (0.75, 0.70, 60),  # margin 0.05: the weakest informative score
        (0.70, 0.575, 80),  # halfway to full_margin
        (0.80, 0.40, 100),  # beyond full_margin: capped
        (0.50, 0.75, None),  # closer to a genuine message: uninformative, never "safe"
    ],
)
def test_score_follows_the_margin_not_raw_similarity(
    scam: float, genuine: float, expected: float | None
) -> None:
    out = rag.pattern_signal(retrieval([scam, 0.3], genuine), PARAMS)
    if expected is None:
        assert (out.score, out.informative) == (0, False)
        assert "not clearly closer to a scam" in out.detail
        assert out.scam_type is None
    else:
        assert out.informative and out.score == pytest.approx(expected, abs=0.1)
        assert out.scam_type is ScamType.PHISHING_LINK
    assert out.floor is None and out.can_decide_scam is False


def test_high_raw_similarity_alone_is_not_evidence() -> None:
    # A genuine bank SMS can be very similar to a scam pattern; what matters is the margin.
    out = rag.pattern_signal(retrieval([0.92], 0.90), PARAMS)
    assert not out.informative


def test_weakly_similar_scam_match_does_not_count() -> None:
    out = rag.pattern_signal(retrieval([0.30], 0.05), PARAMS)
    assert not out.informative and out.similar_patterns == ()


def test_similar_patterns_filtered_and_clamped() -> None:
    r = rag.Retrieval(
        scam=[match("a", 1.0000001), match("b", 0.5), match("c", 0.2)],
        genuine=match("g", 0.1, PatternKind.GENUINE),
    )
    similar = rag.similar_patterns(r, PARAMS)
    assert [(p.slug, p.similarity, p.category) for p in similar] == [
        ("a", 1.0, "phishing_link"),
        ("b", 0.5, "phishing_link"),
    ]


def test_empty_knowledge_base_or_no_genuine_docs() -> None:
    assert rag.pattern_signal(rag.Retrieval([], None), PARAMS).detail == "knowledge base is empty"
    out = rag.pattern_signal(retrieval([0.9], None), PARAMS)
    assert not out.informative and "no genuine patterns" in out.detail


async def test_unavailable_embedder_marks_signal_unavailable() -> None:
    search = rag.PatternSearch(UnavailableEmbedder(), rag.InMemoryRetriever([]), PARAMS)
    out = await rag.pattern_similarity("anything", search)
    assert out.score is None and out.detail == "embedding model is still loading"


# ----------------------------------------------------------------------------- retrieval


async def test_in_memory_retriever_ranks_and_filters_by_kind() -> None:
    docs = [
        parse_doc(GOOD.replace("slug: demo", "slug: qr").replace("Demo scam", "scan qr code")),
        parse_doc(GOOD.replace("slug: demo", "slug: task").replace("Demo scam", "youtube likes")),
        parse_doc(
            GOOD.replace("slug: demo", "slug: otp")
            .replace("kind: scam", "kind: genuine")
            .replace("qr_code", "genuine")
            .replace("Demo scam", "scan qr code otp")
        ),
    ]
    search = rag.PatternSearch(
        FakeEmbedder(), await rag.InMemoryRetriever.from_docs(docs, FakeEmbedder()), PARAMS
    )
    r = await rag.retrieve("please scan this qr code", search)
    assert [m.slug for m in r.scam] == ["qr", "task"]
    assert r.genuine is not None and r.genuine.slug == "otp"
    assert r.scam[0].similarity > r.scam[1].similarity


# ----------------------------------------------------------------------------- scoring


def test_supporting_signal_cannot_make_a_scam_on_its_own() -> None:
    # Rules alone: 65 (suspicious). A heavily weighted pattern match would lift it past 70.
    rules = rule_result("remote_access_app")
    base = score(rules, WEIGHTS, Thresholds())
    assert base.verdict is Verdict.SUSPICIOUS
    boosted = score(
        rules,
        {**WEIGHTS, "pattern_similarity": 0.5},
        Thresholds(),
        extra=[SignalOutcome("pattern_similarity", 100, "close", can_decide_scam=False)],
    )
    assert (boosted.risk_score, boosted.verdict, boosted.scam_capped) == (
        69,
        Verdict.SUSPICIOUS,
        True,
    )
    detail = next(s.detail for s in boosted.signal_breakdown if s.source == "pattern_similarity")
    assert "cannot make a result a scam alone" in detail


def test_supporting_signal_does_not_cap_an_existing_scam() -> None:
    result = score(
        rule_result("pin_to_receive", "credential_request"),
        WEIGHTS,
        Thresholds(),
        extra=[SignalOutcome("pattern_similarity", 100, "close", can_decide_scam=False)],
    )
    assert result.verdict is Verdict.SCAM and not result.scam_capped


# ----------------------------------------------------------------------------- pipeline

SETTINGS = get_settings().model_copy(update={"SAFE_BROWSING_API_KEY": ""})


async def _analyze(text: str, patterns: rag.PatternSearch | None) -> Checks:
    with respx.mock as router:
        router.route().mock(side_effect=httpx.ConnectError("offline"))
        async with httpx.AsyncClient() as client:
            checks = Checks(client, LookupCache(None, timedelta(hours=1)), None, patterns)
            return (await analyze(text, SETTINGS, checks=checks)).result


async def test_scam_lists_similar_patterns() -> None:
    result = await _analyze(SCAM_EXAMPLES[16][1], fake_pattern_search())  # prepaid task job
    assert result.verdict is Verdict.SCAM
    assert result.similar_patterns
    assert result.similar_patterns[0].category == ScamType.TASK_JOB
    by_source = {s.source: s for s in result.signal_breakdown}
    assert "closest scam pattern task-job-" in by_source["pattern_similarity"].detail


async def test_safe_result_lists_no_similar_patterns() -> None:
    result = await _analyze(GENUINE_EXAMPLES[3][1], fake_pattern_search())  # UPI debit alert
    assert result.verdict is Verdict.SAFE and result.similar_patterns == []


async def test_missing_embedder_leaves_the_rest_working() -> None:
    result = await _analyze(SCAM_EXAMPLES[0][1], None)
    by_source = {s.source: s for s in result.signal_breakdown}
    assert by_source["pattern_similarity"].detail == "unavailable: embedding model not configured"
    assert result.verdict is Verdict.SCAM


async def test_bare_url_skips_pattern_similarity() -> None:
    with respx.mock as router:
        router.route().mock(side_effect=httpx.ConnectError("offline"))
        async with httpx.AsyncClient() as client:
            checks = Checks(
                client, LookupCache(None, timedelta(hours=1)), None, fake_pattern_search()
            )
            out = await analyze(
                "https://example.com/a", SETTINGS, checks=checks, message_text=False
            )
    assert "pattern_similarity" not in {s.source for s in out.result.signal_breakdown}
