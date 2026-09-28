"""The analysis steps: extract -> rules + real-world checks -> scoring -> explanation.

The API runs these steps through the LangGraph agent (app/services/agent), which adds the
LLM reasoning step between the checks and scoring. The steps themselves live here:

- `extract_step`: extractors + rules (pure).
- `run_checks`: the network signals (url_intel, reputation, pattern_similarity) plus the
  UPI check, run concurrently with asyncio.gather. Every network signal has a timeout and
  fails soft: it shows up as "unavailable" in the breakdown and the rest still returns.
  Then the trained classifier (`classifier_step`: in-process, a few ms, message text only).
- `finish`: scoring + explanations (pure). Uses the LLM's narrative when there is one.

`analyze_text` (pure, offline) and `analyze` (no LLM) compose them directly, for tests and
scripts.
"""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import Literal

import httpx

from app.core.config import Settings
from app.core.enums import EntityType, ScamType, Verdict
from app.schemas.analysis import AnalysisResult, RedFlag
from app.schemas.entities import ExtractedEntities
from app.services import classifier, explain, rag, reputation, rules, scoring, upi, url_intel
from app.services.cache import LookupCache
from app.services.extractors import extract_entities
from app.services.scoring import SignalOutcome, severity_for

logger = logging.getLogger(__name__)

LLM_SOURCE = "llm"
MAX_LLM_ADVICE = 5


@dataclass(frozen=True)
class Narrative:
    """The LLM's explanation, used instead of the templates when the LLM counted."""

    explanation_en: str
    explanation_hi: str
    advice: list[str]
    confidence: Literal["low", "medium", "high"]


@dataclass(frozen=True)
class PipelineOutput:
    result: AnalysisResult
    entities: ExtractedEntities
    latency_ms: dict[str, float]


@dataclass(frozen=True)
class Checks:
    """What the network signals need. Without it, only the pure layers run."""

    client: httpx.AsyncClient
    cache: LookupCache
    find_reported: reputation.FindReported | None  # None: reputation is reported unavailable
    patterns: rag.PatternSearch | None = None  # None: pattern_similarity is reported unavailable
    # False: url_intel makes no network calls and is reported unavailable (offline evaluation
    # runs, see ml/evaluate.py). Reputation is switched off with find_reported=None.
    network: bool = True


def thresholds_from(settings: Settings) -> scoring.Thresholds:
    return scoring.Thresholds(
        suspicious_min=settings.VERDICT_SUSPICIOUS_MIN,
        scam_min=settings.VERDICT_SCAM_MIN,
        strong_rule_weight=settings.STRONG_RULE_WEIGHT,
    )


def signal_timeout(settings: Settings) -> float:
    """Upper bound for one network signal: link expansion, then RDAP + Safe Browsing in
    parallel, plus cache reads/writes."""
    return settings.HTTP_TIMEOUT_S * 3


def red_flags(hits: list[rules.RuleHit]) -> list[RedFlag]:
    return [
        RedFlag(
            code=h.rule.id,
            message=h.rule.description_en,
            message_hi=h.rule.description_hi,
            severity=severity_for(h.rule.weight),
            evidence=h.evidence,
        )
        for h in hits
    ]


def _scam_type(
    verdict: Verdict, rule_type: ScamType | None, outcomes: list[SignalOutcome]
) -> ScamType | None:
    if verdict is Verdict.SAFE:
        return None
    if rule_type not in (None, ScamType.GENERIC):
        return rule_type
    guesses = [o for o in outcomes if o.scam_type and o.score]
    if guesses:
        return max(guesses, key=lambda o: o.score or 0).scam_type
    return rule_type or ScamType.GENERIC


class Timer:
    def __init__(self) -> None:
        self.latency: dict[str, float] = {}

    def lap(self, name: str, start: float) -> float:
        now = time.perf_counter()
        self.latency[name] = round((now - start) * 1000, 2)
        return now


def _with_report_line(advice: list[str], hindi: bool) -> list[str]:
    """LLM advice for a warning must still say where to report."""
    if any("1930" in a for a in advice):
        return advice
    line = explain.REPORT_HI if hindi else explain.REPORT_EN
    return [*advice[: MAX_LLM_ADVICE - 1], line]


def finish(
    entities: ExtractedEntities,
    rule_result: rules.RuleResult,
    outcomes: list[SignalOutcome],
    settings: Settings,
    language_hint: str | None,
    message_text: bool,
    timer: Timer,
    narrative: Narrative | None = None,
) -> PipelineOutput:
    """Score and explain. Pure. `narrative` is used unless scoring overruled the LLM."""
    t = time.perf_counter()
    scored = scoring.score(
        rule_result,
        settings.SIGNAL_WEIGHTS,
        thresholds_from(settings),
        outcomes,
        rules_informative_if_empty=message_text,
    )
    t = timer.lap("scoring", t)

    counted = [o for o in outcomes if o.source not in scored.ignored]
    scam_type = _scam_type(scored.verdict, rule_result.scam_type, counted)
    flags = red_flags(rule_result.hits) + [f for o in outcomes for f in o.red_flags]
    hindi = language_hint == "hi"
    llm_overruled = LLM_SOURCE in scored.ignored
    confidence: Literal["low", "medium", "high"] | None = None
    if narrative is not None and not llm_overruled:
        explanation_en, explanation_hi = narrative.explanation_en, narrative.explanation_hi
        advice = narrative.advice
        if scored.verdict is not Verdict.SAFE:
            advice = _with_report_line(advice, hindi)
        confidence = narrative.confidence
    else:
        explanation_en, explanation_hi = explain.explain(
            scored.verdict, scored.risk_score, scam_type, flags
        )
        advice = explain.advice_for(scored.verdict, scam_type, rule_result.hits, hindi=hindi)
        if llm_overruled:
            confidence = "low"
    timer.lap("explain", t)

    # Knowledge-base matches explain a warning; on a safe verdict they would only alarm.
    similar = (
        [p for o in outcomes for p in o.similar_patterns]
        if scored.verdict is not Verdict.SAFE
        else []
    )
    result = AnalysisResult(
        risk_score=scored.risk_score,
        verdict=scored.verdict,
        scam_type=scam_type,
        red_flags=flags,
        signal_breakdown=scored.signal_breakdown,
        explanation_en=explanation_en,
        explanation_hi=explanation_hi,
        advice=advice,
        similar_patterns=similar,
        confidence=confidence,
        entities=reputation.reportable(entities),
    )
    return PipelineOutput(result=result, entities=entities, latency_ms=timer.latency)


def extract_step(text: str, timer: Timer) -> tuple[ExtractedEntities, rules.RuleResult]:
    t = time.perf_counter()
    entities = extract_entities(text)
    t = timer.lap("extract", t)
    rule_result = rules.evaluate(entities)
    timer.lap("rules", t)
    return entities, rule_result


def classifier_step(
    text: str,
    entities: ExtractedEntities,
    settings: Settings,
    message_text: bool,
    timer: Timer,
) -> list[SignalOutcome]:
    """The trained classifier's signal (pure, in-process, a few ms). Only for message text:
    a bare URL/UPI ID/QR payload is nothing like what it was trained on. On a fraud-awareness
    notice (rules.advisory_evidence) its weight is scaled down by
    CLASSIFIER_ADVISORY_WEIGHT_FACTOR. Fails soft."""
    if not message_text or not settings.CLASSIFIER_ENABLED:
        return []
    start = time.perf_counter()
    try:
        model = classifier.get_classifier(settings.CLASSIFIER_MODEL_PATH)
        threshold = settings.CLASSIFIER_MIN_SCAM_PROBABILITY
        outcome = classifier.classifier_signal(text, model, threshold)
        factor = settings.CLASSIFIER_ADVISORY_WEIGHT_FACTOR
        if outcome.score is not None and factor != 1 and (cue := rules.advisory_evidence(entities)):
            outcome = replace(
                outcome,
                weight_factor=factor,
                detail=f"{outcome.detail}; weight x{factor:g}: fraud-awareness wording "
                f"({cue!r}) and no link, UPI ID, phone number or payment request",
            )
        return [outcome]
    except Exception as exc:  # fail soft: the analysis goes on without this signal
        logger.warning("signal classifier failed: %s: %s", type(exc).__name__, exc)
        return [SignalOutcome(classifier.SOURCE, None, type(exc).__name__)]
    finally:
        timer.lap(classifier.SOURCE, start)


def analyze_text(text: str, settings: Settings, language_hint: str | None = None) -> PipelineOutput:
    """Pure, offline analysis: extractors, rules, the classifier and UPI checks only."""
    timer = Timer()
    entities, rule_result = extract_step(text, timer)
    outcomes = [o for o in [upi.upi_signal(entities.upi_ids, entities.upi_uris)] if o]
    outcomes += classifier_step(text, entities, settings, True, timer)
    return finish(entities, rule_result, outcomes, settings, language_hint, True, timer)


async def _timed(
    name: str,
    make: Callable[[], Awaitable[SignalOutcome | None]],
    timer: Timer,
    limit_s: float,
) -> SignalOutcome | None:
    start = time.perf_counter()
    try:
        async with asyncio.timeout(limit_s):
            return await make()
    except Exception as exc:  # fail soft: the analysis goes on without this signal
        reason = "timed out" if isinstance(exc, TimeoutError) else type(exc).__name__
        logger.warning("signal %s failed: %s: %s", name, type(exc).__name__, exc)
        return SignalOutcome(name, None, reason)
    finally:
        timer.lap(name, start)


async def _reputation(keys: list[tuple[EntityType, str]], checks: Checks) -> SignalOutcome | None:
    if checks.find_reported is None:
        return SignalOutcome("reputation", None, "database not configured")
    found = await checks.find_reported(keys)
    return reputation.reputation_signal(keys, found)


async def _offline(source: str) -> SignalOutcome:
    return SignalOutcome(source, None, "offline (network checks disabled)")


async def _patterns(text: str, checks: Checks) -> SignalOutcome:
    if checks.patterns is None:
        return SignalOutcome(rag.SOURCE, None, "embedding model not configured")
    return await rag.pattern_similarity(text, checks.patterns)


async def run_checks(
    text: str,
    entities: ExtractedEntities,
    settings: Settings,
    checks: Checks | None,
    message_text: bool,
    timer: Timer,
) -> list[SignalOutcome]:
    """Every signal except rules and llm, concurrently. Each fails soft."""
    timeout = signal_timeout(settings)

    async def upi_check() -> SignalOutcome | None:
        return upi.upi_signal(entities.upi_ids, entities.upi_uris)

    jobs: list[Awaitable[SignalOutcome | None]] = []
    if entities.upi_ids or entities.upi_uris:
        jobs.append(_timed("upi_check", upi_check, timer, timeout))
    if checks is not None:
        if entities.urls and not checks.network:
            jobs.append(_timed("url_intel", lambda: _offline("url_intel"), timer, timeout))
        elif entities.urls:
            jobs.append(_timed(
                "url_intel",
                lambda: url_intel.url_intel(
                    entities.urls, client=checks.client, cache=checks.cache, settings=settings
                ),
                timer, timeout,
            ))  # fmt: skip
        keys = reputation.entity_keys(entities)
        if keys:
            jobs.append(_timed("reputation", lambda: _reputation(keys, checks), timer, timeout))
        # Bare URLs/UPI IDs/QR payloads have no wording to compare with the knowledge base.
        if message_text:
            jobs.append(_timed(rag.SOURCE, lambda: _patterns(text, checks), timer, timeout))

    outcomes = [o for o in await asyncio.gather(*jobs) if o is not None]
    return outcomes + classifier_step(text, entities, settings, message_text, timer)


async def analyze(
    text: str,
    settings: Settings,
    *,
    checks: Checks | None,
    language_hint: str | None = None,
    message_text: bool = True,
) -> PipelineOutput:
    """Full analysis without the LLM. `message_text=False` for bare URL/UPI/QR inputs,
    where the phrase rules have nothing to read and "no rules matched" is no evidence of
    safety. The API uses the agent graph instead (app/services/agent/graph.py)."""
    timer = Timer()
    entities, rule_result = extract_step(text, timer)
    outcomes = await run_checks(text, entities, settings, checks, message_text, timer)
    return finish(entities, rule_result, outcomes, settings, language_hint, message_text, timer)
