"""The analysis pipeline: extract -> rules + real-world checks -> scoring -> explanation.

`analyze_text` is the pure, synchronous core (extractors, rules, UPI checks, scoring).
`analyze` adds the network signals (url_intel, reputation), run concurrently with
asyncio.gather. Every network signal has a timeout and fails soft: it shows up as
"unavailable" in the breakdown and the rest of the analysis still returns.
"""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx

from app.core.config import Settings
from app.core.enums import EntityType, ScamType, Verdict
from app.db.session import SessionFactory
from app.schemas.analysis import AnalysisResult, RedFlag
from app.schemas.entities import ExtractedEntities
from app.services import explain, reputation, rules, scoring, upi, url_intel
from app.services.cache import LookupCache
from app.services.extractors import extract_entities
from app.services.scoring import SignalOutcome, severity_for

logger = logging.getLogger(__name__)


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
    session_factory: SessionFactory | None  # None: reputation is reported unavailable


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


class _Timer:
    def __init__(self) -> None:
        self.latency: dict[str, float] = {}

    def lap(self, name: str, start: float) -> float:
        now = time.perf_counter()
        self.latency[name] = round((now - start) * 1000, 2)
        return now


def _finish(
    entities: ExtractedEntities,
    rule_result: rules.RuleResult,
    outcomes: list[SignalOutcome],
    settings: Settings,
    language_hint: str | None,
    message_text: bool,
    timer: _Timer,
) -> PipelineOutput:
    """Score and explain. Pure."""
    t = time.perf_counter()
    scored = scoring.score(
        rule_result,
        settings.SIGNAL_WEIGHTS,
        thresholds_from(settings),
        outcomes,
        rules_informative_if_empty=message_text,
    )
    t = timer.lap("scoring", t)

    scam_type = _scam_type(scored.verdict, rule_result.scam_type, outcomes)
    flags = red_flags(rule_result.hits) + [f for o in outcomes for f in o.red_flags]
    explanation_en, explanation_hi = explain.explain(
        scored.verdict, scored.risk_score, scam_type, flags
    )
    advice = explain.advice_for(
        scored.verdict, scam_type, rule_result.hits, hindi=language_hint == "hi"
    )
    timer.lap("explain", t)

    result = AnalysisResult(
        risk_score=scored.risk_score,
        verdict=scored.verdict,
        scam_type=scam_type,
        red_flags=flags,
        signal_breakdown=scored.signal_breakdown,
        explanation_en=explanation_en,
        explanation_hi=explanation_hi,
        advice=advice,
    )
    return PipelineOutput(result=result, entities=entities, latency_ms=timer.latency)


def _pure_layers(text: str, timer: _Timer) -> tuple[ExtractedEntities, rules.RuleResult]:
    t = time.perf_counter()
    entities = extract_entities(text)
    t = timer.lap("extract", t)
    rule_result = rules.evaluate(entities)
    timer.lap("rules", t)
    return entities, rule_result


def analyze_text(text: str, settings: Settings, language_hint: str | None = None) -> PipelineOutput:
    """Pure, offline analysis: extractors, rules and UPI checks only."""
    timer = _Timer()
    entities, rule_result = _pure_layers(text, timer)
    outcomes = [o for o in [upi.upi_signal(entities.upi_ids, entities.upi_uris)] if o]
    return _finish(entities, rule_result, outcomes, settings, language_hint, True, timer)


async def _timed(
    name: str,
    make: Callable[[], Awaitable[SignalOutcome | None]],
    timer: _Timer,
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
    if checks.session_factory is None:
        return SignalOutcome("reputation", None, "database not configured")
    async with checks.session_factory() as session:
        found = await reputation.find_reported(session, keys)
    return reputation.reputation_signal(keys, found)


async def analyze(
    text: str,
    settings: Settings,
    *,
    checks: Checks | None,
    language_hint: str | None = None,
    message_text: bool = True,
) -> PipelineOutput:
    """Full analysis. `message_text=False` for bare URL/UPI/QR inputs, where the phrase
    rules have nothing to read and "no rules matched" is no evidence of safety."""
    timer = _Timer()
    entities, rule_result = _pure_layers(text, timer)
    timeout = signal_timeout(settings)

    async def upi_check() -> SignalOutcome | None:
        return upi.upi_signal(entities.upi_ids, entities.upi_uris)

    jobs: list[Awaitable[SignalOutcome | None]] = []
    if entities.upi_ids or entities.upi_uris:
        jobs.append(_timed("upi_check", upi_check, timer, timeout))
    if checks is not None:
        if entities.urls:
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

    outcomes = [o for o in await asyncio.gather(*jobs) if o is not None]
    return _finish(entities, rule_result, outcomes, settings, language_hint, message_text, timer)
