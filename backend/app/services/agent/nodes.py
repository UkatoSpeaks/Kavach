"""Graph nodes. Thin wrappers around the pipeline steps; each records its own latency."""

import asyncio
import logging
import time
from typing import Any

from langgraph.runtime import Runtime

from app.core.config import Settings
from app.core.enums import ScamType
from app.services import pipeline
from app.services.agent.llm import ReasonResult, build_evidence
from app.services.agent.state import AnalysisContext, AnalysisState
from app.services.pipeline import LLM_SOURCE, Narrative, Timer
from app.services.scoring import SignalOutcome, rules_signal

logger = logging.getLogger(__name__)

AI_MANIPULATION_RULE = "ai_manipulation_attempt"
_V1_TYPES = {t.value for t in ScamType if t is not ScamType.GENERIC}


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)


async def extract(state: AnalysisState, runtime: Runtime[AnalysisContext]) -> dict[str, Any]:
    start, timer = time.perf_counter(), Timer()
    entities, rule_result = pipeline.extract_step(state["text"], timer)
    return {
        "entities": entities,
        "rule_result": rule_result,
        "latency_ms": {**timer.latency, "node.extract": _ms(start)},
    }


async def run_checks(state: AnalysisState, runtime: Runtime[AnalysisContext]) -> dict[str, Any]:
    start, timer, ctx = time.perf_counter(), Timer(), runtime.context
    outcomes = await pipeline.run_checks(
        state["text"], state["entities"], ctx.settings, ctx.checks, state["message_text"], timer
    )
    return {"outcomes": outcomes, "latency_ms": {**timer.latency, "node.run_checks": _ms(start)}}


def llm_signal(
    result: ReasonResult, settings: Settings, manipulated: bool
) -> tuple[SignalOutcome, Narrative | None]:
    """The "llm" signal and the narrative to show. Pure.

    When the message tries to manipulate an AI checker, the LLM's risk is left out of the
    score, and its text is only used if it saw through the attempt (risk at least
    "suspicious"). A low risk there means the injection may have worked.
    """
    a = result.assessment
    if a is None:
        return SignalOutcome(LLM_SOURCE, None, result.detail), None
    detail = (
        f"{result.model}{' (cached)' if result.cached else ''}: risk {a.llm_risk}, "
        f"{a.confidence} confidence, cites {', '.join(a.cited_flags) or 'no flags'}"
    )
    if result.notes:
        detail += f" (after {'; '.join(result.notes)})"
    narrative = Narrative(a.explanation_en, a.explanation_hi, a.advice, a.confidence)
    if manipulated:
        detail += "; ignored: the message tries to manipulate an AI checker"
        fooled = a.llm_risk < settings.VERDICT_SUSPICIOUS_MIN
        outcome = SignalOutcome(
            LLM_SOURCE, a.llm_risk, detail, informative=False, can_decide_scam=False
        )
        return outcome, None if fooled else narrative
    outcome = SignalOutcome(
        LLM_SOURCE,
        a.llm_risk,
        detail,
        scam_type=ScamType(a.scam_type) if a.scam_type in _V1_TYPES else None,
        can_decide_scam=False,
        max_disagreement=settings.LLM_MAX_DISAGREEMENT,
    )
    return outcome, narrative


async def reason(state: AnalysisState, runtime: Runtime[AnalysisContext]) -> dict[str, Any]:
    start, ctx = time.perf_counter(), runtime.context
    rule_result, outcomes = state["rule_result"], state["outcomes"]

    def done(outcome: SignalOutcome, narrative: Narrative | None = None) -> dict[str, Any]:
        ms = _ms(start)
        return {
            "llm_outcome": outcome,
            "narrative": narrative,
            "latency_ms": {"llm": ms, "node.reason": ms},
        }

    if ctx.reasoner is None:
        return done(SignalOutcome(LLM_SOURCE, None, "not configured (no GROQ_API_KEY)"))

    flags = pipeline.red_flags(rule_result.hits) + [f for o in outcomes for f in o.red_flags]
    evidence = build_evidence(
        state["text"],
        state["entities"],
        flags,
        [rules_signal(rule_result, state["message_text"]), *outcomes],
        [p for o in outcomes for p in o.similar_patterns],
        advice_language="hi" if state.get("language_hint") == "hi" else "en",
    )
    try:
        # The reasoner has its own per-call timeouts; this only guards against bugs.
        async with asyncio.timeout(ctx.settings.LLM_TIMEOUT_S * 2 + 2):
            result = await ctx.reasoner.reason(evidence)
    except Exception as exc:  # fail soft: templates instead
        logger.warning("llm step failed: %s: %s", type(exc).__name__, exc)
        return done(SignalOutcome(LLM_SOURCE, None, f"{type(exc).__name__}"))
    manipulated = any(h.rule.id == AI_MANIPULATION_RULE for h in rule_result.hits)
    return done(*llm_signal(result, ctx.settings, manipulated))


async def finalize(state: AnalysisState, runtime: Runtime[AnalysisContext]) -> dict[str, Any]:
    start, timer, ctx = time.perf_counter(), Timer(), runtime.context
    llm = state.get("llm_outcome") or SignalOutcome(LLM_SOURCE, None, "skipped (explain=false)")
    out = pipeline.finish(
        state["entities"],
        state["rule_result"],
        [*state["outcomes"], llm],
        ctx.settings,
        state.get("language_hint"),
        state["message_text"],
        timer,
        narrative=state.get("narrative"),
    )
    return {"output": out, "latency_ms": {**timer.latency, "node.finalize": _ms(start)}}
