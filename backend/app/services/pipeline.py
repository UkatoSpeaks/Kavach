"""The text analysis pipeline: extract -> rules -> scoring -> explanation. No I/O."""

import time
from dataclasses import dataclass

from app.core.config import Settings
from app.core.enums import ScamType, Severity, Verdict
from app.schemas.analysis import AnalysisResult, RedFlag
from app.schemas.entities import ExtractedEntities
from app.services import explain, rules, scoring
from app.services.extractors import extract_entities


@dataclass(frozen=True)
class PipelineOutput:
    result: AnalysisResult
    entities: ExtractedEntities
    latency_ms: dict[str, float]


def thresholds_from(settings: Settings) -> scoring.Thresholds:
    return scoring.Thresholds(
        suspicious_min=settings.VERDICT_SUSPICIOUS_MIN,
        scam_min=settings.VERDICT_SCAM_MIN,
        strong_rule_weight=settings.STRONG_RULE_WEIGHT,
    )


def _severity(weight: float) -> Severity:
    if weight >= 0.7:
        return Severity.HIGH
    return Severity.MEDIUM if weight >= 0.4 else Severity.LOW


def red_flags(hits: list[rules.RuleHit]) -> list[RedFlag]:
    return [
        RedFlag(
            code=h.rule.id,
            message=h.rule.description_en,
            message_hi=h.rule.description_hi,
            severity=_severity(h.rule.weight),
            evidence=h.evidence,
        )
        for h in hits
    ]


def analyze_text(text: str, settings: Settings, language_hint: str | None = None) -> PipelineOutput:
    latency: dict[str, float] = {}

    def lap(name: str, start: float) -> float:
        now = time.perf_counter()
        latency[name] = round((now - start) * 1000, 2)
        return now

    t = time.perf_counter()
    entities = extract_entities(text)
    t = lap("extract", t)
    rule_result = rules.evaluate(entities)
    t = lap("rules", t)
    scored = scoring.score(rule_result, settings.SIGNAL_WEIGHTS, thresholds_from(settings))
    t = lap("scoring", t)

    scam_type: ScamType | None = None if scored.verdict is Verdict.SAFE else rule_result.scam_type
    if scored.verdict is not Verdict.SAFE and scam_type is None:
        scam_type = ScamType.GENERIC
    explanation_en, explanation_hi = explain.explain(
        scored.verdict, scored.risk_score, scam_type, rule_result.hits
    )
    advice = explain.advice_for(
        scored.verdict, scam_type, rule_result.hits, hindi=language_hint == "hi"
    )
    lap("explain", t)

    result = AnalysisResult(
        risk_score=scored.risk_score,
        verdict=scored.verdict,
        scam_type=scam_type,
        red_flags=red_flags(rule_result.hits),
        signal_breakdown=scored.signal_breakdown,
        explanation_en=explanation_en,
        explanation_hi=explanation_hi,
        advice=advice,
    )
    return PipelineOutput(result=result, entities=entities, latency_ms=latency)
