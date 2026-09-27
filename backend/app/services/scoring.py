"""Combine per-layer signals into the final risk score and verdict.

Each layer (rules now; classifier, url_intel, reputation, pattern_similarity, llm later)
reports a SignalOutcome with a 0-100 score. The final score is the weighted mean of the
available signals, with weights from config renormalized over the signals that are present.
A layer that failed (score=None) is skipped but still listed in the breakdown, so the
response shows which signal was missing.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from app.core.enums import Verdict
from app.schemas.analysis import Signal
from app.services.rules import RuleResult


@dataclass(frozen=True)
class SignalOutcome:
    source: str
    score: float | None  # 0-100, or None if the layer failed / timed out
    detail: str = ""


@dataclass(frozen=True)
class Thresholds:
    suspicious_min: int = 35
    scam_min: int = 70
    strong_rule_weight: float = 0.8


@dataclass(frozen=True)
class ScoreResult:
    risk_score: int
    verdict: Verdict
    signal_breakdown: list[Signal]
    strong_rule_floor_applied: bool = False


def rules_signal(result: RuleResult) -> SignalOutcome:
    if not result.hits:
        return SignalOutcome("rules", 0, "no rules matched")
    ids = ", ".join(h.rule.id for h in result.hits)
    return SignalOutcome("rules", result.score, f"{len(result.hits)} rule(s) matched: {ids}")


def combine_signals(
    outcomes: Sequence[SignalOutcome], weights: Mapping[str, float]
) -> tuple[int, list[Signal]]:
    """Weighted mean of the available signals; weights renormalize over what's present.

    Signals with no configured weight are ignored. Failed signals are listed with
    weight 0 so the caller can see what was missing.
    """
    available = [o for o in outcomes if o.score is not None and weights.get(o.source, 0) > 0]
    total_weight = sum(weights[o.source] for o in available)

    breakdown: list[Signal] = []
    score = 0.0
    for o in available:
        w = weights[o.source] / total_weight
        score += w * o.score  # type: ignore[operator]  # filtered above
        breakdown.append(
            Signal(source=o.source, score=o.score, weight=round(w, 4), detail=o.detail)
        )
    for o in outcomes:
        if o.score is None:
            detail = f"unavailable: {o.detail}" if o.detail else "unavailable"
            breakdown.append(Signal(source=o.source, score=0, weight=0, detail=detail))
    return round(score), breakdown


def verdict_for(score: int, t: Thresholds) -> Verdict:
    if score >= t.scam_min:
        return Verdict.SCAM
    if score >= t.suspicious_min:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


def score(
    rule_result: RuleResult,
    weights: Mapping[str, float],
    thresholds: Thresholds,
    extra: Sequence[SignalOutcome] = (),
) -> ScoreResult:
    """Final score from the rules signal plus any other layers' outcomes."""
    risk_score, breakdown = combine_signals([rules_signal(rule_result), *extra], weights)
    verdict = verdict_for(risk_score, thresholds)

    # One very strong rule (e.g. "enter PIN to receive money") must never end up "safe",
    # even if other signals average it down. Lift the score too so it matches the verdict.
    floor_applied = False
    if verdict is Verdict.SAFE and rule_result.max_weight >= thresholds.strong_rule_weight:
        risk_score, verdict, floor_applied = thresholds.suspicious_min, Verdict.SUSPICIOUS, True

    return ScoreResult(risk_score, verdict, breakdown, floor_applied)
