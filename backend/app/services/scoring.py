"""Combine per-layer signals into the final risk score and verdict.

Each layer (rules, url_intel, upi_check, reputation; classifier, pattern_similarity, llm
later) reports a SignalOutcome with a 0-100 score. The final score is the weighted mean of
the available signals, with weights from config renormalized over the signals that count.

A signal is listed in the breakdown but left out of the mean when it
- failed (score=None): marked "unavailable", or
- ran but found no evidence either way (informative=False), e.g. a domain that is not on
  any blocklist. "Not reported yet" is not proof of safety, so it must not dilute the
  evidence from other layers.

Some evidence is decisive on its own (a Google Safe Browsing match, a verified scam UPI ID):
averaging it with a quiet rules layer would call a known phishing link safe. Such a signal
sets `floor`, the minimum final score its evidence justifies.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from app.core.enums import ScamType, Severity, Verdict
from app.schemas.analysis import RedFlag, Signal
from app.services.rules import RuleResult


@dataclass(frozen=True)
class SignalOutcome:
    source: str
    score: float | None  # 0-100, or None if the layer failed / timed out
    detail: str = ""
    informative: bool = True  # False: ran fine, found nothing to go on either way
    floor: int | None = None  # minimum final score this evidence justifies
    red_flags: tuple[RedFlag, ...] = ()
    scam_type: ScamType | None = None  # the layer's guess, used if the rules have none


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
    floor_source: str | None = None  # signal whose evidence floor set the score


def severity_for(weight: float) -> Severity:
    """Red-flag severity for a 0-1 evidence weight."""
    if weight >= 0.7:
        return Severity.HIGH
    return Severity.MEDIUM if weight >= 0.4 else Severity.LOW


def rules_signal(result: RuleResult, informative_if_empty: bool = True) -> SignalOutcome:
    """`informative_if_empty=False` for bare URL/UPI/QR inputs: the phrase rules have
    nothing to read there, so "no rules matched" says nothing about safety."""
    if not result.hits:
        if informative_if_empty:
            return SignalOutcome("rules", 0, "no rules matched")
        return SignalOutcome("rules", 0, "no rules matched (no message text)", informative=False)
    ids = ", ".join(h.rule.id for h in result.hits)
    return SignalOutcome("rules", result.score, f"{len(result.hits)} rule(s) matched: {ids}")


def combine_signals(
    outcomes: Sequence[SignalOutcome], weights: Mapping[str, float]
) -> tuple[int, list[Signal]]:
    """Weighted mean of the informative signals; weights renormalize over what's present.

    Signals with no configured weight are ignored. Failed and uninformative signals are
    listed with weight 0 so the caller can see what was checked and what was missing.
    """
    weighted = [o for o in outcomes if weights.get(o.source, 0) > 0]
    available = [o for o in weighted if o.score is not None and o.informative]
    total_weight = sum(weights[o.source] for o in available)

    breakdown: list[Signal] = []
    score = 0.0
    for o in available:
        w = weights[o.source] / total_weight
        score += w * o.score  # type: ignore[operator]  # filtered above
        breakdown.append(
            Signal(source=o.source, score=o.score, weight=round(w, 4), detail=o.detail)
        )
    for o in weighted:
        if o.score is not None and not o.informative:
            breakdown.append(Signal(source=o.source, score=o.score, weight=0, detail=o.detail))
    for o in weighted:
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
    *,
    rules_informative_if_empty: bool = True,
) -> ScoreResult:
    """Final score from the rules signal plus any other layers' outcomes."""
    outcomes = [rules_signal(rule_result, rules_informative_if_empty), *extra]
    risk_score, breakdown = combine_signals(outcomes, weights)

    # Decisive evidence from one layer (see module docstring) lifts the score.
    floor_source = None
    floors = [o for o in extra if o.floor is not None and o.score is not None]
    top = max(floors, key=lambda o: o.floor or 0, default=None)
    if top is not None and top.floor is not None and risk_score < top.floor:
        risk_score, floor_source = top.floor, top.source
        breakdown = [
            s.model_copy(update={"detail": f"{s.detail}; sets the minimum score to {top.floor}"})
            if s.source == top.source
            else s
            for s in breakdown
        ]
    verdict = verdict_for(risk_score, thresholds)

    # One very strong rule (e.g. "enter PIN to receive money") must never end up "safe",
    # even if other signals average it down. Lift the score too so it matches the verdict.
    floor_applied = False
    if verdict is Verdict.SAFE and rule_result.max_weight >= thresholds.strong_rule_weight:
        risk_score, verdict, floor_applied = thresholds.suspicious_min, Verdict.SUSPICIOUS, True

    return ScoreResult(risk_score, verdict, breakdown, floor_applied, floor_source)
