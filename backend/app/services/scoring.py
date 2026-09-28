"""Combine per-layer signals into the final risk score and verdict.

Each layer (rules, url_intel, upi_check, reputation, pattern_similarity, llm; classifier
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

The opposite also exists: weak, supporting evidence (similarity to known scam patterns) sets
`can_decide_scam=False`. It may nudge the score, but if the result is only a scam because of
such signals, the score is capped just below the scam threshold.

The LLM ("llm" signal) gets the tightest limits, because it is the one layer the message
itself can try to steer (prompt injection) and the one that can hallucinate:
- Low weight in config (SIGNAL_WEIGHTS["llm"], 0.15 by default).
- It never sets a floor, and floors from other signals are applied after the weighted mean,
  so it can never pull the score below a minimum another signal set.
- can_decide_scam=False: it can never make a result "scam" on its own (same cap as
  pattern_similarity: the score stops at scam_min - 1).
- max_disagreement=50: if its risk differs from the score of all the other signals by more
  than 50 points, it is left out of the score entirely, so the verdict stays the one the
  rules and checks produced. The caller reports confidence "low" and uses the template
  explanation, since the LLM's text would contradict the verdict.
- When the message tries to manipulate an AI checker (rule ai_manipulation_attempt), the
  LLM's risk is left out of the score altogether, and its text is only used if it saw
  through the attempt (see agent/nodes.llm_signal).
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

from app.core.enums import ScamType, Severity, Verdict
from app.schemas.analysis import RedFlag, Signal, SimilarPattern
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
    similar_patterns: tuple[SimilarPattern, ...] = ()
    can_decide_scam: bool = True  # False: must not make a result "scam" on its own
    # Left out of the score if it differs from the other signals' score by more than this.
    max_disagreement: float | None = None


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
    scam_capped: bool = False  # only supporting signals made it a scam, so it was capped
    ignored: tuple[str, ...] = ()  # signals left out for disagreeing with all the others


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
    detail = f"{len(result.hits)} rule(s) matched: {ids}"
    if result.supporting_only:
        detail += "; only weak signs, common in ads too: score capped"
    return SignalOutcome("rules", result.score, detail)


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
    outcomes, ignored = _drop_strong_disagreement(outcomes, weights)
    extra = outcomes[1:]
    risk_score, breakdown = combine_signals(outcomes, weights)
    risk_score, top = _apply_floor(risk_score, extra)
    floor_source = None
    if top is not None:
        floor_source = top.source
        breakdown = _note(breakdown, top.source, f"sets the minimum score to {top.floor}")
    verdict = verdict_for(risk_score, thresholds)

    # Supporting-only signals (can_decide_scam=False) must not tip a result into "scam".
    scam_capped = False
    if verdict is Verdict.SCAM:
        deciding = [o for o in outcomes if o.can_decide_scam]
        supporting = {o.source for o in outcomes if not o.can_decide_scam}
        base, _ = combine_signals(deciding, weights)
        base, _ = _apply_floor(base, [o for o in extra if o.can_decide_scam])
        if supporting and verdict_for(base, thresholds) is not Verdict.SCAM:
            risk_score, scam_capped = thresholds.scam_min - 1, True
            verdict = verdict_for(risk_score, thresholds)
            for source in supporting:
                breakdown = _note(breakdown, source, "capped: cannot make a result a scam alone")

    # One very strong rule (e.g. "enter PIN to receive money") must never end up "safe",
    # even if other signals average it down. Lift the score too so it matches the verdict.
    floor_applied = False
    if verdict is Verdict.SAFE and rule_result.max_weight >= thresholds.strong_rule_weight:
        risk_score, verdict, floor_applied = thresholds.suspicious_min, Verdict.SUSPICIOUS, True

    return ScoreResult(
        risk_score, verdict, breakdown, floor_applied, floor_source, scam_capped, ignored
    )


def _drop_strong_disagreement(
    outcomes: list[SignalOutcome], weights: Mapping[str, float]
) -> tuple[list[SignalOutcome], tuple[str, ...]]:
    """Mark signals with max_disagreement as uninformative when they are further than that
    from the score (floors included) of every other signal."""
    kept: list[SignalOutcome] = []
    ignored: list[str] = []
    for o in outcomes:
        if o.max_disagreement is None or o.score is None or not o.informative:
            kept.append(o)
            continue
        others = [x for x in outcomes if x is not o]
        base, _ = combine_signals(others, weights)
        base, _ = _apply_floor(base, others)
        if abs(o.score - base) > o.max_disagreement:
            ignored.append(o.source)
            o = replace(
                o,
                informative=False,
                detail=f"{o.detail}; ignored: disagrees with the other signals ({base}) by "
                f"more than {o.max_disagreement:g} points",
            )
        kept.append(o)
    return kept, tuple(ignored)


def _apply_floor(
    risk_score: int, outcomes: Sequence[SignalOutcome]
) -> tuple[int, SignalOutcome | None]:
    """Decisive evidence from one layer (see module docstring) lifts the score."""
    floors = [o for o in outcomes if o.floor is not None and o.score is not None]
    top = max(floors, key=lambda o: o.floor or 0, default=None)
    if top is not None and top.floor is not None and risk_score < top.floor:
        return top.floor, top
    return risk_score, None


def _note(breakdown: list[Signal], source: str, note: str) -> list[Signal]:
    return [
        s.model_copy(update={"detail": f"{s.detail}; {note}"}) if s.source == source else s
        for s in breakdown
    ]
