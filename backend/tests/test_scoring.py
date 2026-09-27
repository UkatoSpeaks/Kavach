import pytest

from app.core.config import get_settings
from app.core.enums import ScamType, Verdict
from app.services.explain import REPORT_EN, advice_for
from app.services.extractors import extract_entities
from app.services.pipeline import analyze_text
from app.services.rules import RULES_BY_ID, RuleHit, RuleResult, evaluate, saturating_score
from app.services.scoring import SignalOutcome, Thresholds, combine_signals, score, verdict_for
from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES

WEIGHTS = {"rules": 0.3, "classifier": 0.25, "url_intel": 0.15, "llm": 0.3}
T = Thresholds()


def rule_result(*rule_ids: str) -> RuleResult:
    hits = [RuleHit(RULES_BY_ID[r], "x") for r in rule_ids]
    return RuleResult(hits, saturating_score(h.rule.weight for h in hits), None)


# ----------------------------------------------------------------------------- combining


def test_only_rules_signal_gets_full_weight() -> None:
    risk, breakdown = combine_signals([SignalOutcome("rules", 80)], WEIGHTS)
    assert risk == 80
    assert [(s.source, s.weight) for s in breakdown] == [("rules", 1.0)]


def test_weights_renormalize_over_present_signals() -> None:
    risk, breakdown = combine_signals(
        [SignalOutcome("rules", 90), SignalOutcome("llm", 30)], WEIGHTS
    )
    assert risk == 60  # (0.3*90 + 0.3*30) / 0.6
    assert {s.source: s.weight for s in breakdown} == {"rules": 0.5, "llm": 0.5}


def test_failed_signal_is_skipped_but_reported() -> None:
    risk, breakdown = combine_signals(
        [SignalOutcome("rules", 70), SignalOutcome("url_intel", None, "timeout")], WEIGHTS
    )
    assert risk == 70
    missing = next(s for s in breakdown if s.source == "url_intel")
    assert (missing.weight, missing.detail) == (0, "unavailable: timeout")


def test_unknown_signal_is_ignored() -> None:
    risk, breakdown = combine_signals(
        [SignalOutcome("rules", 40), SignalOutcome("astrology", 100)], WEIGHTS
    )
    assert risk == 40
    assert [s.source for s in breakdown] == ["rules"]


def test_no_signals_scores_zero() -> None:
    assert combine_signals([], WEIGHTS) == (0, [])


@pytest.mark.parametrize(
    ("risk", "verdict"),
    [(0, Verdict.SAFE), (34, Verdict.SAFE), (35, Verdict.SUSPICIOUS), (69, Verdict.SUSPICIOUS),
     (70, Verdict.SCAM), (100, Verdict.SCAM)],
)  # fmt: skip
def test_verdict_thresholds(risk: int, verdict: Verdict) -> None:
    assert verdict_for(risk, T) is verdict


def test_strong_rule_floor() -> None:
    # PIN-to-receive (0.9) scores 90 from rules, but a benign classifier + LLM pull the
    # average below 35. The verdict must still be at least suspicious.
    result = score(
        rule_result("pin_to_receive"),
        WEIGHTS,
        T,
        extra=[SignalOutcome("classifier", 0), SignalOutcome("llm", 0)],
    )
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.risk_score == T.suspicious_min
    assert result.strong_rule_floor_applied


def test_weak_rules_get_no_floor() -> None:
    result = score(rule_result("urgency"), WEIGHTS, T, extra=[SignalOutcome("llm", 0)])
    assert result.verdict is Verdict.SAFE
    assert not result.strong_rule_floor_applied


# ----------------------------------------------------------------------------- examples


@pytest.mark.parametrize(
    ("expected_type", "text"),
    SCAM_EXAMPLES,
    ids=[f"{t}-{i}" for i, (t, _) in enumerate(SCAM_EXAMPLES)],
)
def test_scam_examples_score_high(expected_type: ScamType, text: str) -> None:
    result = analyze_text(text, get_settings()).result
    assert result.risk_score >= 70, [f.code for f in result.red_flags]
    assert result.verdict is Verdict.SCAM
    assert result.scam_type == expected_type


def test_each_v1_type_has_two_scam_examples() -> None:
    for scam_type in ScamType:
        if scam_type is not ScamType.GENERIC:
            assert sum(t is scam_type for t, _ in SCAM_EXAMPLES) >= 2, scam_type


@pytest.mark.parametrize(("label", "text"), GENUINE_EXAMPLES, ids=[g[0] for g in GENUINE_EXAMPLES])
def test_genuine_examples_score_low(label: str, text: str) -> None:
    result = analyze_text(text, get_settings()).result
    assert result.risk_score < 35, [f.code for f in result.red_flags]
    assert result.verdict is Verdict.SAFE
    assert result.scam_type is None


# ----------------------------------------------------------------------------- explanation


def test_scam_result_is_explained_in_both_languages() -> None:
    result = analyze_text(SCAM_EXAMPLES[0][1], get_settings()).result
    assert "UPI PIN" in result.explanation_en
    assert "पिन" in result.explanation_hi
    assert 2 <= len(result.advice) <= 4
    assert result.advice[-1] == REPORT_EN
    assert result.red_flags[0].code == "pin_to_receive"
    assert result.red_flags[0].severity == "high"


def test_advice_in_hindi() -> None:
    hits = evaluate(extract_entities("Please share the OTP")).hits
    advice = advice_for(Verdict.SCAM, ScamType.GENERIC, hits, hindi=True)
    assert "1930" in advice[-1] and "शिकायत" in advice[-1]


@pytest.mark.parametrize("scam_type", list(ScamType))
def test_advice_count_per_type(scam_type: ScamType) -> None:
    assert 2 <= len(advice_for(Verdict.SCAM, scam_type, [])) <= 4


def test_safe_result_has_no_scam_type() -> None:
    result = analyze_text("See you at 6 for dinner", get_settings()).result
    assert (result.verdict, result.scam_type, result.red_flags) == (Verdict.SAFE, None, [])
    assert result.explanation_en.startswith("Low risk")
