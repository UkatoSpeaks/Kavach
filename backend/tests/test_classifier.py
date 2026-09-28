"""The scam classifier: shared preprocessing, JSON inference vs scikit-learn, the signal."""

import json
import random
from pathlib import Path

import numpy as np
import pytest
from sklearn.feature_extraction.text import TfidfVectorizer

from app.core.config import BACKEND_DIR, get_settings
from app.services import classifier, rules
from app.services.classifier import ModelError, ScamClassifier, classifier_signal
from app.services.extractors import extract_entities
from app.services.features import char_ngrams, preprocess, word_ngrams
from app.services.pipeline import analyze_text
from app.services.scoring import SignalOutcome, combine_signals
from ml.anonymize import anonymize_text
from ml.common import read_csv, text_id
from ml.train_classifier import CLASSES, export_model, fit_model, parity
from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES

# ----------------------------------------------------------------------------- features


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Rs.82,850 Credited to yOur A/c GET Cash N0W http://9lp7.com/x",
         "<amount> credited to your a/c get cash now <url>"),
        ("Update KYC at https://sbi-kyc.top/a", "update kyc at <url_lookalike>"),
        ("Claim at bit.ly/3xYz now", "claim at <url_short> now"),
        ("Visit http://win-prize.xyz", "visit <url_riskytld>"),
        ("Join t.me/earnjobs", "join <url_msg>"),
        ("Track at amzn.in/d/abc", "track at <url_official>"),
        ("Pay upi://pay?pa=a@ybl&am=10 or rahul@okaxis", "pay <upi_link> or <upi>"),
        ("Call 98765 43210 or 1800-111-109", "call <phone> or <phone_tollfree>"),
        ("OTP 482913 valid till 12-09-24", "otp <num> valid till <num>"),
        ("Mail help@company.com", "mail <email>"),
    ],
)  # fmt: skip
def test_preprocess_masks_entities_and_folds_leetspeak(text: str, expected: str) -> None:
    assert preprocess(text) == expected


def test_leetspeak_is_never_folded_inside_identifiers() -> None:
    # The UPI ID and the link keep their digits: they are masked whole, not folded.
    assert preprocess("B0nus to s0nu4@ybl") == "bonus to <upi>"
    assert "<url>" in preprocess("go to w1n.com/b0nus")


def test_hindi_words_stay_whole() -> None:
    assert word_ngrams(preprocess("बिजली कट जाएगी"))[:3] == ["बिजली", "कट", "जाएगी"]


def test_char_ngrams_match_scikit_learn_char_wb() -> None:
    ref = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), lowercase=False)
    analyze = ref.build_analyzer()
    for text in ("your account is blocked", "a ok!", "hi", "kyc update karo abhi"):
        assert char_ngrams(text) == analyze(text)


def test_mask_tokens_are_single_char_features() -> None:
    assert char_ngrams("<url>") == ["<url>"]


# ----------------------------------------------------------------------------- JSON parity


def _training_texts() -> tuple[list[str], list[str]]:
    texts = [t for _, t in SCAM_EXAMPLES] + [t for _, t in GENUINE_EXAMPLES]
    labels = ["scam"] * len(SCAM_EXAMPLES) + ["genuine"] * len(GENUINE_EXAMPLES)
    promos = [
        "Flat 50% off on shoes, shop now at myntra.com T&C apply",
        "Jio: recharge with Rs 299 plan and get 2GB/day unlimited calls",
        "Big Billion Days sale is live! Up to 80% off on Flipkart",
        "Swiggy: 60% off up to Rs 120 on your next order, use code TRYNEW",
    ]
    return texts + promos, labels + ["promo_spam"] * len(promos)


def _samples(texts: list[str], n: int = 200) -> list[str]:
    """n messages made by recombining words of the training texts (fixed seed)."""
    rng = random.Random(0)
    pool = " ".join(texts).split()
    return [" ".join(rng.choices(pool, k=rng.randint(3, 40))) for _ in range(n)]


def test_json_inference_matches_scikit_learn_on_200_messages() -> None:
    texts, labels = _training_texts()
    pre = [preprocess(t) for t in texts]
    vec, lr = fit_model(pre, labels, np.ones(len(texts)), c=4.0, min_df=1)
    model = ScamClassifier.from_dict(export_model(vec, lr, 1.3, {}))
    samples = _samples(texts)
    diff, disagreements = parity(model, vec, lr, samples)
    assert disagreements == 0
    assert diff < 1e-5
    # Calibration only rescales the logits: same predicted class.
    for t in samples[:20]:
        raw, cal = model.predict_proba(t, calibrated=False), model.predict_proba(t)
        assert max(raw, key=raw.get) == max(cal, key=cal.get)


def test_model_for_other_features_version_is_refused() -> None:
    texts, labels = _training_texts()
    vec, lr = fit_model([preprocess(t) for t in texts], labels, np.ones(len(texts)), c=1.0,
                        min_df=1)  # fmt: skip
    data = export_model(vec, lr, 1.0, {})
    data["features_version"] = -1
    with pytest.raises(ModelError):
        ScamClassifier.from_dict(data)
    assert CLASSES == ["genuine", "promo_spam", "scam"]


# ----------------------------------------------------------------------------- the signal


def test_missing_model_fails_soft(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    assert classifier.get_classifier(missing) is None
    outcome = classifier_signal("anything", None)
    assert outcome.score is None and outcome.floor is None

    settings = get_settings().model_copy(update={"CLASSIFIER_MODEL_PATH": missing})
    result = analyze_text(SCAM_EXAMPLES[0][1], settings).result
    by_source = {s.source: s for s in result.signal_breakdown}
    assert by_source["classifier"].weight == 0
    assert by_source["classifier"].detail.startswith("unavailable")
    off = get_settings().model_copy(update={"CLASSIFIER_ENABLED": False})
    assert result.verdict is analyze_text(SCAM_EXAMPLES[0][1], off).result.verdict


def test_signal_never_sets_a_floor_and_low_scam_probability_does_not_count() -> None:
    texts, labels = _training_texts()
    vec, lr = fit_model([preprocess(t) for t in texts], labels, np.ones(len(texts)), c=4.0,
                        min_df=1)  # fmt: skip
    model = ScamClassifier.from_dict(export_model(vec, lr, 1.0, {}))
    for text in ("See you at 6 for dinner", SCAM_EXAMPLES[0][1]):
        outcome = classifier_signal(text, model)
        assert outcome.floor is None
        p_scam = model.predict_proba(text)["scam"]
        assert outcome.informative is (p_scam >= classifier.MIN_SCAM_PROBABILITY)


MODEL = get_settings().CLASSIFIER_MODEL_PATH


@pytest.mark.skipif(not MODEL.exists(), reason="no trained model (ml/train_classifier.py)")
@pytest.mark.parametrize("text", [t for _, t in SCAM_EXAMPLES + GENUINE_EXAMPLES])
def test_built_in_examples_keep_their_verdicts_with_the_trained_model(text: str) -> None:
    on = get_settings()
    off = on.model_copy(update={"CLASSIFIER_ENABLED": False})
    with_clf = analyze_text(text, on).result
    assert any(s.source == "classifier" and s.weight >= 0 for s in with_clf.signal_breakdown)
    assert with_clf.verdict is analyze_text(text, off).result.verdict


def test_no_space_before_punctuation_so_removed_placeholders_leave_no_trace() -> None:
    # IMC25 rows lose "<NAMED_ENTITY>" before a full stop; a real message has none there.
    assert preprocess("Your a/c is blocked . Click , now !") == preprocess(
        "Your a/c is blocked. Click, now!"
    )


# ----------------------------------------------------------------------------- privacy

COLLECTED_DIR = BACKEND_DIR / "data" / "datasets" / "collected"
TRAIN_CSV = BACKEND_DIR / "data" / "datasets" / "processed" / "train.csv"


def _ngrams(text: str) -> set[str]:
    pre = preprocess(text)
    return {f"char:{t}" for t in char_ngrams(pre)} | {f"word:{t}" for t in word_ngrams(pre)}


@pytest.mark.skipif(
    not (MODEL.exists() and TRAIN_CSV.exists() and any(COLLECTED_DIR.glob("*.csv"))),
    reason="needs models/classifier.json and your local (gitignored) datasets",
)
def test_no_ngram_only_your_collected_messages_have_is_in_the_model() -> None:
    """Collected messages are test-only. Their n-grams (as written, and anonymized as the
    pipeline stores them) may be in the model only if some other training message has them."""
    model = json.loads(MODEL.read_text(encoding="utf-8"))
    vocab = {f"{b['analyzer']}:{t}" for b in model["blocks"] for t in b["terms"]}
    mine = [r["text"] for path in COLLECTED_DIR.glob("*.csv") for r in read_csv(path)]
    candidates = set().union(*(_ngrams(t) | _ngrams(anonymize_text(t).text) for t in mine))
    candidates &= vocab
    train = read_csv(TRAIN_CSV)
    collected_ids = {text_id(t) for t in mine}
    assert not [r for r in train if r["dataset"] == "collected" or r["id"] in collected_ids]
    for r in train:
        if r["parent_id"] in collected_ids:
            continue  # a synthetic variation of your message is not "someone else's"
        candidates -= _ngrams(r["text"])
        if not candidates:
            break
    assert not candidates, f"n-grams only in your collected messages: {sorted(candidates)[:20]}"


# ----------------------------------------------------------------------------- advisory guard

ADVISORIES = [
    "Kotak Bank never asks for your OTP, PIN or CVV. Stay safe from fraudsters.",
    "Do not share your card details with anyone claiming to be from the bank. -PNB",
    "Beware of fake KYC update calls. Report cyber fraud by calling 1930.",
    "Bank kabhi bhi aapka OTP nahi maangta. Kisi ke saath share na karein.",
    "सावधान! बैंक कभी भी आपका पिन नहीं मांगता। किसी से साझा न करें।",
]
NOT_ADVISORIES = [
    # Same wording, but the message asks the reader to act on something.
    "Beware! Your KYC expires today, update at http://kyc-verify.top/sbi",
    "Never share this OTP. Call our officer on 9876543210 to verify your account.",
    "Do not share with anyone. Pay Rs 10 verification fee now to unblock your card.",
    "Stay safe: send money only to verify@ybl to confirm your refund.",
    "Don't share this code, just transfer the amount to receive your cashback.",
    # No advisory wording at all.
    "Your account is blocked. Contact the branch today.",
]


@pytest.mark.parametrize("text", ADVISORIES)
def test_advisory_wording_without_any_ask_is_recognised(text: str) -> None:
    assert rules.advisory_evidence(extract_entities(text))


@pytest.mark.parametrize("text", NOT_ADVISORIES)
def test_advisory_wording_with_a_link_phone_upi_or_payment_is_not(text: str) -> None:
    assert rules.advisory_evidence(extract_entities(text)) is None


class _AlwaysScam:
    """Stands in for a model that is sure every message is a scam."""

    def predict_proba(self, text: str) -> dict[str, float]:
        return {"genuine": 0.02, "promo_spam": 0.01, "scam": 0.97}


def _classifier_weight(text: str, monkeypatch: pytest.MonkeyPatch) -> tuple[float, str]:
    monkeypatch.setattr(classifier, "get_classifier", lambda path: _AlwaysScam())
    result = analyze_text(text, get_settings()).result
    sig = next(s for s in result.signal_breakdown if s.source == "classifier")
    return sig.weight, result.verdict.value


def test_classifier_weight_is_halved_on_an_advisory(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    w_rules, w_clf = settings.SIGNAL_WEIGHTS["rules"], settings.SIGNAL_WEIGHTS["classifier"]
    factor = settings.CLASSIFIER_ADVISORY_WEIGHT_FACTOR
    advisory, verdict = _classifier_weight(ADVISORIES[0], monkeypatch)
    assert advisory == pytest.approx(w_clf * factor / (w_rules + w_clf * factor), abs=1e-3)
    assert verdict == "safe"  # a confident classifier alone no longer flags a notice
    plain, verdict = _classifier_weight("Your account is blocked today.", monkeypatch)
    assert plain == pytest.approx(w_clf / (w_rules + w_clf), abs=1e-3)
    assert verdict != "safe"


def test_weight_factor_scales_a_signal_in_the_weighted_mean() -> None:
    weights = {"rules": 0.5, "classifier": 0.5}
    full = [SignalOutcome("rules", 0), SignalOutcome("classifier", 100)]
    half = [SignalOutcome("rules", 0), SignalOutcome("classifier", 100, weight_factor=0.5)]
    assert combine_signals(full, weights)[0] == 50
    assert combine_signals(half, weights)[0] == 33
