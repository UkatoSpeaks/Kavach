"""sender_check, fake_payment_proof and the local-OCR field guesses (app/services/screenshot.py).
All senders, numbers and UPI IDs are invented."""

import pytest

from app.core.enums import ScamType, Severity, Verdict
from app.services import pipeline
from app.services.extractors import extract_entities
from app.services.rules import evaluate
from app.services.scoring import SignalOutcome
from app.services.screenshot import (
    HEADER_WEIGHT_FACTOR,
    IMPERSONATION_FLOOR,
    PAYMENT_PROOF_FLOOR,
    ScreenshotContext,
    guess_fields,
    institution_claim,
    parse_sender,
    payment_proof_signal,
    sender_signal,
)
from tests.conftest import settings_for_tests
from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES

RECEIPT = (
    "Payment Successful\n₹5,000\nPaid to Rahul Kumar\nrahul.k1987@ybl\n"
    "UPI transaction ID: 412345678901\n12 Sep 2026, 10:41 AM"
)
MISTAKE = "Sorry bhai, I sent ₹5,000 to your number by mistake. Please return it, it was urgent."
BANK_DEBIT = GENUINE_EXAMPLES[3][1]  # "Dear Customer, Rs.500.00 has been debited ..."


def signal(sender: str | None, text: str, outcomes: list[SignalOutcome] | None = None):  # noqa: ANN201
    entities = extract_entities(text)
    return sender_signal(parse_sender(sender), entities, evaluate(entities), outcomes or [], 35)


async def analyze(text: str, ctx: ScreenshotContext | None):  # noqa: ANN201
    return await pipeline.analyze(text, settings_for_tests(), checks=None, screenshot_ctx=ctx)


# ----------------------------------------------------------------------------- sender


@pytest.mark.parametrize(
    ("raw", "kind", "number"),
    [
        ("VM-SBIINB", "dlt_header", None),
        ("AX-HDFCBK-S", "dlt_header", None),
        ("jd-airtel-t", "dlt_header", None),
        ("BZ-123456-P", "dlt_header", None),
        ("+91 98765 43210", "personal_mobile", "+919876543210"),
        ("98765 43210", "personal_mobile", "+919876543210"),
        ("+44 7911 123456", "international", "+447911123456"),
        ("+1 (415) 555-0100", "international", "+14155550100"),
        ("0044 7911 123456", "international", "+447911123456"),
        ("1800 425 3800", "other_number", "18004253800"),
        ("VM-SBIINB-X", "name", None),  # not a DLT suffix
        ("Mummy", "name", None),
    ],
)
def test_parse_sender(raw: str, kind: str, number: str | None) -> None:
    sender = parse_sender(raw)
    assert sender is not None
    assert (sender.kind, sender.number) == (kind, number)


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_no_sender(raw: str | None) -> None:
    assert parse_sender(raw) is None


@pytest.mark.parametrize(
    "text",
    [
        "Dear Customer, your account will be blocked today.",
        "Your SBI account will be blocked, update KYC now",
        "This is Rohit calling from HDFC Bank about your credit card.",
        "Main SBI se bol raha hoon, OTP bata dijiye",
        "Your statement is ready. -ICICI Bank",
        "Your electricity connection will be cut tonight",
        "Aapka KYC pending hai, turant update karein",
        "प्रिय ग्राहक, आपका खाता बंद हो जाएगा",
    ],
)
def test_institution_claims(text: str) -> None:
    assert institution_claim(extract_entities(text)) is not None


@pytest.mark.parametrize(
    "text",
    [
        "Maa, bank se paise nikal liye",
        "I ordered a phone from Amazon yesterday",
        "I am going to the bank tomorrow, need anything?",
        "Kal milte hai, 6 baje",
    ],
)
def test_mentioning_an_institution_is_not_a_claim(text: str) -> None:
    assert institution_claim(extract_entities(text)) is None


def test_personal_number_claiming_to_be_a_bank_is_a_strong_flag() -> None:
    out = signal("+91 98765 43210", BANK_DEBIT)
    assert out.score == 90 and out.floor == IMPERSONATION_FLOOR and out.informative
    [flag] = out.red_flags
    assert flag.code == "sender_personal_number" and flag.severity is Severity.HIGH
    assert "+91 98765 43210" in (flag.evidence or "")


def test_international_number_claiming_to_be_official() -> None:
    out = signal("+44 7911 123456", "Dear Customer, your parcel is held at customs.")
    assert out.floor == IMPERSONATION_FLOOR
    assert out.red_flags[0].code == "sender_personal_number"
    assert "international" in out.detail


def test_international_number_alone_is_a_medium_flag() -> None:
    out = signal("+44 7911 123456", "Hi, are you free to talk?")
    assert out.score == 50 and out.floor is None and out.informative
    assert out.red_flags[0].code == "sender_international_number"


@pytest.mark.parametrize("sender", ["+91 98765 43210", "Mummy", "1800 425 3800", None])
def test_ordinary_senders_are_not_counted(sender: str | None) -> None:
    out = signal(sender, "Kal milte hai, 6 baje")
    assert not out.informative and not out.red_flags


def test_business_header_lowers_risk_only_when_nothing_fired() -> None:
    quiet = signal("VM-SBIINB", "Your account statement for August is ready.")
    assert quiet.informative and quiet.score == 0
    assert quiet.weight_factor == HEADER_WEIGHT_FACTOR

    scam = signal("VM-SBIINB", SCAM_EXAMPLES[9][1])  # KYC-expiry phishing link
    assert not scam.informative
    assert "can be faked" in scam.detail

    risky_link = SignalOutcome("url_intel", 80, "blocklisted")
    other = signal("VM-SBIINB", "Your statement is ready.", [risky_link])
    assert not other.informative


# ----------------------------------------------------------------------------- receipts


def test_plain_receipt_is_not_suspicious() -> None:
    entities = extract_entities(RECEIPT)
    out = payment_proof_signal(True, entities, evaluate(entities))
    assert out is not None
    assert not out.informative and out.floor is None and not out.red_flags


def test_not_a_receipt_has_no_signal() -> None:
    entities = extract_entities(MISTAKE)
    assert payment_proof_signal(False, entities, evaluate(entities)) is None


@pytest.mark.parametrize(
    "context",
    [
        MISTAKE,
        "Bhai galti se aapko paise chale gaye, wapas kar do please",
        "मैंने गलती से आपके खाते में पैसे भेज दिए, कृपया वापस कर दीजिए",
        "Accidentally transferred to you. Please send it back today.",
    ],
)
def test_receipt_with_a_return_request_is_fake_payment_proof(context: str) -> None:
    entities = extract_entities(f"{RECEIPT}\n{context}")
    out = payment_proof_signal(True, entities, evaluate(entities))
    assert out is not None
    assert out.score == 90 and out.floor == PAYMENT_PROOF_FLOOR
    assert out.scam_type is ScamType.SENT_BY_MISTAKE
    assert out.red_flags[0].code == "fake_payment_proof"


# ----------------------------------------------------------------------------- local OCR


def test_guess_fields_sms() -> None:
    ctx = guess_fields("AX-HDFCBK-S\nRs.500.00 debited from A/c XX1234\n10:42 AM")
    assert ctx == ScreenshotContext(sender="AX-HDFCBK-S", app="sms", is_payment_receipt=False)


def test_guess_fields_receipt() -> None:
    ctx = guess_fields(RECEIPT)
    assert ctx.is_payment_receipt and ctx.app == "payment_app"


def test_guess_fields_phone_sender() -> None:
    ctx = guess_fields("+91 98765 43210\nHi, I sent money by mistake\n10:42 AM")
    assert ctx.sender == "+91 98765 43210" and ctx.app == "other"


def test_guess_fields_nothing() -> None:
    assert guess_fields("just some words\nand more") == ScreenshotContext(app="other")


def test_bank_debit_sms_is_not_a_receipt() -> None:
    assert not guess_fields(BANK_DEBIT).is_payment_receipt


# ----------------------------------------------------------------------------- scoring


async def test_fake_payment_proof_makes_it_a_scam() -> None:
    ctx = ScreenshotContext(sender="+91 91234 56780", app="whatsapp", is_payment_receipt=True)
    out = await analyze(f"{RECEIPT}\n{MISTAKE}", ctx)
    assert out.result.verdict is Verdict.SCAM
    assert out.result.risk_score >= PAYMENT_PROOF_FLOOR
    assert out.result.scam_type == ScamType.SENT_BY_MISTAKE
    assert "fake_payment_proof" in {f.code for f in out.result.red_flags}


async def test_receipt_alone_is_safe() -> None:
    ctx = ScreenshotContext(app="payment_app", is_payment_receipt=True)
    out = await analyze(RECEIPT, ctx)
    assert out.result.verdict is Verdict.SAFE
    proof = next(s for s in out.result.signal_breakdown if s.source == "fake_payment_proof")
    assert proof.weight == 0


async def test_bank_message_from_a_personal_number_is_at_least_suspicious() -> None:
    plain = await analyze(BANK_DEBIT, None)
    spoofed = await analyze(BANK_DEBIT, ScreenshotContext(sender="+91 98765 43210", app="sms"))
    assert plain.result.verdict is Verdict.SAFE
    assert spoofed.result.verdict is not Verdict.SAFE
    assert spoofed.result.risk_score >= IMPERSONATION_FLOOR


async def test_header_slightly_lowers_a_weak_signal_score() -> None:
    text = "Your order is out for delivery. Track it: bit.ly/trk-4821 -Delhivery"
    without = await analyze(text, ScreenshotContext())
    with_header = await analyze(text, ScreenshotContext(sender="VM-DLHVRY", app="sms"))
    assert 0 < without.result.risk_score
    assert with_header.result.risk_score <= without.result.risk_score
    assert without.result.risk_score - with_header.result.risk_score <= 10
    assert with_header.result.verdict is without.result.verdict


@pytest.mark.parametrize(("scam_type", "text"), SCAM_EXAMPLES)
@pytest.mark.parametrize("sender", [None, "VM-SBIINB", "+91 98765 43210"])
async def test_scam_examples_stay_scams_as_screenshots(
    scam_type: ScamType, text: str, sender: str | None
) -> None:
    """A legit-looking header must never make a scam safe (it can be spoofed)."""
    out = await analyze(text, ScreenshotContext(sender=sender, app="sms"))
    assert out.result.verdict is Verdict.SCAM, out.result.signal_breakdown


@pytest.mark.parametrize(("label", "text"), GENUINE_EXAMPLES)
@pytest.mark.parametrize("sender", [None, "VM-SBIINB"])
async def test_genuine_examples_stay_safe_as_screenshots(
    label: str, text: str, sender: str | None
) -> None:
    out = await analyze(text, ScreenshotContext(sender=sender, app="sms"))
    assert out.result.verdict is Verdict.SAFE, out.result.signal_breakdown
