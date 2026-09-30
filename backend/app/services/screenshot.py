"""Signals only a screenshot has: who sent it, and whether it shows a payment receipt. Pure.

- sender_check: SMS from Indian businesses arrive under a DLT-registered header such as
  "VM-SBIINB" or "AX-HDFCBK-S"; a bank, company or government office never messages from a
  personal mobile number. A message that claims to be one of them but was sent from a
  personal or international number is a strong red flag. The reverse does not hold: a
  screenshot can show any header (edited image, spoofed sender), so a business header only
  counts, at half weight, when nothing else in the message looks wrong.
- fake_payment_proof: a "payment successful" screen next to a request to send money back is
  the "sent by mistake" scam (the screenshot is fake or edited). A receipt on its own is not
  suspicious.

`guess_fields` fills in sender / app / is_payment_receipt from plain OCR text when the local
OCR (which only returns text) was used instead of the vision model.
"""

import re
from dataclasses import dataclass
from typing import Literal

from app.core.enums import ScamType, Severity
from app.schemas.analysis import RedFlag
from app.schemas.entities import ExtractedEntities
from app.services import rules
from app.services.extractors import extract_phones
from app.services.rules import RuleResult
from app.services.scoring import SignalOutcome

SENDER_SOURCE = "sender_check"
PAYMENT_PROOF_SOURCE = "fake_payment_proof"

AppKind = Literal["sms", "whatsapp", "email", "payment_app", "other"]
SenderKind = Literal["dlt_header", "personal_mobile", "international", "other_number", "name"]

# Claims to be an institution + a personal/international sender: at least "suspicious".
IMPERSONATION_SCORE = 90
IMPERSONATION_FLOOR = 50
INTERNATIONAL_SCORE = 50
# A business header lowers the risk only a little, and only when nothing else fired.
HEADER_WEIGHT_FACTOR = 0.5
# Receipt + "send it back": at least "scam".
PAYMENT_PROOF_SCORE = 90
PAYMENT_PROOF_FLOOR = 75

# DLT header: 2-letter operator/circle prefix, 6-character sender id, optional -S/-T/-P/-G
# (service, transactional, promotional, government). "VM-SBIINB", "JD-AIRTEL-S".
DLT_HEADER = re.compile(r"\b([A-Z]{2})[-‐–]([A-Z0-9]{6})(?:[-‐–]([SPTG]))?\b")
_DLT_HEADER_FULL = re.compile(rf"^{DLT_HEADER.pattern}$")
_PHONE_LIKE = re.compile(r"^\+?[\d\s().-]{8,20}$")
_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$")

# Wording that presents the message as coming from a bank, company or government office.
# Merely mentioning one ("Maa, bank se paise nikal liye") is not a claim; the message has to
# speak as the institution: a bulk-message salutation, "from/team/-SBI", or a named
# institution talking about "your account/card/parcel".
_NAMED = (
    r"(?:sbi|yono|hdfc|icici|axis|kotak|pnb|canara|bank of baroda|indusind|idfc|paytm|phonepe"
    r"|google ?pay|gpay|bhim|npci|rbi|reserve bank|amazon|flipkart|airtel|jio|vodafone|bsnl"
    r"|india ?post|delhivery|blue ?dart|fedex|dtdc|bses|tata power|income ?tax|uidai"
    r"|parivahan|epfo|trai|cyber ?cell|police)"
)
_GENERIC = (
    r"(?:bank|electricity (?:board|department|office)|bijli (?:vibhag|vibhaag|board|office)"
    r"|government|govt|customs)"
)
_BODY = rf"(?:{_NAMED}|{_GENERIC})"
INSTITUTION_CLAIMS = [
    r"\bdear (?:customer|consumer|user|card ?holder|member|subscriber|valued customer)\b",
    r"\bpriya (?:grahak|upbhokta)\b",
    # The speaker introduces themselves: "this is Rohit from HDFC", "calling from SBI".
    rf"\b(?:this is|we are|i am|i'm|calling|message|sms)\s+(?:\w+\s+){{0,2}}?from\s+(?:the\s+)?"
    rf"(?:\w+\s+)?{_BODY}\b",
    rf"\bteam\s+{_BODY}\b",
    rf"(?:^|\s)[-–]\s*(?:\w+\s+){{0,2}}?{_BODY}\b",  # sign-off: "-SBI", "- ICICI Bank"
    rf"\b{_BODY}\s+(?:customer care|support|helpline|team|official|department|dept|head office"
    r"|officer)\b",
    rf"\b{_BODY}\s+se\s+(?:bol|call|message)",
    rf"\b{_NAMED}\b(?:\W+\w+){{0,6}}?\W+(?:your|aapk[aie]|apk[aie])\s+(?:\w+\s+){{0,2}}?"
    r"(?:account|a/c|card|kyc|wallet|order|parcel|shipment|consignment|sim|number|policy"
    r"|refund|reward|khata|khate)\b",
    rf"\b(?:your|aapk[aie]|apk[aie])\s+(?:\w+\s+){{0,2}}?{_NAMED}\s+(?:account|a/c|card|kyc"
    r"|wallet|order|parcel|sim|number|policy|refund|khata|khate)\b",
    # objects only institutions send notices about
    r"\b(?:your|aapk[aie]|apk[aie])\s+(?:\w+\s+){0,2}?(?:kyc|e-?challan|challan"
    r"|electricity (?:connection|bill)|bijli (?:connection|bill)|power connection|pan card)\b",
    "प्रिय ग्राहक", "प्रिय उपभोक्ता", r"(?:बैंक|बिजली विभाग|पुलिस|आयकर विभाग)\s*(?:से|की ओर से)",
    r"आपका\s+(?:\S+\s+){0,2}?(?:खाता|केवाईसी|KYC|बिजली कनेक्शन|चालान)",
]  # fmt: skip
_INSTITUTION = re.compile("|".join(f"(?:{p})" for p in INSTITUTION_CLAIMS), re.IGNORECASE)
# "Payment successful" screens (payment apps, bank apps). Bank debit SMS don't count.
RECEIPT_PHRASES = [
    r"\bpayment (?:successful|success|completed|done)\b", r"\bpaid successfully\b",
    r"\b(?:money |amount )?(?:sent|transferred) successfully\b",
    r"\btransaction (?:successful|completed)\b", r"\btransfer (?:successful|completed)\b",
    r"\bpayment received successfully\b",
    "भुगतान सफल", "पेमेंट सफल", "सफलतापूर्वक भेजा",
]  # fmt: skip
_RECEIPT = re.compile("|".join(f"(?:{p})" for p in RECEIPT_PHRASES), re.IGNORECASE)
# The "send it back" story, even without money named in the same clause.
_RETURN_STORY = re.compile("|".join(f"(?:{p})" for p in rules.SENT_BY_MISTAKE + rules.RETURN_MONEY))
_RETURN_RULES = frozenset({"sent_by_mistake", "return_money", "money_back_request"})
# Strong rules (weight >= this) mean "something else fired" for the header check.
_HEADER_BLOCKING_RULE_WEIGHT = 0.4


@dataclass(frozen=True)
class Sender:
    raw: str
    kind: SenderKind
    number: str | None = None  # +91XXXXXXXXXX or the international digits


@dataclass(frozen=True)
class ScreenshotContext:
    """What OCR saw besides the text: passed through the analysis graph."""

    sender: str | None = None
    app: AppKind | None = None
    is_payment_receipt: bool = False


def parse_sender(raw: str | None) -> Sender | None:
    """Classify the sender line of a screenshot. None for an empty sender."""
    if raw is None or not raw.strip():
        return None
    value = " ".join(raw.split())
    if _DLT_HEADER_FULL.match(value.upper()):
        return Sender(value, "dlt_header")
    if _PHONE_LIKE.match(value):
        digits = re.sub(r"\D", "", value)
        # Before the mobile check: "+44 7911 123456" ends in ten digits that look Indian.
        if value.startswith("+") and not digits.startswith("91"):
            return Sender(value, "international", "+" + digits)
        if value.startswith("00") and not digits.startswith("0091"):
            return Sender(value, "international", "+" + digits[2:])
        mobiles = [p for p in extract_phones(value) if p.kind == "mobile"]
        if mobiles:
            return Sender(value, "personal_mobile", mobiles[0].number)
        return Sender(value, "other_number", digits)
    return Sender(value, "name")


def institution_claim(entities: ExtractedEntities) -> str | None:
    """The wording that presents the message as a bank's, company's or government's."""
    for text in [entities.normalized_text, *entities.rule_texts]:
        if m := _INSTITUTION.search(text):
            return m.group()
    return None


def _flag(code: str, en: str, hi: str, severity: Severity, evidence: str) -> RedFlag:
    return RedFlag(code=code, message=en, message_hi=hi, severity=severity, evidence=evidence)


def sender_signal(
    sender: Sender | None,
    entities: ExtractedEntities,
    rule_result: RuleResult,
    outcomes: list[SignalOutcome],
    suspicious_min: int,
) -> SignalOutcome:
    if sender is None:
        return SignalOutcome(SENDER_SOURCE, 0, "no sender visible", informative=False)
    claim = institution_claim(entities)
    if sender.kind in ("personal_mobile", "international") and claim:
        what = (
            "a personal mobile number"
            if sender.kind == "personal_mobile"
            else ("an international number")
        )
        flag = _flag(
            "sender_personal_number",
            f"Claims to be a bank, company or government office but was sent from {what}",
            "बैंक, कंपनी या सरकारी दफ़्तर होने का दावा है, पर संदेश निजी या विदेशी नंबर से आया है",
            Severity.HIGH,
            f"{sender.raw} … {claim}",
        )
        return SignalOutcome(
            SENDER_SOURCE,
            IMPERSONATION_SCORE,
            f"sent from {what} ({sender.raw}) but claims to be official ('{claim}')",
            floor=IMPERSONATION_FLOOR,
            red_flags=(flag,),
        )
    if sender.kind == "international":
        flag = _flag(
            "sender_international_number",
            "Sent from an unknown international number",
            "संदेश किसी अनजान विदेशी नंबर से आया है",
            Severity.MEDIUM,
            sender.raw,
        )
        detail = f"sent from an international number ({sender.raw})"
        return SignalOutcome(SENDER_SOURCE, INTERNATIONAL_SCORE, detail, red_flags=(flag,))
    if sender.kind == "dlt_header":
        return _header_signal(sender, rule_result, outcomes, suspicious_min)
    detail = {
        "personal_mobile": f"personal mobile number ({sender.raw}), no claim to be official",
        "other_number": f"sent from {sender.raw}",
        "name": "sender shown by name (a saved contact or business profile)",
    }[sender.kind]
    return SignalOutcome(SENDER_SOURCE, 0, detail, informative=False)


def _header_signal(
    sender: Sender, rule_result: RuleResult, outcomes: list[SignalOutcome], suspicious_min: int
) -> SignalOutcome:
    strong_rules = [h for h in rule_result.hits if h.rule.weight >= _HEADER_BLOCKING_RULE_WEIGHT]
    other_risk = [
        o.source for o in outcomes
        if o.informative and o.score is not None and o.score >= suspicious_min
    ]  # fmt: skip
    if strong_rules or other_risk:
        return SignalOutcome(
            SENDER_SOURCE,
            0,
            f"business SMS header ({sender.raw}), not counted: headers can be faked in a "
            "screenshot and other signs point to a scam",
            informative=False,
        )
    return SignalOutcome(
        SENDER_SOURCE,
        0,
        f"business SMS header ({sender.raw}) and nothing else looks wrong; half weight, since "
        "headers can be faked in a screenshot",
        weight_factor=HEADER_WEIGHT_FACTOR,
    )


def payment_proof_signal(
    is_payment_receipt: bool, entities: ExtractedEntities, rule_result: RuleResult
) -> SignalOutcome | None:
    """None when the image is not a payment receipt."""
    if not is_payment_receipt:
        return None
    story = next((h.evidence for h in rule_result.hits if h.rule.id in _RETURN_RULES), None)
    if story is None:
        texts = [entities.normalized_text, *entities.rule_texts]
        story = next((m.group() for t in texts if (m := _RETURN_STORY.search(t))), None)
    if story is None:
        return SignalOutcome(
            PAYMENT_PROOF_SOURCE,
            0,
            "a payment receipt; nothing asks you to send money back",
            informative=False,
        )
    flag = _flag(
        PAYMENT_PROOF_SOURCE,
        "Shows a 'payment successful' screen and asks you to send money back: such screenshots "
        "are easy to fake",
        "'पेमेंट सफल' की स्क्रीन दिखाकर पैसे वापस मांगे गए हैं: ऐसे स्क्रीनशॉट आसानी से नकली बनते हैं",
        Severity.HIGH,
        story,
    )
    return SignalOutcome(
        PAYMENT_PROOF_SOURCE,
        PAYMENT_PROOF_SCORE,
        f"payment receipt with a request to return money ('{story}')",
        floor=PAYMENT_PROOF_FLOOR,
        red_flags=(flag,),
        scam_type=ScamType.SENT_BY_MISTAKE,
    )


def screenshot_signals(
    ctx: ScreenshotContext,
    entities: ExtractedEntities,
    rule_result: RuleResult,
    outcomes: list[SignalOutcome],
    suspicious_min: int,
) -> list[SignalOutcome]:
    sender = sender_signal(
        parse_sender(ctx.sender), entities, rule_result, outcomes, suspicious_min
    )
    proof = payment_proof_signal(ctx.is_payment_receipt, entities, rule_result)
    return [sender, *([proof] if proof else [])]


# --------------------------------------------------------------------------- local OCR


def find_sender(text: str, max_lines: int = 5) -> str | None:
    """A DLT header or phone number on one of the first lines (where apps show the sender)."""
    lines = [line.strip() for line in text.splitlines() if line.strip()][:max_lines]
    for line in lines:
        if m := DLT_HEADER.search(line.upper()):
            return m.group()
    for line in lines:
        if _PHONE_LIKE.match(line) or _EMAIL.match(line):
            return line
    return None


def looks_like_receipt(text: str) -> bool:
    return bool(_RECEIPT.search(text))


def guess_fields(text: str) -> ScreenshotContext:
    """sender / app / is_payment_receipt from OCR text alone (the local OCR's fallback)."""
    sender = find_sender(text)
    receipt = looks_like_receipt(text)
    app: AppKind = "other"
    if receipt:
        app = "payment_app"
    elif sender and _EMAIL.match(sender):
        app = "email"
    elif sender and DLT_HEADER.search(sender.upper()):
        app = "sms"
    return ScreenshotContext(sender=sender, app=app, is_payment_receipt=receipt)
