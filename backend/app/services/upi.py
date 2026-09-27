"""UPI ID and upi:// payment-link checks -> the "upi_check" signal. Pure, no I/O.

Scammers pick VPAs such as "sbi-kyc@ybl" or "refund.helpdesk@axl" and payee names such as
"SBI Refund" so the payment screen looks official. Real banks and government bodies never
collect money through a personal UPI handle.
"""

import math
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from app.core.enums import ScamType
from app.schemas.analysis import RedFlag
from app.schemas.entities import ExtractedUPI, UPIPaymentURI
from app.services.extractors import KNOWN_UPI_HANDLES
from app.services.scoring import SignalOutcome, severity_for

# Names of banks, apps and government bodies scammers put in a VPA or payee name.
BRAND_WORDS = frozenset(
    {"sbi", "yono", "hdfc", "icici", "axis", "kotak", "pnb", "paytm", "phonepe", "gpay",
     "googlepay", "amazon", "flipkart", "bhim", "npci", "rbi", "uidai", "incometax", "govt",
     "gov", "police", "cybercell", "electricity", "bijli"}
)  # fmt: skip
# Roles and bait no individual's VPA needs.
ROLE_WORDS = frozenset(
    {"kyc", "refund", "customercare", "custcare", "care", "support", "helpdesk", "helpline",
     "cashback", "reward", "rewards", "prize", "lottery", "winner", "official"}
)  # fmt: skip
IMPERSONATION_WORDS = BRAND_WORDS | ROLE_WORDS
_KEYWORDS_LONGEST_FIRST = sorted(IMPERSONATION_WORDS, key=lambda w: (-len(w), w))
# May follow a short keyword inside one token: "sbikyc", "kycupdate", "rbihelp".
_SUFFIX_WORDS = IMPERSONATION_WORDS | {
    "update", "verify", "verification", "help", "desk", "team", "office", "service",
    "services", "dept", "india", "bank", "pay", "online",
}  # fmt: skip
NOTE_BAIT_WORDS = frozenset(
    {"refund", "cashback", "prize", "reward", "kyc", "lottery", "winner", "won", "bonus",
     "gift", "verify", "verification", "unblock"}
)  # fmt: skip

# A brand's own handles, where its merchant VPAs legitimately carry its name
# (e.g. "paytmqr28...@paytm").
BRAND_HANDLES: dict[str, frozenset[str]] = {
    "paytm": frozenset({"paytm", "pthdfc", "ptsbi", "ptyes", "ptaxis"}),
    "phonepe": frozenset({"ybl", "ibl", "axl"}),
    "amazon": frozenset({"apl", "yapl", "rapl"}),
    "sbi": frozenset({"sbi"}),
    "hdfc": frozenset({"hdfcbank", "hdfc"}),
    "icici": frozenset({"icici"}),
    "axis": frozenset({"axisbank", "axis"}),
    "kotak": frozenset({"kotak"}),
    "pnb": frozenset({"pnb", "pnbpay"}),
}
# Merchant-acquirer handles missing from the extractor's consumer list.
MERCHANT_HANDLES = frozenset({"fbpe", "hdfcbankjd", "icicibank", "kmbl", "yesbankltd"})

# Final-score floor: an official-looking payee *and* a pre-filled amount or bait note is
# the textbook fake-refund QR.
IMPERSONATION_WITH_PAYMENT_FLOOR = 75

_WORD_RE = re.compile(r"[a-z]+")


@dataclass(frozen=True)
class Finding:
    code: str
    weight: float
    en: str
    hi: str
    evidence: str
    # The rules engine flags this too (it reads the same upi:// text): score, don't repeat.
    duplicate_of_rule: bool = False


def _impersonated(words: Iterable[str]) -> str | None:
    """The keyword a list of lower-case alphabetic tokens impersonates, if any."""
    for token in words:
        for kw in _KEYWORDS_LONGEST_FIRST:
            if len(kw) >= 5:
                if kw in token:
                    return kw
            elif token == kw or (token.startswith(kw) and token[len(kw) :] in _SUFFIX_WORDS):
                return kw
    return None


def _is_brand_handle(keyword: str, handle: str) -> bool:
    return handle in BRAND_HANDLES.get(keyword, frozenset())


def check_upi_id(upi: ExtractedUPI) -> list[Finding]:
    local, _, handle = upi.value.partition("@")
    findings: list[Finding] = []
    kw = _impersonated(_WORD_RE.findall(local))
    if kw and not _is_brand_handle(kw, handle):
        findings.append(Finding(
            "upi_id_impersonation", 0.6,
            f"UPI ID pretends to be '{kw}' but is an ordinary personal UPI ID",
            f"UPI आईडी '{kw}' होने का दिखावा करती है, पर यह एक आम निजी UPI आईडी है",
            upi.value,
        ))  # fmt: skip
    if handle not in KNOWN_UPI_HANDLES and handle not in MERCHANT_HANDLES:
        findings.append(Finding(
            "upi_unknown_handle", 0.35,
            f"'@{handle}' is not a known bank or UPI app handle",
            f"'@{handle}' किसी जाने-माने बैंक या UPI ऐप का हैंडल नहीं है",
            upi.value,
        ))  # fmt: skip
    return findings


def check_upi_uri(uri: UPIPaymentURI) -> list[Finding]:
    findings: list[Finding] = []
    local, _, handle = (uri.pa or "").partition("@")
    pn_words = _WORD_RE.findall((uri.pn or "").lower())

    kw = _impersonated(pn_words)
    if kw and not _is_brand_handle(kw, handle):
        findings.append(Finding(
            "upi_payee_impersonation", 0.5,
            f"Payee name '{uri.pn}' claims to be '{kw}' on a personal UPI ID",
            f"पाने वाले का नाम '{uri.pn}' खुद को '{kw}' बताता है, पर UPI आईडी निजी है",
            f"{uri.pn} ({uri.pa})",
        ))  # fmt: skip
    local_letters = re.sub(r"[^a-z]", "", local)
    names = [w for w in pn_words if len(w) >= 3]
    if len(local_letters) >= 3 and names and not any(w in local_letters for w in names):
        findings.append(Finding(
            "upi_payee_mismatch", 0.35,
            "The payee name does not match the UPI ID",
            "पाने वाले का नाम UPI आईडी से मेल नहीं खाता",
            f"payee name '{uri.pn}' vs UPI ID '{uri.pa}'", duplicate_of_rule=True,
        ))  # fmt: skip
    if uri.am and uri.am > 0:
        findings.append(Finding(
            "upi_prefilled_amount", 0.3,
            "The payment link has the amount already filled in",
            "पेमेंट लिंक में रकम पहले से भरी हुई है",
            f"amount {uri.am:g}", duplicate_of_rule=True,
        ))  # fmt: skip
    bait = sorted(set(_WORD_RE.findall((uri.tn or "").lower())) & NOTE_BAIT_WORDS)
    if bait:
        findings.append(Finding(
            "upi_bait_note", 0.45,
            f"Payment note uses bait words ({', '.join(bait)}): you would be paying, not "
            "receiving",
            f"पेमेंट नोट में लालच वाले शब्द हैं ({', '.join(bait)}): इससे आप पैसे देंगे, पाएंगे नहीं",
            f"note: {uri.tn}",
        ))  # fmt: skip
    return findings


def upi_signal(
    upi_ids: Sequence[ExtractedUPI], upi_uris: Sequence[UPIPaymentURI]
) -> SignalOutcome | None:
    """None if there is nothing to check."""
    if not upi_ids and not upi_uris:
        return None
    id_findings = [f for u in upi_ids for f in check_upi_id(u)]
    uri_findings = [f for u in upi_uris for f in check_upi_uri(u)]
    findings = id_findings + uri_findings
    checked = ", ".join([u.value for u in upi_ids] + [u.raw for u in upi_uris if not u.pa])
    if not findings:
        return SignalOutcome("upi_check", 0, f"no issues found: {checked}", informative=False)

    codes = {f.code for f in findings}
    impersonates = codes & {"upi_id_impersonation", "upi_payee_impersonation"}
    asks_payment = codes & {"upi_prefilled_amount", "upi_bait_note"}
    floor = None
    if impersonates and asks_payment:
        floor = IMPERSONATION_WITH_PAYMENT_FLOOR
    score = round(100 * (1 - math.prod(1 - f.weight for f in findings)))
    flags = {
        (f.code, f.evidence): RedFlag(
            code=f.code, message=f.en, message_hi=f.hi,
            severity=severity_for(f.weight), evidence=f.evidence,
        )
        for f in findings
        if not f.duplicate_of_rule
    }  # fmt: skip
    return SignalOutcome(
        "upi_check",
        score,
        "; ".join(f"{f.code}: {f.evidence}" for f in findings),
        floor=floor,
        red_flags=tuple(flags.values()),
        scam_type=ScamType.QR_CODE if uri_findings else None,
    )
