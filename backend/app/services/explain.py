"""Template explanations and advice (no LLM). Built from the triggered rules."""

from app.core.enums import ScamType, Severity, Verdict
from app.schemas.analysis import RedFlag
from app.services.rules import RuleHit

SCAM_TYPE_LABELS: dict[ScamType, tuple[str, str]] = {
    ScamType.UPI_RECEIVE_MONEY: ("UPI 'receive money' scam", "UPI से पैसे पाने का झांसा"),
    ScamType.QR_CODE: ("QR code scam", "QR कोड धोखाधड़ी"),
    ScamType.SENT_BY_MISTAKE: ("'sent by mistake' refund scam", "'गलती से पैसे भेजे' वाला धोखा"),
    ScamType.PHISHING_LINK: ("phishing scam (fake link or notice)",
                             "फ़िशिंग धोखा (नकली लिंक या नोटिस)"),
    ScamType.TASK_JOB: ("task-based job scam", "टास्क वाली नौकरी का धोखा"),
    ScamType.FAKE_CUSTOMER_CARE: ("fake customer care scam", "नकली कस्टमर केयर धोखा"),
    ScamType.GENERIC: ("scam", "धोखाधड़ी"),
}  # fmt: skip

REPORT_EN = "Report it at cybercrime.gov.in or call the cyber helpline 1930."
REPORT_HI = "cybercrime.gov.in पर शिकायत करें या साइबर हेल्पलाइन 1930 पर कॉल करें।"
NEVER_SHARE_EN = "Never share your OTP, UPI PIN, CVV or passwords with anyone, even bank staff."
NEVER_SHARE_HI = "अपना OTP, UPI पिन, CVV या पासवर्ड किसी को न बताएं, बैंक कर्मचारी को भी नहीं।"

# (english, hindi) advice per scam type; the report line is appended automatically.
ADVICE: dict[ScamType, list[tuple[str, str]]] = {
    ScamType.UPI_RECEIVE_MONEY: [
        ("You never need to enter your UPI PIN or scan a QR code to receive money.",
         "पैसे पाने के लिए कभी UPI पिन डालने या QR स्कैन करने की ज़रूरत नहीं होती।"),
        ("Decline collect requests from people you don't know.",
         "अनजान लोगों की पेमेंट रिक्वेस्ट स्वीकार न करें।"),
    ],
    ScamType.QR_CODE: [
        ("Scanning a QR code is only for paying, never for receiving money.",
         "QR कोड स्कैन करना सिर्फ पैसे देने के लिए होता है, पैसे पाने के लिए नहीं।"),
        ("Check the payee name in your UPI app before you enter your PIN.",
         "पिन डालने से पहले UPI ऐप में पाने वाले का नाम ज़रूर देखें।"),
    ],
    ScamType.SENT_BY_MISTAKE: [
        ("Check your bank app or statement, not the SMS, to see if money really arrived.",
         "पैसे सच में आए या नहीं, यह SMS से नहीं, बैंक ऐप या स्टेटमेंट से जांचें।"),
        ("If money really came by mistake, let the sender raise it with their bank. Don't "
         "send it back yourself.",
         "अगर सच में गलती से पैसे आए हैं, तो भेजने वाले को उसके बैंक से संपर्क करने दें। खुद पैसे वापस न भेजें।"),
    ],
    ScamType.PHISHING_LINK: [
        ("Don't click the link. Type the official website yourself or use the official app.",
         "लिंक पर क्लिक न करें। आधिकारिक वेबसाइट खुद टाइप करें या आधिकारिक ऐप इस्तेमाल करें।"),
        ("Banks, electricity boards and India Post don't ask you to pay or update KYC via "
         "SMS links or personal numbers.",
         "बैंक, बिजली विभाग और इंडिया पोस्ट SMS लिंक या निजी नंबर से पेमेंट या KYC अपडेट नहीं मांगते।"),
        ("Verify by calling the number printed on your bill, card or the official website.",
         "बिल, कार्ड या आधिकारिक वेबसाइट पर दिए नंबर पर कॉल करके पुष्टि करें।"),
    ],
    ScamType.TASK_JOB: [
        ("Real jobs never ask you to pay, deposit or 'recharge' to unlock tasks or earnings.",
         "असली नौकरी में टास्क या कमाई अनलॉक करने के लिए कभी पैसे जमा नहीं कराए जाते।"),
        ("Don't join Telegram or WhatsApp groups that pay for likes or reviews.",
         "लाइक या रिव्यू के बदले पैसे देने वाले टेलीग्राम/व्हाट्सऐप ग्रुप में न जुड़ें।"),
    ],
    ScamType.FAKE_CUSTOMER_CARE: [
        ("Never install AnyDesk, TeamViewer or other screen-sharing apps because a caller "
         "asked you to.",
         "किसी कॉलर के कहने पर AnyDesk, TeamViewer जैसे स्क्रीन शेयर ऐप कभी इंस्टॉल न करें।"),
        ("Get customer care numbers only from the company's official app or website.",
         "कस्टमर केयर नंबर सिर्फ कंपनी के आधिकारिक ऐप या वेबसाइट से लें।"),
        ("Don't install .apk files sent over SMS or WhatsApp.",
         "SMS या व्हाट्सऐप पर भेजी गई .apk फ़ाइल इंस्टॉल न करें।"),
    ],
    ScamType.GENERIC: [(NEVER_SHARE_EN, NEVER_SHARE_HI)],
}  # fmt: skip
SAFE_ADVICE = [
    ("No common scam signs were found, but stay alert.",
     "कोई आम धोखाधड़ी का संकेत नहीं मिला, फिर भी सावधान रहें।"),
    (NEVER_SHARE_EN, NEVER_SHARE_HI),
    ("If in doubt, check through the official app or website.",
     "शक हो तो आधिकारिक ऐप या वेबसाइट से जांच करें।"),
]  # fmt: skip
MAX_ADVICE = 4
MAX_REASONS = 4
_SEVERITY_RANK = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


def explain(
    verdict: Verdict, score: int, scam_type: ScamType | None, flags: list[RedFlag]
) -> tuple[str, str]:
    """(explanation_en, explanation_hi). Reasons are the red flags, most severe first."""
    ranked = sorted(flags, key=lambda f: _SEVERITY_RANK[f.severity])[:MAX_REASONS]
    reasons_en = "; ".join(f.message for f in ranked)
    reasons_hi = "; ".join(f.message_hi or f.message for f in ranked)
    label_en, label_hi = SCAM_TYPE_LABELS[scam_type or ScamType.GENERIC]

    if verdict is Verdict.SCAM:
        en = f"High risk ({score}/100): this looks like a {label_en}. Warning signs: {reasons_en}."
        hi = f"उच्च जोखिम ({score}/100): यह {label_hi} लगता है। चेतावनी के संकेत: {reasons_hi}।"
    elif verdict is Verdict.SUSPICIOUS:
        en = (
            f"Be careful ({score}/100): this message has signs of a {label_en}. "
            f"Warning signs: {reasons_en}. Verify through official channels before acting."
        )
        hi = (
            f"सावधान ({score}/100): इस संदेश में {label_hi} के संकेत हैं। "
            f"चेतावनी के संकेत: {reasons_hi}। कुछ भी करने से पहले आधिकारिक माध्यम से जांच करें।"
        )
    else:
        en = f"Low risk ({score}/100): no common scam patterns were found."
        hi = f"कम जोखिम ({score}/100): कोई आम धोखाधड़ी का तरीका नहीं मिला।"
        if flags:
            en += f" Minor signs: {reasons_en}."
            hi += f" छोटे संकेत: {reasons_hi}।"
    return en, hi


def advice_for(
    verdict: Verdict, scam_type: ScamType | None, hits: list[RuleHit], hindi: bool = False
) -> list[str]:
    """2-4 advice lines for the scam type, in Hindi if `hindi`."""
    lang = 1 if hindi else 0
    if verdict is Verdict.SAFE:
        return [pair[lang] for pair in SAFE_ADVICE]

    pairs = list(ADVICE[scam_type or ScamType.GENERIC])
    asks_credentials = any(h.rule.id == "credential_request" for h in hits)
    if asks_credentials and (NEVER_SHARE_EN, NEVER_SHARE_HI) not in pairs:
        pairs.insert(0, (NEVER_SHARE_EN, NEVER_SHARE_HI))
    pairs = pairs[: MAX_ADVICE - 1] + [(REPORT_EN, REPORT_HI)]
    return [pair[lang] for pair in pairs]
