"""Weighted rule engine. Rules are data: an id, bilingual descriptions, a scam type, a weight
and a pure check function (normalized_text, entities) -> evidence | None.

Phrase lists cover English, Hinglish and Devanagari and are matched against
ExtractedEntities.rule_texts: the normalized text (lower-cased, NFKC, invisible characters
removed) with leetspeak folded back ("N0W" -> "now", app/services/normalize.py). Evidence is
mapped back to the words as written, so the frontend can highlight it.
Most text rules look for two phrase groups within a small window of clauses, so
"PIN" in one message and "receive" three paragraphs later does not count.
"""

import math
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from app.core.config import RULE_WEIGHTS, SUPPORTING_ONLY_MAX_SCORE, SUPPORTING_RULES
from app.core.enums import ScamType
from app.schemas.entities import ExtractedEntities, ExtractedURL

Check = Callable[[str, ExtractedEntities], str | None]


@dataclass(frozen=True)
class Rule:
    id: str
    description_en: str
    description_hi: str
    scam_type: ScamType
    weight: float
    check: Check


@dataclass(frozen=True)
class RuleHit:
    rule: Rule
    evidence: str


@dataclass(frozen=True)
class RuleResult:
    hits: list[RuleHit]
    score: int  # 0-100
    scam_type: ScamType | None
    type_weights: dict[ScamType, float] = field(default_factory=dict)
    supporting_only: bool = False  # only SUPPORTING_RULES fired: score capped

    @property
    def max_weight(self) -> float:
        return max((h.rule.weight for h in self.hits), default=0.0)


# =========================================================================== phrase lists
# Regex fragments. \b only works for ASCII here: Python's \w does not match Devanagari
# vowel signs, so Devanagari phrases are plain substrings.

RECEIVE_MONEY = [
    r"\breceiv\w*", r"\bcredit(?:ed)?\b", r"\bclaim\w*",
    r"\bget (?:the |your )?(?:money|payment|amount|cashback|refund|prize|reward)",
    r"\bpaise? (?:lene|paane|milenge|milega|aayenge|aa jayenge)", r"\bmil(?:ega|enge|egi)\b",
    r"\baa jaye?(?:nge|ga|gi)\b", r"\bpaane\b",
    "प्राप्त", "मिलेंगे", "मिलेगा", "मिलेगी", "पाने के लिए", "आ जाएंगे", "आ जाएगा",
]  # fmt: skip
PIN_WORDS = [r"\bupi[\s-]?pin\b", r"\bm[\s-]?pin\b", r"\bpin\b(?![\s-]?code)", "पिन"]
# Awareness phrasing ("you never need a PIN to receive money") must not trigger.
PIN_NEGATION = [
    r"\bnever\b", r"\bno need\b", r"\b(?:do|does)(?: not|n't) need\b",
    r"\bnot (?:required|needed|necessary)\b", r"\bzaru?rat nahi", r"\bnahi (?:chahiye|lagta)",
    "ज़रूरत नहीं", "जरूरत नहीं", "कभी नहीं", "आवश्यकता नहीं",
]  # fmt: skip
SCAN = [r"\bscan\w*", "स्कैन"]
QR = [r"\bqr\b", r"\bq\.r\.", r"\bbarcode\b", "क्यूआर"]
QR_BAIT = [
    r"\breceiv\w*", r"\brefund\w*", r"\badvance\b", r"\bcashback\b", r"\btoken (?:amount|money)",
    r"\bpayment (?:received|credited)", r"\bget (?:the |your )?(?:money|payment|amount)",
    r"\baa jaye?(?:nge|ga|gi)\b", r"\bmil(?:ega|enge|egi)\b",
    "प्राप्त", "रिफंड", "एडवांस", "मिलेंगे", "आ जाएंगे",
]  # fmt: skip
PRIZE = [
    r"\bwon\b", r"\bwinner\b", r"\bprize\b", r"\bcashback\b", r"\breward\w*", r"\blottery\b",
    r"\blucky draw\b", r"\bjackpot\b", r"\bina+m\b", r"\bjeet\w*",
    "इनाम", "पुरस्कार", "लॉटरी", "कैशबैक", "जीत",
]  # fmt: skip
COLLECT_REQUEST = [
    r"\bcollect request\b", r"\bpayment request\b", r"\bmoney request\b", r"\brequest money\b",
    r"\b(?:accept|approve) (?:the |this |my )?(?:payment )?request\b",
    r"\brequest (?:sent|bheji|accept|approve)\w*", "रिक्वेस्ट",
]  # fmt: skip
SENT_BY_MISTAKE = [
    r"\bby mistake\b", r"\bmistakenly\b", r"\bwrongly (?:sent|transferred|credited)",
    r"\baccidentally (?:sent|transferred)", r"\bsent (?:it )?to (?:the )?wrong (?:number|account)",
    r"\bgal[a]?ti se\b", r"\bgalat (?:number|account|khate)", "गलती से", "ग़लती से",
]  # fmt: skip
RETURN_MONEY = [
    r"\breturn (?:it|the money|the amount|my money)", r"\bsend (?:it|the money|them) back\b",
    r"\bpay (?:it )?back\b", r"\brefund (?:it|the amount|me)\b",
    r"\bwapas (?:kar|bhej|de|karo|kare)\w*", r"\bwaapas\b", r"\blauta\w*",
    "वापस कर", "वापस भेज", "वापस दे", "लौटा",
]  # fmt: skip
# "Return it" is only about money when money is mentioned nearby ("return the book" is not).
# Extracted amounts and UPI IDs count too (see _money_near).
MONEY_WORDS = [
    "₹", r"\brs\b", r"\binr\b", r"\brupe\w*", r"\brupa\w*", r"\bpaise?\b", r"\bpaisa\b",
    r"\bmoney\b", r"\bamount\b", r"\bpayment\b", r"\btransfer\w*", r"\bupi\b", r"\baccount\b",
    r"\ba/c\b", r"\bkhate\b", r"\bgpay\b", r"\bphonepe\b", r"\bpaytm\b",
    "पैसे", "पैसा", "रुपये", "रुपए", "राशि", "खाते",
]  # fmt: skip
ACCOUNT_BLOCKED = [
    r"\b(?:account|a/c|acct|khata|card|sim|yono|net ?banking|wallet|upi)\b(?:\W+\w+){0,4}?"
    r"\W+(?:blocked|block ho\w*|suspended|deactivated|frozen|freezed|band ho\w*|band kar\w*"
    r"|will be closed)\b",
    r"\bkyc\b(?:\W+\w+){0,3}?\W+(?:expired|expires?|expiry|pending|incomplete|not updated"
    r"|blocked|suspended)\b",
    r"\b(?:kyc|pan|aadhaa?r)\b(?:\W+\w+){0,2}?\W+(?:update|link)"
    r" (?:karein|karo|kare|now|immediately|today)",
    r"खाता(?:\s+\S+){0,3}?\s+(?:बंद|ब्लॉक|निलंबित)",
    r"केवाईसी(?:\s+\S+){0,3}?\s+(?:समाप्त|अपडेट|लंबित)",
]  # fmt: skip
ELECTRICITY = [
    r"\belectricity\b", r"\bbijli\b", r"\bpower (?:supply|connection)\b",
    r"\belectric (?:connection|supply)\b", r"\bbses\b", r"\btata power\b",
    "बिजली", "विद्युत",
]  # fmt: skip
DISCONNECT = [
    r"\bdisconnect\w*", r"\bwill be (?:cut|stopped)\b", r"\bkat (?:jaye?gi|jaye?ga|di jaye?gi)",
    r"\bkaat (?:di|diya) jaye?(?:gi|ga)", r"\bband (?:ho|kar di) jaye?(?:gi|ga)",
    "कट जाएगा", "कट जाएगी", "काट दी जाएगी", "काट दिया जाएगा", "बंद कर दी जाएगी", "डिस्कनेक्ट",
]  # fmt: skip
HELD_ITEM = [
    r"\bparcel\b", r"\bpackage\b", r"\bshipment\b", r"\bconsignment\b", r"\bcourier\b",
    r"\bcustoms\b", r"\be-?challan\b", r"\bchallan\b", r"\btraffic (?:fine|violation)",
    "पार्सल", "चालान", "कूरियर",
]  # fmt: skip
HELD = [
    r"\bheld\b", r"\bon hold\b", r"\bpending\b", r"\bunpaid\b", r"\bundelivered\b",
    r"\bcould not be delivered\b", r"\bincomplete address\b", r"\bdelivery failed\b",
    r"\brok (?:liya|diya)\b", "रोका", "लंबित", "बकाया",
]  # fmt: skip
FEE = [
    r"\bfees?\b", r"\bpay\b", r"\bcharges?\b", r"\bpenalty\b", r"\bfine\b", r"\bshulk\b",
    "शुल्क", "भुगतान", "जुर्माना",
]  # fmt: skip
URGENCY = [
    r"\bwithin \d+ ?(?:hours?|hrs?|minutes?|mins?|days?)\b",
    r"\b(?:in|valid for|only) \d+ ?(?:hours?|hrs?)\b", r"\b\d+ ?(?:hours?|hrs?) only\b",
    r"\blast (?:warning|chance|reminder)\b", r"\bfinal (?:notice|warning)\b",
    r"\bimmediately\b", r"\burgent(?:ly)?\b", r"\bturant\b", r"\bjaldi\b",
    "तुरंत", "जल्दी", "अंतिम चेतावनी", "24 घंटे",
]  # fmt: skip
# "Text me tonight" is not pressure. A day word only counts next to a threat or a payment
# demand in the same clause ("will be disconnected tonight", "pay today").
TIME_WORDS = [r"\btoday\b", r"\btonight\b", r"\baaj\b", "आज"]
CONSEQUENCE = [
    r"\bblock(?:ed)?\b", r"\bdisconnect\w*", r"\b(?:be|get|gets|getting) cut\b", r"\bcut off\b",
    r"\bsuspend\w*", r"\bdeactivat\w*", r"\bpenalty\b", r"\blegal action\b", r"\bcourt\b",
    r"\bband (?:ho|kar)\w*(?: \w+)? jaye?(?:ga|gi|nge)\b", r"\bkat (?:jaye?(?:ga|gi)|di)\b",
    r"\bpay\b", r"\bpayment\b", r"\bbhugtan\b", r"\brecharge\b", r"\bdeposit\b",
    "बंद", "कट जा", "काट दी", "ब्लॉक", "जुर्माना", "कानूनी कार्रवाई", "भुगतान",
]  # fmt: skip
EARN = [
    r"\bearn\w*", r"\bincome\b", r"\bsalary\b", r"\bpayout\b", r"\bkamai\b",
    r"\bkama(?:o|ye|yein|ein|iye)\b", r"\bpaise kamaye?",
    "कमाएं", "कमाई", "कमाइए", "कमाओ", "कमाए",
]  # fmt: skip
PER_TASK = [
    r"\bper (?:day|like|review|task|video|hour|rating|order)\b", r"\bdaily\b", r"/day\b",
    r"\ba day\b", r"\broz(?:ana)?\b", r"\bhar din\b",
    r"\blik(?:e|ing) (?:youtube |yt |instagram )?(?:videos?|posts?)", r"\bvideos? like\b",
    r"\brat(?:e|ing) (?:hotels?|restaurants?|products?|movies?)", r"\bgoogle reviews?\b",
    "प्रतिदिन", "रोज़", "रोज", "हर दिन",
]  # fmt: skip
PART_TIME = [
    r"\bpart[\s-]?time\b", r"\bwork from home\b", r"\bwfh\b", r"\bghar baithe\b",
    r"\bhome based (?:job|work)\b", "घर बैठे", "पार्ट टाइम",
]  # fmt: skip
JOB_WORDS = [
    r"\bjobs?\b", r"\bhiring\b", r"\btasks?\b", r"\bpart[\s-]?time\b", r"\bearn\w*",
    r"\bsalary\b", r"\bhr\b", r"\bnaukri\b", r"\bvacanc(?:y|ies)\b", r"\brecruit\w*",
    r"\bwork from home\b", "नौकरी", "भर्ती",
]  # fmt: skip
PREPAID_TASK = [
    r"\bprepaid tasks?\b", r"\b(?:recharge|deposit|pay|invest)\w* (?:\S+ ){0,4}?to unlock\b",
    r"\bunlock (?:the |your )?(?:next |vip |premium )?(?:task|level|earning|commission)",
    r"\bmerchant tasks?\b", r"\bvip tasks?\b", r"\btask (?:unlock|recharge)\b",
    r"\bcommission (?:task|order)s?\b",
]  # fmt: skip
CARE_WORDS = [
    r"\bcustomer (?:care|support|service)\b", r"\bhelp ?line\b", r"\bhelp ?desk\b",
    r"\btoll[\s-]?free\b", r"\brefund\w*", r"\bcomplaint\b", r"\bofficer\b", r"\bexecutive\b",
    r"\badhikari\b", r"\bsampark\b", r"\bsupport team\b",
    "कस्टमर केयर", "हेल्पलाइन", "शिकायत", "रिफंड", "अधिकारी",
]  # fmt: skip
CREDENTIALS = [
    r"\botps?\b", r"\bo\.t\.p\b", r"\bupi[\s-]?pin\b", r"\bm[\s-]?pin\b",
    r"\bpin\b(?![\s-]?code)", r"\bcvv\b", r"\bpass(?:word|code)s?\b", r"\bverification code\b",
    r"\bcard (?:number|details)\b",
    "ओटीपी", "पिन", "पासवर्ड", "सीवीवी",
]  # fmt: skip
SHARE_VERBS = [
    # not "confirm"/"enter": genuine SMS say "OTP to confirm your txn is 123456"
    r"\b(?:share|send|tell|give|provide|forward|disclose|reply with)\b",
    r"\bbata(?:o|do|dein|dijiye|iye|ye|yein|na)?\b", r"\bbhej(?:o|do|iye|ein|dijiye)?\b",
    r"\bde do\b", r"\bdedo\b", r"\bdijiye\b", r"\bbol(?:o| do)\b", r"\blikh(?:o| do)\b",
    "बताएं", "बताएँ", "बताइए", "बताओ", "बता दें", "भेजें", "भेजो", "शेयर करें", "शेयर करो",
    "दीजिए", "बोलें",
]  # fmt: skip
# "Do not share your OTP" is what genuine bank SMS say; it must not count as a request.
NEGATED_SHARE = [
    r"\b(?:do not|don't|dont|never|not to|must not|should not|shouldn't)\s+(?:\w+\s+){0,4}?"
    r"(?:share|send|tell|disclose|give|reveal|provide|forward)",
    r"\b(?:share|bata\w*|bhej\w*|de|dein|do|karein)\s+(?:\w+\s+){0,2}?(?:na|mat|nahi|nahin)\b",
    r"\b(?:na|mat|kabhi (?:bhi )?nahi?n?)\s+(?:\w+\s+)?(?:share|bata\w*|bhej\w*|de\w*)",
    r"(?:न|ना|मत)\s+(?:करें|बताएं|बताएँ|बताइए|बताओ|भेजें|दें)", r"(?:शेयर|साझा)\s+(?:न|ना|मत)",
    r"\bnever (?:ask|call)s?\b",
]  # fmt: skip
# Text aimed at an AI checker rather than at a person: telling the model to drop its
# instructions, change role or call the message safe. A genuine SMS never talks to a
# classifier, so this is itself a strong scam sign. Kept narrow: "you are now eligible" and
# "mark as read" must not match.
_GAP = r"[^.!?\n]{0,30}"
AI_MANIPULATION = [
    rf"\b(?:ignore|disregard|forget|override|skip)\b{_GAP}\b(?:previous|prior|above|earlier|"
    rf"all|your|system|original)\b{_GAP}\b(?:instructions?|prompts?|rules|guidelines)\b",
    r"\byou are now (?:an? |in |my )?(?:ai|assistant|bot|chatbot|model|dan|jailbroken|"
    r"unrestricted|(?:developer|admin|god) mode)\b",
    rf"\b(?:mark|classify|label|flag|rate|treat|report|consider)\b{_GAP}\bas\s+(?:100% )?"
    r"(?:safe|genuine|legit(?:imate)?|not (?:a )?(?:scam|fraud)|harmless)\b",
    r"\bsystem prompt\b", r"\bprompt injection\b",
    r"\b(?:pichle|pehle ke|upar ke) (?:sab |saare )?(?:instructions?|nirdesh)\b",
    rf"\b(?:isko|ise|is message ko)\b{_GAP}\bsafe\b{_GAP}\b(?:mark|batao|bolo|likho|dikhao)",
    "पिछले निर्देश", "निर्देशों को अनदेखा", "सुरक्षित मार्क",
]  # fmt: skip
# A big credit or win that has "arrived", and a link to cash it out.
FAKE_CREDIT = [
    r"(?<!to be )(?<!will be )\bcredited\b", r"\breceived?\b", r"\bdeposited\b",
    r"\badded (?:to|in|into) (?:your |ur )?(?:wallet|account|a/c|acc?t?)\b",
    r"\btransaction (?:is |was |has been )?success(?:ful(?:ly)?)?\b",
    r"\bsuccessfully (?:credited|transferred|done|added)\b",
]  # fmt: skip
CASH_OUT = [
    r"\bwithdraw(?:al)?\b", r"\bget (?:the |your )?cash\b", r"\bcash ?out\b",
    r"\b(?:move|transfer)\w* (?:\w+ ){0,2}?to (?:your |ur )?bank\b",
    r"\bdirect(?:ly)? (?:to )?(?:your |ur )?(?:bank|a/c|ac|account)\b",
    r"\bclaim(?: it)? now\b", r"\bto claim\b",
    r"\bclaim (?:your|the|it|bonus|cash|reward|amount|money|prize)\b",
]  # fmt: skip
# An offer that needs a deposit first is an ad (betting "bonus on first deposit").
DEPOSIT_FIRST = [r"\bfirst deposit\b", r"\bon (?:a |your )?deposit\b"]
FAKE_CREDIT_MIN = 1000  # promos say "Rs.250 credited as cash points"; these claim more
# "Rs.44,OOO": the scams write letter O for zero in amounts too. Possessive, so "rs.500off"
# is not read as 5000.
_AMOUNT_WITH_O = re.compile(r"(?:₹|\brs\.?|\binr)\s*(\d[\d,o]*+)(?![a-z])")
# "OI1.in/2vclen!8cpr814": a letter or digit, "!", then a code with a digit in it. Not
# Flipkart's "fkrt.it/!..." (the "!" right after the slash).
_TRACKING_SUFFIX = re.compile(r"[A-Za-z0-9]!(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{4,}(?![A-Za-z0-9])")
# Real services whose 3-5 character domain name mixes letters and digits.
KNOWN_DIGIT_DOMAINS = frozenset({"1mg.com", "zee5.com", "a23.games", "a23.com"})

ID_DOCS = [r"\baadhaa?r\b", r"\badhaa?r\b", r"\bpan\b", "आधार", "पैन"]
DOC_VERBS = SHARE_VERBS + [r"\bupload\b", r"\bupdate\b", r"\bsubmit\b", r"\bverify\b", "अपडेट"]

# Messaging links used to move job-scam victims into Telegram/WhatsApp groups.
MESSAGING_DOMAINS = frozenset({"t.me", "telegram.me", "wa.me", "whatsapp.com", "wa.link"})
SUSPICIOUS_TLDS = frozenset(
    {"xyz", "top", "click", "icu", "buzz", "shop", "live", "online", "site", "tk", "ml", "ga",
     "cf", "gq", "cyou", "sbs", "cfd", "bond", "vip", "win", "loan", "rest", "quest"}
)  # fmt: skip

# Brands scammers impersonate -> the registered domains they actually use. A URL that
# contains a brand token (or a near-miss like "paytrn", "amaz0n") on any other domain is a
# lookalike. Official domains are allowed.
BRAND_OFFICIAL_DOMAINS: dict[str, frozenset[str]] = {
    brand: frozenset(domains)
    for brand, domains in {
        "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbilife.co.in",
                "sbimf.com", "sbigeneral.in", "sbisecurities.in", "yonobusiness.sbi"},
        "yono": {"sbi.co.in", "onlinesbi.sbi", "yonobusiness.sbi", "sbiyono.sbi"},
        "hdfc": {"hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcergo.com", "hdfcsec.com",
                 "hdfcfund.com", "hdfcbank.net"},
        "icici": {"icicibank.com", "icicidirect.com", "iciciprulife.com", "icicilombard.com"},
        "axis": {"axisbank.com", "axisdirect.in", "axismf.com"},
        "kotak": {"kotak.com", "kotaksecurities.com", "kotakmf.com", "kotaklife.com"},
        "pnb": {"pnbindia.in", "netpnb.com", "pnbcard.in"},
        "paytm": {"paytm.com", "paytm.in", "paytmbank.com", "paytmmoney.com", "paytm.me"},
        "phonepe": {"phonepe.com"},
        "gpay": {"google.com", "goo.gl"},
        "googlepay": {"google.com"},
        "npci": {"npci.org.in"},
        "bhim": {"bhimupi.org.in", "npci.org.in"},
        "rbi": {"rbi.org.in"},
        "indiapost": {"indiapost.gov.in", "ippbonline.com"},
        "bses": {"bsesdelhi.com"},
        "tatapower": {"tatapower.com", "tatapower-ddl.com"},
        "parivahan": {"parivahan.gov.in"},
        "echallan": {"parivahan.gov.in"},
        "amazon": {"amazon.in", "amazon.com", "amzn.in", "amzn.to", "amazonaws.com",
                   "amazonpay.in", "media-amazon.com"},
        "flipkart": {"flipkart.com", "fkrt.it", "fkrt.co"},
        "bluedart": {"bluedart.com"},
        "delhivery": {"delhivery.com"},
        "fedex": {"fedex.com"},
    }.items()
}  # fmt: skip
_OFFICIAL_DOMAINS = frozenset().union(*BRAND_OFFICIAL_DOMAINS.values())
# Brands that are also ordinary words one typo away ("delivery") only match exactly.
NO_FUZZY_BRANDS = frozenset({"delhivery"})
# Only government bodies / banks can register these, so they are never lookalikes.
RESTRICTED_SUFFIXES = (".gov.in", ".nic.in", ".bank.in", ".fin.in", ".mil.in", ".sbi")


# =========================================================================== helpers


def _rx(patterns: Iterable[str]) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


_RX_CACHE: dict[int, re.Pattern[str]] = {}


def _compiled(patterns: list[str]) -> re.Pattern[str]:
    key = id(patterns)
    if key not in _RX_CACHE:
        _RX_CACHE[key] = _rx(patterns)
    return _RX_CACHE[key]


# Clause boundaries: sentence punctuation. A "." only ends a clause before whitespace or
# the end, so "3,250.00", "Rs.500" and URLs like "sbi-kyc.xyz/login" stay whole.
_CLAUSE_SPLIT = re.compile(r"[!?।\n]+|\.(?=\s|$)")
_EVIDENCE_MAX = 160


def _clauses(text: str) -> list[str]:
    return [c.strip() for c in _CLAUSE_SPLIT.split(text) if c.strip()]


def _snippet(text: str) -> str:
    text = text.strip()
    return text if len(text) <= _EVIDENCE_MAX else text[: _EVIDENCE_MAX - 1] + "…"


def _find(text: str, patterns: list[str]) -> str | None:
    m = _compiled(patterns).search(text)
    return m.group(0) if m else None


def _near(
    text: str,
    *groups: list[str],
    window: int = 2,
    unless: list[str] | None = None,
) -> str | None:
    """Evidence if every phrase group matches within `window` consecutive clauses.

    `unless`: skip a window if the clause holding the first group's match also matches
    one of these (e.g. "do not share" next to "OTP").
    """
    clauses = _clauses(text)
    for i in range(len(clauses)):
        chunk_clauses = clauses[i : i + window]
        chunk = " . ".join(chunk_clauses)
        if not all(_compiled(g).search(chunk) for g in groups):
            continue
        if unless is not None:
            anchor = next((c for c in chunk_clauses if _compiled(groups[0]).search(c)), chunk)
            if _compiled(unless).search(anchor):
                continue
        return _snippet(chunk)
    return None


def _tld(url: ExtractedURL) -> str:
    return url.host.rsplit(".", 1)[-1]


# Leetspeak / homoglyph folding for domain tokens: amaz0n -> amazon, paytrn -> paytm.
_LEET = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _fold(token: str) -> set[str]:
    base = token.translate(_LEET).replace("rn", "m").replace("vv", "w")
    return {base.replace("1", "l"), base.replace("1", "i")}


def _edit_distance_le1(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b, strict=True)) <= 1
    if len(a) > len(b):
        a, b = b, a
    return any(a == b[:i] + b[i + 1 :] for i in range(len(b)))


def _is_official(url: ExtractedURL, domains: frozenset[str]) -> bool:
    return url.registered_domain in domains


def _brand_in_host(host: str, suffix_labels: int) -> str | None:
    """Return the impersonated brand if any host label looks like one."""
    labels = host.split(".")[: -suffix_labels or None]
    tokens = {t for label in labels for t in re.split(r"[-_]", label) if t}
    tokens |= {label.replace("-", "") for label in labels}  # "e-challan" -> "echallan"
    for raw_token in tokens:
        for token in _fold(raw_token):
            for brand in BRAND_OFFICIAL_DOMAINS:
                if len(brand) <= 4:  # short brands (sbi, rbi, axis): whole token or prefix
                    if token == brand or token.startswith(brand):
                        return brand
                elif brand in token or (
                    brand not in NO_FUZZY_BRANDS
                    and len(token) >= 5
                    and _edit_distance_le1(token, brand)
                ):
                    return brand
    return None


def lookalike_brand(url: ExtractedURL) -> str | None:
    """The brand a URL imitates, or None. Official and restricted domains never match."""
    if url.is_ip or url.registered_domain.endswith(RESTRICTED_SUFFIXES):
        return None
    if ("." + url.host).endswith(RESTRICTED_SUFFIXES):
        return None
    suffix_labels = url.registered_domain.count(".")  # labels after the brand-able part
    brand = _brand_in_host(url.host, suffix_labels)
    if brand and not _is_official(url, BRAND_OFFICIAL_DOMAINS[brand]):
        return brand
    return None


def _all_links_official(entities: ExtractedEntities) -> bool:
    return bool(entities.urls) and all(
        u.registered_domain.endswith(RESTRICTED_SUFFIXES)
        or any(u.registered_domain in d for d in BRAND_OFFICIAL_DOMAINS.values())
        for u in entities.urls
    )


def _mobile_numbers(entities: ExtractedEntities) -> list[str]:
    return [p.raw for p in entities.phones if p.kind == "mobile"]


def _has_upi(entities: ExtractedEntities) -> bool:
    return bool(entities.upi_ids or entities.upi_uris)


# =========================================================================== checks


def _pin_to_receive(text: str, e: ExtractedEntities) -> str | None:
    hit = _near(text, PIN_WORDS, RECEIVE_MONEY)
    if hit and not _find(hit, PIN_NEGATION):
        return hit
    return None


def _scan_to_receive(text: str, e: ExtractedEntities) -> str | None:
    return _near(text, SCAN, RECEIVE_MONEY, unless=PIN_NEGATION)


def _prize_with_upi(text: str, e: ExtractedEntities) -> str | None:
    prize = _find(text, PRIZE)
    if prize and _has_upi(e):
        target = e.upi_ids[0].value if e.upi_ids else e.upi_uris[0].raw
        return _snippet(f"{prize} … {target}")
    return None


def _collect_request(text: str, e: ExtractedEntities) -> str | None:
    return _find(text, COLLECT_REQUEST)


def _scan_qr_bait(text: str, e: ExtractedEntities) -> str | None:
    return _near(text, QR, QR_BAIT)


def _upi_uri_with_amount(text: str, e: ExtractedEntities) -> str | None:
    for uri in e.upi_uris:
        if uri.am and uri.am > 0:
            return f"upi:// link pre-filled with amount {uri.am:g} (payee {uri.pa})"
    return None


def _payee_name_mismatch(text: str, e: ExtractedEntities) -> str | None:
    for uri in e.upi_uris:
        if not uri.pn or not uri.pa or "@" not in uri.pa:
            continue
        local = re.sub(r"[^a-z]", "", uri.pa.split("@", 1)[0])
        if len(local) < 3:  # phone-number VPAs can't be compared with a name
            continue
        names = re.findall(r"[a-z]{3,}", uri.pn.lower())
        if names and not any(w in local for w in names):
            return f"payee name '{uri.pn}' vs UPI ID '{uri.pa}'"
    return None


def _sent_by_mistake(text: str, e: ExtractedEntities) -> str | None:
    phrase = _find(text, SENT_BY_MISTAKE)
    if phrase and (e.amounts or e.upi_ids):
        return _near(text, SENT_BY_MISTAKE, window=1) or phrase
    return None


def _money_near(text: str, e: ExtractedEntities, group: list[str]) -> str | None:
    """Evidence if `group` matches in a clause and money is mentioned in that clause or a
    neighbouring one (a money word, an extracted amount or a UPI ID)."""
    clauses = _clauses(text)
    money = [a.raw.lower() for a in e.amounts] + [u.value for u in e.upi_ids]
    for i, clause in enumerate(clauses):
        if not _compiled(group).search(clause):
            continue
        chunk = " . ".join(clauses[max(0, i - 1) : i + 2])
        if _compiled(MONEY_WORDS).search(chunk) or any(m in chunk for m in money):
            return _snippet(clause)
    return None


def _return_money(text: str, e: ExtractedEntities) -> str | None:
    if not _find(text, SENT_BY_MISTAKE):
        return None
    return _money_near(text, e, RETURN_MONEY)


def _money_back_request(text: str, e: ExtractedEntities) -> str | None:
    """The weak version of return_money: no "sent by mistake" story (friends settling a
    loan say "I'll pay the money back" too)."""
    if _find(text, SENT_BY_MISTAKE):
        return None
    return _money_near(text, e, RETURN_MONEY)


def _short_url(text: str, e: ExtractedEntities) -> str | None:
    return next((u.raw for u in e.urls if u.is_shortener), None)


def _lookalike_domain(text: str, e: ExtractedEntities) -> str | None:
    for url in e.urls:
        brand = lookalike_brand(url)
        if brand:
            return f"{url.host} (imitates '{brand}')"
    return None


def _suspicious_tld(text: str, e: ExtractedEntities) -> str | None:
    return next((u.raw for u in e.urls if _tld(u) in SUSPICIOUS_TLDS), None)


def _account_blocked(text: str, e: ExtractedEntities) -> str | None:
    return _find(text, ACCOUNT_BLOCKED)


def _electricity_disconnection(text: str, e: ExtractedEntities) -> str | None:
    return _near(text, ELECTRICITY, DISCONNECT)


def _fee_to_release(text: str, e: ExtractedEntities) -> str | None:
    if _all_links_official(e):
        return None
    return _near(text, HELD_ITEM, HELD, FEE, window=3)


def _urgency(text: str, e: ExtractedEntities) -> str | None:
    return _find(text, URGENCY) or _near(text, TIME_WORDS, CONSEQUENCE, window=1)


def _earn_per_task(text: str, e: ExtractedEntities) -> str | None:
    return _near(text, EARN, PER_TASK)


def _part_time_high_pay(text: str, e: ExtractedEntities) -> str | None:
    phrase = _find(text, PART_TIME)
    big = [a for a in e.amounts if a.value >= 1000]
    if phrase and big:
        return f"{phrase} … {big[0].raw}"
    return None


def _messaging_link_job(text: str, e: ExtractedEntities) -> str | None:
    link = next((u.raw for u in e.urls if u.registered_domain in MESSAGING_DOMAINS), None)
    if link and _find(text, JOB_WORDS):
        return link
    return None


def _prepaid_task(text: str, e: ExtractedEntities) -> str | None:
    return _find(text, PREPAID_TASK)


def _remote_access_app(text: str, e: ExtractedEntities) -> str | None:
    return ", ".join(e.remote_access_apps) or None


def _apk_link(text: str, e: ExtractedEntities) -> str | None:
    return next(iter(e.apk_links or e.apk_files), None)


def _helpline_personal_mobile(text: str, e: ExtractedEntities) -> str | None:
    mobiles = _mobile_numbers(e)
    care = _find(text, CARE_WORDS)
    if mobiles and care:
        return f"{care} … {mobiles[0]}"
    return None


def _credential_request(text: str, e: ExtractedEntities) -> str | None:
    return _near(text, CREDENTIALS, SHARE_VERBS, window=1, unless=NEGATED_SHARE)


def _id_document_request(text: str, e: ExtractedEntities) -> str | None:
    return _near(text, ID_DOCS, DOC_VERBS, window=1, unless=NEGATED_SHARE)


def _ai_manipulation_attempt(text: str, e: ExtractedEntities) -> str | None:
    return _find(text, AI_MANIPULATION)


def largest_amount(text: str, e: ExtractedEntities) -> float:
    """Largest amount mentioned, counting "Rs.51OOO" (letter O for zero) as 51000."""
    folded = [float(m.group(1).replace(",", "").replace("o", "0"))
              for m in _AMOUNT_WITH_O.finditer(text)]  # fmt: skip
    return max([a.value for a in e.amounts] + folded, default=0.0)


def _fake_credit_alert(text: str, e: ExtractedEntities) -> str | None:
    if not e.urls or _all_links_official(e) or _find(text, DEPOSIT_FIRST):
        return None
    credit, cash_out = _find(text, FAKE_CREDIT), _find(text, CASH_OUT)
    if credit and cash_out and largest_amount(text, e) >= FAKE_CREDIT_MIN:
        return f"{credit} … {cash_out}"
    return None


def _tracking_suffix_link(text: str, e: ExtractedEntities) -> str | None:
    for u in e.urls:
        path = u.url[u.url.find(u.host) + len(u.host) :]
        if u.registered_domain not in _OFFICIAL_DOMAINS and _TRACKING_SUFFIX.search(path):
            return u.raw
    return None


def throwaway_name(url: ExtractedURL) -> bool:
    """A 3-5 character domain name mixing letters and digits: 9lp7.com, OI1.in."""
    name = url.registered_domain.split(".", 1)[0]
    return (
        3 <= len(name) <= 5
        and re.search(r"\d", name) is not None
        and re.search(r"[a-z]", name) is not None
        and not url.is_shortener
        and url.registered_domain not in KNOWN_DIGIT_DOMAINS
    )


def _throwaway_domain(text: str, e: ExtractedEntities) -> str | None:
    return next((u.raw for u in e.urls if throwaway_name(u)), None)


def _filter_evasion(text: str, e: ExtractedEntities) -> str | None:
    return " … ".join(e.evasions[:3]) or None


# =========================================================================== the rules

T = ScamType
RULES: tuple[Rule, ...] = (
    # --- receive-money UPI scam
    Rule("pin_to_receive", "Asks you to enter your UPI PIN to receive money",
         "पैसे पाने के लिए UPI पिन डालने को कहा गया है", T.UPI_RECEIVE_MONEY, 0.9,
         _pin_to_receive),
    Rule("scan_to_receive", "Asks you to scan something to receive money",
         "पैसे पाने के लिए स्कैन करने को कहा गया है", T.UPI_RECEIVE_MONEY, 0.6,
         _scan_to_receive),
    Rule("prize_with_upi", "Promises a prize, cashback or reward and gives a UPI ID",
         "इनाम या कैशबैक का लालच और साथ में UPI आईडी", T.UPI_RECEIVE_MONEY, 0.5,
         _prize_with_upi),
    Rule("collect_request", "Mentions a UPI collect/payment request to accept",
         "UPI पेमेंट रिक्वेस्ट स्वीकार करने को कहा गया है", T.UPI_RECEIVE_MONEY, 0.45,
         _collect_request),
    # --- QR scam
    Rule("scan_qr_bait", "Asks you to scan a QR code to get a refund, advance or payment",
         "रिफंड या एडवांस पाने के लिए QR कोड स्कैन करने को कहा गया है", T.QR_CODE, 0.75,
         _scan_qr_bait),
    Rule("upi_uri_with_amount", "Contains a UPI payment link with the amount already filled in",
         "UPI पेमेंट लिंक में रकम पहले से भरी हुई है", T.QR_CODE, 0.3, _upi_uri_with_amount),
    Rule("payee_name_mismatch", "The payee name does not match the UPI ID",
         "पाने वाले का नाम UPI आईडी से मेल नहीं खाता", T.QR_CODE, 0.35, _payee_name_mismatch),
    # --- sent-by-mistake refund
    Rule("sent_by_mistake", "Claims money was sent to you by mistake",
         "दावा किया गया है कि पैसे गलती से आपको भेजे गए", T.SENT_BY_MISTAKE, 0.6,
         _sent_by_mistake),
    Rule("return_money", "Claims money was sent by mistake and asks you to send it back",
         "गलती से भेजे गए पैसे वापस भेजने को कहा गया है", T.SENT_BY_MISTAKE, 0.45,
         _return_money),
    Rule("money_back_request", "Asks you to send money back",
         "पैसे वापस भेजने को कहा गया है", T.SENT_BY_MISTAKE, 0.2, _money_back_request),
    # --- phishing links / fake notices
    Rule("fake_credit_alert",
         "Claims a large amount was credited to you and gives a link to withdraw it",
         "बड़ी रकम जमा होने का दावा और उसे निकालने के लिए लिंक दिया गया है", T.PHISHING_LINK,
         RULE_WEIGHTS["fake_credit_alert"], _fake_credit_alert),
    Rule("short_url", "Uses a shortened link that hides the real website",
         "छोटा (शॉर्ट) लिंक है जो असली वेबसाइट छुपाता है", T.PHISHING_LINK,
         RULE_WEIGHTS["short_url"], _short_url),
    Rule("tracking_suffix_link",
         "Link ends in a per-recipient code after '!', as bulk scam campaigns use",
         "लिंक के आखिर में '!' के बाद हर व्यक्ति के लिए अलग कोड है, जैसा ठगी वाले मैसेज में होता है",
         T.PHISHING_LINK, RULE_WEIGHTS["tracking_suffix_link"], _tracking_suffix_link),
    Rule("throwaway_domain", "Link uses a short, random-looking domain name (like 9lp7.com)",
         "लिंक का डोमेन छोटा और बेतरतीब है (जैसे 9lp7.com)", T.PHISHING_LINK,
         RULE_WEIGHTS["throwaway_domain"], _throwaway_domain),
    Rule("lookalike_domain", "Link imitates a bank, brand or government website",
         "लिंक किसी बैंक, कंपनी या सरकारी वेबसाइट की नकल है", T.PHISHING_LINK, 0.6,
         _lookalike_domain),
    Rule("suspicious_tld", "Link uses a cheap domain ending often used by scammers",
         "लिंक का डोमेन (जैसे .xyz, .top) अक्सर ठग इस्तेमाल करते हैं", T.PHISHING_LINK, 0.3,
         _suspicious_tld),
    Rule("account_blocked", "Threatens that your account, card or KYC is blocked or expiring",
         "खाता, कार्ड या KYC बंद होने की धमकी दी गई है", T.PHISHING_LINK, 0.45,
         _account_blocked),
    Rule("electricity_disconnection", "Threatens to disconnect your electricity",
         "बिजली कनेक्शन काटने की धमकी दी गई है", T.PHISHING_LINK, 0.55,
         _electricity_disconnection),
    Rule("fee_to_release", "Asks for a fee to release a parcel or clear a pending challan",
         "पार्सल छुड़ाने या चालान के लिए शुल्क मांगा गया है", T.PHISHING_LINK, 0.5,
         _fee_to_release),
    Rule("urgency", "Pressures you to act immediately",
         "तुरंत कुछ करने का दबाव बनाया गया है", T.PHISHING_LINK, 0.3, _urgency),
    # --- task-based job scam
    Rule("earn_per_task", "Offers money per like, review, task or day",
         "हर लाइक, रिव्यू, टास्क या दिन के हिसाब से कमाई का वादा", T.TASK_JOB, 0.5,
         _earn_per_task),
    Rule("part_time_high_pay", "Part-time or work-from-home job with unusually high pay",
         "पार्ट-टाइम या घर बैठे काम के लिए बहुत ज़्यादा कमाई का वादा", T.TASK_JOB, 0.45,
         _part_time_high_pay),
    Rule("messaging_link_job", "Job offer that moves you to Telegram or WhatsApp",
         "नौकरी का ऑफर जो टेलीग्राम या व्हाट्सऐप पर बुलाता है", T.TASK_JOB, 0.45,
         _messaging_link_job),
    Rule("prepaid_task", "Asks you to pay or recharge to unlock tasks or earnings",
         "टास्क या कमाई अनलॉक करने के लिए पैसे जमा करने को कहा गया है", T.TASK_JOB, 0.75,
         _prepaid_task),
    # --- fake customer care
    Rule("remote_access_app", "Asks you to install a screen-sharing app",
         "स्क्रीन शेयर करने वाला ऐप (जैसे AnyDesk) इंस्टॉल करने को कहा गया है",
         T.FAKE_CUSTOMER_CARE, 0.65, _remote_access_app),
    Rule("apk_link", "Asks you to install an app file (.apk) from outside the Play Store",
         "प्ले स्टोर के बाहर से ऐप फ़ाइल (.apk) इंस्टॉल करने को कहा गया है",
         T.FAKE_CUSTOMER_CARE, 0.8, _apk_link),
    Rule("helpline_personal_mobile", "A 'helpline' or 'officer' that is a personal mobile number",
         "'हेल्पलाइन' या 'अधिकारी' का नंबर एक निजी मोबाइल नंबर है", T.FAKE_CUSTOMER_CARE,
         0.4, _helpline_personal_mobile),
    # --- generic
    Rule("credential_request", "Asks you to share an OTP, PIN, CVV or password",
         "OTP, पिन, CVV या पासवर्ड बताने को कहा गया है", T.GENERIC, 0.85,
         _credential_request),
    Rule("id_document_request", "Asks you to share or update Aadhaar/PAN details",
         "आधार/पैन की जानकारी भेजने या अपडेट करने को कहा गया है", T.GENERIC, 0.35,
         _id_document_request),
    Rule("filter_evasion",
         "Writes words with digits or odd capitals (N0W, yOur) to slip past spam filters",
         "स्पैम फ़िल्टर से बचने के लिए शब्दों में अंक या अजीब बड़े अक्षर लिखे गए हैं (N0W, yOur)",
         T.GENERIC, RULE_WEIGHTS["filter_evasion"], _filter_evasion),
    # Weight 0.8: with any other scam sign (e.g. a UPI ID) it reaches "scam" without the LLM,
    # whose judgement is exactly what the message tries to hijack.
    Rule("ai_manipulation_attempt",
         "Contains instructions aimed at an AI or scam checker (e.g. 'mark this as safe')",
         "संदेश में AI या जांच करने वाले सिस्टम को धोखा देने वाले निर्देश हैं", T.GENERIC, 0.8,
         _ai_manipulation_attempt),
)  # fmt: skip
RULES_BY_ID = {rule.id: rule for rule in RULES}


# =========================================================================== evaluation


def saturating_score(weights: Iterable[float]) -> int:
    """1 - prod(1 - w), scaled to 0-100. Each extra rule adds less than the last."""
    return round(100 * (1 - math.prod(1 - w for w in weights)))


# Separators rule evidence joins its pieces with ("clause . clause", "phrase … entity").
_EVIDENCE_JOINS = re.compile(r"( \. | … |…)")


def _unfold(evidence: str, folded: str, original: str) -> str:
    """Evidence found in a folded text, as written in the original ("withdraw n0w", not
    "withdraw now"). Folding keeps positions, so each piece maps back by index."""
    if folded == original:
        return evidence
    out = []
    for piece in _EVIDENCE_JOINS.split(evidence):
        at = folded.find(piece) if piece and not _EVIDENCE_JOINS.fullmatch(piece) else -1
        out.append(original[at : at + len(piece)] if at >= 0 else piece)
    return "".join(out)


def evaluate(entities: ExtractedEntities, rules: Iterable[Rule] = RULES) -> RuleResult:
    rules = tuple(rules)
    original = entities.normalized_text
    texts = [t for t in entities.rule_texts if len(t) == len(original)] or [original]
    found: dict[str, RuleHit] = {}
    for text in texts:  # the 1->l copy only adds rules the 1->i copy missed
        for rule in rules:
            if rule.id not in found and (evidence := rule.check(text, entities)) is not None:
                found[rule.id] = RuleHit(rule, _unfold(evidence, text, original))
    hits = [found[r.id] for r in rules if r.id in found]
    hits.sort(key=lambda h: h.rule.weight, reverse=True)

    type_weights: dict[ScamType, float] = {}
    for hit in hits:
        t = hit.rule.scam_type
        type_weights[t] = round(type_weights.get(t, 0.0) + hit.rule.weight, 4)

    # Generic signs (an OTP request) fit every type; only use GENERIC if nothing else fired.
    specific = {t: w for t, w in type_weights.items() if t is not ScamType.GENERIC}
    pool = specific or type_weights
    scam_type = max(pool, key=lambda t: (pool[t], _max_weight(hits, t))) if pool else None

    score = saturating_score(h.rule.weight for h in hits)
    supporting_only = bool(hits) and all(h.rule.id in SUPPORTING_RULES for h in hits)
    if supporting_only:
        score = min(score, SUPPORTING_ONLY_MAX_SCORE)
    return RuleResult(
        hits=hits,
        score=score,
        scam_type=scam_type,
        type_weights=type_weights,
        supporting_only=supporting_only,
    )


def _max_weight(hits: list[RuleHit], scam_type: ScamType) -> float:
    return max(h.rule.weight for h in hits if h.rule.scam_type is scam_type)
