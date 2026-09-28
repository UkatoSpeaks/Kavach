"""Pre-classify public "spam" into promo_spam, scam or uncertain, offline.

Most Indian spam is promotional (sales, recharge plans, betting ads), so "spam" is not our
"scam". This runs the offline rules pipeline (pipeline.analyze_text: extractors, rules,
UPI check; no network, no LLM) and adds a few labelling-only heuristics:

- promo cues: sale/offer/% off/T&C wording and well-known brand names;
- scam cues of its own: fake credit/winnings alerts with a "withdraw / get cash" link, loan
  "approved" + link, random 4-5 character domains with digits (9lp7.com), leetspeak (N0W,
  yOur). The rules now have versions of most of these (fake_credit_alert, throwaway_domain,
  filter_evasion); the labelling heuristics stay as they were so labels already reviewed
  keep their meaning.

Decision:
- a strong scam sign (a rule other than the weak link/urgency ones, or a fake-credit /
  loan-approved lure) and no promo wording -> scam (a brand name alone does not count:
  scams name brands too); with promo wording -> scam only if the pipeline's verdict is
  scam or it is a fake-credit lure, else uncertain;
- only a soft scam sign (random domain, leetspeak) -> scam without promo cues, else uncertain;
- promo cues and no scam sign -> promo_spam (short links and "today only" are normal in ads);
- nothing either way -> uncertain.

Every result goes to review in part (ml/prepare_dataset.py writes review_queue.csv).
"""

import re
from dataclasses import dataclass

from app.core.config import Settings, get_settings
from app.core.enums import ScamType, Verdict
from app.schemas.entities import ExtractedEntities
from app.services import pipeline, upi
from ml.common import OTHER_SCAM_TYPE

UNCERTAIN = "uncertain"

# Rules that fire on ordinary brand promotions too: they never make a message a scam alone.
# throwaway_domain and filter_evasion count through random_domain/leetspeak below instead.
WEAK_RULES = frozenset({"short_url", "suspicious_tld", "urgency", "money_back_request",
                        "upi_unknown_handle", "throwaway_domain", "tracking_suffix_link",
                        "filter_evasion"})  # fmt: skip

PROMO_CUES = re.compile(
    "|".join([
        r"\b\d{1,3} ?% ?(?:off|discount|cashback|bonus)\b", r"\boffers?\b", r"\bsale\b",
        r"\bdiscounts?\b", r"\bt ?& ?cs?a?\b", r"\btnc\b", r"\bcoupons?\b", r"\buse code\b",
        r"\bbuy ?\d+,? ?get ?\d+\b", r"\bbogo\b", r"\b(?:reward|bonus) points\b",
        r"\bapply now\b", r"\bcashback\b",
        r"\bpromo ?code\b", r"\b(?:shop|buy|order|book|download|install|subscribe) now\b",
        r"\bdeals?\b", r"\bflat (?:rs\.? ?|₹ ?|inr ?)?\d", r"\bfree (?:delivery|shipping|data"
        r"|talktime|trial|cash|spins?|bets?)\b", r"\bunlimited (?:calls|data|5g)\b",
        r"\bplans? (?:starting|start|at|@|of)\b", r"\b(?:recharge|pack) (?:of|with|@)\b",
        r"\d ?(?:gb|mb)/day\b", r"\bnew (?:arrivals?|collection|launch)\b", r"\bexclusive\b",
        r"\bto (?:unsubscribe|opt[ -]?out)\b", r"\bsms stop\b", r"\bdeposit bonus\b",
        r"\bwelcome bonus\b", r"\bcashback offer\b", r"\bmega (?:sale|contest)\b",
        r"\blimited (?:period|time) (?:offer|deal)\b", r"\bvalid (?:till|until|on|for)\b",
        r"\bbest price\b", r"\bupto \d", r"\bup to \d", r"\bstarting (?:at|from|@)\b",
    ]),
    re.IGNORECASE,
)  # fmt: skip

# Brands that send promotional SMS in India. A mention is a promo cue, not proof: scams
# impersonate brands too, which is why lookalike links and credential requests override it.
KNOWN_BRANDS = frozenset(
    """
    myntra flipkart amazon ajio nykaa meesho snapdeal tatacliq swiggy zomato blinkit zepto
    bigbasket jiomart dominos domino's kfc mcdonald's mcdonalds dunzo airtel jio vi vodafone
    idea bsnl dream11 my11circle mpl winzo rummycircle junglee paytm phonepe cred mobikwik
    hdfc icici sbi axis kotak indusind idfc bajaj tanishq reliance croma makemytrip goibibo
    oyo ixigo redbus easemytrip uber ola rapido lenskart pharmeasy 1mg netmeds apollo
    unacademy byju's byjus vedantu upgrad policybazaar zerodha groww upstox hotstar netflix
    sonyliv zee5 bookmyshow decathlon pantaloons westside lifestyle bewakoof mamaearth boat
    samsung oneplus xiaomi realme vivo oppo tata titan puma adidas nike levis urbanic firstcry
    dmart spencers zudio trends lic muthoot manappuram bajajfinserv kreditbee moneyview
    navi slice fibe cashe indibet parimatch 1xbet stake fun88 dafabet wynk jiocinema
    """.split()
)

# Labelling-only scam heuristics (see the module docstring).
# They run on a copy with zeros inside words turned back into "o" ("t0" -> "to").
_FAKE_CREDIT = re.compile(
    r"\b(?:credited|received?|deposited|added|won|winnings?|transaction (?:is )?successful(?:ly)?"
    r"(?: done)?|successfully (?:credited|transferred|done))\b",
    re.IGNORECASE,
)
_CASH_OUT = re.compile(
    r"\b(?:withdraw\w*|get cash|claim\w*|redeem\w*|collect (?:it|now|your)|cash ?out|"
    r"(?:transfer|move) (?:it )?(?:directly )?to (?:your )?bank)\b",
    re.IGNORECASE,
)
# "Rs.44,OOO": scammers write letter O for zero in amounts, too.
_AMOUNT = re.compile(r"(?:rs\.?|₹|inr)\s*(\d[\d,oO]*)", re.IGNORECASE)
FAKE_CREDIT_MIN = 1000  # promos say "Rs.250 credited as cash points"; the scams claim more
_ZERO_IN_WORD = re.compile(r"(?<=[A-Za-z])0|0(?=[A-Za-z])")
_LOAN_APPROVED = re.compile(
    r"\bloan\b[^.!?\n]{0,40}\b(?:approved|sanctioned|disbursed|credited)\b", re.IGNORECASE
)
# A word of letters with a zero in it ("N0W", "0N"; not "00AM", "100GB"), or a capital
# vowel after one or two lower-case letters ("yOur"; not "iPhone", nor "daysAlso", a
# missing space).
_ZERO_FOR_O = re.compile(
    r"\b(?!0+(?:am|pm|gb|mb|kb|kg|ml|g|l|d)\b)(?=[a-z0]*[a-z])(?=[a-z0]*0)[a-z0]{2,}\b",
    re.IGNORECASE,
)
_ODD_CAPITAL = re.compile(r"\b[a-z]{1,2}[AEIOU][a-z]+\b")


def random_domain(e: ExtractedEntities) -> str | None:
    """A throwaway domain like 9lp7.com: a 3-5 character name mixing letters and digits."""
    for u in e.urls:
        name = u.registered_domain.split(".", 1)[0]
        if 3 <= len(name) <= 5 and re.search(r"\d", name) and re.search(r"[a-z]", name):
            return u.registered_domain
    return None


def leetspeak(text: str) -> str | None:
    """'N0W', '0N', 'yOur': digits for letters or odd capitals, used to dodge filters."""
    m = _ZERO_FOR_O.search(text) or _ODD_CAPITAL.search(text)
    return m.group(0) if m else None


def largest_amount(text: str) -> int:
    values = [int(m.group(1).translate(str.maketrans("oO", "00", ","))) for m in
              _AMOUNT.finditer(text)]  # fmt: skip
    return max(values, default=0)


def fake_credit_alert(text: str, e: ExtractedEntities) -> bool:
    """'Rs.82,850 credited to your A/c ... GET Cash NOW <link>': a big credit or win with a
    link to cash it out."""
    plain = _ZERO_IN_WORD.sub("o", text)
    return bool(
        e.urls
        and _FAKE_CREDIT.search(plain)
        and _CASH_OUT.search(plain)
        and largest_amount(text) >= FAKE_CREDIT_MIN
    )


def brands_in(text: str) -> list[str]:
    words = set(re.findall(r"[a-z0-9']+", text.lower()))
    words |= {w.removesuffix("'s") for w in words}
    return sorted(words & KNOWN_BRANDS)


def _without_links(text: str, e: ExtractedEntities) -> str:
    # Entities come from the normalized (lower-cased) text; match the links case-insensitively.
    for u in sorted(e.urls, key=lambda u: -len(u.raw)):
        text = re.sub(re.escape(u.raw), " ", text, flags=re.IGNORECASE)
    return text


@dataclass(frozen=True)
class AutoLabel:
    label: str  # scam | promo_spam | uncertain
    scam_type: str  # for scam: a v1 type or "other"
    signals: list[str]  # what decided it, most important first
    risk_score: int
    verdict: str

    @property
    def top_signals(self) -> str:
        return "; ".join(self.signals[:6])


def auto_label(text: str, settings: Settings | None = None) -> AutoLabel:
    # pipeline.analyze_text, step by step: the rules' own scam type is needed even when the
    # verdict is safe (the result's scam_type is then empty).
    timer = pipeline.Timer()
    e, rule_result = pipeline.extract_step(text, timer)
    outcomes = [o for o in [upi.upi_signal(e.upi_ids, e.upi_uris)] if o]
    result = pipeline.finish(e, rule_result, outcomes, settings or get_settings(), None, True,
                             timer).result  # fmt: skip
    codes = [f.code for f in result.red_flags]
    strong_rules = [c for c in codes if c not in WEAK_RULES]
    weak_rules = [c for c in codes if c in WEAK_RULES]

    fake_credit = fake_credit_alert(text, e)
    loan_link = bool(_LOAN_APPROVED.search(_ZERO_IN_WORD.sub("o", text)) and e.urls)
    rnd = random_domain(e)
    leet = leetspeak(_without_links(text, e))  # link slugs mix digits and capitals anyway
    promo = sorted({m.group(0).lower() for m in PROMO_CUES.finditer(text)})
    brands = brands_in(text)

    signals = [f"rule:{c}" for c in strong_rules]
    signals += ["fake_credit_alert"] * fake_credit + ["loan_approved_link"] * loan_link
    signals += [f"random_domain:{rnd}"] * bool(rnd) + [f"leetspeak:{leet}"] * bool(leet)
    signals += [f"rule:{c}" for c in weak_rules]
    signals += [f"promo:{p}" for p in promo[:3]] + [f"brand:{b}" for b in brands[:2]]

    strong = bool(strong_rules) or fake_credit or loan_link
    # Lead-generation ads and e-receipts use short random domains too (1kx.in, bl1.in); only
    # together with leetspeak is it a scam sign on its own.
    soft = bool(rnd and leet)
    # Scams name brands too ("Amazon is hiring part-time..."), so against a strong scam sign
    # only promo wording counts; a brand name alone does not.
    if strong and not promo:
        label = "scam"
    elif strong:
        label = "scam" if result.verdict is Verdict.SCAM else UNCERTAIN
    elif soft:
        label = UNCERTAIN if promo or brands else "scam"
    elif rnd or leet:
        label = UNCERTAIN
    elif promo or brands:
        label = "promo_spam"
    else:
        label = UNCERTAIN

    scam_type = ""
    if label == "scam":
        if rule_result.scam_type is not None:
            scam_type = rule_result.scam_type.value
        elif fake_credit or loan_link or rnd:
            scam_type = ScamType.PHISHING_LINK.value
        else:
            scam_type = OTHER_SCAM_TYPE
    return AutoLabel(label, scam_type, signals or ["none"], result.risk_score,
                     result.verdict.value)  # fmt: skip
