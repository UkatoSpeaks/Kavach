"""Undo filter-evasion spellings before the phrase rules run.

Scam SMS write "N0W", "t0 your", "Cl@im" or "yOur" so that keyword filters miss them. The
rules read folded copies of the normalized text in which leet characters inside words are
letters again: 0->o, 1->i (or l, in a second copy), 3->e, 4->a, 5->s, @->a. Odd capitals
need no folding (the rules read lower-cased text); like leetspeak, they are reported as
evasion (rule filter_evasion).

Never folded:
- protected spans the caller passes in: URLs, upi:// URIs, UPI IDs and emails, phone
  numbers and amounts;
- tokens that look like codes or text-speak: any other digit ("PAYTMVI20", "XX32"), two
  digits in a row ("MY400", "00AM"), a digit at the end of a longer token ("B1G1", "Vi5"),
  a digit before a unit ("Tide5kg", "5pm"), a leading digit other than 0 ("4the", "4GB":
  "for", not a hidden letter), a digit other than 0 in capitals (coupon codes like
  "WHSTD4K"), or more digits than a word would hide.

Folding replaces one character with one, so each folded copy lines up with the
lower-cased text position by position, and evidence found in it maps back to what the
message actually says (see rules.evaluate).
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass

LEET_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "@": "a"})
LEET_L = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a"})
_LEET_CHARS = frozenset("01345@")

_TOKEN_RE = re.compile(r"[A-Za-z0-9@]+")
# Two-character tokens (with a 0) are only folded into these words: "0n", "t0", "N0".
SHORT_WORDS = frozenset(
    "on to no in is so as at an of or go do me we be he it up us my by am if".split()
)
# A digit before these is a quantity, not a letter: "0days", "Tide5kg".
UNITS = frozenset(
    """
    am pm gb mb kb tb kg gm ml km cm mm hr hrs min mins sec secs day days week weeks month
    months year years yr yrs st nd rd th lakh lac lakhs cr rs inr bhk mp mah hz fps pcs pc
    """.split()
)
# First-letter-lower brand spellings that are not odd capitals: iPhone, eKYC, mAadhaar.
_BRAND_PREFIX_RE = re.compile(r"[iemk][A-Z]")
# "daysAlso", "atHome", "moreFrmMob": missing spaces before capitalized words, not evasion.
_MISSING_SPACE_RE = re.compile(r"[a-z]{2,}(?:[A-Z][a-z]*)+")


@dataclass(frozen=True)
class Folded:
    texts: tuple[str, ...]  # lower-cased; the first folds 1->i, a second (if any) 1->l
    evasions: tuple[str, ...]  # tokens as written that were leet or oddly capitalized


def _overlaps(start: int, end: int, spans: Sequence[tuple[int, int]]) -> bool:
    return any(start < e and s < end for s, e in spans)


def _case_consistent(letters: str) -> bool:
    capitalized = letters[0].isupper() and letters[1:].islower()
    return letters.islower() or letters.isupper() or capitalized


def _is_leet(token: str) -> bool:
    """A word with leet characters in it ("N0W", "B0nus", "t0", "Cl@im"), not a code."""
    leet = [i for i, c in enumerate(token) if c in _LEET_CHARS]
    if not leet:
        return False
    letters = "".join(c for c in token if c.isalpha())
    if not letters or re.search(r"[26789]|\d\d", token):
        return False
    if len(token) == 2:  # "0n", "t0"; not "4T" or "5G"
        return "0" in token and token.lower().translate(LEET_I) in SHORT_WORDS
    if "@" in token and (len(token) > 10 or not _case_consistent(letters)):
        return False  # "Bonus@JioMart", "WEDNESDAY@STAR": "at", joining two words
    if len(leet) > 1 and 3 * len(leet) > len(letters):
        return False  # "BA1GA1": more digits than a word would hide
    if len(letters) < 2 or not _case_consistent(letters):
        return False
    if letters.isupper() and any(token[i] not in "0@" for i in leet):
        return False  # "WHSTD4K", "REBU1UUYSC": codes; capitals hide only O ("N0W", "L0AN")
    for i in leet:
        rest = token[i + 1 :]
        if re.match(r"[a-z]+$", rest, re.IGNORECASE) and rest.lower() in UNITS:
            return False  # a quantity: "Tide5kg", "0days"
        before = token[:i]
        if token[i] != "0" and len(before) >= 4 and len(rest) >= 4:
            return False  # a digit joining two words: "Only1more", "least5times"
        inside = 0 < i < len(token) - 1 and token[i - 1].isalpha() and token[i + 1].isalpha()
        # "0nly", "0ffer": a leading zero before a lower-case word; not "4the" (for the).
        leading_zero = i == 0 and token[0] == "0" and rest.isalpha() and rest.islower()
        if not (inside or (leading_zero and len(rest) >= 3)):
            return False
    return True


def _is_odd_caps(token: str) -> bool:
    """'yOur', 'wOrk': a lower-case start with capitals later on."""
    return (
        len(token) >= 3
        and token.isalpha()
        and token[0].islower()
        and not token.islower()
        and _BRAND_PREFIX_RE.match(token) is None
        and _MISSING_SPACE_RE.fullmatch(token) is None
    )


def fold(cleaned: str, protected: Sequence[tuple[int, int]] = ()) -> Folded:
    """Folded copies of `cleaned` (case preserved, from extractors.clean_text) for the rules,
    and the evasive tokens found. `protected`: spans of `cleaned` that are left as written."""
    lowered = cleaned.lower()
    if len(lowered) != len(cleaned):  # a rare character whose lower case is longer
        return Folded((lowered,), ())
    chars_i, chars_l = list(lowered), list(lowered)
    evasions: list[str] = []
    for m in _TOKEN_RE.finditer(cleaned):
        token = m.group(0)
        if _overlaps(m.start(), m.end(), protected):
            continue
        if _is_leet(token):
            evasions.append(token)
            lower = token.lower()
            chars_i[m.start() : m.end()] = lower.translate(LEET_I)
            chars_l[m.start() : m.end()] = lower.translate(LEET_L)
        elif _is_odd_caps(token):
            evasions.append(token)
    texts = ("".join(chars_i),)
    if chars_l != chars_i:
        texts += ("".join(chars_l),)
    return Folded(texts, tuple(dict.fromkeys(evasions)))
