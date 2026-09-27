"""Replace personal data in collected messages with realistic fakes of the same format.

Every collected message goes through `anonymize_text` before it is written anywhere
under data/datasets/processed/ (ml/prepare_dataset.py calls it; there is no way around it).
Replacements are consistent within a message: the same number or name maps to the same fake.

What is replaced
- Indian mobile numbers (all of them: a personal number and a scammer's look the same, and
  the detectors only care about the format) -> 99999xxxxx, keeping the original prefix and
  separators: "+91 98765 43210" -> "+91 99999 10234".
- The name after a greeting ("Dear Rahul", "Hi Priya Sharma", "प्रिय राहुल") -> a placeholder
  name, everywhere it appears in the message. Generic greetings ("Dear Customer", "Hi
  Sir") are left alone.
- Account and card numbers: full ones after "a/c", "account", "card" ... and masked tails
  like "XX1234" / "XXXX 1234" -> "XX" + 4 fake digits.
- Emails at personal mail providers (gmail, yahoo, ...) -> a fake local part, same domain.

What is never changed: URLs and domains, UPI IDs and upi:// URIs, amounts, toll-free and
short numbers. Those are what the detectors look at. A UPI ID can contain a phone number
(9876543210@ybl); it is kept as is and `review_notes` points it out.

    uv run python -m ml.anonymize data/datasets/collected/my_sms.csv   # preview, writes nothing
    uv run python -m ml.anonymize --text "Dear Rahul, call 9876543210"
"""

import argparse
import hashlib
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from app.services.extractors import (
    _AT_ADDRESS_RE,
    _MOBILE_RE,
    _UPI_URI_RE,
    _URL_RE,
    _preceded_by_id_or_currency,
)
from ml.common import read_csv

FAKE_NAMES = ("Amit", "Neha", "Rohan", "Pooja", "Vikram", "Sneha")
FAKE_NAMES_HI = ("अमित", "नेहा", "रोहन", "पूजा", "विक्रम", "स्नेहा")
FAKE_SURNAMES = ("Verma", "Iyer", "Gupta", "Nair", "Joshi", "Das")
PERSONAL_MAIL = frozenset({
    "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", "rediffmail.com",
    "live.com", "icloud.com", "protonmail.com", "ymail.com",
})  # fmt: skip

# Words after a greeting that are not names.
NOT_NAMES = frozenset(
    """
    customer customers sir sirji madam maam ma'am mam user users member members consumer
    consumers cardholder card holder valued esteemed team all everyone friend friends there
    guys dear sir/madam client subscriber applicant candidate beneficiary investor patron
    shopper traveller passenger holder account policyholder grahak upbhokta ji bhai bhaiya
    didi uncle aunty sister brother mom mummy maa papa dad beta
    """.split()
) | {"ग्राहक", "उपभोक्ता", "सदस्य", "महोदय", "महोदया", "मित्र", "जी", "भाई", "साथी", "ग्राहकों"}

# The greeting is case-insensitive; the name must be capitalized ("hi there" is no name).
_GREETING_RE = re.compile(
    r"(?P<greet>\b(?i:dear|hi+|hello|hey|namaste|namaskar)\b[\s,]+)"
    r"(?P<name>[A-Z][a-z]{1,20}(?:\s[A-Z][a-z]{1,20})?|[A-Z]{2,20}(?:\s[A-Z]{2,20})?)\b"
    r"|(?P<greet_hi>(?:प्रिय|नमस्ते|नमस्कार)[\s,]+)(?P<name_hi>[ऀ-ॿ]+)"
)
# Full account/card numbers after a keyword, and masked tails (XX1234, XXXX-XXXX-1234, **1234).
_ACCOUNT_RE = re.compile(
    r"(?P<kw>\b(?:a/c|acct|account|card|khata|खाता)(?:\s*(?:no|number|num|ending(?:\s+with)?))?"
    r"\.?\s*[:#-]?\s*)(?P<num>\d(?:[\s-]?\d){8,17})\b",
    re.IGNORECASE,
)
_MASKED_RE = re.compile(r"\b(?P<mask>(?:[Xx*]{2,}[\s-]?)+)(?P<tail>\d{3,6})\b")
_CARD_RE = re.compile(r"(?<![\d\w])\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}(?![\d\w])")


@dataclass
class Result:
    text: str
    replaced: dict[str, str] = field(default_factory=dict)  # original -> fake
    review_notes: list[str] = field(default_factory=list)


def _digits(seed: str, n: int) -> str:
    h = int(hashlib.sha256(seed.encode()).hexdigest(), 16)
    return str(h % 10**n).zfill(n)


def _protected_spans(text: str) -> list[tuple[int, int]]:
    """URLs, upi:// URIs and name@handle addresses: never touched."""
    spans = [m.span() for m in _UPI_URI_RE.finditer(text)]
    spans += [m.span() for m in _URL_RE.finditer(text)]
    spans += [m.span() for m in _AT_ADDRESS_RE.finditer(text)]
    return spans


def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    return any(span[0] < e and s < span[1] for s, e in spans)


class _Anonymizer:
    def __init__(self, text: str) -> None:
        self.text = text
        self.map: dict[str, str] = {}
        self.notes: list[str] = []

    def fake(self, kind: str, original: str, make: Callable[[int], str]) -> str:
        key = f"{kind}:{original}"
        if key not in self.map:
            used = {v for k, v in self.map.items() if k.startswith(kind + ":")}
            i = len(used)  # a new original never shares a fake with an earlier one
            while (candidate := make(i)) in used:
                i += 1
            self.map[key] = candidate
        return self.map[key]

    def sub(self, pattern: re.Pattern[str], repl: Callable[[re.Match[str]], str | None]) -> None:
        """Replace matches outside protected spans; repl returning None keeps the match."""
        protected = _protected_spans(self.text)
        out, last = [], 0
        for m in pattern.finditer(self.text):
            if _overlaps(m.span(), protected):
                continue
            new = repl(m)
            if new is None:
                continue
            out += [self.text[last : m.start()], new]
            last = m.end()
        self.text = "".join(out) + self.text[last:]

    # --- phones
    def phone(self, m: re.Match[str]) -> str | None:
        if _preceded_by_id_or_currency(self.text, m.start()):
            return None
        num = m.group("num")
        digits = re.sub(r"\D", "", num)
        fake = self.fake("phone", digits, lambda i: "99999" + _digits(f"{digits}/{i}", 5))
        it = iter(fake)
        fake_num = "".join(next(it) if c.isdigit() else c for c in num)
        return m.group(0)[: m.start("num") - m.start()] + fake_num

    # --- account / card numbers
    def account(self, m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group("num"))
        return m.group("kw") + "XX" + self._tail(digits)

    def masked(self, m: re.Match[str]) -> str | None:
        tail = m.group("tail")
        if tail in self.map.values():  # written by account()/card() just before
            return None
        return m.group("mask") + self._tail(tail, len(tail))

    def card(self, m: re.Match[str]) -> str:
        return "XX" + self._tail(re.sub(r"\D", "", m.group(0)))

    def _tail(self, digits: str, n: int = 4) -> str:
        return self.fake(f"acct{n}", digits[-n:], lambda i: _digits(f"{digits}/{i}", n))

    # --- emails at personal providers
    def email(self, m: re.Match[str]) -> str | None:
        handle = m.group("handle").lower()
        if handle not in PERSONAL_MAIL:
            return None
        local = m.group("local")
        return self.fake("email", local.lower(), lambda i: f"user{_digits(local + str(i), 4)}")

    # --- names
    def names(self) -> None:
        found: list[tuple[str, bool]] = []
        for m in _GREETING_RE.finditer(self.text):
            name = m.group("name") or m.group("name_hi")
            hindi = m.group("name_hi") is not None
            words = name.split()
            if any(w.lower() in NOT_NAMES or w in NOT_NAMES for w in words):
                # "Dear Customer Rahul" is rare; "Dear Sir" is common. Keep only real names.
                words = [w for w in words if w.lower() not in NOT_NAMES and w not in NOT_NAMES]
                if not words:
                    continue
                name = " ".join(words)
            found.append((name, hindi))
        for name, hindi in found:
            pool = FAKE_NAMES_HI if hindi else FAKE_NAMES
            two = len(name.split()) > 1

            def make(i: int, pool: tuple[str, ...] = pool, two: bool = two) -> str:
                first = pool[i % len(pool)]
                return f"{first} {FAKE_SURNAMES[i % len(FAKE_SURNAMES)]}" if two else first

            fake = self.fake("name", name, make)
            if name.isupper():
                fake = fake.upper()
            # Every occurrence of the name, not just the one after the greeting.
            boundary = r"(?<![\wऀ-ॿ]){}(?![\wऀ-ॿ])"
            pattern = re.compile(boundary.format(re.escape(name)))
            self.sub(pattern, lambda _m, fake=fake: fake)
            # Also the first name alone ("Dear Rahul Sharma ... Rahul, please").
            first = name.split()[0]
            if first != name and len(first) > 2:
                self.sub(re.compile(boundary.format(re.escape(first))),
                         lambda _m, fake=fake: fake.split()[0])  # fmt: skip

    def emails(self) -> None:
        """Emails sit inside the protected name@handle spans, so they get their own pass."""

        def repl(m: re.Match[str]) -> str:
            new = self.email(m)
            return m.group(0) if new is None else f"{new}@{m.group('handle')}"

        self.text = _AT_ADDRESS_RE.sub(repl, self.text)

    def run(self) -> Result:
        self.names()
        # Full numbers before masked tails, both keyed on the last 4 digits, so
        # "A/c 123456789012 (XX9012)" becomes "A/c XX4821 (XX4821)".
        self.sub(_ACCOUNT_RE, self.account)
        self.sub(_CARD_RE, self.card)
        self.sub(_MASKED_RE, self.masked)
        self.sub(_MOBILE_RE, self.phone)
        self.emails()
        for m in _AT_ADDRESS_RE.finditer(self.text):
            if re.search(r"[6-9]\d{9}", m.group("local")) and "." not in m.group("handle"):
                self.notes.append(f"UPI ID contains a phone number, kept as is: {m.group(0)}")
        replaced = {k.split(":", 1)[1]: v for k, v in self.map.items()}
        return Result(self.text, replaced, self.notes)


def anonymize_text(text: str) -> Result:
    return _Anonymizer(text).run()


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]  # ₹ and Hindi on Windows
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("csv", nargs="?", type=Path, help="a collected CSV to preview")
    parser.add_argument("--text", help="anonymize one message")
    args = parser.parse_args()
    if args.text:
        texts = [args.text]
    elif args.csv:
        texts = [r.get("text", "") for r in read_csv(args.csv)]
    else:
        parser.error("give a CSV path or --text")
    changed = 0
    for i, text in enumerate(texts, 1):
        r = anonymize_text(text)
        if r.text == text and not r.review_notes:
            continue
        changed += 1
        print(f"--- {i}\n  before: {text}\n  after:  {r.text}")
        for note in r.review_notes:
            print(f"  review: {note}")
    print(f"\n{changed}/{len(texts)} messages changed. Nothing was written.")


if __name__ == "__main__":
    main()
