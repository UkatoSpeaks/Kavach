"""Shared by the dataset scripts: paths, the unified schema, text normalization, the
language heuristic and CSV helpers. Standard library only."""

import csv
import hashlib
import re
import unicodedata
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from app.core.config import BACKEND_DIR
from app.core.enums import ScamType

DATASETS_DIR = BACKEND_DIR / "data" / "datasets"
RAW_DIR = DATASETS_DIR / "raw"  # public downloads (gitignored)
COLLECTED_DIR = DATASETS_DIR / "collected"  # your real messages, NOT anonymized (gitignored)
SYNTHETIC_DIR = DATASETS_DIR / "synthetic"  # Groq generations (anonymized parents only)
PROCESSED_DIR = DATASETS_DIR / "processed"  # anonymized, unified CSVs only
REPORTS_DIR = BACKEND_DIR / "ml" / "reports"

LABELS = ("scam", "genuine")
# Public datasets keep their own labels: their "spam" mixes promotions with scams, so it
# is not our "scam" (see data/datasets/README.md).
OOD_LABELS = ("spam", "smishing")
V1_SCAM_TYPES = tuple(t.value for t in ScamType)

# The unified schema of every processed CSV.
COLUMNS = (
    "id", "text", "label", "original_label", "scam_type", "language", "source", "dataset",
    "is_synthetic", "is_indian", "parent_id", "split",
)  # fmt: skip

_DEVA_RE = re.compile(r"[ऀ-ॿ]")
_LATIN_WORD_RE = re.compile(r"[a-z]+")
_WS_RE = re.compile(r"\s+")

# Frequent romanized-Hindi words that are not English words. Two or more hits in a Latin-
# script message make it Hinglish.
HINGLISH_WORDS = frozenset(
    """
    aap aapka aapke aapki aapko apna apne apni hai hain ho hoga hogi hoge tha thi the kar karo
    karein karna karke kare kiya kijiye kijie dijiye dijie diya diye de do dena lena liye
    mein mera meri mere tera teri tumhara tumhare hum humara hamara yeh ye woh wo kya kyun
    kyunki nahi nahin nhi mat bhi aur ya par pe se ko ka ki ke ek sirf abhi turant jaldi
    paisa paise rupaye wapas galti bhej bheja bheje bhejo raha rahi rahe gaya gayi gaye jayega
    jayegi milega milegi mila mili baje aaj kal raat din ghar baithe kamaye kamao roz bhai
    bhaiya didi ji haan theek accha acha sahab bijli kat band hoga lijiye batao bata
    """.split()
)
# Short English words the list above would otherwise overlap with ("do", "to", "par" ...)
# only count when the message has few real English words; see guess_language.
_AMBIGUOUS = frozenset({"do", "de", "par", "the", "ho", "ya", "se", "ki", "ke", "ka", "mat",
                        "bata", "band", "aur", "pe", "kal", "din", "ek"})  # fmt: skip


def normalize_for_hash(text: str) -> str:
    """Casefolded, NFKC, whitespace-collapsed: two messages that differ only in case,
    spacing or look-alike Unicode forms get the same hash."""
    text = unicodedata.normalize("NFKC", text).casefold()
    return _WS_RE.sub(" ", text).strip()


def clean(text: str) -> str:
    """What is stored: NFC, stray whitespace collapsed, nothing else changed."""
    return _WS_RE.sub(" ", unicodedata.normalize("NFC", text)).strip()


def text_id(text: str) -> str:
    """Stable id of a message: the hash of its normalized text."""
    return hashlib.sha256(normalize_for_hash(text).encode()).hexdigest()[:16]


def tokens(text: str) -> set[str]:
    return set(re.findall(r"\w+", normalize_for_hash(text)))


def jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def guess_language(text: str) -> str:
    """en | hi | hinglish. Devanagari-heavy -> hi; Latin script with several romanized
    Hindi words -> hinglish; otherwise en. A heuristic, good enough for a breakdown."""
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return "en"
    deva = sum(1 for c in letters if _DEVA_RE.match(c))
    if deva / len(letters) > 0.3:
        return "hi"
    words = _LATIN_WORD_RE.findall(text.lower())
    strong = sum(1 for w in words if w in HINGLISH_WORDS and w not in _AMBIGUOUS)
    weak = sum(1 for w in words if w in _AMBIGUOUS)
    if strong >= 2 or (strong >= 1 and weak >= 2):
        return "hinglish"
    return "en"


def as_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def read_csv(path: Path) -> list[dict[str, str]]:
    # utf-8-sig: Excel on Windows saves CSVs with a BOM.
    with path.open(encoding="utf-8-sig", newline="") as f:
        return [dict(row) for row in csv.DictReader(f)]


def write_csv(path: Path, rows: Iterable[Mapping[str, Any]], columns: Iterable[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = list(columns)
    n = 0
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow({c: _cell(row.get(c)) for c in cols})
            n += 1
    return n


def _cell(value: Any) -> Any:
    if isinstance(value, bool):
        return "true" if value else "false"
    return "" if value is None else value
