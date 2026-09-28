"""Load every source -> normalize -> anonymize -> dedupe -> unified schema -> processed CSVs.

Sources
- data/datasets/raw/uci_sms_spam/SMSSpamCollection (ml/download_public.py): out-of-domain
  evaluation only, never training.
- data/datasets/raw/mendeley_sms_phishing/*.csv (ml/download_public.py): smishing -> scam,
  spam -> promo_spam, ham -> genuine; is_indian=false (train/val/held-out only).
- data/datasets/raw/imc25_smishing/final_dataset_output.csv (ml/download_public.py): user-
  reported smishing, English and Hindi rows, all scam; is_indian only for Indian networks.
  Its anonymization placeholders (<URL>, <DATE_TIME>, <NAMED_ENTITY> ...) appear only in
  scam rows, so they are turned into ordinary text first (see neutralize_imc_placeholders)
  or a classifier would learn the placeholders instead of the scams.
- data/datasets/raw/india_spam_sms/spam_ham_india.csv (ml/download_public.py): real Indian
  SMS. "ham" -> genuine; "spam" is pre-classified by ml/autolabel.py into promo_spam /
  scam / uncertain (label_source "auto") unless it was reviewed (reviewed_labels.csv:
  label_source "manual" if you labelled it, "assisted" if an AI assistant did).
- data/datasets/collected/*.csv (your messages; columns as in collected_template.csv)
- data/datasets/synthetic/generated.csv (ml/generate_synthetic.py; train split only)

Outputs in data/datasets/processed/ (columns: ml.common.COLUMNS)
- ood_<dataset>.csv: the public non-Indian datasets. OUT-OF-DOMAIN evaluation only, never
  training. Their "spam" mixes promotions and scams, so `label` keeps their own word
  ("spam", "smishing") and `original_label` their exact label; only "ham" -> "genuine".
- india_spam_sms.csv: every India row after dedupe, uncertain ones included (evaluation).
- collected.csv: your collected messages, anonymized (evaluation).
- train.csv / val.csv / test.csv / heldout.csv. Rows are grouped into near-duplicate
  templates (template_groups: token Jaccard on the classifier's masked text) and whole
  groups go to one split, so no template is in both train and an evaluation set.
  heldout.csv: ~15% of the groups, every source (Indian and not), for evaluation; also every
  row whose template is in test.csv. test.csv holds only reviewed messages: yours (collected,
  or reviewed India rows; "manual") and AI-assisted reviews ("assisted"), stratified by
  label and scam_type. Every evaluation report on it states how many test labels are
  manual and how many AI-assisted, and gives metrics for each (ml/evaluate.py). It is frozen in
  split_manifest.json the first time there are enough of them, and never changes after
  that unless you pass --rebuild-test. The manifest may carry "notes" about the split
  (e.g. a bug found on it); ml/evaluate.py prints them in every test report, and a
  re-drawn split starts without them. Rows labelled by a dataset or auto-labelled never
  enter test.csv; uncertain rows are left out until reviewed; synthetic rows only to train.
- ood_uci_sms_spam.csv (all of UCI) and ood_uci_unseen.csv: the UCI rows whose template is
  in no train/val row. Mendeley copies most of UCI, so only the latter is out-of-domain for
  a model trained on these splits.
And data/datasets/review_queue.csv: every uncertain India row plus a random ~10% of the
auto-labelled scam and promo rows. Fill in my_label / my_scam_type, then run
ml/apply_review.py.

    uv run python -m ml.prepare_dataset
    uv run python -m ml.prepare_dataset --rebuild-test   # re-draw the test split (breaks
                                                          # comparability with old reports)
"""

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from ml.anonymize import anonymize_text
from ml.autolabel import UNCERTAIN, auto_label
from ml.common import (
    COLLECTED_DIR,
    COLUMNS,
    LABELS,
    PROCESSED_DIR,
    RAW_DIR,
    REVIEW_COLUMNS,
    REVIEW_QUEUE,
    REVIEWED_SOURCES,
    SYNTHETIC_DIR,
    clean,
    guess_language,
    jaccard,
    label_problem,
    load_reviewed,
    read_csv,
    text_id,
    tokens,
    write_csv,
)
from ml.features import preprocess, words

UCI_FILE = RAW_DIR / "uci_sms_spam" / "SMSSpamCollection"
MENDELEY_DIR = RAW_DIR / "mendeley_sms_phishing"
MENDELEY_DATASET = "mendeley_sms_phishing"
IMC_FILE = RAW_DIR / "imc25_smishing" / "final_dataset_output.csv"
IMC_DATASET = "imc25_smishing"
IMC_LANGUAGES = frozenset({"English", "Hindi"})  # IMC's "Hindi" includes Hinglish
# IMC "spam" is marketing mixed with lures and "" is unlabelled: left out.
IMC_SKIP_TYPES = frozenset({"spam", ""})
INDIA_FILE = RAW_DIR / "india_spam_sms" / "spam_ham_india.csv"
INDIA_DATASET = "india_spam_sms"
SYNTHETIC_FILE = SYNTHETIC_DIR / "generated.csv"
MANIFEST = PROCESSED_DIR / "split_manifest.json"

MIN_TEST_MESSAGES = 30
NEAR_DUP = 0.8  # token Jaccard at or above this: the same message with small edits
SYNTHETIC_LEAK = 0.7  # synthetic rows this close to a val/test message are dropped
# Masked-text token Jaccard at or above this puts two messages in one template group.
GROUP_JACCARD = 0.7
HELDOUT_FRAC = 0.15
REVIEW_SAMPLE = 0.10  # share of auto-labelled scam/promo rows sent to review

Row = dict[str, Any]


# ----------------------------------------------------------------------------- loading


def _row(text: str, **fields: Any) -> Row:
    text = clean(text)
    row: Row = {c: "" for c in COLUMNS}
    row.update(id=text_id(text), text=text, language=guess_language(text), is_synthetic=False,
               is_indian=False)  # fmt: skip
    row.update(fields)
    return row


def load_uci(path: Path = UCI_FILE) -> list[Row]:
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        label, sep, text = line.partition("\t")
        if not sep or not text.strip():
            continue
        rows.append(_row(
            text, label="genuine" if label == "ham" else "spam", original_label=label,
            source="UCI SMS Spam Collection", dataset="uci_sms_spam", split="ood",
            label_source="dataset",
        ))  # fmt: skip
    return rows


def _read_any_encoding(path: Path) -> list[dict[str, str]]:
    try:
        return read_csv(path)
    except UnicodeDecodeError:
        import csv

        with path.open(encoding="cp1252", newline="") as f:
            return [dict(r) for r in csv.DictReader(f)]


# Mendeley's labels -> ours. Its "spam" is mostly promotions, premium-rate services and
# property/product ads (checked on a sample); "smishing" is prize/reward lures and phishing.
MENDELEY_LABELS = {"ham": "genuine", "spam": "promo_spam", "smishing": "scam"}


def load_mendeley(directory: Path = MENDELEY_DIR) -> list[Row]:
    files = sorted(directory.glob("*.csv")) if directory.exists() else []
    if not files:
        return []
    rows = []
    for raw in _read_any_encoding(files[0]):
        r = {k.strip().lower(): (v or "") for k, v in raw.items() if k}
        label, text = r.get("label", "").strip().lower(), r.get("text", "")
        if not text.strip() or label not in MENDELEY_LABELS:
            continue
        rows.append(_row(
            text, label=MENDELEY_LABELS[label], original_label=label,
            source="Mendeley SMS Phishing Dataset (Mishra & Soni)",
            dataset=MENDELEY_DATASET, label_source="dataset",
        ))  # fmt: skip
    return rows


# IMC25 replaced personal data with placeholders. Number-like ones become a number (real
# messages have one there), links and phones a stand-in the extractors recognise, and the
# rest (names, places, dates) nothing. A placeholder glued to a word ("<URL>ease") is split.
_IMC_NUMBERLIKE = frozenset({
    "US_DRIVER_LICENSE", "US_BANK_NUMBER", "UK_NHS", "US_PASSPORT", "US_SSN", "IBAN_CODE",
    "CREDIT_CARD", "MEDICAL_LICENSE", "US_ITIN", "IP_ADDRESS", "CRYPTO",
})  # fmt: skip
_IMC_PLACEHOLDER_RE = re.compile(r"<([A-Z_]+)>")
IMC_URL = "https://link.example/masked"  # a plain link: its real domain is unknown
IMC_PHONE = "9999912345"
IMC_EMAIL = "user@mail.example"


def neutralize_imc_placeholders(text: str, shortener: str = "") -> str:
    def sub(m: re.Match[str]) -> str:
        kind = m.group(1)
        if kind == "URL":
            return f" https://{shortener}/masked " if shortener else f" {IMC_URL} "
        if kind == "PHONE_NUMBER":
            return f" {IMC_PHONE} "
        if kind == "EMAIL_ADDRESS":
            return f" {IMC_EMAIL} "
        if kind in _IMC_NUMBERLIKE:
            return " 123456 "
        return " "

    return _IMC_PLACEHOLDER_RE.sub(sub, text)


def load_imc25(path: Path = IMC_FILE) -> list[Row]:
    """Smishing Dataset IMC 2025: every row is a user-reported smishing message -> scam.
    English and Hindi only; IMC "spam" and unlabelled rows are skipped."""
    if not path.exists():
        return []
    csv.field_size_limit(10**8)
    rows = []
    with path.open(encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            imc_type = (r.get("scam_type") or "").strip()
            if r.get("language") not in IMC_LANGUAGES or imc_type in IMC_SKIP_TYPES:
                continue
            text = neutralize_imc_placeholders(r["text"], (r.get("url_shortener") or "").strip())
            if len(clean(text)) < 15:
                continue
            country = (r.get("original_network_country") or "").strip()
            rows.append(_row(
                text, label="scam", original_label=f"imc:{imc_type}",
                source="Smishing Dataset IMC 2025", dataset=IMC_DATASET,
                label_source="dataset", is_indian=country == "IND",
            ))  # fmt: skip
    return rows


_MOJIBAKE_RE = re.compile(r"[\u0080-\u00ff]{2,}")


def fix_mojibake(text: str) -> str:
    """Undo UTF-8 read as Latin-1 (up to twice): "Ã°ÂÂÂ" -> "🙏". The India
    Spam SMS file has it in ~150 ham rows, where it would be a pure dataset marker."""

    def repair(m: re.Match[str]) -> str:
        run = m.group(0)
        for _ in range(2):
            try:
                run = run.encode("latin-1").decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                break
        return run

    return _MOJIBAKE_RE.sub(repair, text)


def load_india_spam(
    path: Path = INDIA_FILE, reviewed: dict[str, dict[str, str]] | None = None
) -> list[Row]:
    """India Spam SMS Classification (columns Msg, Label = spam|ham), anonymized.

    ham -> genuine (label_source "dataset"). spam -> ml.autolabel (label_source "auto";
    label promo_spam, scam or "uncertain"). A row you reviewed takes your label
    (label_source "manual", or "assisted" for an AI-assisted review). Every row keeps
    auto_label / auto_scam_type / top_signals
    (not in COLUMNS) for the review queue.
    """
    reviewed = reviewed or {}
    rows = []
    for raw in _read_any_encoding(path):
        r = {k.strip().lower(): (v or "") for k, v in raw.items() if k}
        text, original = r.get("msg", ""), r.get("label", "").strip().lower()
        if not text.strip() or original not in {"spam", "ham"}:
            continue
        anon = anonymize_text(clean(fix_mojibake(text)))
        row = _row(anon.text, original_label=original, source=INDIA_DATASET,
                   dataset=INDIA_DATASET, is_indian=True)  # fmt: skip
        row["id"] = text_id(text)  # of the original text, like collected rows
        if original == "ham":
            row.update(label="genuine", label_source="dataset")
        else:
            auto = auto_label(anon.text)
            row.update(label=auto.label, scam_type=auto.scam_type, label_source="auto",
                       auto_label=auto.label, auto_scam_type=auto.scam_type,
                       top_signals=auto.top_signals)  # fmt: skip
        if mine := reviewed.get(row["id"]):
            row.update(
                label=mine["label"],
                scam_type=mine["scam_type"],
                label_source=mine.get("label_source") or "manual",
            )
        rows.append(row)
    return rows


def validate_collected(r: dict[str, str]) -> str | None:
    """Why a collected row is unusable, or None."""
    if not (r.get("text") or "").strip():
        return "empty text"
    label = (r.get("label") or "").strip().lower()
    return label_problem(label, (r.get("scam_type") or "").strip().lower())


def load_collected(directory: Path = COLLECTED_DIR) -> tuple[list[Row], list[str]]:
    """Every collected row, anonymized. Returns (rows, problems)."""
    rows: list[Row] = []
    problems: list[str] = []
    for path in sorted(directory.glob("*.csv")) if directory.exists() else []:
        for n, r in enumerate(read_csv(path), start=2):  # line 1 is the header
            missing = [c for c in ("text", "label") if c not in r]
            if missing:
                problems.append(f"{path.name}: missing columns {missing}; skipped the file")
                break
            why = validate_collected(r)
            if why:
                problems.append(f"{path.name}:{n}: {why}")
                continue
            anon = anonymize_text(clean(r["text"]))
            problems += [f"{path.name}:{n}: {note}" for note in anon.review_notes]
            label = r["label"].strip().lower()
            row = _row(
                anon.text, label=label, original_label=label,
                scam_type=(r.get("scam_type") or "").strip().lower(),
                source=(r.get("source") or "").strip() or "collected",
                dataset="collected", is_indian=True, label_source="manual",
            )  # fmt: skip
            # The id comes from the original text, so it stays the same if the anonymizer's
            # fakes ever change (the frozen test split is a list of ids).
            row["id"] = text_id(r["text"])
            rows.append(row)
    return rows, problems


def load_synthetic(path: Path = SYNTHETIC_FILE) -> list[Row]:
    if not path.exists():
        return []
    rows = []
    for r in read_csv(path):
        if not (r.get("text") or "").strip() or r.get("label") not in LABELS:
            continue
        rows.append(_row(
            r["text"], label=r["label"], original_label=r["label"],
            scam_type=r.get("scam_type", ""), source=r.get("source") or "groq synthetic",
            dataset="synthetic", is_synthetic=True, is_indian=True,
            parent_id=r.get("parent_id", ""), label_source="synthetic",
        ))  # fmt: skip
    return rows


# ----------------------------------------------------------------------------- dedupe


@dataclass
class DedupeReport:
    exact: int = 0
    near: int = 0
    conflicts: int = 0  # copies dropped because the same text has another label


# Whose label wins when the same text appears twice with different labels. An assisted
# review read the message itself, so it outranks the dataset's own spam/ham label.
_AUTHORITY = {"manual": 0, "assisted": 1, "dataset": 2, "auto": 3}


def _rank(row: Row) -> int:
    return _AUTHORITY.get(row.get("label_source", ""), 4)


def _near_duplicate_pairs(
    token_sets: list[set[str]], threshold: float
) -> Iterable[tuple[int, int]]:
    """(i, j), i < j, with Jaccard >= threshold. Candidates must share one of the three
    rarest tokens of j, which near-duplicates always do in practice; keeps it ~linear."""
    df: Counter[str] = Counter(t for s in token_sets for t in s)
    index: dict[str, list[int]] = defaultdict(list)
    for j, s in enumerate(token_sets):
        rare = sorted(s, key=lambda t: (df[t], t))[:3]
        seen: set[int] = set()
        for t in rare:
            for i in index[t]:
                if i in seen:
                    continue
                seen.add(i)
                a, b = token_sets[i], s
                # Jaccard can't reach the threshold if the sizes differ too much.
                if min(len(a), len(b)) < threshold * max(len(a), len(b)):
                    continue
                if jaccard(a, b) >= threshold:
                    yield i, j
            index[t].append(j)


def dedupe(rows: list[Row], threshold: float = NEAR_DUP) -> tuple[list[Row], DedupeReport]:
    """Exact duplicates (same normalized text) and near-duplicates (token Jaccard >=
    threshold) collapse to one row: the first, unless a later copy's label is more
    authoritative (manual > dataset > auto). When the same text has different labels, the
    most authoritative label wins if its copies agree; otherwise every copy is dropped."""
    report = DedupeReport()
    copies: dict[str, list[Row]] = defaultdict(list)
    for r in rows:
        copies[r["id"]].append(r)
    keep_label: dict[str, str | None] = {}  # id -> the winning label (None: drop all)
    for row_id, group in copies.items():
        if len({r["label"] for r in group}) > 1:
            best = min(map(_rank, group))
            winners = {r["label"] for r in group if _rank(r) == best}
            keep_label[row_id] = winners.pop() if len(winners) == 1 else None

    unique: list[Row] = []
    seen: set[str] = set()
    for r in rows:
        if r["id"] in keep_label and r["label"] != keep_label[r["id"]]:
            report.conflicts += 1
        elif r["id"] in seen:
            report.exact += 1
        else:
            seen.add(r["id"])
            best_copy = min((c for c in copies[r["id"]] if c["label"] == r["label"]), key=_rank)
            unique.append(best_copy)

    token_sets = [tokens(r["text"]) for r in unique]
    dropped: set[int] = set()
    for i, j in _near_duplicate_pairs(token_sets, threshold):
        if i in dropped or j in dropped or unique[i]["label"] != unique[j]["label"]:
            continue
        dropped.add(i if _rank(unique[j]) < _rank(unique[i]) else j)
    report.near = len(dropped)
    return [r for k, r in enumerate(unique) if k not in dropped], report


# ----------------------------------------------------------------------------- groups


def template_groups(rows: list[Row], threshold: float = GROUP_JACCARD) -> dict[str, str]:
    """Message id -> template group id (the id of one of its members).

    Near-duplicates by the dedupe logic (_near_duplicate_pairs), but on the classifier's
    masked text, where links, amounts, phone numbers and other numbers are already tokens:
    two copies of a template with different links or amounts match. Transitive: if A is
    close to B and B to C, all three are one group, so a template family never straddles
    two splits."""
    token_sets = [set(words(preprocess(r["text"]))) for r in rows]
    parent = list(range(len(rows)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, j in _near_duplicate_pairs(token_sets, threshold):
        a, b = find(i), find(j)
        if a != b:
            parent[max(a, b)] = min(a, b)
    return {r["id"]: rows[find(k)]["id"] for k, r in enumerate(rows)}


def group_bucket(group: str, heldout_frac: float, val_frac: float) -> str:
    """heldout | val | train for a whole template group, by a hash of its id (fixed)."""
    u = int(_order(group, "split"), 16) / 16**64
    if u < heldout_frac:
        return "heldout"
    return "val" if u < heldout_frac + val_frac else "train"


def _close_to_any(candidates: list[Row], held: list[Row], threshold: float) -> set[int]:
    """Indexes of candidates with token Jaccard >= threshold to some held row."""
    sets = [tokens(r["text"]) for r in held] + [tokens(r["text"]) for r in candidates]
    n = len(held)
    return {j - n for i, j in _near_duplicate_pairs(sets, threshold) if i < n <= j}


# ----------------------------------------------------------------------------- splits


def _order(row_id: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{row_id}".encode()).hexdigest()


def stratified_pick(rows: list[Row], frac: float, salt: str) -> set[str]:
    """Ids of ~frac of the rows from every (label, scam_type) group, chosen by a hash of
    the id (deterministic; no RNG). Groups of 1-2 rows stay out: too small to split."""
    groups: dict[tuple[str, str], list[Row]] = defaultdict(list)
    for r in rows:
        groups[(r["label"], r["scam_type"])].append(r)
    picked: set[str] = set()
    for group in groups.values():
        if len(group) < 3:
            continue
        k = max(1, round(len(group) * frac))
        picked |= {r["id"] for r in sorted(group, key=lambda r: _order(r["id"], salt))[:k]}
    return picked


def _fingerprint(ids: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest()[:16]


def load_manifest() -> dict[str, Any] | None:
    return json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else None


def _is_collected(row: Row) -> bool:
    return row.get("dataset") == "collected"


def test_eligible(row: Row) -> bool:
    """Only reviewed messages (yours, or AI-assisted) may enter the test split."""
    return row.get("label_source") in REVIEWED_SOURCES and not row.get("is_synthetic")


def label_note(rows: list[Row]) -> str:
    """'N manual (author), M AI-assisted (Claude)', for every report on the test split."""
    n = Counter(r.get("label_source") for r in rows)
    return f"{n['manual']} manual (author), {n['assisted']} AI-assisted (Claude)"


@dataclass
class Splits:
    train: list[Row]
    val: list[Row]
    test: list[Row]
    notes: list[str]
    heldout: list[Row] = field(default_factory=list)


def make_splits(
    real: list[Row],
    synthetic: list[Row],
    *,
    rebuild_test: bool,
    test_frac: float,
    val_frac: float,
    manifest: dict[str, Any] | None,
    today: str,
    groups: Mapping[str, str] | None = None,
    heldout_frac: float = 0.0,
) -> tuple[Splits, dict[str, Any] | None]:
    """Returns the splits and the manifest to save (None: no test split yet). Only
    test-eligible rows (see test_eligible) are drawn into test; the others (dataset or
    auto labels) go to train/val/heldout.

    With `groups` (message id -> template group, see template_groups), whole groups go to
    heldout / val / train by a hash of the group id, and every other member of a test
    message's group goes to heldout: no template is in train and in an evaluation split.
    Without it, val is a stratified pick of single messages.

    Your collected messages (dataset "collected") are for testing only: those not in test go
    to heldout, never to train or val, with their whole template group, so the model's
    vocabulary never contains an n-gram that only your messages have."""
    notes: list[str] = []
    by_id = {r["id"]: r for r in real}
    eligible = [r for r in real if test_eligible(r)]
    test_ids: set[str] = set()

    if manifest and not rebuild_test:
        test_ids = set(manifest["test_ids"])
        missing = test_ids - {r["id"] for r in eligible}
        if missing:
            notes.append(
                f"WARNING: {len(missing)} frozen test message(s) are no longer in "
                "data/datasets/collected/ or reviewed_labels.csv (deleted or edited). The test "
                "split shrank; results are not comparable with earlier reports. Restore them, "
                "or accept this with --rebuild-test."
            )
        test_ids -= missing
        notes.append(f"test split: frozen since {manifest['created']} ({len(test_ids)} messages)")
    elif len(eligible) < MIN_TEST_MESSAGES:
        notes.append(
            f"NO INDIAN TEST SPLIT YET: {len(eligible)} reviewed message(s) (collected, "
            f"reviewed or AI-assisted), need at least {MIN_TEST_MESSAGES}. Add more to "
            "data/datasets/collected/ or review more rows, and re-run."
        )
        if manifest and rebuild_test:
            notes.append("--rebuild-test: the old frozen test split was discarded.")
        manifest = None
    else:
        test_ids = stratified_pick(eligible, test_frac, salt=f"test:{today}")
        verb = "re-drawn (--rebuild-test)" if rebuild_test and manifest else "created"
        notes.append(f"test split: {verb} with {len(test_ids)} messages; frozen from now on")
        manifest = {
            "created": today,
            "min_messages": MIN_TEST_MESSAGES,
            "test_frac": test_frac,
            "test_ids": sorted(test_ids),
            "fingerprint": _fingerprint(test_ids),
        }

    rest = [r for r in real if r["id"] not in test_ids]
    test = [dict(by_id[i], split="test") for i in sorted(test_ids)]
    if test:
        notes.append(f"Test labels: {label_note(test)}")
    heldout: list[Row] = []
    if groups is not None:

        def group_of(r: Row) -> str:
            return groups.get(r["id"], r["id"])

        test = [dict(r, group=group_of(r)) for r in test]
        test_groups = {r["group"] for r in test}
        reserved = test_groups | {group_of(r) for r in rest if _is_collected(r)}
        bucket = {
            r["id"]: "heldout" if group_of(r) in reserved
            else group_bucket(group_of(r), heldout_frac, val_frac)
            for r in rest
        }  # fmt: skip
        split_rows = {"train": [], "val": [], "heldout": []}
        for r in rest:
            split_rows[bucket[r["id"]]].append(dict(r, split=bucket[r["id"]], group=group_of(r)))
        train, val, heldout = split_rows["train"], split_rows["val"], split_rows["heldout"]
        near_test = sum(1 for r in rest if group_of(r) in reserved and not _is_collected(r))
        notes.append(
            f"template groups: {len({group_of(r) for r in real})} for {len(real)} messages; "
            f"{sum(map(_is_collected, rest))} collected message(s) outside test and "
            f"{near_test} sharing a template with test or collected went to heldout"
        )
    else:
        heldout = [dict(r, split="heldout") for r in rest if _is_collected(r)]
        rest = [r for r in rest if not _is_collected(r)]
        val_ids = stratified_pick(rest, val_frac, salt="val") if len(rest) >= 10 else set()
        val = [dict(r, split="val") for r in rest if r["id"] in val_ids]
        train = [dict(r, split="train") for r in rest if r["id"] not in val_ids]

    # Synthetic rows only ever join train: their parent must be a train message, and they
    # must not be close to any val/test message (a paraphrase of a test message would leak).
    train_ids = {r["id"]: r for r in train}
    orphans = [s for s in synthetic if s["parent_id"] and s["parent_id"] not in train_ids]
    candidates = [s for s in synthetic if not s["parent_id"] or s["parent_id"] in train_ids]
    leaks = _close_to_any(candidates, [*val, *test, *heldout], SYNTHETIC_LEAK)
    dropped_parent, dropped_leak = len(orphans), len(leaks)
    kept = 0
    for k, s in enumerate(candidates):
        if k in leaks:
            continue
        parent = train_ids.get(s["parent_id"])
        # A variation belongs to its parent's template group; a hard negative to its own.
        group = parent.get("group", "") if parent else s["id"]
        train.append(dict(s, split="train", group=group if groups is not None else ""))
        kept += 1
    if synthetic:
        notes.append(
            f"synthetic: {kept} added to train; {dropped_parent} dropped (parent not in "
            f"train); {dropped_leak} dropped (too close to a val/test message)"
        )
    return Splits(train, val, test, notes, heldout), manifest


# ----------------------------------------------------------------------------- review


def in_review_sample(row_id: str, frac: float = REVIEW_SAMPLE) -> bool:
    """A fixed ~frac of all ids (by hash): the same rows every run, whatever else changes."""
    return int(_order(row_id, "review"), 16) < frac * 16**64


def review_queue(rows: list[Row], frac: float = REVIEW_SAMPLE) -> list[Row]:
    """Unreviewed auto-labelled rows to check by hand: every uncertain one, and ~frac of
    the scam and promo_spam ones (an unbiased sample, to measure the auto-labeller)."""
    auto = [r for r in rows if r.get("label_source") == "auto"]
    picked = [r for r in auto if r["label"] == UNCERTAIN]
    picked += [r for r in auto if r["label"] != UNCERTAIN and in_review_sample(r["id"], frac)]
    return [
        {"id": r["id"], "text": r["text"], "auto_label": r["auto_label"],
         "auto_scam_type": r["auto_scam_type"], "top_signals": r["top_signals"],
         "my_label": "", "my_scam_type": "", "label_reason": "", "confidence": "",
         "label_source": ""}
        for r in picked
    ]  # fmt: skip


def unapplied_reviews(path: Path, reviewed: dict[str, dict[str, str]]) -> int:
    """Rows of an existing queue that you filled in but have not applied yet."""
    if not path.exists():
        return 0
    return sum(
        1 for r in read_csv(path) if (r.get("my_label") or "").strip() and r["id"] not in reviewed
    )


# ----------------------------------------------------------------------------- main


def _counts(rows: list[Row], key: Callable[[Row], str]) -> str:
    return ", ".join(f"{k or '-'}: {v}" for k, v in sorted(Counter(map(key, rows)).items()))


def _table(rows: list[Row], keys: tuple[str, ...]) -> list[str]:
    """A markdown table of row counts per value of each key."""
    lines = ["| column | value | rows |", "|---|---|---:|"]
    for key in keys:
        for value, n in sorted(Counter(str(r[key]) for r in rows).items(), key=lambda x: -x[1]):
            lines.append(f"| {key} | {value or '-'} | {n} |")
    return lines


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rebuild-test", action="store_true",
                        help="re-draw the frozen Indian test split")  # fmt: skip
    parser.add_argument("--test-frac", type=float, default=0.2)
    parser.add_argument("--val-frac", type=float, default=0.15)
    parser.add_argument("--heldout-frac", type=float, default=HELDOUT_FRAC,
                        help="share of template groups held out for evaluation")  # fmt: skip
    parser.add_argument("--near-dup", type=float, default=NEAR_DUP,
                        help="token Jaccard threshold for near-duplicates")  # fmt: skip
    args = parser.parse_args()

    # --- public, out-of-domain: UCI (evaluation only)
    uci: list[Row] = []
    try:
        uci, rep = dedupe(load_uci(), args.near_dup)
    except FileNotFoundError:
        print("[uci_sms_spam] not found, skipped (run: uv run python -m ml.download_public)")
    if uci:
        write_csv(PROCESSED_DIR / "ood_uci_sms_spam.csv", uci, COLUMNS)
        print(
            f"[uci_sms_spam] {len(uci)} kept (exact dups {rep.exact}, near dups {rep.near}, "
            f"label conflicts {rep.conflicts}). OUT-OF-DOMAIN, eval only.\n"
            f"  original labels: {_counts(uci, lambda r: r['original_label'])}"
        )

    # --- public, trainable: Mendeley and IMC25 (mostly non-Indian)
    public: list[Row] = []
    for name, loader in ((MENDELEY_DATASET, load_mendeley), (IMC_DATASET, load_imc25)):
        rows = loader()
        if not rows:
            print(f"[{name}] not found, skipped (run: uv run python -m ml.download_public)")
            continue
        print(f"[{name}] {len(rows)} loaded; labels {_counts(rows, lambda r: r['label'])}; "
              f"is_indian {_counts(rows, lambda r: str(r['is_indian']))}")  # fmt: skip
        public += rows

    # --- collected (yours) + India Spam SMS (real Indian, auto-labelled spam)
    collected, problems = load_collected()
    for p in problems:
        print(f"  collected: {p}")
    reviewed = load_reviewed()
    india: list[Row] = []
    if INDIA_FILE.exists():
        print(f"[{INDIA_DATASET}] auto-labelling spam rows (offline rules)...", flush=True)
        india = load_india_spam(reviewed=reviewed)
    else:
        print(f"[{INDIA_DATASET}] not found, skipped (run: uv run python -m ml.download_public)")

    # Collected and India rows first: on a tie, the first copy of a duplicate is kept.
    everything, rep = dedupe(collected + india + public, args.near_dup)
    print(
        f"[collected + {INDIA_DATASET} + public] {len(collected)} + {len(india)} + "
        f"{len(public)} rows -> {len(everything)} after dedupe (exact {rep.exact}, near "
        f"{rep.near}, label conflicts {rep.conflicts}); collected and India anonymized"
    )
    india_kept = [r for r in everything if r["dataset"] == INDIA_DATASET]
    write_csv(PROCESSED_DIR / "collected.csv",
              [r for r in everything if r["dataset"] == "collected"], COLUMNS)  # fmt: skip
    write_csv(PROCESSED_DIR / f"{INDIA_DATASET}.csv", india_kept, COLUMNS)
    real = [r for r in everything if r["label"] != UNCERTAIN]  # uncertain: not until reviewed

    synthetic, _ = dedupe(load_synthetic(), args.near_dup)
    real_ids = {r["id"] for r in everything}
    synthetic = [s for s in synthetic if s["id"] not in real_ids]

    # UCI joins the grouping (not the splits) to find its rows that no model has seen.
    print(f"grouping {len(real) + len(uci)} messages into templates...", flush=True)
    groups = template_groups(real + uci)
    splits, manifest = make_splits(
        real, synthetic, rebuild_test=args.rebuild_test, test_frac=args.test_frac,
        val_frac=args.val_frac, manifest=load_manifest(), today=date.today().isoformat(),
        groups=groups, heldout_frac=args.heldout_frac,
    )  # fmt: skip
    for note in splits.notes:
        print(f"  {note}")

    seen = {r["group"] for r in splits.train + splits.val}
    unseen = [dict(r, group=groups[r["id"]]) for r in uci if groups[r["id"]] not in seen]
    if uci:
        write_csv(PROCESSED_DIR / "ood_uci_unseen.csv", unseen, COLUMNS)
        print(f"  ood_uci_unseen: {len(unseen)} of {len(uci)} UCI rows share no template with "
              f"train/val ({_counts(unseen, lambda r: r['original_label'])})")  # fmt: skip

    for name, rows in (("train", splits.train), ("val", splits.val), ("test", splits.test),
                       ("heldout", splits.heldout)):  # fmt: skip
        path = PROCESSED_DIR / f"{name}.csv"
        if not rows:
            if path.exists() and name == "test" and manifest is None:
                path.unlink()  # a stale test file without a manifest would be misleading
            print(f"  {name}: empty")
            continue
        write_csv(path, rows, COLUMNS)
        print(f"  {name}: {len(rows)} ({_counts(rows, lambda r: r['label'])}; "
              f"{_counts(rows, lambda r: r['label_source'])}; "
              f"{_counts(rows, lambda r: r['dataset'])})")  # fmt: skip
    if manifest is not None:
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    elif MANIFEST.exists() and args.rebuild_test:
        MANIFEST.unlink()

    # --- review queue
    pending = unapplied_reviews(REVIEW_QUEUE, reviewed)
    queue = review_queue(india_kept)
    if pending:
        print(f"\nreview queue: NOT rewritten, {REVIEW_QUEUE.name} has {pending} filled-in "
              "row(s) not applied yet. Run: uv run python -m ml.apply_review")  # fmt: skip
    else:
        write_csv(REVIEW_QUEUE, queue, REVIEW_COLUMNS)
        print(f"\nreview queue: {len(queue)} rows -> {REVIEW_QUEUE} "
              f"({_counts(queue, lambda r: r['auto_label'])})")  # fmt: skip

    usable = [r for r in everything if r["label"] != UNCERTAIN]
    print(f"\n## Summary (collected + {INDIA_DATASET}, after dedupe; synthetic not included)\n")
    print(f"rows: {len(everything)} ({len(everything) - len(usable)} uncertain, left out of "
          f"the splits until reviewed)\n")  # fmt: skip
    print("\n".join(_table(everything, ("label", "scam_type", "language", "source",
                                        "label_source"))))  # fmt: skip
    print(f"\nrows in review_queue.csv: {len(queue)}")


if __name__ == "__main__":
    main()
