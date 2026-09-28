"""Apply review labels from data/datasets/review_queue.csv and measure the auto-labeller.

Fill in `my_label` (scam | genuine | promo_spam) and, for scams, `my_scam_type` (a v1 type
or "other"; left empty: the auto type if it said scam, else "other"). Rows with an empty
my_label are skipped. Labels are merged into data/datasets/reviewed_labels.csv (a later
review of the same message replaces the earlier one); ml/prepare_dataset.py then uses
them, so those rows may enter the Indian test split.

Who labelled a row is its `label_source` column: empty or "manual" = you, "assisted" = an
AI assistant (Claude) reading the row. The two are kept apart everywhere (reports show
metrics for each). A manual label is never replaced by an assisted one.

Low-confidence assisted rows are written to data/datasets/review_low_confidence.csv. Edit
my_label / my_scam_type there (or set label_source to "manual" to confirm a label as it
is) and run this script again: those rows become "manual".

Accuracy per auto-label class counts only the random-sample rows (auto label scam or
promo_spam): the uncertain rows are not a random sample, so for them only the
distribution of the review labels is shown.

    uv run python -m ml.apply_review
    uv run python -m ml.prepare_dataset     # then rebuild the splits and the queue
"""

import argparse
import sys
from collections import Counter
from datetime import date
from pathlib import Path

from ml.autolabel import UNCERTAIN
from ml.common import (
    LABELS,
    LOW_CONFIDENCE,
    OTHER_SCAM_TYPE,
    REVIEW_COLUMNS,
    REVIEW_QUEUE,
    REVIEWED_COLUMNS,
    REVIEWED_LABELS,
    label_problem,
    load_reviewed,
    read_csv,
    write_csv,
)

# Shorthands accepted in my_label.
ALIASES = {"promo": "promo_spam", "ham": "genuine", "fraud": "scam"}
ASSISTED = "assisted"
MANUAL = "manual"


def _source(r: dict[str, str]) -> str | None:
    """manual | assisted, or None for an unknown value."""
    value = (r.get("label_source") or "").strip().lower() or MANUAL
    return value if value in (MANUAL, ASSISTED) else None


def parse_review(r: dict[str, str]) -> tuple[dict[str, str] | None, str | None]:
    """(reviewed row, None), (None, problem), or (None, None) if my_label is empty."""
    label = (r.get("my_label") or "").strip().lower()
    if not label:
        return None, None
    label = ALIASES.get(label, label)
    scam_type = (r.get("my_scam_type") or "").strip().lower()
    if label == "scam" and not scam_type:
        auto_scam = r.get("auto_label") == "scam" and r.get("auto_scam_type")
        scam_type = auto_scam or OTHER_SCAM_TYPE
    if why := label_problem(label, scam_type):
        return None, why
    source = _source(r)
    if source is None:
        return None, f"label_source must be empty, manual or assisted, got {r['label_source']!r}"
    return {
        "id": r["id"], "label": label, "scam_type": scam_type,
        "auto_label": r.get("auto_label", ""), "auto_scam_type": r.get("auto_scam_type", ""),
        "reviewed_on": date.today().isoformat(), "label_source": source,
        "label_reason": (r.get("label_reason") or "").strip(),
        "confidence": (r.get("confidence") or "").strip().lower(),
    }, None  # fmt: skip


def accuracy_report(reviewed: list[dict[str, str]]) -> list[str]:
    """Markdown: per auto class, how often the review agreed, and the confusion table."""
    lines = [
        "| auto label | reviewed | review agreed | accuracy | scam_type agreed |",
        "|---|---:|---:|---:|---:|",
    ]
    for auto in ("scam", "promo_spam"):
        rows = [r for r in reviewed if r["auto_label"] == auto]
        agreed = [r for r in rows if r["label"] == auto]
        acc = f"{len(agreed) / len(rows):.1%}" if rows else "–"
        typed = "–"
        if auto == "scam" and agreed:
            same = sum(1 for r in agreed if r["scam_type"] == r["auto_scam_type"])
            typed = f"{same}/{len(agreed)}"
        lines.append(f"| {auto} | {len(rows)} | {len(agreed)} | {acc} | {typed} |")

    autos = [a for a in ("scam", "promo_spam", UNCERTAIN) if any(r["auto_label"] == a
                                                                  for r in reviewed)]  # fmt: skip
    counts = Counter((r["auto_label"], r["label"]) for r in reviewed)
    lines += ["", "| auto \\ review | " + " | ".join(LABELS) + " |",
              "|---|" + "---:|" * len(LABELS)]  # fmt: skip
    for a in autos:
        lines.append(f"| {a} | " + " | ".join(str(counts[(a, lab)]) for lab in LABELS) + " |")
    return lines


def _merge(reviewed: dict[str, dict[str, str]], row: dict[str, str]) -> bool:
    """Store `row` unless it would replace a manual label with an assisted one."""
    old = reviewed.get(row["id"])
    if old and old.get("label_source") == MANUAL and row["label_source"] == ASSISTED:
        return False
    reviewed[row["id"]] = row
    return True


def apply(queue: Path, store: Path) -> tuple[dict[str, dict[str, str]], int, list[str]]:
    """Merge the filled queue rows into the store. Returns (all reviewed, new, problems)."""
    reviewed = load_reviewed(store)
    problems, new = [], 0
    for n, r in enumerate(read_csv(queue), start=2):
        row, why = parse_review(r)
        if why:
            problems.append(f"{queue.name}:{n}: {why}")
        elif row and _merge(reviewed, row):
            new += 1
    write_csv(store, reviewed.values(), REVIEWED_COLUMNS)
    return reviewed, new, problems


def apply_low_confidence(path: Path, store: Path) -> tuple[int, list[str]]:
    """Your edits to the low-confidence file: a row whose label, scam_type or label_source
    ("manual") you changed becomes a manual label. Returns (changed, problems)."""
    if not path.exists():
        return 0, []
    reviewed = load_reviewed(store)
    changed, problems = 0, []
    for n, r in enumerate(read_csv(path), start=2):
        old = reviewed.get(r["id"])
        if old is None or old.get("label_source") != ASSISTED:
            continue  # already yours
        row, why = parse_review({**r, "label_source": ASSISTED})
        if why:
            problems.append(f"{path.name}:{n}: {why}")
            continue
        if row is None:
            problems.append(f"{path.name}:{n}: my_label is empty; kept the assisted label")
            continue
        confirmed = _source(r) == MANUAL
        edited = (row["label"], row["scam_type"]) != (old["label"], old["scam_type"])
        if confirmed or edited:
            row = {**row, "label_source": MANUAL, "auto_label": old.get("auto_label", ""),
                   "auto_scam_type": old.get("auto_scam_type", "")}  # fmt: skip
            reviewed[r["id"]] = row
            changed += 1
    write_csv(store, reviewed.values(), REVIEWED_COLUMNS)
    return changed, problems


def write_low_confidence(
    path: Path, queue: Path, reviewed: dict[str, dict[str, str]]
) -> list[dict[str, str]]:
    """Every low-confidence reviewed row, with its current label and label_source: rows
    already in the file keep their text, new ones come from the queue."""
    rows: dict[str, dict[str, str]] = {}
    if path.exists():
        rows = {r["id"]: r for r in read_csv(path)}
    if queue.exists():
        for r in read_csv(queue):
            if (r.get("confidence") or "").strip().lower() == "low" and r["id"] not in rows:
                rows[r["id"]] = r
    out = []
    for row_id, r in rows.items():
        if not (mine := reviewed.get(row_id)):
            continue
        out.append({**r, "my_label": mine["label"], "my_scam_type": mine["scam_type"],
                    "label_source": mine["label_source"]})  # fmt: skip
    write_csv(path, out, REVIEW_COLUMNS)
    return out


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--queue", type=Path, default=REVIEW_QUEUE)
    args = parser.parse_args()
    if not args.queue.exists():
        sys.exit(f"{args.queue} not found. Run: uv run python -m ml.prepare_dataset")

    edited, problems = apply_low_confidence(LOW_CONFIDENCE, REVIEWED_LABELS)
    reviewed, new, more = apply(args.queue, REVIEWED_LABELS)
    for p in problems + more:
        print(f"  skipped {p}")
    by_source = Counter(r["label_source"] for r in reviewed.values())
    print(f"applied {new} label(s) from the queue, {edited} edited in {LOW_CONFIDENCE.name}; "
          f"{len(reviewed)} reviewed in total ({by_source[MANUAL]} manual, "
          f"{by_source[ASSISTED]} AI-assisted) -> {REVIEWED_LABELS}")  # fmt: skip

    low = write_low_confidence(LOW_CONFIDENCE, args.queue, reviewed)
    pending = sum(1 for r in low if r["label_source"] == ASSISTED)
    print(f"low-confidence rows: {len(low)} ({pending} still AI-assisted, to check by hand) "
          f"-> {LOW_CONFIDENCE}\n")  # fmt: skip
    if reviewed:
        print("Auto-label accuracy (all reviews so far; the scam/promo rows are a random "
              "~10% sample, uncertain rows are all of them):\n")  # fmt: skip
        for title, rows in (
            ("all reviews", list(reviewed.values())),
            ("manual only", [r for r in reviewed.values() if r["label_source"] == MANUAL]),
            ("AI-assisted only", [r for r in reviewed.values() if r["label_source"] == ASSISTED]),
        ):
            if rows:
                print(f"### {title} ({len(rows)})\n")
                print("\n".join(accuracy_report(rows)) + "\n")
    print("Next: uv run python -m ml.prepare_dataset")


if __name__ == "__main__":
    main()
