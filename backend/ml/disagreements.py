"""List messages where the rules and the classifier strongly disagree, for review.

Two kinds:
- rules_only:      the rules score it high (>= --rules-high) but the classifier gives
                   P(scam) < --p-low. A rule firing on an ordinary message (a false alarm to
                   fix in rules.py), or a scam the classifier has never seen the like of.
- classifier_only: no rule, or only weak ones (score < --rules-low), but P(scam) >=
                   --p-high. A scam the rules miss (a rule to write), or a classifier false
                   alarm (a hard negative to add to the training data).

Runs on every processed row (train/val/heldout/test, UCI unseen) with the offline rules
(pipeline.analyze_text, classifier off) and the exported model. Writes
data/datasets/review_disagreements.csv (gitignored: it quotes real messages), strongest
disagreement first, with an empty my_label column to fill in.

    uv run python -m ml.disagreements
    uv run python -m ml.disagreements --p-high 0.95 --limit 200
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

from app.core.config import get_settings
from app.services import pipeline
from app.services.classifier import ScamClassifier
from ml.common import DATASETS_DIR, PROCESSED_DIR, read_csv, write_csv

OUT_FILE = DATASETS_DIR / "review_disagreements.csv"
SOURCES = ("train.csv", "val.csv", "heldout.csv", "test.csv", "ood_uci_unseen.csv")
COLUMNS = ("kind", "strength", "split", "dataset", "label", "label_source", "rules_score",
           "rules_verdict", "rules", "p_scam", "p_promo_spam", "p_genuine", "text", "id",
           "my_label", "notes")  # fmt: skip


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules-high", type=int, default=70)
    parser.add_argument("--rules-low", type=int, default=20)
    parser.add_argument("--p-low", type=float, default=0.10)
    parser.add_argument("--p-high", type=float, default=0.90)
    parser.add_argument("--limit", type=int, default=0, help="keep the N strongest (0: all)")
    parser.add_argument("--model", type=Path, default=get_settings().CLASSIFIER_MODEL_PATH)
    parser.add_argument("--include-synthetic", action="store_true")
    args = parser.parse_args()

    model = ScamClassifier.load(args.model)
    rules_only = get_settings().model_copy(update={"CLASSIFIER_ENABLED": False})
    found = []
    seen: set[str] = set()
    for name in SOURCES:
        path = PROCESSED_DIR / name
        if not path.exists():
            continue
        for r in read_csv(path):
            if r["id"] in seen or (r.get("is_synthetic") == "true" and not args.include_synthetic):
                continue
            seen.add(r["id"])
            result = pipeline.analyze_text(r["text"], rules_only).result
            rules_score = next(s.score for s in result.signal_breakdown if s.source == "rules")
            probs = model.predict_proba(r["text"])
            p = probs["scam"]
            if rules_score >= args.rules_high and p < args.p_low:
                kind, strength = "rules_only", rules_score / 100 - p
            elif rules_score < args.rules_low and p >= args.p_high:
                kind, strength = "classifier_only", p - rules_score / 100
            else:
                continue
            found.append({
                "kind": kind, "strength": round(strength, 3), "split": r.get("split") or name,
                "dataset": r.get("dataset", ""), "label": r["label"],
                "label_source": r.get("label_source", ""), "rules_score": rules_score,
                "rules_verdict": result.verdict.value,
                "rules": " ".join(f.code for f in result.red_flags),
                "p_scam": round(p, 3), "p_promo_spam": round(probs["promo_spam"], 3),
                "p_genuine": round(probs["genuine"], 3), "text": r["text"], "id": r["id"],
                "my_label": "", "notes": "",
            })  # fmt: skip
    found.sort(key=lambda d: -d["strength"])
    if args.limit:
        found = found[: args.limit]
    write_csv(OUT_FILE, found, COLUMNS)
    print(f"{len(seen)} messages checked; {len(found)} strong disagreements -> {OUT_FILE}")
    for (kind, label), n in sorted(Counter((d["kind"], d["label"]) for d in found).items()):
        print(f"  {kind:<16} labelled {label:<11} {n}")


if __name__ == "__main__":
    main()
