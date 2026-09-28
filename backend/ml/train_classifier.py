"""Train the baseline scam classifier and export it as JSON for app/services/classifier.py.

Model: TF-IDF on character 2-5 grams inside words (app/services/features.char_ngrams) and
word 1-2 grams, each block l2-normalized, then 3-class logistic regression (genuine /
promo_spam / scam). Input text goes through app/services/features.preprocess first
(leetspeak folding, entity masking, lower case): the same code the service runs.

Data: processed/train.csv (fit) and processed/val.csv (choose C, calibrate) from
ml/prepare_dataset.py. Sample weights:
- class balance: every class gets the same total weight ("class weights");
- template cap: a template group with more than --group-cap messages in train counts as
  --group-cap messages (the SBI YONO template alone has hundreds of copies in IMC25);
- --indian-weight for is_indian rows (real Indian messages are few; the rest is UK,
  Singapore and IMC25 reports from many countries).

Calibration: one temperature T on the logits, fitted on val by log loss (temperature
scaling: it changes the probabilities, never the ranking or the predicted class).

After export, the JSON model is loaded with the numpy inference code and compared with
scikit-learn on 200 val messages; the run fails if they disagree.

    uv run python -m ml.train_classifier
    uv run python -m ml.train_classifier --c 4,16 --indian-weight 2
"""

import argparse
import hashlib
import json
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Sequence
from datetime import date
from pathlib import Path
from typing import Any

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, log_loss

from app.core.config import get_settings
from app.services.classifier import MODEL_FORMAT, ScamClassifier
from ml.common import LABELS, PROCESSED_DIR, as_bool, read_csv
from ml.features import FEATURES_VERSION, char_ngrams, preprocess, word_ngrams

CLASSES = sorted(LABELS)  # ["genuine", "promo_spam", "scam"]: scikit-learn's order too
PARITY_SAMPLES = 200
PARITY_TOLERANCE = 1e-5  # coefficients are stored with 7 significant digits

Row = dict[str, str]


# ----------------------------------------------------------------------------- data


def load_split(name: str) -> list[Row]:
    path = PROCESSED_DIR / f"{name}.csv"
    if not path.exists():
        sys.exit(f"{path} not found. Run: uv run python -m ml.prepare_dataset")
    return [r for r in read_csv(path) if r["label"] in LABELS]


def sample_weights(rows: Sequence[Row], group_cap: int, indian_weight: float) -> np.ndarray:
    """Template cap x Indian weight, then rescaled so every class has the same total."""
    sizes = Counter(r.get("group") or r["id"] for r in rows)
    w = np.array([
        min(1.0, group_cap / sizes[r.get("group") or r["id"]])
        * (indian_weight if as_bool(r.get("is_indian")) else 1.0)
        for r in rows
    ])  # fmt: skip
    labels = np.array([r["label"] for r in rows])
    for c in CLASSES:
        mask = labels == c
        if mask.any():
            w[mask] *= len(rows) / (len(CLASSES) * w[mask].sum())
    return w


# ----------------------------------------------------------------------------- model


class Vectorizer:
    """The char and word TF-IDF blocks side by side."""

    def __init__(self, char_max: int, word_max: int, min_df: int) -> None:
        common: dict[str, Any] = {"min_df": min_df, "sublinear_tf": True, "dtype": np.float64}
        self.blocks = [
            ("char", TfidfVectorizer(analyzer=char_ngrams, max_features=char_max, **common)),
            ("word", TfidfVectorizer(analyzer=word_ngrams, max_features=word_max, **common)),
        ]

    def fit_transform(self, pre: Sequence[str]) -> csr_matrix:
        return hstack([v.fit_transform(pre) for _, v in self.blocks]).tocsr()

    def transform(self, pre: Sequence[str]) -> csr_matrix:
        return hstack([v.transform(pre) for _, v in self.blocks]).tocsr()

    def feature_names(self) -> list[str]:
        return [f"{name}:{t}" for name, v in self.blocks for t in v.get_feature_names_out()]


def fit_model(
    pre: Sequence[str],
    labels: Sequence[str],
    weights: np.ndarray,
    c: float,
    char_max: int = 60_000,
    word_max: int = 20_000,
    min_df: int = 2,
) -> tuple[Vectorizer, LogisticRegression]:
    vec = Vectorizer(char_max, word_max, min_df)
    x = vec.fit_transform(pre)
    lr = LogisticRegression(C=c, max_iter=5000, tol=1e-6)
    lr.fit(x, labels, sample_weight=weights)
    assert list(lr.classes_) == CLASSES, lr.classes_
    return vec, lr


def fit_temperature(logits: np.ndarray, y: np.ndarray) -> float:
    """The T > 0 minimizing log loss of softmax(logits / T) on (logits, y)."""

    def nll(t: float) -> float:
        z = logits / t
        z = z - z.max(axis=1, keepdims=True)
        logp = z - np.log(np.exp(z).sum(axis=1, keepdims=True))
        return float(-logp[np.arange(len(y)), y].mean())

    grid = np.exp(np.linspace(np.log(0.2), np.log(5.0), 161))
    return float(min(grid, key=nll))


def _sig(x: float) -> float:
    return float(f"{x:.7g}")


def export_model(
    vec: Vectorizer, lr: LogisticRegression, temperature: float, meta: dict[str, Any]
) -> dict[str, Any]:
    """The JSON-able model that app/services/classifier.ScamClassifier.from_dict reads."""
    blocks = []
    for name, v in vec.blocks:
        terms = [""] * len(v.vocabulary_)
        for term, idx in v.vocabulary_.items():
            terms[idx] = term
        blocks.append({"analyzer": name, "sublinear_tf": True, "terms": terms,
                       "idf": [_sig(x) for x in v.idf_]})  # fmt: skip
    return {
        "format": MODEL_FORMAT,
        "features_version": FEATURES_VERSION,
        "classes": list(lr.classes_),
        "blocks": blocks,
        "coef": [[_sig(x) for x in row] for row in lr.coef_],
        "intercept": [_sig(x) for x in lr.intercept_],
        "temperature": _sig(temperature),
        "meta": meta,
    }


def parity(
    model: ScamClassifier, vec: Vectorizer, lr: LogisticRegression, texts: Sequence[str]
) -> tuple[float, int]:
    """(max |p_numpy - p_sklearn|, argmax disagreements) over texts, uncalibrated."""
    ref = lr.predict_proba(vec.transform([preprocess(t) for t in texts]))
    ours = np.array([[model.predict_proba(t, calibrated=False)[c] for c in CLASSES]
                     for t in texts])  # fmt: skip
    return float(np.abs(ref - ours).max()), int((ref.argmax(1) != ours.argmax(1)).sum())


# ----------------------------------------------------------------------------- main


def _git_rev() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()  # fmt: skip
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _counts(rows: Sequence[Row], key: str) -> dict[str, int]:
    return dict(sorted(Counter(r[key] for r in rows).items()))


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--c", default="1,4,16,32,64", help="inverse regularization grid")
    parser.add_argument("--group-cap", type=int, default=10)
    parser.add_argument("--indian-weight", type=float, default=5.0)
    parser.add_argument("--char-max", type=int, default=60_000)
    parser.add_argument("--word-max", type=int, default=20_000)
    parser.add_argument("--min-df", type=int, default=2,
                        help="an n-gram must occur in this many train messages")  # fmt: skip
    parser.add_argument("--no-synthetic", action="store_true", help="train on real rows only")
    parser.add_argument("--out", type=Path, default=get_settings().CLASSIFIER_MODEL_PATH)
    args = parser.parse_args()

    train, val = load_split("train"), load_split("val")
    if leaked := [r["id"] for r in train + val if r["dataset"] == "collected"]:
        sys.exit(f"{len(leaked)} collected message(s) in train/val: they are test-only. "
                 "Re-run: uv run python -m ml.prepare_dataset")  # fmt: skip
    if args.no_synthetic:
        train = [r for r in train if not as_bool(r["is_synthetic"])]
    print(f"train {len(train)} {_counts(train, 'label')}; synthetic "
          f"{sum(as_bool(r['is_synthetic']) for r in train)}; val {len(val)} "
          f"{_counts(val, 'label')}")  # fmt: skip
    t0 = time.perf_counter()
    pre_train = [preprocess(r["text"]) for r in train]
    pre_val = [preprocess(r["text"]) for r in val]
    y_train = [r["label"] for r in train]
    y_val = np.array([CLASSES.index(r["label"]) for r in val])
    weights = sample_weights(train, args.group_cap, args.indian_weight)
    print(f"preprocessed in {time.perf_counter() - t0:.0f}s")

    best: tuple[float, float, Vectorizer, LogisticRegression] | None = None
    for c in [float(x) for x in args.c.split(",")]:
        t0 = time.perf_counter()
        vec, lr = fit_model(pre_train, y_train, weights, c, args.char_max, args.word_max,
                            args.min_df)  # fmt: skip
        proba = lr.predict_proba(vec.transform(pre_val))
        f1 = f1_score(y_val, proba.argmax(1), average="macro")
        loss = log_loss(y_val, proba, labels=range(len(CLASSES)))
        print(f"  C={c:<5g} val macro-F1 {f1:.4f}  log loss {loss:.4f}  "
              f"({time.perf_counter() - t0:.0f}s)")  # fmt: skip
        if best is None or f1 > best[0] + 1e-4:
            best = (f1, c, vec, lr)
    assert best is not None
    f1, c, vec, lr = best
    logits = lr.decision_function(vec.transform(pre_val))
    temperature = fit_temperature(logits, y_val)
    print(f"chosen C={c:g} (val macro-F1 {f1:.4f}); temperature {temperature:.3f}")

    meta = {
        "trained": date.today().isoformat(),
        "code": _git_rev(),
        "C": c,
        "group_cap": args.group_cap,
        "indian_weight": args.indian_weight,
        "min_df": args.min_df,
        "n_features": int(lr.coef_.shape[1]),
        "val_macro_f1": round(f1, 4),
        "train_labels": _counts(train, "label"),
        "train_datasets": _counts(train, "dataset"),
        "synthetic_rows": sum(as_bool(r["is_synthetic"]) for r in train),
    }
    data = export_model(vec, lr, temperature, meta)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    args.out.write_text(raw, encoding="utf-8")
    sha = hashlib.sha256(raw.encode()).hexdigest()[:16]
    print(f"model: {args.out} ({args.out.stat().st_size / 1e6:.1f} MB, sha256 {sha}...)")

    # The exported JSON, run by the service's code, must agree with scikit-learn.
    model = ScamClassifier.load(args.out)
    sample = [r["text"] for r in sorted(val, key=lambda r: r["id"])[:PARITY_SAMPLES]]
    diff, disagreements = parity(model, vec, lr, sample)
    print(f"parity on {len(sample)} val messages: max |dp| {diff:.2e}, "
          f"{disagreements} class disagreements")  # fmt: skip
    if disagreements or diff > PARITY_TOLERANCE:
        sys.exit("PARITY FAILED: the JSON model does not reproduce scikit-learn")


if __name__ == "__main__":
    main()
