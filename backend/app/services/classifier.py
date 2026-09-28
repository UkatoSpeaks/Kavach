"""The trained scam classifier (TF-IDF n-grams + logistic regression), in numpy only.

The model is trained by ml/train_classifier.py with scikit-learn and exported as plain JSON
(vocabularies, idf, coefficients, calibration temperature), so the service needs neither
scikit-learn nor a pickle: loading ~6 MB of JSON fits the 512 MB instance.

Three classes: genuine, promo_spam, scam. The "classifier" signal's score is 100 * the
calibrated P(scam); it counts only when P(scam) is at least CLASSIFIER_MIN_SCAM_PROBABILITY
(see classifier_signal). Like every other layer it only feeds the weighted mean: it never
sets a minimum score (no floor). A missing or incompatible model file is logged once and
the signal is reported unavailable.
"""

import json
import logging
import math
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np

from app.services.features import FEATURES_VERSION, char_ngrams, preprocess, word_ngrams
from app.services.scoring import SignalOutcome

logger = logging.getLogger(__name__)

SOURCE = "classifier"
MODEL_FORMAT = "kavach-tfidf-logreg"
SCAM = "scam"
# Default for Settings.CLASSIFIER_MIN_SCAM_PROBABILITY (see classifier_signal).
MIN_SCAM_PROBABILITY = 0.5

ANALYZERS: dict[str, Callable[[str], list[str]]] = {"char": char_ngrams, "word": word_ngrams}


class ModelError(ValueError):
    """The model file is not one this code can run."""


@dataclass(frozen=True)
class Block:
    """One TF-IDF vectorizer: its analyzer, vocabulary (term -> column) and idf."""

    analyzer: Callable[[str], list[str]]
    vocabulary: dict[str, int]
    idf: np.ndarray
    offset: int  # first column of this block in the coefficient matrix
    sublinear_tf: bool


class ScamClassifier:
    def __init__(
        self,
        classes: list[str],
        blocks: list[Block],
        coef: np.ndarray,
        intercept: np.ndarray,
        temperature: float,
        meta: dict | None = None,
    ) -> None:
        self.classes = classes
        self.blocks = blocks
        self.coef = coef  # (n_classes, n_features)
        self.intercept = intercept
        self.temperature = temperature
        self.meta = meta or {}

    @classmethod
    def from_dict(cls, data: dict) -> "ScamClassifier":
        if data.get("format") != MODEL_FORMAT:
            raise ModelError(f"not a {MODEL_FORMAT} model")
        if data.get("features_version") != FEATURES_VERSION:
            raise ModelError(
                f"model built for features v{data.get('features_version')}, code has "
                f"v{FEATURES_VERSION}: retrain (ml/train_classifier.py)"
            )
        blocks, offset = [], 0
        for b in data["blocks"]:
            if b["analyzer"] not in ANALYZERS:
                raise ModelError(f"unknown analyzer {b['analyzer']!r}")
            terms = b["terms"]
            blocks.append(Block(ANALYZERS[b["analyzer"]], {t: i for i, t in enumerate(terms)},
                                np.asarray(b["idf"], dtype=np.float64), offset,
                                bool(b.get("sublinear_tf", True))))  # fmt: skip
            offset += len(terms)
        coef = np.asarray(data["coef"], dtype=np.float64)
        if coef.shape != (len(data["classes"]), offset):
            raise ModelError(f"coef shape {coef.shape} does not match the vocabularies")
        return cls(
            classes=list(data["classes"]),
            blocks=blocks,
            coef=coef,
            intercept=np.asarray(data["intercept"], dtype=np.float64),
            temperature=float(data.get("temperature", 1.0)),
            meta=data.get("meta", {}),
        )

    @classmethod
    def load(cls, path: Path) -> "ScamClassifier":
        with path.open(encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    def logits(self, text: str) -> np.ndarray:
        """Uncalibrated decision values, as scikit-learn's decision_function."""
        pre = preprocess(text)
        out = self.intercept.copy()
        for block in self.blocks:
            counts = Counter(t for t in block.analyzer(pre) if t in block.vocabulary)
            if not counts:
                continue
            cols = np.fromiter((block.vocabulary[t] for t in counts), dtype=np.int64)
            tf = np.fromiter(counts.values(), dtype=np.float64)
            if block.sublinear_tf:
                tf = 1.0 + np.log(tf)
            values = tf * block.idf[cols]
            values /= math.sqrt(float(values @ values))  # l2, per block
            out += self.coef[:, block.offset + cols] @ values
        return out

    def predict_proba(self, text: str, calibrated: bool = True) -> dict[str, float]:
        z = self.logits(text)
        if calibrated:
            z = z / self.temperature
        z = np.exp(z - z.max())
        p = z / z.sum()
        return {c: float(v) for c, v in zip(self.classes, p, strict=True)}


@lru_cache(maxsize=4)
def get_classifier(path: Path) -> ScamClassifier | None:
    """The model at `path`, loaded once per process; None (logged) if it is missing or
    unusable, so the analysis goes on without the signal."""
    try:
        model = ScamClassifier.load(path)
    except FileNotFoundError:
        logger.warning("classifier model not found at %s; signal disabled", path)
        return None
    except (OSError, ValueError, KeyError, TypeError) as exc:
        logger.warning("classifier model at %s unusable (%s: %s)", path, type(exc).__name__, exc)
        return None
    logger.info("classifier model loaded from %s", path)
    return model


def classifier_signal(
    text: str, model: ScamClassifier | None, min_scam_probability: float = MIN_SCAM_PROBABILITY
) -> SignalOutcome:
    """Score 100 * P(scam). Below `min_scam_probability` the signal is listed but does not
    count (informative=False): most of the training data is not Indian, so "unlike the scams
    I was trained on" is no evidence that a message is safe (a new Indian UPI trick looks
    unlike them too), and it must not dilute what the rules found."""
    if model is None:
        return SignalOutcome(SOURCE, None, "model not available")
    probs = model.predict_proba(text)
    p_scam = probs.get(SCAM, 0.0)
    detail = ", ".join(f"P({c}) {p:.2f}" for c, p in sorted(probs.items(), key=lambda x: -x[1]))
    if p_scam < min_scam_probability:
        detail += f"; below {min_scam_probability:g}: not counted"
        return SignalOutcome(SOURCE, round(100 * p_scam, 1), detail, informative=False)
    return SignalOutcome(SOURCE, round(100 * p_scam, 1), detail)
