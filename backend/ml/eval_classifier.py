"""Evaluate the trained classifier, the rules and both combined, on held-out data only.

Systems (same messages, same labels):
- rules:      pipeline.analyze_text with the classifier off (extractors, rules, UPI check).
              Continuous score: risk_score. Flagged: verdict suspicious or scam.
- classifier: the exported JSON model (models/classifier.json), run by the service's code.
              Continuous score: calibrated P(scam). Flagged: P(scam) >= 0.5.
- combined:   pipeline.analyze_text with the classifier signal (weights from config).
              Continuous score: risk_score. Flagged: verdict suspicious or scam.
No network, no LLM, no pattern similarity: the offline pipeline, reproducible.

Evaluation sets (processed/, from ml/prepare_dataset.py; none of them trained on):
- indian_test:     the frozen Indian test split (reviewed labels, manual or AI-assisted).
- india_heldout:   held-out template groups of Indian rows: India Spam SMS ham (dataset
                   label) and promos (auto/assisted labels), IMC25 reports from Indian
                   networks, collected messages.
- mendeley_heldout, imc_heldout (non-Indian IMC25): held-out template groups.
- uci_unseen:      UCI rows sharing no template with train/val (out-of-domain). Its "spam"
                   is not our "scam": only the ham false-positive rate means much.
- examples:        the 36 built-in messages (tests/examples.py): a regression check.

Writes ml/reports/private/<date>_<name>.md (it quotes messages, some of them collected)
and ml/reports/private/<date>_<name>_pr.svg; --name defaults to "classifier".

    uv run python -m ml.eval_classifier
"""

import argparse
import hashlib
import json
import math
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import numpy as np

from app.core.config import Settings, get_settings
from app.core.enums import Verdict
from app.services import pipeline
from app.services.classifier import ScamClassifier
from ml.common import LABELS, PROCESSED_DIR, REPORTS_DIR, as_bool, read_csv
from ml.evaluate import _git_rev, _one_line

PRIVATE_DIR = REPORTS_DIR / "private"
CLASSES = sorted(LABELS)  # genuine, promo_spam, scam
SYSTEMS = ("rules", "classifier", "combined")
FLAGGED = {Verdict.SUSPICIOUS, Verdict.SCAM}
CLF_THRESHOLD = 0.5
TARGET_RECALL = 0.90


@dataclass
class Scored:
    id: str
    text: str
    label: str  # genuine | promo_spam | scam, or UCI's "spam"
    dataset: str
    is_indian: bool
    label_source: str
    probs: dict[str, float] = field(default_factory=dict)
    score: dict[str, float] = field(default_factory=dict)  # system -> continuous score
    flagged: dict[str, bool] = field(default_factory=dict)
    verdict: dict[str, str] = field(default_factory=dict)

    @property
    def positive(self) -> bool:
        return self.label in ("scam", "spam")

    @property
    def predicted(self) -> str:
        return max(self.probs, key=self.probs.__getitem__)


# ----------------------------------------------------------------------------- scoring


def score_rows(
    rows: Sequence[dict[str, str]], model: ScamClassifier, settings: Settings
) -> list[Scored]:
    rules_only = settings.model_copy(update={"CLASSIFIER_ENABLED": False})
    out = []
    for r in rows:
        s = Scored(r.get("id", ""), r["text"], r["label"], r.get("dataset", ""),
                   as_bool(r.get("is_indian")), r.get("label_source", ""))  # fmt: skip
        s.probs = model.predict_proba(s.text)
        rules = pipeline.analyze_text(s.text, rules_only).result
        combined = pipeline.analyze_text(s.text, settings).result
        s.score = {"rules": rules.risk_score, "classifier": s.probs["scam"],
                   "combined": combined.risk_score}  # fmt: skip
        s.flagged = {"rules": rules.verdict in FLAGGED,
                     "classifier": s.probs["scam"] >= CLF_THRESHOLD,
                     "combined": combined.verdict in FLAGGED}  # fmt: skip
        s.verdict = {"rules": rules.verdict.value, "combined": combined.verdict.value}
        out.append(s)
    return out


# ----------------------------------------------------------------------------- metrics


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson interval for k successes out of n."""
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def rate(k: int, n: int) -> str:
    """'12.3% (k/n, 95% CI a–b)'."""
    if n == 0:
        return "– (n=0)"
    lo, hi = wilson(k, n)
    return f"{k / n:.1%} ({k}/{n}, CI {lo:.0%}–{hi:.0%})"


def average_precision(scores: np.ndarray, y: np.ndarray) -> float:
    """Step-wise AP (like scikit-learn's), ties handled as one threshold."""
    if y.sum() == 0:
        return math.nan
    order = np.argsort(-scores, kind="stable")
    s, t = scores[order], y[order]
    tp = np.cumsum(t)
    last = np.r_[np.diff(s) != 0, True]  # last index of each tie block
    tp_at, n_at = tp[last], np.arange(1, len(s) + 1)[last]
    precision, recall = tp_at / n_at, tp_at / y.sum()
    return float(np.sum(np.diff(np.r_[0.0, recall]) * precision))


def pr_curve(scores: np.ndarray, y: np.ndarray) -> list[tuple[float, float, float]]:
    """(threshold, precision, recall) at every distinct threshold, high to low."""
    order = np.argsort(-scores, kind="stable")
    s, t = scores[order], y[order]
    tp = np.cumsum(t)
    last = np.r_[np.diff(s) != 0, True]
    n_at = np.arange(1, len(s) + 1)[last]
    pos = max(1, int(y.sum()))
    return [
        (float(th), float(k / n), float(k / pos))
        for th, k, n in zip(s[last], tp[last], n_at, strict=True)
    ]


def fpr_at_recall(
    scores: np.ndarray, y: np.ndarray, target: float = TARGET_RECALL
) -> tuple[float, float] | None:
    """(FPR, threshold) at the highest threshold whose recall is >= target."""
    pos, neg = scores[y == 1], scores[y == 0]
    if len(pos) == 0 or len(neg) == 0:
        return None
    for th in np.unique(scores)[::-1]:
        if (pos >= th).mean() >= target:
            return float((neg >= th).mean()), float(th)
    return None


@dataclass
class Binary:
    tp: int
    fp: int
    tn: int
    fn: int

    @classmethod
    def of(cls, rows: Sequence[Scored], system: str) -> "Binary":
        c = Counter((r.positive, r.flagged[system]) for r in rows)
        return cls(c[(True, True)], c[(False, True)], c[(False, False)], c[(True, False)])

    def f1(self) -> float:
        d = 2 * self.tp + self.fp + self.fn
        return 2 * self.tp / d if d else math.nan


def _pct(x: float | None) -> str:
    return "–" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.1%}"


# ----------------------------------------------------------------------------- report parts


def per_class_table(rows: Sequence[Scored]) -> list[str]:
    """Classifier (argmax) per-class precision / recall / F1, with support."""
    lines = ["| class | support | precision | recall | F1 |", "|---|---:|---:|---:|---:|"]
    f1s = []
    for c in CLASSES:
        tp = sum(r.label == c and r.predicted == c for r in rows)
        pred = sum(r.predicted == c for r in rows)
        sup = sum(r.label == c for r in rows)
        p = tp / pred if pred else math.nan
        rc = tp / sup if sup else math.nan
        f1 = 2 * p * rc / (p + rc) if pred and sup and (p + rc) else math.nan
        if sup:
            f1s.append(0.0 if math.isnan(f1) else f1)
        lines.append(
            f"| {c} | {sup} | {_pct(p)} ({tp}/{pred}) | {_pct(rc)} ({tp}/{sup}) | {_pct(f1)} |"
        )
    macro = float(np.mean(f1s)) if f1s else math.nan
    lines.append(f"| **macro (classes present)** | {len(rows)} | | | **{_pct(macro)}** |")
    return lines


def confusion(rows: Sequence[Scored]) -> list[str]:
    lines = [
        "| true \\ predicted | " + " | ".join(CLASSES) + " |",
        "|---|" + "---:|" * len(CLASSES),
    ]
    for t in CLASSES:
        if not any(r.label == t for r in rows):
            continue
        lines.append(
            f"| **{t}** | "
            + " | ".join(str(sum(r.label == t and r.predicted == p for r in rows)) for p in CLASSES)
            + " |"
        )
    return lines


def ablation_table(rows: Sequence[Scored]) -> list[str]:
    y = np.array([r.positive for r in rows], dtype=int)
    lines = [
        "| system | precision | recall (scam) | F1 | FPR (not scam) | AP | FPR at 90% recall |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for sys_ in SYSTEMS:
        b = Binary.of(rows, sys_)
        s = np.array([r.score[sys_] for r in rows], dtype=float)
        at = fpr_at_recall(s, y)
        at_txt = "–" if at is None else f"{at[0]:.1%} (≥{at[1]:.2f})"
        prec = b.tp / (b.tp + b.fp) if b.tp + b.fp else math.nan
        lines.append(
            f"| {sys_} | {_pct(prec)} | {rate(b.tp, b.tp + b.fn)} | {_pct(b.f1())} | "
            f"{rate(b.fp, b.fp + b.tn)} | {_pct(average_precision(s, y))} | {at_txt} |"
        )
    return lines


def fpr_rows(name: str, rows: Sequence[Scored]) -> list[str]:
    out = []
    for sys_ in SYSTEMS:
        k = sum(r.flagged[sys_] for r in rows)
        out.append(f"| {name} | {sys_} | {rate(k, len(rows))} |")
    return out


def _md_code(term: str) -> str:
    return term.replace("|", "\\|").replace("`", "'")


def top_ngrams(model: ScamClassifier, k: int = 20) -> list[str]:
    names = []
    for b in model.blocks:
        kind = "char" if b.analyzer.__name__.startswith("char") else "word"
        inv = sorted(b.vocabulary, key=b.vocabulary.__getitem__)
        names += [f"{kind} `{_md_code(t)}`" for t in inv]
    lines = []
    for ci, c in enumerate(model.classes):
        # A feature's pull towards one class relative to the others (softmax is shift-invariant).
        rel = model.coef[ci] - np.delete(model.coef, ci, axis=0).mean(axis=0)
        top = np.argsort(-rel)[:k]
        lines += [f"**{c}**: " + ", ".join(f"{names[i]} ({rel[i]:+.1f})" for i in top), ""]
    return lines


def worst_errors(rows: Sequence[Scored], k: int = 20) -> list[str]:
    wrong = [r for r in rows if r.label in CLASSES and r.predicted != r.label]
    wrong.sort(key=lambda r: -r.probs[r.predicted])
    lines = []
    for r in wrong[:k]:
        probs = ", ".join(f"{c} {r.probs[c]:.2f}" for c in CLASSES)
        lines.append(
            f"- true **{r.label}** → predicted **{r.predicted}** ({probs}) · {r.dataset}"
            f"{' (IN)' if r.is_indian else ''} · rules {r.verdict['rules']}, combined "
            f"{r.verdict['combined']}\n  > {_one_line(r.text, 300)}"
        )
    return lines


# ----------------------------------------------------------------------------- PR chart

# Categorical slots 1-3 of the validated default palette (dataviz skill), fixed order:
# classifier, rules, combined. Dashes are the second encoding so identity is not colour alone.
SERIES = {
    "classifier": ("#2a78d6", "#3987e5", ""),
    "rules": ("#eb6834", "#d95926", "6 4"),
    "combined": ("#1baf7a", "#199e70", "2 3"),
}


def pr_svg(panels: list[tuple[str, Sequence[Scored]]]) -> str:
    w, h, pad_l, pad_b, pad_t, gap = 360, 300, 46, 40, 34, 36
    total_w = len(panels) * (w + gap)
    css = [
        ".bg{fill:#ffffff}.ink{fill:#1f1f1e}.muted{fill:#6b6a63}.grid{stroke:#e4e3dd}",
        ".ax{stroke:#8d8c84}",
        *(f".s-{k}{{stroke:{light}}}.f-{k}{{fill:{light}}}" for k, (light, _, _) in SERIES.items()),
        "@media (prefers-color-scheme: dark){.bg{fill:#1a1a19}.ink{fill:#ffffff}"
        ".muted{fill:#c3c2b7}"
        ".grid{stroke:#34342f}.ax{stroke:#6b6a63}"
        + "".join(
            f".s-{k}{{stroke:{dark}}}.f-{k}{{fill:{dark}}}" for k, (_, dark, _) in SERIES.items()
        )
        + "}",
    ]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_w} {h + 40}" '
        f'font-family="system-ui,sans-serif" font-size="12" role="img" '
        f'aria-label="Precision-recall curves, scam versus rest">',
        f"<style>{''.join(css)}</style>",
        f'<rect class="bg" width="{total_w}" height="{h + 40}"/>',
    ]
    for pi, (title, rows) in enumerate(panels):
        x0 = pi * (w + gap) + pad_l
        pw, ph = w - pad_l - 10, h - pad_t - pad_b

        def px(r: float, x0: float = x0, pw: float = pw) -> float:
            return x0 + r * pw

        def py(p: float, ph: float = ph) -> float:
            return pad_t + (1 - p) * ph

        n_pos = sum(r.positive for r in rows)
        parts.append(f'<text class="ink" x="{x0}" y="18" font-weight="600">{title} '
                     f'({n_pos} scams / {len(rows)})</text>')  # fmt: skip
        for v in (0, 0.25, 0.5, 0.75, 1):
            parts.append(
                f'<line class="grid" x1="{px(0)}" x2="{px(1)}" y1="{py(v)}" y2="{py(v)}"/>'
            )
            parts.append(
                f'<text class="muted" x="{x0 - 6}" y="{py(v) + 4}" text-anchor="end">{v:.2g}</text>'
            )
            parts.append(
                f'<text class="muted" x="{px(v)}" y="{pad_t + ph + 16}" '
                f'text-anchor="middle">{v:.2g}</text>'
            )
        parts.append(f'<line class="ax" x1="{px(0)}" x2="{px(1)}" y1="{py(0)}" y2="{py(0)}"/>')
        parts.append(
            f'<text class="muted" x="{px(0.5)}" y="{pad_t + ph + 32}" '
            'text-anchor="middle">recall</text>'
        )
        parts.append(
            f'<text class="muted" x="{x0 - 34}" y="{py(0.5)}" '
            f'transform="rotate(-90 {x0 - 34} {py(0.5)})" text-anchor="middle">precision</text>'
        )
        y = np.array([r.positive for r in rows], dtype=int)
        for li, (sys_, (_, _, dash)) in enumerate(SERIES.items()):
            s = np.array([r.score[sys_] for r in rows], dtype=float)
            curve = pr_curve(s, y)
            pts = [(0.0, curve[0][1])] + [(rc, p) for _, p, rc in curve]
            d = " ".join(
                f"{'M' if i == 0 else 'L'}{px(rc):.1f},{py(p):.1f}" for i, (rc, p) in enumerate(pts)
            )
            dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
            ap = average_precision(s, y)
            parts.append(f'<path class="s-{sys_}" d="{d}" fill="none" stroke-width="2"{dash_attr}>'
                         f"<title>{sys_}: AP {ap:.3f}</title></path>")  # fmt: skip
            # Legend (always present for 3 series) doubles as the direct label, with AP.
            ly = pad_t + ph - 12 - (2 - li) * 16
            parts.append(
                f'<line class="s-{sys_}" x1="{px(0.04)}" x2="{px(0.04) + 22}" y1="{ly}" '
                f'y2="{ly}" stroke-width="2"{dash_attr}/>'
            )
            parts.append(
                f'<text class="ink" x="{px(0.04) + 28}" y="{ly + 4}">{sys_} · AP {ap:.2f}</text>'
            )
    parts.append("</svg>")
    return "\n".join(parts)


# ----------------------------------------------------------------------------- main


def load_sets() -> dict[str, list[dict[str, str]]]:
    def csv_rows(name: str) -> list[dict[str, str]]:
        path = PROCESSED_DIR / name
        if not path.exists():
            sys.exit(f"{path} not found. Run: uv run python -m ml.prepare_dataset")
        return read_csv(path)

    heldout = csv_rows("heldout.csv")
    from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES

    examples = [{"id": f"ex{i}", "text": t, "label": "scam", "dataset": "examples"}
                for i, (_, t) in enumerate(SCAM_EXAMPLES)]  # fmt: skip
    examples += [{"id": f"ex-g{i}", "text": t, "label": "genuine", "dataset": "examples"}
                 for i, (_, t) in enumerate(GENUINE_EXAMPLES)]  # fmt: skip
    uci = [
        dict(r, label="spam" if r["label"] == "spam" else "genuine")
        for r in csv_rows("ood_uci_unseen.csv")
    ]
    return {
        "indian_test": csv_rows("test.csv"),
        "india_heldout": [r for r in heldout if as_bool(r["is_indian"])],
        "mendeley_heldout": [r for r in heldout if r["dataset"] == "mendeley_sms_phishing"],
        "imc_heldout": [
            r for r in heldout if r["dataset"] == "imc25_smishing" and not as_bool(r["is_indian"])
        ],
        "uci_unseen": uci,
        "examples": examples,
    }


TRUST = {
    "indian_test": "**Weak.** 29 messages, only 2 scams; recall on 2 messages is not a rate. 27 of "
    "the labels are AI-assisted (Claude), 2 are yours. Read it as a smoke test.",
    "india_heldout": "**Moderate.** Real Indian messages. Scams are IMC25 user reports from Indian "
    "networks (dataset labels, masked links: the rules cannot see the real domain) plus 2 of "
    "yours; ham is India Spam SMS 'ham' (dataset label, some noise); promos are mostly auto "
    "labels from ml/autolabel.py, which uses these same rules, so the rules' promo FPR here is "
    "optimistic (circular).",
    "mendeley_heldout": "**Moderate, but not Indian.** Mostly UK/Singapore SMS (much of it UCI); "
    "its spam/smishing split is noisy.",
    "imc_heldout": "**Scam recall only** (every row is a scam). Non-Indian, many countries; links "
    "masked by the dataset, so the rules are handicapped here.",
    "uci_unseen": "**Ham FPR only.** UCI rows no model saw (the rest of UCI shares a "
    "template with Mendeley train/val). UCI 'spam' ≠ our scam, so its recall is not scam recall.",
    "examples": "**Regression check, not accuracy.** Written together with the rules.",
}


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", type=Path, default=get_settings().CLASSIFIER_MODEL_PATH)
    parser.add_argument("--name", default="classifier", help="report file name")
    args = parser.parse_args()
    settings = get_settings().model_copy(update={"CLASSIFIER_MODEL_PATH": args.model,
                                                 "SAFE_BROWSING_API_KEY": ""})  # fmt: skip
    raw = args.model.read_bytes()
    model = ScamClassifier.from_dict(json.loads(raw))
    sets = {name: score_rows(rows, model, settings) for name, rows in load_sets().items()}
    print("scored: " + ", ".join(f"{k} {len(v)}" for k, v in sets.items()))

    today = date.today().isoformat()
    pooled = [*sets["india_heldout"], *sets["mendeley_heldout"], *sets["imc_heldout"]]
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    svg_path = PRIVATE_DIR / f"{today}_{args.name}_pr.svg"
    svg_path.write_text(pr_svg([("India held-out", sets["india_heldout"]),
                                ("All held-out + Indian test", [*pooled, *sets["indian_test"]])]),
                        encoding="utf-8")  # fmt: skip

    ind = sets["india_heldout"]
    test = sets["indian_test"]
    manual = [r for r in test if r.label_source == "manual"]
    assisted = [r for r in test if r.label_source == "assisted"]
    meta = model.meta
    lines = [
        "# Classifier evaluation",
        "",
        f"- date {today} · code `{_git_rev()}` · model `{args.model.name}` "
        f"{len(raw) / 1e6:.1f} MB, sha256 `{hashlib.sha256(raw).hexdigest()[:16]}`",
        f"- model: TF-IDF char 2-5 + word 1-2 → logistic regression, C={meta.get('C')}, "
        f"{meta.get('n_features')} features, temperature {model.temperature:.3f}; trained "
        f"{meta.get('trained')} on {sum(meta.get('train_labels', {}).values())} rows "
        f"{meta.get('train_labels')} ({meta.get('synthetic_rows')} synthetic)",
        f"- classifier flagged = calibrated P(scam) ≥ {CLF_THRESHOLD}; rules / combined flagged = "
        "verdict suspicious or scam. Offline pipeline (no network, LLM or pattern similarity).",
        f"- weights: `{settings.SIGNAL_WEIGHTS}`",
        "- Every set below is held out: no message (and no near-duplicate template) was in "
        "train or val. 95% Wilson intervals in brackets.",
        f"- **Test labels: {len(manual)} manual (author), {len(assisted)} AI-assisted (Claude)**",
        "",
        "## How much to trust each number",
        "",
        *[f"- `{k}` ({len(sets[k])} messages): {v}" for k, v in TRUST.items()],
        "",
        "## Per-class metrics (classifier, argmax of 3 classes)",
        "",
    ]
    for title, rows in (
        ("India held-out", ind),
        ("Mendeley held-out", sets["mendeley_heldout"]),
        ("All held-out pooled (India + Mendeley + IMC25)", pooled),
        ("Indian test split · combined labels", test),
        ("Indian test split · manual labels only", manual),
        ("Indian test split · AI-assisted labels only", assisted),
    ):
        lines += [
            f"### {title} ({len(rows)})",
            "",
            *per_class_table(rows),
            "",
            *confusion(rows),
            "",
        ]

    lines += ["## Scam vs rest: ablation (same messages for every system)", ""]
    for name in ("india_heldout", "indian_test", "mendeley_heldout", "imc_heldout", "uci_unseen"):
        extra = " — positives are UCI 'spam', not our scam" if name == "uci_unseen" else ""
        lines += [f"### {name} ({len(sets[name])}){extra}", "", *ablation_table(sets[name]), ""]
    lines += [f"### all held-out pooled ({len(pooled)})", "", *ablation_table(pooled), ""]

    india_ham = [r for r in ind if r.label == "genuine"]
    india_promo = [r for r in ind if r.label == "promo_spam"]
    uci_ham = [r for r in sets["uci_unseen"] if r.label == "genuine"]
    lines += [
        "## False-positive rates on not-scam messages",
        "",
        "| set | system | flagged |",
        "|---|---|---:|",
        *fpr_rows("India ham (held-out)", india_ham),
        *fpr_rows("India promo (held-out)", india_promo),
        *fpr_rows(
            "Mendeley ham (held-out)", [r for r in sets["mendeley_heldout"] if r.label == "genuine"]
        ),
        *fpr_rows("UCI ham (unseen)", uci_ham),
        "",
    ]

    ex = sets["examples"]
    changed = [r for r in ex if r.verdict["rules"] != r.verdict["combined"]]
    lines += [
        "## Built-in examples (36)",
        "",
        f"{len(ex) - len(changed)} of {len(ex)} keep their verdict with the classifier signal "
        f"added. Rules: {Counter(r.verdict['rules'] for r in ex)}; combined: "
        f"{Counter(r.verdict['combined'] for r in ex)}.",
        "",
        *[
            f"- **changed** {r.verdict['rules']} → {r.verdict['combined']}: "
            f"{_one_line(r.text, 160)}"
            for r in changed
        ],
        "",
        "## PR curves (scam vs rest)",
        "",
        f"![PR curves]({svg_path.name})",
        "",
        "## Most influential n-grams per class",
        "",
        "Coefficient of the class minus the mean of the other classes (log-odds per unit of "
        "tf-idf). Mask tokens like `<url>` come from features.preprocess.",
        "",
        *top_ngrams(model),
        "## 20 worst errors (held-out + Indian test, most confident first)",
        "",
        *worst_errors([*pooled, *test]),
        "",
    ]
    out = PRIVATE_DIR / f"{today}_{args.name}.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"report: {out}\nchart: {svg_path}")

    # The headline numbers, for the terminal.
    print(f"\nTest labels: {len(manual)} manual (author), {len(assisted)} AI-assisted (Claude)")
    for name in ("india_heldout", "indian_test", "mendeley_heldout", "imc_heldout", "uci_unseen"):
        print(f"\n[{name}] ({len(sets[name])})")
        print("\n".join(ablation_table(sets[name])))
    print(f"\n[all held-out pooled] ({len(pooled)})\n" + "\n".join(ablation_table(pooled)))
    print(
        "\nFPR\n"
        + "\n".join(
            [
                *fpr_rows("India ham", india_ham),
                *fpr_rows("India promo", india_promo),
                *fpr_rows("UCI ham unseen", uci_ham),
            ]
        )
    )
    print(f"\nexamples keeping verdict: {len(ex) - len(changed)}/{len(ex)}")
    for title, rows in (
        ("India held-out", ind),
        ("pooled held-out", pooled),
        ("Indian test", test),
    ):
        print(
            f"\nper-class, {title}\n"
            + "\n".join(per_class_table(rows))
            + "\n"
            + "\n".join(confusion(rows))
        )


if __name__ == "__main__":
    main()
