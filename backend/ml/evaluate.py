"""Run the real analysis pipeline (in-process, not over HTTP) on an eval set and write
ml/reports/<date>_<name>.md.

Modes (--modes, comma-separated):
- rules:  extractors + rules + UPI check (pipeline.analyze_text). Pure, offline.
- checks: the agent graph with explain=false: rules + pattern similarity (local fastembed
          model, knowledge base retrieved in memory, no database) + url_intel/reputation
          when --network is given. No LLM.
- llm:    the full graph with the Groq LLM step, on a balanced sample of --llm-limit
          messages, --llm-sleep seconds apart (free tier). The same sample's "checks"
          numbers are shown next to it.

Without --network, url_intel and reputation are reported unavailable, so runs are offline
and reproducible. With it, links are expanded/looked up and reputation is read from the
database (DATABASE_URL).

"Flagged" = verdict suspicious or scam. Positives: label "scam" (collected data), or the
public datasets' "spam"/"smishing" (NOT the same thing as our "scam"; see the report).

    uv run python -m ml.evaluate --dataset examples
    uv run python -m ml.evaluate --dataset uci
    uv run python -m ml.evaluate --dataset india --modes checks   # ham / promo FPR
    uv run python -m ml.evaluate --dataset collected --modes checks   # every message
    uv run python -m ml.evaluate --dataset test --modes rules,checks,llm --llm-limit 30
    uv run python -m ml.evaluate --dataset path/to/file.csv --name my_set   # text,label

Reports quote messages. A set that contains your collected messages (any row with dataset
"collected": collected, and the val/test splits) or a custom CSV is written to
ml/reports/private/ (gitignored), and --out must be a path git ignores or one outside the
repository.
"""

import argparse
import asyncio
import hashlib
import json
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable, Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass, field, replace
from datetime import date, timedelta
from pathlib import Path

from app.core.config import Settings, get_settings
from app.core.enums import Verdict
from app.schemas.analysis import AnalysisResult
from app.services import pipeline, rag, reputation
from app.services.agent.graph import get_graph, run_analysis
from app.services.agent.llm import GroqReasoner, LRUTTLCache, Reasoner
from app.services.cache import LookupCache
from app.services.embeddings import FastEmbedder
from app.services.knowledge_base import load_docs
from ml.autolabel import UNCERTAIN
from ml.common import OOD_LABELS, PROCESSED_DIR, REPORTS_DIR, guess_language, read_csv

# Reports that quote your collected messages. Gitignored (see the repository .gitignore).
PRIVATE_REPORTS_DIR = REPORTS_DIR / "private"

FLAGGED = {Verdict.SUSPICIOUS, Verdict.SCAM}
MODES = ("rules", "checks", "llm")


# ----------------------------------------------------------------------------- data


@dataclass(frozen=True)
class Item:
    id: str
    text: str
    positive: bool
    group: str  # scam_type for positives when known, else the original label; for
    # negatives the label (genuine, promo_spam)
    language: str
    scam_type: str = ""
    label: str = ""
    label_source: str = ""  # manual | dataset | auto | synthetic (processed CSVs)


@dataclass(frozen=True)
class EvalSet:
    name: str
    items: list[Item]
    caveat: str
    positive_desc: str
    private: bool = False  # quotes your collected messages: report kept out of git
    notes: tuple[str, ...] = ()  # printed in every report (e.g. the test split's history)


EXAMPLES_CAVEAT = (
    "**Not a real accuracy number.** These 36 messages (tests/examples.py) were written "
    "alongside the rules, and the test suite requires every one to be classified correctly. "
    "They are a regression check that the pipeline still does what it was built to do, "
    "nothing more."
)
UCI_CAVEAT = (
    "**Out-of-domain baseline.** UCI SMS Spam Collection (2011/2012): mostly UK and "
    'Singapore SMS, no UPI, almost no Indian brands. Its "spam" label mixes promotions, '
    "premium-rate prize lures and subscription services with outright scams, and our "
    'detector only targets v1 Indian UPI/link fraud, so **recall on "spam" is not scam '
    "recall** and a low number is expected. The meaningful number here is the **false "
    "positive rate on ham**: how often ordinary messages get flagged."
)
INDIAN_CAVEAT = (
    "Real, anonymized Indian messages with reviewed labels: your collected messages and India "
    "Spam SMS rows labelled by you (manual) or by an AI assistant (assisted, Claude). Metrics "
    "are shown for each label source and combined. No synthetic data in val/test."
)
INDIA_SPAM_CAVEAT = (
    "**Real Indian SMS** (India Spam SMS Classification, MIT). `genuine` = the dataset's own "
    "ham label. `scam` and `promo_spam` are mostly **auto labels** from ml/autolabel.py, which "
    "uses these same rules, so recall on auto-labelled scams is circular and inflated: read "
    "the **false-positive rates** (ham, and promo spam) below, not recall. Reviewed rows "
    "count as label_source manual (you) or assisted (Claude). Uncertain rows are left out."
)
COLLECTED_CAVEAT = (
    "**Your collected messages** (anonymized), every one, labelled by you. Too few for a "
    "rate to mean much: read the per-message table."
)


def _item(i: int, text: str, positive: bool, group: str, scam_type: str = "") -> Item:
    short = hashlib.sha256(text.encode()).hexdigest()[:8]
    return Item(f"{i}-{short}", text, positive, group, guess_language(text), scam_type)


def load_examples() -> EvalSet:
    from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES

    items = [_item(i, t, True, st.value, st.value) for i, (st, t) in enumerate(SCAM_EXAMPLES)]
    items += [
        _item(len(items) + i, t, False, "genuine") for i, (_, t) in enumerate(GENUINE_EXAMPLES)
    ]
    return EvalSet("examples", items, EXAMPLES_CAVEAT, "the scam examples")


def load_csv_set(path: Path, name: str, caveat: str, private: bool = False) -> EvalSet:
    """`private`: treat as personal data even if no row says it comes from collected/."""
    items = []
    for i, r in enumerate(read_csv(path)):
        private = private or (r.get("dataset") or "").strip() == "collected"
        label = (r.get("label") or "").strip().lower()
        if label == UNCERTAIN:  # auto-labeller undecided: no ground truth
            continue
        original = (r.get("original_label") or label).strip().lower()
        positive = label == "scam" or label in OOD_LABELS
        scam_type = (r.get("scam_type") or "").strip()
        # promo_spam is not a scam (a negative), but keeps its own group so its
        # false-positive rate shows separately from genuine messages.
        group = (scam_type or original or label) if positive else (label or "genuine")
        lang = r.get("language") or guess_language(r["text"])
        items.append(Item(r.get("id") or str(i), r["text"], positive, group, lang, scam_type,
                          label, (r.get("label_source") or "").strip()))  # fmt: skip
    ood = any(it.group in OOD_LABELS for it in items)
    desc = 'original label spam/smishing (not our "scam")' if ood else "label scam"
    return EvalSet(name, items, caveat, desc, private)


def test_split_notes() -> tuple[str, ...]:
    """Notes about the frozen test split, kept in split_manifest.json ("notes"): they stay
    with the split until it is re-drawn (prepare_dataset --rebuild-test)."""
    path = PROCESSED_DIR / "split_manifest.json"
    if not path.exists():
        return ()
    return tuple(json.loads(path.read_text(encoding="utf-8")).get("notes", []))


def load_eval_set(dataset: str) -> EvalSet:
    if dataset == "examples":
        return load_examples()
    named = {
        "uci": ("ood_uci_sms_spam.csv", UCI_CAVEAT),
        "mendeley": ("ood_mendeley_sms_phishing.csv",
                     "**Out-of-domain.** Mendeley SMS Phishing Dataset; see "
                     "data/datasets/README.md for its caveats."),
        "test": ("test.csv", INDIAN_CAVEAT + " The frozen test split."),
        "val": ("val.csv", INDIAN_CAVEAT + " The validation split."),
        "india": ("india_spam_sms.csv", INDIA_SPAM_CAVEAT),
        "collected": ("collected.csv", COLLECTED_CAVEAT),
    }  # fmt: skip
    if dataset in named:
        file, caveat = named[dataset]
        path = PROCESSED_DIR / file
        if not path.exists():
            sys.exit(f"{path} not found. Run: uv run python -m ml.prepare_dataset "
                     "(and ml.download_public for uci)")  # fmt: skip
        es = load_csv_set(path, dataset, caveat)
        if dataset == "test":
            es = replace(es, notes=test_split_notes())
        return es
    path = Path(dataset)
    if not path.exists():
        sys.exit(f"unknown dataset {dataset!r}: use {'|'.join(['examples', *named])} or a "
                 "CSV path")  # fmt: skip
    return load_csv_set(path, path.stem, "Custom CSV.", private=True)  # may be your messages


# ----------------------------------------------------------------------------- running


@dataclass
class Prediction:
    item: Item
    result: AnalysisResult | None
    latency_ms: float
    error: str = ""

    @property
    def flagged(self) -> bool:
        return self.result is not None and self.result.verdict in FLAGGED


Analyze = Callable[[str], Awaitable[AnalysisResult]]


async def run_mode(
    items: Sequence[Item], analyze: Analyze, label: str, sleep_s: float = 0.0
) -> list[Prediction]:
    preds = []
    for n, it in enumerate(items, 1):
        if sleep_s and n > 1:
            await asyncio.sleep(sleep_s)
        start = time.perf_counter()
        try:
            result, error = await analyze(it.text), ""
        except Exception as exc:  # one bad message must not end the run
            result, error = None, f"{type(exc).__name__}: {exc}"
        preds.append(Prediction(it, result, (time.perf_counter() - start) * 1000, error))
        if n % 500 == 0 or n == len(items):
            print(f"  [{label}] {n}/{len(items)}", flush=True)
    return preds


def balanced_sample(items: Sequence[Item], n: int) -> list[Item]:
    """Up to n/2 positives and n/2 negatives, in a fixed hash order (same sample every run)."""
    order = sorted(items, key=lambda it: hashlib.sha256(it.id.encode()).hexdigest())
    pos = [it for it in order if it.positive]
    neg = [it for it in order if not it.positive]
    k = n // 2
    take_pos = pos[: max(k, n - len(neg))]
    return (take_pos + neg[: n - len(take_pos)])[:n]


# ----------------------------------------------------------------------------- metrics


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @classmethod
    def of(cls, preds: Sequence[Prediction], flagged: Callable[[Prediction], bool]) -> "Metrics":
        m = cls()
        for p in preds:
            if p.result is None:
                continue
            hit = flagged(p)
            if p.item.positive:
                m.tp, m.fn = m.tp + hit, m.fn + (not hit)
            else:
                m.fp, m.tn = m.fp + hit, m.tn + (not hit)
        return m

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @staticmethod
    def _div(a: int, b: int) -> float | None:
        return a / b if b else None

    @property
    def precision(self) -> float | None:
        return self._div(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float | None:
        return self._div(self.tp, self.tp + self.fn)

    @property
    def fpr(self) -> float | None:
        return self._div(self.fp, self.fp + self.tn)

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None:
            return None
        return 2 * p * r / (p + r) if p + r else 0.0


def pct(x: float | None) -> str:
    return "–" if x is None else f"{x:.1%}"


def percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    return statistics.quantiles(values, n=100, method="inclusive")[round(q) - 1]


def is_flagged(p: Prediction) -> bool:
    return p.flagged


def is_scam(p: Prediction) -> bool:
    return p.result is not None and p.result.verdict is Verdict.SCAM


# ----------------------------------------------------------------------------- report


@dataclass
class ModeRun:
    mode: str
    preds: list[Prediction]
    note: str = ""
    same_sample_checks: list[Prediction] = field(default_factory=list)


def _one_line(text: str, limit: int = 400) -> str:
    text = " ".join(text.split()).replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def top_signals(result: AnalysisResult, k: int = 3) -> str:
    counted = [s for s in result.signal_breakdown if s.weight > 0]
    counted.sort(key=lambda s: s.score * s.weight, reverse=True)
    return ", ".join(f"{s.source} {s.score:.0f} (w {s.weight:.2f})" for s in counted[:k]) or "none"


def _metrics_row(label: str, preds: Sequence[Prediction]) -> str:
    m = Metrics.of(preds, is_flagged)
    s = Metrics.of(preds, is_scam)
    lat = [p.latency_ms for p in preds if p.result is not None]
    errors = sum(1 for p in preds if p.result is None)
    return (
        f"| {label} | {m.n} | {pct(m.precision)} | {pct(m.recall)} | {pct(m.f1)} | "
        f"{pct(m.fpr)} | {pct(s.precision)} / {pct(s.recall)} | {percentile(lat, 50):.0f} | "
        f"{percentile(lat, 95):.0f} | {errors} |"
    )


METRICS_HEADER = (
    "| mode | n | precision | recall | F1 | FPR | scam-only P / R | p50 ms | p95 ms | errors |\n"
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
)


def _confusion(preds: Sequence[Prediction]) -> list[str]:
    m = Metrics.of(preds, is_flagged)
    return [
        "| | flagged | not flagged |",
        "|---|---:|---:|",
        f"| **positive** | TP {m.tp} | FN {m.fn} |",
        f"| **negative** | FP {m.fp} | TN {m.tn} |",
    ]


def _breakdown(preds: Sequence[Prediction], key: Callable[[Item], str], title: str) -> list[str]:
    groups: dict[str, list[Prediction]] = defaultdict(list)
    for p in preds:
        if p.result is not None:
            groups[key(p.item)].append(p)
    lines = [
        f"| {title} | n | positives | flagged (TP) | recall | negatives | flagged (FP) | FPR "
        "| scam_type matches |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name in sorted(groups):
        g = groups[name]
        m = Metrics.of(g, is_flagged)
        typed = [p for p in g if p.item.positive and p.item.scam_type and p.flagged]
        match = sum(1 for p in typed if p.result and p.result.scam_type == p.item.scam_type)
        type_col = f"{match}/{len(typed)}" if typed else "–"
        lines.append(
            f"| {name} | {len(g)} | {m.tp + m.fn} | {m.tp} | {pct(m.recall)} | {m.fp + m.tn} | "
            f"{m.fp} | {pct(m.fpr)} | {type_col} |"
        )
    return lines


def _negative_fpr(preds: Sequence[Prediction]) -> list[str]:
    """False-positive rate per not-scam label and who labelled it (genuine from the
    dataset, promo_spam from the auto-labeller, ...). Empty for sets without labels."""
    groups: dict[tuple[str, str], list[Prediction]] = defaultdict(list)
    for p in preds:
        if p.result is not None and not p.item.positive and p.item.label:
            groups[(p.item.label, p.item.label_source or "–")].append(p)
    if not groups:
        return []
    lines = [
        "| not-scam label | labelled by | n | flagged | FPR | of which verdict scam |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for (label, source), g in sorted(groups.items()):
        flagged = sum(p.flagged for p in g)
        scam = sum(is_scam(p) for p in g)
        lines.append(f"| {label} | {source} | {len(g)} | {flagged} | {pct(flagged / len(g))} "
                     f"| {scam} |")  # fmt: skip
    return lines


PER_MESSAGE_MAX = 100  # sets this small get a table of every message


def _outcome(p: Prediction) -> str:
    if p.item.positive and not p.flagged:
        return "**MISSED**"
    if not p.item.positive and p.flagged:
        return "**FALSE ALARM**"
    return "ok"


def _per_message(preds: Sequence[Prediction]) -> list[str]:
    lines = [
        "| # | expected | score | verdict | outcome | top signals | message |",
        "|---:|---|---:|---|---|---|---|",
    ]
    for n, p in enumerate(preds, 1):
        expected = p.item.label or ("scam" if p.item.positive else "genuine")
        if p.item.scam_type:
            expected += f" ({p.item.scam_type})"
        if p.result is None:
            lines.append(f"| {n} | {expected} | – | error | {p.error} | | "
                         f"{_one_line(p.item.text, 160)} |")  # fmt: skip
            continue
        flags = ", ".join(f.code for f in p.result.red_flags) or "none"
        lines.append(
            f"| {n} | {expected} | {p.result.risk_score} | {p.result.verdict.value} | "
            f"{_outcome(p)} | {top_signals(p.result)}; flags: {flags} | "
            f"{_one_line(p.item.text, 160)} |"
        )
    return lines


def _mistakes(preds: Sequence[Prediction]) -> tuple[list[Prediction], list[Prediction]]:
    fps = sorted(
        (p for p in preds if p.result and not p.item.positive and p.flagged),
        key=lambda p: -p.result.risk_score,  # type: ignore[union-attr]
    )
    fns = sorted(
        (p for p in preds if p.result and p.item.positive and not p.flagged),
        key=lambda p: p.result.risk_score,  # type: ignore[union-attr]
    )
    return fps, fns


def _mistake_line(p: Prediction) -> str:
    r = p.result
    assert r is not None
    flags = ", ".join(f.code for f in r.red_flags) or "none"
    return (
        f"- **{r.risk_score} {r.verdict.value}** · group `{p.item.group}` · lang "
        f"{p.item.language} · top: {top_signals(r)} · flags: {flags}\n"
        f"  > {_one_line(p.item.text)}"
    )


def _git_rev() -> str:
    try:
        rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                             text=True, check=True).stdout.strip()  # fmt: skip
        dirty = subprocess.run(["git", "status", "--porcelain", "--", "app"],
                               capture_output=True, text=True).stdout.strip()  # fmt: skip
        return f"{rev}{' + uncommitted changes in app/' if dirty else ''}"
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def git_would_track(path: Path) -> bool:
    """True if `path` is inside this repository and not gitignored (or already tracked)."""
    try:
        r = subprocess.run(["git", "check-ignore", "-q", str(path.resolve())],
                           cwd=REPORTS_DIR.parent, capture_output=True)  # fmt: skip
    except OSError:  # no git: only the private folder counts as safe
        return not path.resolve().is_relative_to(PRIVATE_REPORTS_DIR.resolve())
    # 0: ignored. 1: not ignored (tracked files never count as ignored). 128: outside the
    # repository, or not a repository at all.
    return r.returncode == 1


def report_path(es: EvalSet, name: str, out: str | None) -> Path:
    if out:
        path = Path(out)
        if es.private and git_would_track(path):
            sys.exit(f"{path}: this report quotes your collected messages and git would "
                     f"track it. Leave out --out (it goes to {PRIVATE_REPORTS_DIR}) or pick "
                     "a gitignored path.")  # fmt: skip
        return path
    folder = PRIVATE_REPORTS_DIR if es.private else REPORTS_DIR
    return folder / f"{date.today().isoformat()}_{name}.md"


REVIEWED = ("manual", "assisted")


def label_note(es: EvalSet, name: str) -> str | None:
    """'Test labels: N manual (author), M AI-assisted (Claude)' for sets with reviewed
    labels; None for sets labelled only by a dataset or the auto-labeller."""
    sources = [it.label_source for it in es.items]
    if not any(src in REVIEWED for src in sources):
        return None
    what = "Test labels" if name == "test" else "Labels"
    note = (f"{what}: {sources.count('manual')} manual (author), "
            f"{sources.count('assisted')} AI-assisted (Claude)")  # fmt: skip
    if other := len(sources) - sources.count("manual") - sources.count("assisted"):
        note += f", {other} from the dataset or the auto-labeller"
    return note


def by_label_source(label: str, preds: Sequence[Prediction]) -> list[tuple[str, list[Prediction]]]:
    """(row label, predictions): combined, then manual-only and assisted-only when the set
    mixes the two, so AI-assisted labels never hide inside one number."""
    groups = [(label, list(preds))]
    manual = [p for p in preds if p.item.label_source == "manual"]
    assisted = [p for p in preds if p.item.label_source == "assisted"]
    if assisted:
        groups = [(f"{label} · combined", list(preds)), (f"{label} · manual labels", manual),
                  (f"{label} · AI-assisted labels", assisted)]  # fmt: skip
    return groups


def render(es: EvalSet, runs: list[ModeRun], settings: Settings, network: bool, name: str) -> str:
    pos = sum(it.positive for it in es.items)
    lines = [
        f"# Evaluation: {name}",
        "",
        f"> {es.caveat}",
        "",
        f"- date: {date.today().isoformat()} · code: `{_git_rev()}`",
        f"- messages: {len(es.items)} ({pos} positives = {es.positive_desc}; "
        f"{len(es.items) - pos} negatives)",
        f"- network checks (url_intel, reputation): {'ON' if network else 'OFF (offline)'}",
        f"- weights: `{settings.SIGNAL_WEIGHTS}` · thresholds: suspicious ≥ "
        f"{settings.VERDICT_SUSPICIOUS_MIN}, scam ≥ {settings.VERDICT_SCAM_MIN}",
        '- flagged = verdict suspicious or scam. "scam-only" counts only verdict scam.',
        *([f"- **{note}**"] if (note := label_note(es, name)) else []),
        *(f"- **Note:** {n}" for n in es.notes),
        "",
        "## Summary",
        "",
        METRICS_HEADER,
    ]
    for run in runs:
        lines += [_metrics_row(label, g) for label, g in by_label_source(run.mode, run.preds)]
        if run.same_sample_checks:
            lines.append(_metrics_row("checks (same sample as llm)", run.same_sample_checks))
    for run in runs:
        fps, fns = _mistakes(run.preds)
        lines += ["", f"## Mode: {run.mode}", ""]
        if run.note:
            lines += [run.note, ""]
        lines += ["### Confusion matrix", "", *_confusion(run.preds), ""]
        if fpr_lines := _negative_fpr(run.preds):
            lines += ["### False-positive rate per not-scam label", "", *fpr_lines, ""]
        if len(run.preds) <= PER_MESSAGE_MAX:
            lines += ["### Every message", "", *_per_message(run.preds), ""]
        lines += ["### Per group (scam_type, or the dataset's own label)", ""]
        lines += [*_breakdown(run.preds, lambda it: it.group, "group"), ""]
        lines += ["### Per language (heuristic)", ""]
        lines += [*_breakdown(run.preds, lambda it: it.language, "language"), ""]
        errors = [p for p in run.preds if p.result is None]
        if errors:
            lines += [f"### Errors ({len(errors)})", ""]
            lines += [f"- {p.error} · > {_one_line(p.item.text, 120)}" for p in errors[:50]]
            lines.append("")
        for title, items in (("False positives", fps), ("False negatives", fns)):
            order = "highest score first" if title.startswith("False p") else "lowest first"
            lines += [f"### {title} ({len(items)}, {order})", ""]
            if not items:
                lines += ["None.", ""]
                continue
            lines += ["<details><summary>show all</summary>", ""]
            lines += [_mistake_line(p) for p in items]
            lines += ["", "</details>", ""]
    return "\n".join(lines).rstrip() + "\n"


# ----------------------------------------------------------------------------- main


async def run(args: argparse.Namespace) -> None:
    es = load_eval_set(args.dataset)
    if args.limit:
        es.items[:] = es.items[: args.limit]
    name = args.name or es.name
    out = report_path(es, name, args.out)  # before the run: a refused path fails fast
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    if bad := [m for m in modes if m not in MODES]:
        sys.exit(f"unknown mode(s) {bad}; choose from {MODES}")
    # Safe Browsing only with --network, whatever .env says.
    settings = get_settings()
    if not args.network:
        settings = settings.model_copy(update={"SAFE_BROWSING_API_KEY": ""})
    print(f"{name}: {len(es.items)} messages, modes {modes}, network "
          f"{'on' if args.network else 'off'}")  # fmt: skip

    runs: list[ModeRun] = []
    async with AsyncExitStack() as stack:
        checks: pipeline.Checks | None = None
        if "checks" in modes or "llm" in modes:
            checks = await _build_checks(settings, args.network, stack)

        async def rules_only(text: str) -> AnalysisResult:
            return pipeline.analyze_text(text, settings).result

        def graph_mode(reasoner: Reasoner | None, explain: bool) -> Analyze:
            graph = get_graph()

            async def analyze(text: str) -> AnalysisResult:
                out = await run_analysis(text, settings, checks=checks, reasoner=reasoner,
                                         explain=explain, graph=graph)  # fmt: skip
                return out.result

            return analyze

        checks_preds: dict[str, Prediction] = {}
        if "rules" in modes:
            runs.append(ModeRun("rules", await run_mode(es.items, rules_only, "rules")))
        if "checks" in modes:
            preds = await run_mode(es.items, graph_mode(None, False), "checks")
            checks_preds = {p.item.id: p for p in preds}
            runs.append(ModeRun("checks", preds))
        if "llm" in modes:
            if not settings.GROQ_API_KEY:
                sys.exit("--modes llm needs GROQ_API_KEY in .env")
            reasoner = GroqReasoner(
                api_key=settings.GROQ_API_KEY, model=settings.GROQ_MODEL,
                fallback_model=settings.GROQ_FALLBACK_MODEL, timeout_s=settings.LLM_TIMEOUT_S,
                reasoning_effort=settings.GROQ_REASONING_EFFORT,
                cache=LRUTTLCache(settings.LLM_CACHE_SIZE, settings.LLM_CACHE_TTL_S),
            )  # fmt: skip
            sample = balanced_sample(es.items, args.llm_limit)
            print(f"  llm: {len(sample)} messages, {args.llm_sleep:g}s apart "
                  f"(~{len(sample) * args.llm_sleep / 60:.0f} min)")  # fmt: skip
            preds = await run_mode(sample, graph_mode(reasoner, True), "llm", args.llm_sleep)
            fell_back = sum(
                1 for p in preds if p.result and p.result.confidence is None
            )  # no narrative used: the LLM failed or was not counted
            note = (
                f"Balanced sample of {len(sample)} (fixed hash order), {args.llm_sleep:g}s "
                f"between calls. The LLM's text was not used for {fell_back} of them (failed, "
                "rate limited, or overruled). Latency includes the Groq round trip."
            )
            same = [checks_preds[it.id] for it in sample if it.id in checks_preds]
            runs.append(ModeRun("llm (full pipeline)", preds, note, same))

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(es, runs, settings, args.network, name), encoding="utf-8")
    print(f"\nreport: {out}\n")
    if note := label_note(es, name):
        print(note + "\n")
    for n in es.notes:
        print(f"Note: {n}\n")
    print(METRICS_HEADER)
    for r in runs:
        for label, g in by_label_source(r.mode, r.preds):
            print(_metrics_row(label, g))
        if r.same_sample_checks:
            print(_metrics_row("checks (same sample as llm)", r.same_sample_checks))
    for r in runs:
        if fpr_lines := _negative_fpr(r.preds):
            print(f"\n[{r.mode}] false-positive rate per not-scam label\n" + "\n".join(fpr_lines))


async def _build_checks(
    settings: Settings, network: bool, stack: AsyncExitStack
) -> pipeline.Checks:
    """Pattern retrieval runs in memory over the knowledge-base docs with the real local
    embedding model: no database needed, same docs as scripts/ingest_patterns.py."""
    import httpx

    from app.api.deps import new_http_client

    embedder = FastEmbedder(
        settings.EMBEDDING_MODEL, settings.EMBEDDING_CACHE_DIR, settings.EMBEDDING_DIM
    )
    patterns: rag.PatternSearch | None = None
    try:
        await embedder.load_async()
        retriever = await rag.InMemoryRetriever.from_docs(load_docs(), embedder)
        patterns = rag.PatternSearch(embedder, retriever, rag.PatternParams.from_settings(settings))
    except Exception as exc:  # fail soft, like the app: the signal is reported unavailable
        print(f"  embedding model unavailable ({type(exc).__name__}: {exc}); "
              "pattern_similarity will be missing")  # fmt: skip

    ttl = timedelta(hours=settings.URL_CACHE_TTL_HOURS)
    if not network:
        client = httpx.AsyncClient()  # never used: url_intel is off
        await stack.enter_async_context(client)
        return pipeline.Checks(client, LookupCache(None, ttl), None, patterns, network=False)

    from app.db.session import create_engine, create_sessionmaker

    client = new_http_client(settings.HTTP_TIMEOUT_S)
    await stack.enter_async_context(client)
    engine = create_engine(settings.DATABASE_URL)
    stack.push_async_callback(engine.dispose)
    sessions = create_sessionmaker(engine)
    return pipeline.Checks(
        client, LookupCache(sessions, ttl), reputation.find_reported_in(sessions), patterns
    )


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dataset",
        default="examples",
        help="examples | uci | mendeley | test | val | india | collected | path to a CSV",
    )
    parser.add_argument("--name", help="report name (default: the dataset name)")
    parser.add_argument("--modes", default="rules,checks", help=f"comma-separated: {MODES}")
    parser.add_argument(
        "--network",
        action="store_true",
        help="run url_intel (link expansion, RDAP, Safe Browsing) and "
        "reputation (database); off by default for reproducible runs",
    )
    parser.add_argument(
        "--llm-limit",
        type=int,
        default=30,
        help="messages to send through the LLM (balanced sample)",
    )
    parser.add_argument(
        "--llm-sleep",
        type=float,
        default=15.0,
        help="seconds between LLM analyses (free tier: ~8k tokens/min)",
    )
    parser.add_argument("--limit", type=int, help="only the first N messages (quick runs)")
    parser.add_argument(
        "--out",
        help="write the report here instead of ml/reports/ (a "
        "gitignored path for sets with your collected messages)",
    )
    args = parser.parse_args()  # fmt: skip
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
