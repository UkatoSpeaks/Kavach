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
    uv run python -m ml.evaluate --dataset test --modes rules,checks,llm --llm-limit 30
    uv run python -m ml.evaluate --dataset path/to/file.csv --name my_set   # text,label
"""

import argparse
import asyncio
import hashlib
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable, Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
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
from ml.common import OOD_LABELS, PROCESSED_DIR, REPORTS_DIR, guess_language, read_csv

FLAGGED = {Verdict.SUSPICIOUS, Verdict.SCAM}
MODES = ("rules", "checks", "llm")


# ----------------------------------------------------------------------------- data


@dataclass(frozen=True)
class Item:
    id: str
    text: str
    positive: bool
    group: str  # scam_type for positives when known, else the original label
    language: str
    scam_type: str = ""


@dataclass(frozen=True)
class EvalSet:
    name: str
    items: list[Item]
    caveat: str
    positive_desc: str


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
INDIAN_CAVEAT = "Real, collected, anonymized Indian messages (no synthetic data in val/test)."


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


def load_csv_set(path: Path, name: str, caveat: str) -> EvalSet:
    items = []
    for i, r in enumerate(read_csv(path)):
        label = (r.get("label") or "").strip().lower()
        original = (r.get("original_label") or label).strip().lower()
        positive = label == "scam" or label in OOD_LABELS
        scam_type = (r.get("scam_type") or "").strip()
        group = (scam_type or original or label) if positive else "genuine"
        lang = r.get("language") or guess_language(r["text"])
        items.append(Item(r.get("id") or str(i), r["text"], positive, group, lang, scam_type))
    ood = any(it.group in OOD_LABELS for it in items)
    desc = 'original label spam/smishing (not our "scam")' if ood else "label scam"
    return EvalSet(name, items, caveat, desc)


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
    }  # fmt: skip
    if dataset in named:
        file, caveat = named[dataset]
        path = PROCESSED_DIR / file
        if not path.exists():
            sys.exit(f"{path} not found. Run: uv run python -m ml.prepare_dataset "
                     "(and ml.download_public for uci)")  # fmt: skip
        return load_csv_set(path, dataset, caveat)
    path = Path(dataset)
    if not path.exists():
        sys.exit(f"unknown dataset {dataset!r}: use examples|uci|mendeley|test|val or a CSV path")
    return load_csv_set(path, path.stem, "Custom CSV.")


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
        "",
        "## Summary",
        "",
        METRICS_HEADER,
    ]
    for run in runs:
        lines.append(_metrics_row(run.mode, run.preds))
        if run.same_sample_checks:
            lines.append(_metrics_row("checks (same sample as llm)", run.same_sample_checks))
    for run in runs:
        fps, fns = _mistakes(run.preds)
        lines += ["", f"## Mode: {run.mode}", ""]
        if run.note:
            lines += [run.note, ""]
        lines += ["### Confusion matrix", "", *_confusion(run.preds), ""]
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

    out = Path(args.out) if args.out else REPORTS_DIR / f"{date.today().isoformat()}_{name}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(es, runs, settings, args.network, name), encoding="utf-8")
    print(f"\nreport: {out}\n")
    print(METRICS_HEADER)
    for r in runs:
        print(_metrics_row(r.mode, r.preds))
        if r.same_sample_checks:
            print(_metrics_row("checks (same sample as llm)", r.same_sample_checks))


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
        help="examples | uci | mendeley | test | val | path to a CSV",
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
    parser.add_argument("--out", help="write the report here instead of ml/reports/")
    args = parser.parse_args()  # fmt: skip
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
