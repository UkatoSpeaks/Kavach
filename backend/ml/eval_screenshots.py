"""OCR accuracy on synthetic screenshots, and whether OCR changes the verdict.

Renders 30 built-in messages (tests/examples.py: 18 scams, all 12 genuine) as phone
screenshots with tests/screenshots.py (the scams from personal numbers, the genuine
messages under a business SMS header or a contact name), reads each with every engine, and
writes ml/reports/<date>_screenshots.md with, per engine:

- CER: character error rate (edit distance / reference length) against the rendered text
  (sender + message + time, whitespace collapsed), overall and for Latin / Devanagari.
- identifiers kept: all URLs, UPI IDs and phone numbers of the message are extracted from
  the OCR text too (a misread link would send the wrong domain to the link checks).
- verdict = text: the verdict on the OCR text equals the verdict on the original message
  (pipeline.analyze, offline, no LLM, no screenshot signals).
- screenshot verdict ok: the full screenshot verdict (with sender_check /
  fake_payment_proof from what the engine saw) is scam for scams and safe for the rest.

Engines: groq_vision (GROQ_VISION_MODEL; paced for the free tier's 8k tokens/minute, and
retried after a 429), local (RapidOCR + Devanagari), local_latin (RapidOCR, bundled models
only). The images are drawn without complex text shaping on Windows (no libraqm), so the
Devanagari numbers are pessimistic for both engines.

    uv run python -m ml.eval_screenshots
    uv run python -m ml.eval_screenshots --engines local,local_latin   # no Groq quota
"""

import argparse
import asyncio
import re
import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from app.core.config import get_settings
from app.core.enums import Verdict
from app.services import pipeline
from app.services.extractors import extract_entities
from app.services.ocr import GroqVisionOCR, RapidLocalOCR, VisionFailed, prepare_image
from app.services.screenshot import ScreenshotContext, guess_fields
from ml.common import REPORTS_DIR
from ml.evaluate import _git_rev
from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES
from tests.screenshots import reference_text, render_sms, render_whatsapp, to_bytes

ENGINES = ("groq_vision", "local", "local_latin")
# Free tier: 8k tokens/minute and ~1.9k tokens per phone screenshot.
VISION_INTERVAL_S = 16.0
VISION_RETRIES = 4
VISION_RETRY_WAIT_S = 30.0
_DEVANAGARI = re.compile(r"[ऀ-ॿ]")

# Senders for GENUINE_EXAMPLES, in order: business headers, or a contact's name for the
# messages from family and friends.
GENUINE_SENDERS = [
    "AX-ICICIT", "VM-SBIINB", "JD-SBIINB", "VM-CNRBNK", "VK-SWIGGY", "AX-AMAZON",
    "VM-SBIINB", "VM-SBIINB", "Priya", "Rohit", "VM-NPCIOR", "JD-DLHVRY",
]  # fmt: skip


@dataclass(frozen=True)
class Case:
    n: int
    scam: bool
    sender: str
    message: str
    whatsapp: bool

    @property
    def reference(self) -> str:
        return reference_text(self.sender, self.message)

    @property
    def devanagari(self) -> bool:
        return bool(_DEVANAGARI.search(self.message))


@dataclass
class Read:
    text: str
    ctx: ScreenshotContext
    ms: float
    error: str | None = None


@dataclass
class Row:
    case: Case
    reads: dict[str, Read] = field(default_factory=dict)
    cer: dict[str, float] = field(default_factory=dict)
    ids_kept: dict[str, bool] = field(default_factory=dict)
    text_verdict: Verdict | None = None
    ocr_verdict: dict[str, Verdict] = field(default_factory=dict)
    shot_verdict: dict[str, Verdict] = field(default_factory=dict)


def cases() -> list[Case]:
    scams = [(i, t) for i, (_, t) in enumerate(SCAM_EXAMPLES) if i % 4 != 3]  # 18 of 24
    out = [
        Case(n, True, f"+91 9{8 - n % 3}{n:03d} 4{n:04d}"[:15], text, n % 2 == 1)
        for n, (_, text) in enumerate(scams, 1)
    ]
    out += [
        Case(len(out) + n, False, sender, text, sender[0].isupper() and "-" not in sender)
        for n, ((_, text), sender) in enumerate(
            zip(GENUINE_EXAMPLES, GENUINE_SENDERS, strict=True), 1
        )
    ]
    return out


def cer(reference: str, hypothesis: str) -> float:
    """Levenshtein distance / len(reference), whitespace collapsed on both sides."""
    ref, hyp = " ".join(reference.split()), " ".join(hypothesis.split())
    prev = list(range(len(hyp) + 1))
    for i, rc in enumerate(ref, 1):
        cur = [i]
        for j, hc in enumerate(hyp, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (rc != hc)))
        prev = cur
    return prev[-1] / max(len(ref), 1)


def identifiers(text: str) -> set[str]:
    e = extract_entities(text)
    return {u.url for u in e.urls} | {u.value for u in e.upi_ids} | {p.number for p in e.phones}


async def read_vision(vision: GroqVisionOCR, png: bytes) -> Read:
    image = prepare_image(png)
    for attempt in range(VISION_RETRIES + 1):
        start = time.perf_counter()
        try:
            reply, _ = await vision.read(image)
        except VisionFailed as exc:
            if "rate limited" in str(exc) and attempt < VISION_RETRIES:
                print(f"    rate limited, waiting {VISION_RETRY_WAIT_S:g}s")
                await asyncio.sleep(VISION_RETRY_WAIT_S)
                continue
            return Read("", ScreenshotContext(), 0, str(exc))
        ms = (time.perf_counter() - start) * 1000
        ctx = ScreenshotContext(reply.sender, reply.app, reply.is_payment_receipt)
        return Read(reply.extracted_text, ctx, ms)
    raise AssertionError("unreachable")


def read_local(local: RapidLocalOCR, png: bytes) -> Read:
    start = time.perf_counter()
    text = local.read(prepare_image(png).image)
    return Read(text, guess_fields(text), (time.perf_counter() - start) * 1000)


async def run(engines: list[str]) -> list[Row]:
    settings = get_settings().model_copy(update={"SAFE_BROWSING_API_KEY": ""})
    readers: dict[str, Callable[[bytes], object]] = {}
    if "groq_vision" in engines:
        if not settings.GROQ_API_KEY or not settings.GROQ_VISION_MODEL:
            raise SystemExit("groq_vision needs GROQ_API_KEY and GROQ_VISION_MODEL")
        vision = GroqVisionOCR(settings.GROQ_API_KEY, settings.GROQ_VISION_MODEL, 30)
        readers["groq_vision"] = lambda png: read_vision(vision, png)
    for name, dev in (("local", True), ("local_latin", False)):
        if name in engines:
            ocr = RapidLocalOCR(settings.LOCAL_OCR_CACHE_DIR, dev, settings.LOCAL_OCR_MAX_SIDE)
            readers[name] = lambda png, ocr=ocr: asyncio.to_thread(read_local, ocr, png)

    async def verdict(text: str, ctx: ScreenshotContext | None = None) -> Verdict:
        out = await pipeline.analyze(text, settings, checks=None, screenshot_ctx=ctx)
        return out.result.verdict

    rows: list[Row] = []
    last_vision = 0.0
    for case in cases():
        render = render_whatsapp if case.whatsapp else render_sms
        png = to_bytes(render(case.sender, case.message))
        row = Row(case, text_verdict=await verdict(case.message))
        for name, reader in readers.items():
            if name == "groq_vision":
                await asyncio.sleep(max(0.0, last_vision + VISION_INTERVAL_S - time.monotonic()))
                last_vision = time.monotonic()
            read: Read = await reader(png)  # type: ignore[misc]
            row.reads[name] = read
            row.cer[name] = cer(case.reference, read.text)
            row.ids_kept[name] = identifiers(case.message) <= identifiers(read.text)
            row.ocr_verdict[name] = await verdict(read.text) if read.text.strip() else Verdict.SAFE
            row.shot_verdict[name] = (
                await verdict(read.text, read.ctx) if read.text.strip() else Verdict.SAFE
            )
        rows.append(row)
        summary = ", ".join(f"{n} CER {row.cer[n]:.3f}" for n in readers)
        print(f"{case.n:2d} {'scam' if case.scam else 'safe'} {summary}")
    return rows


def _pct(values: list[bool]) -> str:
    return (
        f"{sum(values)}/{len(values)} ({100 * sum(values) / len(values):.0f}%)" if values else "–"
    )


def _mean(values: list[float]) -> str:
    return f"{statistics.mean(values):.3f}" if values else "–"


def report(rows: list[Row], engines: list[str]) -> str:
    s = get_settings()
    lines = [
        "# Evaluation: screenshots (OCR)",
        "",
        "> **Synthetic images.** 30 built-in messages (tests/examples.py) drawn as phone "
        "screenshots by tests/screenshots.py: clean fonts, no photos of screens, no "
        "compression artefacts. Real screenshots are harder. Devanagari is drawn without "
        "complex shaping (no libraqm on Windows), so its numbers are pessimistic.",
        "",
        f"- date: {date.today()} · code: `{_git_rev()}`",
        f"- messages: {len(rows)} ({sum(r.case.scam for r in rows)} scams from personal "
        f"numbers, {sum(not r.case.scam for r in rows)} genuine under a business header or a "
        f"contact name); {sum(r.case.devanagari for r in rows)} in Devanagari",
        f"- vision model: `{s.GROQ_VISION_MODEL}` · local: RapidOCR PP-OCRv6 "
        f"(+ PP-OCRv5 Devanagari for `local`), long side {s.LOCAL_OCR_MAX_SIDE} px",
        "- verdicts: pipeline.analyze offline (no network checks, no LLM)",
        "",
        "## Summary",
        "",
        "| engine | CER all | CER Latin | CER Devanagari | identifiers kept | verdict = text "
        "| screenshot verdict ok | errors | median ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for e in engines:
        latin = [r.cer[e] for r in rows if not r.case.devanagari]
        dev = [r.cer[e] for r in rows if r.case.devanagari]
        expected = [
            (r.shot_verdict[e] is Verdict.SCAM) if r.case.scam
            else (r.shot_verdict[e] is Verdict.SAFE)
            for r in rows
        ]  # fmt: skip
        lines.append(
            f"| {e} | {_mean([r.cer[e] for r in rows])} | {_mean(latin)} | {_mean(dev)} "
            f"| {_pct([r.ids_kept[e] for r in rows])} "
            f"| {_pct([r.ocr_verdict[e] is r.text_verdict for r in rows])} "
            f"| {_pct(expected)} | {sum(r.reads[e].error is not None for r in rows)} "
            f"| {statistics.median(r.reads[e].ms for r in rows):.0f} |"
        )
    lines += [
        "",
        "## Every message",
        "",
        "| # | expected | text verdict | "
        + " | ".join(f"{e} CER / verdict / screenshot" for e in engines)
        + " | message |",
        "|---:|---|---|" + "---|" * len(engines) + "---|",
    ]
    for r in rows:
        cells = [
            f"{r.cer[e]:.3f} / {r.ocr_verdict[e].value} / {r.shot_verdict[e].value}"
            + ("" if r.ids_kept[e] else " ⚠ id")
            + (f" ⚠ {r.reads[e].error}" if r.reads[e].error else "")
            for e in engines
        ]
        msg = " ".join(r.case.message.split())
        lines.append(
            f"| {r.case.n} | {'scam' if r.case.scam else 'safe'} | {r.text_verdict.value} | "
            + " | ".join(cells)
            + f" | `{r.case.sender}` {msg[:90]}{'…' if len(msg) > 90 else ''} |"
        )
    worst = {e: max(rows, key=lambda r, e=e: r.cer[e]) for e in engines}
    lines += ["", "## Worst read per engine", ""]
    for e, r in worst.items():
        lines += [
            f"**{e}** (#{r.case.n}, CER {r.cer[e]:.3f})",
            "",
            "```text",
            r.reads[e].text or "(nothing)",
            "```",
            "",
        ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--engines", default=",".join(ENGINES))
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    engines = [e.strip() for e in args.engines.split(",") if e.strip()]
    if unknown := set(engines) - set(ENGINES):
        raise SystemExit(f"unknown engines: {sorted(unknown)}")
    rows = asyncio.run(run(engines))
    out = args.out or REPORTS_DIR / f"{date.today()}_screenshots.md"
    out.write_text(report(rows, engines) + "\n", encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
