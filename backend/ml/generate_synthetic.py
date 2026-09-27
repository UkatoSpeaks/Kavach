"""Synthetic training data from Groq: variations of real collected scams + hard negatives.

- Variations: for every REAL scam message in processed/train.csv (never val/test), one call
  asks for an English paraphrase, a Hinglish version, a Hindi (Devanagari) version and one
  with a different amount and brand. Same scam mechanics, same scam_type.
- Hard negatives: genuine-looking bank alerts, OTPs, courier updates, KYC reminders and
  receipts, the messages a detector wrongly flags.

Everything is tagged is_synthetic=true and appended to data/datasets/synthetic/generated.csv.
ml/prepare_dataset.py puts it in the train split only (and drops anything too close to a
val/test message). Generated text goes through the anonymizer too, so a phone number the
model makes up can't be a real person's.

Free tier (~8k tokens/min): one request at a time, --sleep seconds between calls, the
Retry-After of a 429 is honoured, --max-calls caps the run, and finished tasks are recorded
in synthetic/progress.json so a re-run resumes where the last one stopped.

    uv run python -m ml.generate_synthetic --max-calls 10
    uv run python -m ml.generate_synthetic --dry-run        # show the plan, call nothing
"""

import argparse
import csv
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import groq

from app.core.config import get_settings
from ml.anonymize import anonymize_text
from ml.common import PROCESSED_DIR, SYNTHETIC_DIR, V1_SCAM_TYPES, as_bool, clean, read_csv

OUT_FILE = SYNTHETIC_DIR / "generated.csv"
PROGRESS_FILE = SYNTHETIC_DIR / "progress.json"
OUT_COLUMNS = ("text", "label", "scam_type", "parent_id", "variant", "source", "model")

MAX_TOKENS = 1800
HARD_NEGATIVES_PER_CALL = 6
HARD_NEGATIVE_KINDS = {
    "bank_alert": "bank debit/credit alerts for UPI, NEFT or card transactions (A/c XX1234 "
                  "style masks, UPI Ref numbers, 'Not you? call <toll-free>' lines)",
    "otp": "OTP messages from banks, UPI apps and shopping sites that warn 'do not share'",
    "courier": "real courier and delivery updates (India Post, Delhivery, Blue Dart, "
               "Amazon, Flipkart): shipped, out for delivery, delivered, delivery attempted",
    "kyc_reminder": "real KYC / re-KYC reminders asking customers to visit the branch or use "
                    "the official app, without links to unknown sites",
    "payment_receipt": "UPI payment receipts, electricity/mobile bill payment confirmations "
                       "and refund-processed notices from real services",
    "personal": "ordinary personal WhatsApp messages about money between family and friends "
                "(splitting a bill, 'sent you ₹500 for groceries'), in English and Hinglish",
}  # fmt: skip

SYSTEM = (
    "You generate training data for an Indian scam-message detector. Output JSON only. "
    "Write like real Indian SMS/WhatsApp messages. Any phone number you write must start "
    "with 99999. Never use a real company's real website domain; keep links that are in "
    "the original, or invent obviously fake ones."
)

VARIATION_PROMPT = """Original {label} message (scam type: {scam_type}):
<<<
{text}
>>>
Write 4 new messages that use the SAME scam trick, each realistic on its own:
1. "paraphrase": English, reworded.
2. "hinglish": Hindi in Roman script, the way people type on WhatsApp.
3. "hindi": Hindi in Devanagari.
4. "new_details": English or Hinglish, with a different amount and a different bank/app/brand.
Keep UPI IDs, links and the call to action of the same kind as the original.
Return {{"variations": [{{"variant": "...", "text": "..."}}, ...]}}"""

HARD_NEGATIVE_PROMPT = """Write {n} different GENUINE (not scam) Indian messages: {desc}.
They must be safe, but look like what people wrongly report as scams. Mix English, Hinglish
and a few in Hindi (Devanagari). Vary banks, apps, amounts and dates.
Return {{"messages": [{{"text": "..."}}, ...]}}"""


@dataclass(frozen=True)
class Task:
    key: str  # recorded in progress.json when done
    prompt: str
    label: str
    scam_type: str
    parent_id: str
    kind: str


def load_parents(train_file: Path = PROCESSED_DIR / "train.csv") -> list[dict[str, str]]:
    """Real (non-synthetic) scam messages from the train split."""
    if not train_file.exists():
        return []
    return [
        r
        for r in read_csv(train_file)
        if r["label"] == "scam" and not as_bool(r["is_synthetic"]) and r["dataset"] == "collected"
    ]


def plan(parents: list[dict[str, str]], hard_negative_rounds: int) -> list[Task]:
    tasks = [
        Task(
            key=f"var:{p['id']}",
            prompt=VARIATION_PROMPT.format(
                label=p["label"], scam_type=p["scam_type"] or "generic", text=p["text"]
            ),
            label="scam",
            scam_type=p["scam_type"] if p["scam_type"] in V1_SCAM_TYPES else "",
            parent_id=p["id"],
            kind="variation",
        )
        for p in parents
    ]
    for rnd in range(hard_negative_rounds):
        for kind, desc in HARD_NEGATIVE_KINDS.items():
            tasks.append(Task(
                key=f"neg:{kind}:{rnd}",
                prompt=HARD_NEGATIVE_PROMPT.format(n=HARD_NEGATIVES_PER_CALL, desc=desc),
                label="genuine", scam_type="", parent_id="", kind=f"hard_negative:{kind}",
            ))  # fmt: skip
    return tasks


def parse_reply(raw: str, task: Task) -> list[tuple[str, str]]:
    """(variant, text) pairs from the model's JSON. Bad items are skipped."""
    data = json.loads(raw)
    items = data.get("variations") or data.get("messages") or []
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        text = clean(str(item.get("text", "")))
        if 15 <= len(text) <= 800:
            out.append((str(item.get("variant", task.kind))[:40], text))
    return out


def load_progress() -> set[str]:
    if not PROGRESS_FILE.exists():
        return set()
    return set(json.loads(PROGRESS_FILE.read_text(encoding="utf-8"))["done"])


def save_progress(done: set[str]) -> None:
    PROGRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
    PROGRESS_FILE.write_text(json.dumps({"done": sorted(done)}, indent=1), encoding="utf-8")


def append_rows(rows: list[dict[str, Any]]) -> None:
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    new = not OUT_FILE.exists()
    with OUT_FILE.open("a", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=OUT_COLUMNS)
        if new:
            w.writeheader()
        w.writerows(rows)


def _retry_after(exc: groq.APIStatusError, default: float) -> float:
    try:
        return float(exc.response.headers.get("retry-after", default))
    except (TypeError, ValueError):
        return default


def call(client: groq.Groq, model: str, effort: str | None, prompt: str) -> str:
    extra: dict[str, Any] = {"reasoning_effort": effort} if effort else {}
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        temperature=0.9,
        max_tokens=MAX_TOKENS,
        **extra,
    )
    return resp.choices[0].message.content or ""


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--max-calls", type=int, default=20, help="stop after this many calls")
    parser.add_argument("--sleep", type=float, default=12.0,
                        help="seconds between calls (free tier: ~8k tokens/min)")  # fmt: skip
    parser.add_argument(
        "--hard-negative-rounds",
        type=int,
        default=2,
        help=f"calls per hard-negative kind ({HARD_NEGATIVES_PER_CALL} each)",
    )
    parser.add_argument("--dry-run", action="store_true", help="print the plan, call nothing")
    args = parser.parse_args()

    parents = load_parents()
    if not parents:
        print(
            "No collected messages yet: there are no real scam messages in the train split.\n"
            "Add your messages to data/datasets/collected/ (see collected_template.csv), run\n"
            "  uv run python -m ml.prepare_dataset\n"
            "and then this script again. Synthetic data is only ever made from real messages."
        )
        sys.exit(0)

    done = load_progress()
    todo = [t for t in plan(parents, args.hard_negative_rounds) if t.key not in done]
    print(f"{len(parents)} real train scams; {len(done)} tasks done before, {len(todo)} to do; "
          f"this run makes at most {args.max_calls} calls")  # fmt: skip
    if args.dry_run:
        for t in todo[: args.max_calls]:
            print(f"  would run {t.key} ({t.kind})")
        return

    settings = get_settings()
    if not settings.GROQ_API_KEY:
        print("GROQ_API_KEY is not set in .env; nothing to do.")
        sys.exit(1)
    client = groq.Groq(api_key=settings.GROQ_API_KEY, max_retries=0, timeout=60)
    models = [settings.GROQ_MODEL, settings.GROQ_FALLBACK_MODEL]

    calls = written = 0
    for task in todo:
        if calls >= args.max_calls:
            break
        rows: list[dict[str, Any]] = []
        for model in models:
            if calls >= args.max_calls:
                break
            if calls:
                time.sleep(args.sleep)
            calls += 1
            try:
                raw = call(client, model, settings.GROQ_REASONING_EFFORT, task.prompt)
                pairs = parse_reply(raw, task)
            except groq.RateLimitError as exc:
                wait = _retry_after(exc, 60)
                print(f"  {task.key}: rate limited on {model}; waiting {wait:.0f}s")
                time.sleep(wait)
                continue
            except (groq.APIError, json.JSONDecodeError) as exc:
                print(f"  {task.key}: {model} failed ({type(exc).__name__}); trying fallback")
                continue
            for variant, text in pairs:
                anon = anonymize_text(text)
                rows.append({
                    "text": anon.text, "label": task.label, "scam_type": task.scam_type,
                    "parent_id": task.parent_id, "variant": variant,
                    "source": f"groq synthetic ({task.kind})", "model": model,
                })  # fmt: skip
            break
        if not rows:
            continue
        append_rows(rows)
        done.add(task.key)
        save_progress(done)
        written += len(rows)
        print(f"  {task.key}: {len(rows)} messages")

    left = len([t for t in todo if t.key not in done])
    print(f"\n{calls} calls, {written} messages written to {OUT_FILE}. {left} tasks left"
          f"{' (re-run to resume)' if left else ''}.\n"
          "Next: uv run python -m ml.prepare_dataset  (adds them to the train split)")  # fmt: skip


if __name__ == "__main__":
    main()
