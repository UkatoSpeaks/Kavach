"""Choose the classifier's threshold and measure what corroboration costs, on val only.

For each CLASSIFIER_MIN_SCAM_PROBABILITY in --thresholds, with and without
CLASSIFIER_REQUIRES_CORROBORATION, runs the offline pipeline (pipeline.analyze_text: rules,
UPI check, classifier; no network) on processed/val.csv and on the 36 built-in examples,
and reports scam recall and false-positive rates (flagged = verdict suspicious or scam).
Also polished_dev (the half of the polished set fixes are developed on), never
polished_test.

The threshold rule (unchanged since 2026-09): the lowest threshold at which all 36 examples
keep their verdicts. Only aggregate numbers are printed: no message is quoted.

    uv run python -m ml.eval_corroboration
"""

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

from app.core.config import Settings, get_settings
from app.core.enums import Verdict
from app.services import pipeline
from ml.common import POLISHED_DEV, PROCESSED_DIR, REPORTS_DIR, as_bool, read_csv

FLAGGED = {Verdict.SUSPICIOUS, Verdict.SCAM}


@dataclass(frozen=True)
class Msg:
    text: str
    label: str  # scam | genuine | promo_spam
    indian: bool
    expected: Verdict | None = None  # the examples' required verdict


def load() -> dict[str, list[Msg]]:
    from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES

    val = [Msg(r["text"], r["label"], as_bool(r["is_indian"]))
           for r in read_csv(PROCESSED_DIR / "val.csv")]  # fmt: skip
    examples = [Msg(t, "scam", True) for _, t in SCAM_EXAMPLES]
    examples += [Msg(t, "genuine", True) for _, t in GENUINE_EXAMPLES]
    dev = [Msg(r["text"], r["label"], True) for r in read_csv(POLISHED_DEV)]
    return {"val": val, "examples": examples, "polished_dev": dev}


def flags(msgs: Sequence[Msg], settings: Settings) -> list[bool]:
    return [pipeline.analyze_text(m.text, settings).result.verdict in FLAGGED for m in msgs]


def rate(k: int, n: int) -> str:
    return f"{k}/{n} ({k / n:.1%})" if n else "–"


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--thresholds", default="0.5,0.6,0.7,0.8,0.9,0.95")
    args = parser.parse_args()
    base = get_settings().model_copy(update={"SAFE_BROWSING_API_KEY": ""})
    sets = load()
    rules_only = base.model_copy(update={"CLASSIFIER_ENABLED": False})
    examples_rules = flags(sets["examples"], rules_only)
    # The examples' verdicts with the rules alone: what "keeps its verdict" compares with.
    expected = [pipeline.analyze_text(m.text, rules_only).result.verdict for m in sets["examples"]]

    header = (
        "| threshold | corroboration | val scam recall | val Indian scam recall | val genuine FPR "
        "| val promo FPR | examples keeping verdict | polished_dev recall | polished_dev FPR |\n"
        "|---:|---|---:|---:|---:|---:|---:|---:|---:|"
    )
    lines = [header]
    lost: dict[float, tuple[int, int]] = {}
    val = sets["val"]
    scams = [i for i, m in enumerate(val) if m.label == "scam"]
    indian_scams = [i for i in scams if val[i].indian]
    for th in [float(x) for x in args.thresholds.split(",")]:
        flagged_by: dict[bool, list[bool]] = {}
        for corr in (False, True):
            s = base.model_copy(update={"CLASSIFIER_MIN_SCAM_PROBABILITY": th,
                                        "CLASSIFIER_REQUIRES_CORROBORATION": corr})  # fmt: skip
            fv = flags(val, s)
            flagged_by[corr] = fv
            ex = [pipeline.analyze_text(m.text, s).result.verdict for m in sets["examples"]]
            keep = sum(a == b for a, b in zip(ex, expected, strict=True))
            fd = flags(sets["polished_dev"], s)
            dev = sets["polished_dev"]

            def count(idx: Sequence[int], f: list[bool] = fv) -> int:
                return sum(f[i] for i in idx)

            gen = [i for i, m in enumerate(val) if m.label == "genuine"]
            promo = [i for i, m in enumerate(val) if m.label == "promo_spam"]
            dev_s = [i for i, m in enumerate(dev) if m.label == "scam"]
            dev_g = [i for i, m in enumerate(dev) if m.label != "scam"]
            lines.append(
                f"| {th:g} | {'on' if corr else 'off'} | {rate(count(scams), len(scams))} | "
                f"{rate(count(indian_scams), len(indian_scams))} | {rate(count(gen), len(gen))} | "
                f"{rate(count(promo), len(promo))} | {keep}/{len(ex)} | "
                f"{rate(sum(fd[i] for i in dev_s), len(dev_s))} | "
                f"{rate(sum(fd[i] for i in dev_g), len(dev_g))} |"
            )
            print(lines[-1], flush=True)
        lost[th] = (
            sum(flagged_by[False][i] and not flagged_by[True][i] for i in scams),
            sum(flagged_by[False][i] and not flagged_by[True][i] for i in indian_scams),
        )
    rules_recall = rate(sum(flags([val[i] for i in scams], rules_only)), len(scams))
    out = [
        "# Classifier threshold and corroboration (val)",
        "",
        f"- date {date.today().isoformat()}; offline pipeline (rules, UPI check, classifier); "
        f"val {len(val)} messages ({len(scams)} scams, {len(indian_scams)} Indian)",
        f"- rules alone, val scam recall: {rules_recall}; examples flagged by rules alone: "
        f"{sum(examples_rules)}/{len(examples_rules)}",
        "- corroboration on: the classifier alone (no rule outside SUPPORTING_RULES of weight "
        f">= {base.CLASSIFIER_CORROBORATION_MIN:g}, no UPI evidence) cannot reach 'suspicious'",
        "",
        *lines,
        "",
        "Scams flagged without corroboration but not with it (val):",
        "",
        *[
            f"- threshold {th:g}: {a} of {len(scams)} scams ({b} of {len(indian_scams)} Indian)"
            for th, (a, b) in lost.items()
        ],  # fmt: skip
        "",
    ]
    path = REPORTS_DIR / f"{date.today().isoformat()}_corroboration_val.md"
    path.write_text("\n".join(out), encoding="utf-8")
    print("\n".join(out[-len(lost) - 2 :]))
    print(f"report: {path}")


if __name__ == "__main__":
    main()
