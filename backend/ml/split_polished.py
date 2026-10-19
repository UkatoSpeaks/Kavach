"""Split data/datasets/polished_eval.csv into polished_dev.csv and polished_test.csv (50/50).

Develop fixes against polished_dev only; polished_test is looked at once, at the end, so its
numbers are not tuned. Stratified: scams by scam_type, genuine messages by category (they
have no scam_type), shuffled with a fixed seed. When a stratum has an odd size, the extra
message goes to dev and test in turn, so both halves have 20 scams and 20 genuine messages.

polished_eval.csv stays the full set (the training leak check reads it). Re-running with
the same seed writes the same files.

    uv run python -m ml.split_polished
"""

import argparse
import random
import sys
from collections import defaultdict

from ml.common import POLISHED_DEV, POLISHED_EVAL, POLISHED_TEST, read_csv, write_csv

SEED = 20261019


def stratum(row: dict[str, str]) -> tuple[str, str]:
    return (row["label"], row["scam_type"] if row["label"] == "scam" else row["category"])


def split(rows: list[dict[str, str]], seed: int = SEED) -> tuple[list[dict], list[dict]]:
    rng = random.Random(seed)
    strata: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for r in rows:
        strata[stratum(r)].append(r)
    dev_ids: set[str] = set()
    extra_to_dev = {"scam": True, "genuine": True}  # per label, so each half gets 20 + 20
    for key in sorted(strata):
        group = sorted(strata[key], key=lambda r: r["id"])
        rng.shuffle(group)
        half = len(group) // 2
        if len(group) % 2:
            half += extra_to_dev[key[0]]
            extra_to_dev[key[0]] = not extra_to_dev[key[0]]
        dev_ids |= {r["id"] for r in group[:half]}
    dev = [r for r in rows if r["id"] in dev_ids]
    test = [r for r in rows if r["id"] not in dev_ids]
    return dev, test


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()
    rows = read_csv(POLISHED_EVAL)
    columns = list(rows[0])
    dev, test = split(rows, args.seed)
    for path, part in ((POLISHED_DEV, dev), (POLISHED_TEST, test)):
        write_csv(path, part, columns)
        labels = defaultdict(int)
        for r in part:
            labels[r["label"]] += 1
        print(f"{path.name}: {len(part)} {dict(labels)}")
    if len(dev) != len(test):
        sys.exit("dev and test differ in size")


if __name__ == "__main__":
    main()
