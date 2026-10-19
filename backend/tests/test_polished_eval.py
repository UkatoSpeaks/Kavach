"""The polished evaluation set (data/datasets/polished_eval.csv), its network fixture and
ml/mock_network.py. Fast: no network, no database."""

import json
from collections import Counter
from datetime import timedelta

import pytest

from app.services import url_intel
from app.services.cache import LookupCache
from app.services.extractors import extract_entities, extract_urls
from app.services.features import preprocess, words
from ml import split_polished
from ml.common import (
    POLISHED_DEV,
    POLISHED_EVAL,
    POLISHED_TEST,
    POLISHED_TRAIN,
    PROCESSED_DIR,
    jaccard,
    polished_leaks,
    read_csv,
    tokens,
)
from ml.mock_network import MockNetwork
from tests.conftest import settings_for_tests

FIXTURE = POLISHED_EVAL.with_name("polished_eval_network.json")
ROWS = read_csv(POLISHED_EVAL)


def test_balanced_synthetic_and_in_every_language() -> None:
    assert Counter(r["label"] for r in ROWS) == {"scam": 40, "genuine": 40}
    assert len({r["id"] for r in ROWS}) == len(ROWS)
    assert all(r["is_synthetic"] == "true" and r["label_source"] == "synthetic" for r in ROWS)
    for label in ("scam", "genuine"):
        assert {r["language"] for r in ROWS if r["label"] == label} == {"en", "hinglish", "hi"}


def test_no_leetspeak_or_odd_capitals() -> None:
    """Polished means polished: nothing for filter_evasion to find."""
    assert {r["id"]: e for r in ROWS if (e := extract_entities(r["text"]).evasions)} == {}


def test_every_scam_link_is_in_the_fixture() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for r in ROWS:
        if r["label"] != "scam":
            continue
        for u in extract_urls(r["text"]):
            key = f"{u.host}{u.url.split(u.host, 1)[1]}".rstrip("/")
            if u.is_shortener:
                assert key in fixture["redirects"], (r["id"], key)
            else:
                assert u.registered_domain in fixture["domains"], (r["id"], u.registered_domain)
    for d, entry in fixture["domains"].items():
        assert ("age_days" in entry) == entry.get("scam_infrastructure", False), d


@pytest.mark.skipif(not (PROCESSED_DIR / "train.csv").exists(), reason="local datasets only")
def test_never_in_train_or_val() -> None:
    for split in ("train", "val"):
        assert polished_leaks(read_csv(PROCESSED_DIR / f"{split}.csv")) == []


async def test_mock_network_runs_url_intel_on_scam_infrastructure() -> None:
    mock = MockNetwork.load(FIXTURE)
    settings = settings_for_tests()
    cache = LookupCache(None, timedelta(hours=1))
    async with mock.client() as client:
        (url,) = extract_urls("bit.ly/3Kq8vZt")  # ps01: shortener -> 3-day-old lookalike
        report = await url_intel.check_url(url, client=client, cache=cache, settings=settings)
        (gone,) = extract_urls("bit.ly/subsidy-refund")  # disabled by the shortener
        taken_down = await url_intel.check_url(gone, client=client, cache=cache, settings=settings)
    assert report.final_domain == "hdfc-rekyc-update.in"
    assert {f.code for f in report.findings} == {
        "url_shortener_redirect", "url_lookalike", "url_new_domain"
    }  # fmt: skip
    assert report.floor == url_intel.LOOKALIKE_CONFIRMED_FLOOR
    assert taken_down.chain == ["http://bit.ly/subsidy-refund"]
    assert mock.unknown == set()


def test_dev_and_test_halves_partition_the_set() -> None:
    dev, test = read_csv(POLISHED_DEV), read_csv(POLISHED_TEST)
    assert sorted(r["id"] for r in dev + test) == sorted(r["id"] for r in ROWS)
    assert not {r["id"] for r in dev} & {r["id"] for r in test}
    for half in (dev, test):
        assert Counter(r["label"] for r in half) == {"scam": 20, "genuine": 20}
    # reproducible from the seed
    again_dev, _ = split_polished.split(ROWS)
    assert [r["id"] for r in again_dev] == [r["id"] for r in dev]


TRAIN = read_csv(POLISHED_TRAIN)


def test_polished_train_is_no_paraphrase_of_the_evaluation_set() -> None:
    """Training messages written for the classifier: none close to an evaluation message,
    by plain tokens (Jaccard < 0.5) or the classifier's masked tokens (< 0.6)."""
    assert {r["label"] for r in TRAIN} == {"scam", "genuine"} and len(TRAIN) >= 400
    ev_raw = [tokens(r["text"]) for r in ROWS]
    ev_masked = [set(words(preprocess(r["text"]))) for r in ROWS]
    for r in TRAIN:
        raw, masked = tokens(r["text"]), set(words(preprocess(r["text"])))
        assert max(jaccard(raw, e) for e in ev_raw) < 0.5, r["id"]
        assert max(jaccard(masked, e) for e in ev_masked) < 0.6, r["id"]
        assert not extract_entities(r["text"]).evasions, r["id"]
