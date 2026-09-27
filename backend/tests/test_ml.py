"""The dataset and evaluation scripts in ml/: anonymization, language heuristic, dedupe,
splits, synthetic-output parsing and metrics. No files, network or Groq."""

import json
import re
from pathlib import Path

import pytest

from app.core.enums import Verdict
from app.schemas.analysis import AnalysisResult
from app.services.extractors import extract_phones, extract_upi_ids, extract_urls
from ml import generate_synthetic, prepare_dataset
from ml.anonymize import anonymize_text
from ml.common import COLUMNS, guess_language, text_id
from ml.evaluate import Item, Metrics, Prediction, balanced_sample, is_flagged
from ml.prepare_dataset import dedupe, make_splits, stratified_pick, validate_collected

# ----------------------------------------------------------------------------- anonymize


def test_phone_numbers_become_99999_in_the_same_format_and_consistently() -> None:
    r = anonymize_text("Call 9876543210 or +91 98765-43210. Again: 9876543210. Or 9123456789")
    assert "9876543210" not in r.text and "98765-43210" not in r.text
    fakes = [p.raw for p in extract_phones(r.text)]
    assert all(p.replace("+91 ", "").startswith("99999") for p in fakes)
    assert "+91 99999-" in r.text  # prefix and separator kept
    assert r.text.count(r.replaced["9876543210"]) == 2  # same number -> same fake
    assert r.replaced["9876543210"] != r.replaced["9123456789"]


def test_scam_features_are_kept() -> None:
    text = (
        "Pay ₹4,999 to refund.help@ybl or 9876543210@paytm at http://sbi-kyc.xyz/9876543210 "
        "via upi://pay?pa=x@ybl&am=4999 — helpline 18001234567"
    )
    r = anonymize_text(text)
    assert r.text == text  # UPI IDs, URLs, upi:// URIs, amounts and toll-free untouched
    assert extract_upi_ids(r.text) == extract_upi_ids(text)
    assert extract_urls(r.text) == extract_urls(text)
    assert r.review_notes  # the UPI ID that embeds a phone number is pointed out


def test_names_after_greetings_are_replaced_everywhere_but_generic_greetings_stay() -> None:
    r = anonymize_text("Dear Rahul Sharma, your refund is ready. Rahul, reply fast.")
    assert "Rahul" not in r.text and "Sharma" not in r.text
    assert r.text.startswith("Dear Amit Verma,") and "Amit, reply" in r.text
    for text in ("Dear Customer, KYC due", "Hi there, how are you", "hello how are you"):
        assert anonymize_text(text).text == text
    assert "राहुल" not in anonymize_text("प्रिय राहुल, आपका खाता बंद होगा").text


def test_account_and_card_numbers_are_masked_consistently() -> None:
    r = anonymize_text(
        "Rs 500 debited from A/c no. 123456789012 (XX9012). Card 4111 1111 1111 1111. "
        "UPI Ref 412345678901"
    )
    assert "123456789012" not in r.text and "9012" not in r.text and "4111" not in r.text
    masks = [w.strip("().") for w in r.text.split() if w.strip("().").startswith("XX")]
    assert len(masks) == 3 and masks[0] == masks[1]  # full number and its mask agree
    assert "Rs 500" in r.text and "412345678901" in r.text  # amounts and refs untouched


def test_personal_emails_get_a_fake_local_part() -> None:
    r = anonymize_text("Mail rahul.s@gmail.com or care@sbi.co.in")
    assert "rahul.s@" not in r.text and "@gmail.com" in r.text and "care@sbi.co.in" in r.text


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("Rs 500 received from RAHUL KUMAR via UPI. Ref 412345678901", "RAHUL KUMAR"),
        ("You have paid Rs.250 to Priya Singh on 12-09", "Priya Singh"),
        ("INR 1,000 credited by Suresh Patel to A/c XX1234", "Suresh Patel"),
        ("Beneficiary Name: MEENA IYER added to your account", "MEENA IYER"),
        ("Money sent to Mr. Ramesh Gupta", "Ramesh Gupta"),
        ("Transfer to Rahul done, ₹500", "Rahul"),  # bare "to" in an alert
        ("Rs.5000 Credited To Your Account By NEFT From ANIL MEHTA", "ANIL MEHTA"),
    ],
)
def test_names_in_bank_and_upi_alerts_are_replaced(text: str, name: str) -> None:
    r = anonymize_text(text)
    for word in name.split():
        assert word not in r.text
    assert name in r.replaced
    fake = r.replaced[name]
    assert (fake.upper() if name.isupper() else fake) in r.text  # ALL-CAPS stays ALL-CAPS


@pytest.mark.parametrize(
    "text",
    [
        "Rs 642 paid to Swiggy. Order from Meghana Foods",
        "Rs 100 received from Zomato by UPI",
        "₹1,299 paid to Flipkart and ₹499 to BigBasket",
        "Rs 200 debited to VPA swiggy.stores@icici. Call 18002586161 to Report",
        "Rs 500 credited to Your Account from HDFC BANK",
        "Meet me at the station and go to Delhi",  # no alert context: bare "to" is ignored
    ],
)
def test_brands_merchants_and_ordinary_words_are_not_names(text: str) -> None:
    assert anonymize_text(text).text == text


def test_genuine_examples_keep_their_merchants() -> None:
    swiggy = (
        "Your Swiggy order #174839201756 from Meghana Foods is out for delivery. Suresh will "
        "reach in 12 mins. Total paid: ₹642."
    )
    assert anonymize_text(swiggy).text == swiggy


def test_aadhaar_and_pan_are_masked_but_transaction_ids_kept() -> None:
    r = anonymize_text(
        "My Aadhaar is 2345 6789 0123, again 234567890123. PAN ABCPE1234F. "
        "UPI Ref 412345678901. UTR: 312345678901. Order no 512345678901"
    )
    assert "2345 6789 0123" not in r.text and "234567890123" not in r.text
    assert "ABCPE1234F" not in r.text
    masked = re.findall(r"XXXX XXXX \d{4}", r.text)
    assert len(masked) == 2 and masked[0] == masked[1]  # same number -> same fake
    assert re.search(r"\bXXXPX\d{4}X\b", r.text)  # PAN format and holder type kept
    for ref in ("412345678901", "312345678901", "512345678901"):
        assert ref in r.text


# ----------------------------------------------------------------------------- language


@pytest.mark.parametrize(
    ("text", "lang"),
    [
        ("Your parcel is held at customs, pay now", "en"),
        ("Maine galti se aapke account me paise bhej diye, wapas kar do", "hinglish"),
        ("मैंने गलती से आपके खाते में ₹2000 भेज दिए हैं", "hi"),
        ("Please do the needful and send the file", "en"),
    ],
)
def test_guess_language(text: str, lang: str) -> None:
    assert guess_language(text) == lang


# ----------------------------------------------------------------------------- dedupe


def _row(text: str, label: str = "scam", scam_type: str = "phishing_link", **kw: str) -> dict:
    row = {c: "" for c in COLUMNS} | {
        "id": text_id(text),
        "text": text,
        "label": label,
        "scam_type": scam_type if label == "scam" else "",
    }
    return row | kw  # fmt: skip


def test_dedupe_exact_near_and_conflicting_labels() -> None:
    base = "Your SBI account will be blocked today, update KYC at http://sbi-kyc.xyz now please"
    rows = [
        _row(base),
        _row(base.upper()),  # exact after normalization
        _row(base.replace("today", "tonight")),  # near duplicate
        _row("Hi, lunch at 1?", "genuine"),
        _row("OK", "genuine"),
        _row("ok", "scam"),  # same text, other label: both dropped
        _row("Pay the e-challan of Rs 500 at http://echallan.top within 24 hours"),
    ]
    kept, report = dedupe(rows)
    assert [r["text"] for r in kept] == [base, "Hi, lunch at 1?", rows[-1]["text"]]
    assert (report.exact, report.near, report.conflicts) == (1, 1, 2)


# ----------------------------------------------------------------------------- splits


def _pool(n_per_group: int) -> list[dict]:
    rows = []
    for st in ("phishing_link", "task_job", "sent_by_mistake"):
        rows += [_row(f"{st} scam message number {i}", "scam", st) for i in range(n_per_group)]
    rows += [_row(f"genuine message number {i}", "genuine") for i in range(n_per_group)]
    return rows


def test_no_test_split_below_30_messages() -> None:
    splits, manifest = make_splits(
        _pool(5), [], rebuild_test=False, test_frac=0.2, val_frac=0.15, manifest=None,
        today="2026-09-28",
    )  # fmt: skip
    assert manifest is None and splits.test == []
    assert any("NO INDIAN TEST SPLIT YET" in n for n in splits.notes)


def test_test_split_is_stratified_and_frozen() -> None:
    pool = _pool(10)
    splits, manifest = make_splits(
        pool, [], rebuild_test=False, test_frac=0.2, val_frac=0.15, manifest=None,
        today="2026-09-28",
    )  # fmt: skip
    assert manifest is not None
    assert {(r["label"], r["scam_type"]) for r in splits.test} == {
        ("scam", "phishing_link"), ("scam", "task_job"), ("scam", "sent_by_mistake"),
        ("genuine", ""),
    }  # fmt: skip
    assert len(splits.test) == 8  # 20% of each group of 10
    ids = {r["id"] for r in splits.test}
    assert not ids & {r["id"] for r in splits.train + splits.val}

    # More data later (and another day): the test split stays exactly the same.
    grown = pool + [_row(f"new phishing message {i}") for i in range(20)]
    again, same = make_splits(
        grown, [], rebuild_test=False, test_frac=0.2, val_frac=0.15,
        manifest=json.loads(json.dumps(manifest)), today="2026-12-01",
    )  # fmt: skip
    assert {r["id"] for r in again.test} == ids and same == manifest

    rebuilt, new_manifest = make_splits(
        grown, [], rebuild_test=True, test_frac=0.2, val_frac=0.15, manifest=manifest,
        today="2026-12-01",
    )  # fmt: skip
    assert new_manifest is not None and new_manifest["created"] == "2026-12-01"
    assert {r["id"] for r in rebuilt.test} != ids


def test_synthetic_rows_only_join_train_and_never_leak_held_out_messages() -> None:
    pool = _pool(10)
    splits, manifest = make_splits(pool, [], rebuild_test=False, test_frac=0.2,
                                   val_frac=0.15, manifest=None, today="d")  # fmt: skip
    train_parent = next(r for r in splits.train if r["label"] == "scam")
    test_parent = splits.test[0]
    synthetic = [
        _row("a brand new paraphrase that shares nothing", parent_id=train_parent["id"],
             is_synthetic="true"),
        _row("another variation of a test message", parent_id=test_parent["id"]),
        _row(test_parent["text"] + " now", parent_id=""),  # a hard negative too close to test
    ]  # fmt: skip
    out, _ = make_splits(pool, synthetic, rebuild_test=False, test_frac=0.2, val_frac=0.15,
                         manifest=manifest, today="d")  # fmt: skip
    synthetic_in_train = [r for r in out.train if r["text"] in {s["text"] for s in synthetic}]
    assert [r["text"] for r in synthetic_in_train] == [synthetic[0]["text"]]
    assert all(r["split"] == "test" for r in out.test)


def test_stratified_pick_skips_tiny_groups() -> None:
    rows = [_row("one qr scam", "scam", "qr_code"), _row("two qr scam", "scam", "qr_code")]
    assert stratified_pick(rows, 0.5, "s") == set()


def test_collected_rows_are_validated() -> None:
    assert validate_collected({"text": "x", "label": "scam", "scam_type": "phishing_link"}) is None
    assert validate_collected({"text": "x", "label": "spam"})
    assert validate_collected({"text": "x", "label": "scam", "scam_type": "loan_app"})
    assert validate_collected({"text": "x", "label": "genuine", "scam_type": "qr_code"})


def test_collected_messages_are_anonymized_on_load(tmp_path: Path) -> None:
    (tmp_path / "mine.csv").write_text(
        "text,label,scam_type\n"
        '"Dear Rahul, I sent ₹3,000 by mistake, return to 9876543210",scam,sent_by_mistake\n'
        "bad row,maybe,\n",
        encoding="utf-8",
    )
    rows, problems = prepare_dataset.load_collected(tmp_path)
    assert len(rows) == 1 and len(problems) == 1
    assert "Rahul" not in rows[0]["text"] and "9876543210" not in rows[0]["text"]
    assert "₹3,000" in rows[0]["text"] and rows[0]["is_indian"] is True


# ----------------------------------------------------------------------------- synthetic


def test_synthetic_plan_and_reply_parsing() -> None:
    parent = {"id": "abc", "label": "scam", "scam_type": "task_job", "text": "Earn ₹500/day"}
    tasks = generate_synthetic.plan([parent], hard_negative_rounds=1)
    assert tasks[0].key == "var:abc" and tasks[0].parent_id == "abc"
    assert len(tasks) == 1 + len(generate_synthetic.HARD_NEGATIVE_KINDS)
    reply = json.dumps({"variations": [
        {"variant": "hinglish", "text": "Ghar baithe ₹500 roz kamao, abhi join karo"},
        {"variant": "junk", "text": "short"},
        "not a dict",
    ]})  # fmt: skip
    assert generate_synthetic.parse_reply(reply, tasks[0]) == [
        ("hinglish", "Ghar baithe ₹500 roz kamao, abhi join karo")
    ]


# ----------------------------------------------------------------------------- evaluate


def _pred(positive: bool, verdict: Verdict) -> Prediction:
    item = Item("i", "t", positive, "g", "en")
    return Prediction(item, AnalysisResult(risk_score=50, verdict=verdict), 1.0)


def test_metrics_treat_suspicious_and_scam_as_flagged() -> None:
    preds = [
        _pred(True, Verdict.SCAM), _pred(True, Verdict.SUSPICIOUS), _pred(True, Verdict.SAFE),
        _pred(False, Verdict.SUSPICIOUS), _pred(False, Verdict.SAFE), _pred(False, Verdict.SAFE),
        Prediction(Item("e", "t", True, "g", "en"), None, 1.0, "boom"),  # errors are left out
    ]  # fmt: skip
    m = Metrics.of(preds, is_flagged)
    assert (m.tp, m.fn, m.fp, m.tn) == (2, 1, 1, 2)
    assert m.precision == pytest.approx(2 / 3) and m.recall == pytest.approx(2 / 3)
    assert m.fpr == pytest.approx(1 / 3) and m.f1 == pytest.approx(2 / 3)


def test_balanced_sample_is_fixed_and_balanced() -> None:
    items = [Item(str(i), "t", i < 10, "g", "en") for i in range(100)]
    sample = balanced_sample(items, 8)
    assert sum(it.positive for it in sample) == 4 and len(sample) == 8
    assert balanced_sample(items, 8) == sample
