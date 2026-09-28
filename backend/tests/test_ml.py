"""The dataset and evaluation scripts in ml/: anonymization, language heuristic, dedupe,
splits, synthetic-output parsing and metrics. No files, network or Groq."""

import json
import re
from pathlib import Path

import pytest

from app.core.enums import Verdict
from app.schemas.analysis import AnalysisResult
from app.services.extractors import (
    extract_entities,
    extract_phones,
    extract_upi_ids,
    extract_urls,
)
from ml import apply_review, autolabel, generate_synthetic, prepare_dataset
from ml.anonymize import anonymize_text
from ml.common import (
    COLUMNS,
    REVIEW_COLUMNS,
    guess_language,
    load_reviewed,
    read_csv,
    text_id,
    write_csv,
)
from ml.evaluate import Item, Metrics, Prediction, balanced_sample, is_flagged, load_csv_set
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


@pytest.mark.parametrize(
    "text",
    [
        "Dear PLAYER, double points on your next game",
        "Hey Champ! Your team line-up is open",
        "Hi User, your wallet is ready",
        "Dear Member, Hello Friend, Dear Sir, Dear Madam",
        "Congrats, Y0UR Received Rs.592000",
        "Congratulations, Amount of Rs.44,000 is credited",
        "Sorry, I sent it by mistake",
        "Myntra, your order is on its way",
    ],
)
def test_generic_salutations_and_openers_are_kept(text: str) -> None:
    assert anonymize_text(text).text == text


def test_name_opening_the_message_is_replaced() -> None:
    r = anonymize_text("Riya, your saved shoes are back in stock. Riya, hurry!")
    assert "Riya" not in r.text
    assert r.text.startswith("Amit, your saved") and "Amit, hurry" in r.text


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
        "label_source": "manual",
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
        _row("ok", "scam"),  # same text, other label, same authority: both dropped
        _row("Pay the e-challan of Rs 500 at http://echallan.top within 24 hours"),
    ]
    kept, report = dedupe(rows)
    assert [r["text"] for r in kept] == [base, "Hi, lunch at 1?", rows[-1]["text"]]
    assert (report.exact, report.near, report.conflicts) == (1, 1, 2)


def test_dedupe_prefers_your_label_over_auto_and_dataset_labels() -> None:
    text = "Flat 50% off on shoes, shop now at myntra"
    auto = _row(text, "scam", label_source="auto")
    mine = _row(text.upper(), "promo_spam", label_source="manual")
    kept, report = dedupe([auto, mine])
    assert [(r["label"], r["label_source"]) for r in kept] == [("promo_spam", "manual")]
    assert report.conflicts == 1

    # A near-duplicate with the same label keeps the more authoritative copy.
    near = _row(text + " today", "promo_spam", label_source="auto")
    kept, _ = dedupe([near, _row(text, "promo_spam", label_source="manual")])
    assert [r["label_source"] for r in kept] == ["manual"]


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


def test_auto_and_dataset_labels_never_enter_the_test_split() -> None:
    mine = _pool(10)
    others = [_row(f"auto promo message {i}", "promo_spam", label_source="auto")
              for i in range(40)]  # fmt: skip
    others += [_row(f"dataset ham message {i}", "genuine", label_source="dataset")
               for i in range(40)]  # fmt: skip
    splits, manifest = make_splits(mine + others, [], rebuild_test=False, test_frac=0.2,
                                   val_frac=0.15, manifest=None, today="d")  # fmt: skip
    assert manifest is not None and splits.test
    assert all(r["label_source"] == "manual" for r in splits.test)
    other_ids = {r["id"] for r in others}
    assert other_ids <= {r["id"] for r in splits.train + splits.val}
    assert any(r["id"] in other_ids for r in splits.val)  # val may hold them

    # 80 auto/dataset rows do not count towards the 30 needed for a test split.
    few, none = make_splits(_pool(5) + others, [], rebuild_test=False, test_frac=0.2,
                            val_frac=0.15, manifest=None, today="d")  # fmt: skip
    assert none is None and few.test == []


def test_review_queue_has_every_uncertain_row_and_a_fixed_sample_of_the_rest() -> None:
    def auto(text: str, label: str) -> dict:
        return _row(text, label, label_source="auto", auto_label=label, auto_scam_type="",
                    top_signals="x")  # fmt: skip

    rows = [auto(f"uncertain {i}", "uncertain") for i in range(5)]
    rows += [auto(f"promo {i}", "promo_spam") for i in range(1000)]
    rows += [_row("reviewed promo", "promo_spam", label_source="manual")]
    queue = prepare_dataset.review_queue(rows)
    labels = [q["auto_label"] for q in queue]
    assert labels.count("uncertain") == 5
    assert 60 <= labels.count("promo_spam") <= 140  # ~10%
    assert "reviewed promo" not in {q["text"] for q in queue}
    assert all(q["my_label"] == "" for q in queue)
    assert prepare_dataset.review_queue(rows) == queue  # same sample every run


def test_stratified_pick_skips_tiny_groups() -> None:
    rows = [_row("one qr scam", "scam", "qr_code"), _row("two qr scam", "scam", "qr_code")]
    assert stratified_pick(rows, 0.5, "s") == set()


def test_collected_rows_are_validated() -> None:
    assert validate_collected({"text": "x", "label": "scam", "scam_type": "phishing_link"}) is None
    assert validate_collected({"text": "x", "label": "spam"})
    assert validate_collected({"text": "x", "label": "scam", "scam_type": "loan_app"})
    assert validate_collected({"text": "x", "label": "genuine", "scam_type": "qr_code"})
    assert validate_collected({"text": "x", "label": "promo_spam"}) is None
    assert validate_collected({"text": "x", "label": "Promo_Spam", "scam_type": ""}) is None
    assert validate_collected({"text": "x", "label": "promo_spam", "scam_type": "qr_code"})
    assert validate_collected({"text": "x", "label": "scam", "scam_type": "other"}) is None


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


# ----------------------------------------------------------------------------- India spam


@pytest.mark.parametrize(
    ("text", "label", "scam_type"),
    [
        ("Neha, get Min. 60% Off on top kids brands. Ajio's Big Bold Sale ends tomorrow "
         "shrt.in/Qw8LpZ", "promo_spam", ""),
        ("Unlimited calls + 2GB/day at Rs 299. Recharge now on the Airtel Thanks app. T&C "
         "apply", "promo_spam", ""),
        ("Your SBI account will be blocked today. Update KYC at http://sbi-kyc.xyz/login and "
         "share the OTP", "scam", "phishing_link"),
        ("Congrats, Rs.64,300/- added to y0ur Wallet today. Withdraw directly: "
         "http://k7q2.com/wz3pvb!51m0qx", "scam", "phishing_link"),
        ("Hi, your payout of Rs.58,120 is credited to the Game Wallet 0N 09 SEP. "
         "Withdraw N0W: http://3tz8.com/qpl0vx!7c2d9k", "scam", "phishing_link"),
        ("Hello, please call me when you are free", "uncertain", ""),
    ],
)  # fmt: skip
def test_auto_label(text: str, label: str, scam_type: str) -> None:
    got = autolabel.auto_label(text)
    assert (got.label, got.scam_type) == (label, scam_type), got.signals
    assert got.top_signals


def test_leetspeak_and_random_domains() -> None:
    assert autolabel.leetspeak("Withdraw N0W") == "N0W"
    assert autolabel.leetspeak("Credited to yOur A/c") == "yOur"
    for text in ("Pay Rs 100 at 10 AM", "Get it on WhatsApp or iPhone", "Call 0120 400 0000",
                 "Valid for 24 daysAlso get", "at 10:00AM"):  # fmt: skip
        assert autolabel.leetspeak(text) is None, text
    assert autolabel.random_domain(extract_entities("go to 9lp7.com/x")) == "9lp7.com"
    assert autolabel.random_domain(extract_entities("go to smsd.in/x or m2.com")) is None


def test_india_rows_ham_is_genuine_spam_is_auto_labelled_and_reviews_win(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "india.csv"
    ham = "Hey, reached home. Call you at 9876543210 later"
    promo = "Flat 60% off on all shoes. Sale ends Sunday. Shop now on Myntra"
    reviewed = "Big Diwali sale, 40% off on TVs at Croma. T&C apply"
    raw.write_text(
        f'Msg,Label\n"{ham}",ham\n"{promo}",spam\n"{reviewed}",spam\n,spam\n', encoding="utf-8"
    )
    mine = {text_id(reviewed): {"label": "scam", "scam_type": "other"}}
    rows = prepare_dataset.load_india_spam(raw, reviewed=mine)
    assert [(r["label"], r["label_source"]) for r in rows] == [
        ("genuine", "dataset"), ("promo_spam", "auto"), ("scam", "manual"),
    ]  # fmt: skip
    assert all(r["is_indian"] and not r["is_synthetic"] for r in rows)
    assert {r["source"] for r in rows} == {"india_spam_sms"}
    assert [r["original_label"] for r in rows] == ["ham", "spam", "spam"]
    assert "9876543210" not in rows[0]["text"] and rows[0]["id"] == text_id(ham)
    assert rows[1]["auto_label"] == "promo_spam" and rows[1]["top_signals"]


def test_download_skips_a_file_with_the_right_checksum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ml import download_public

    path = tmp_path / "spam_ham_india.csv"
    path.write_bytes(b"Msg,Label\nhi,ham\n")
    monkeypatch.setattr(download_public, "INDIA_SPAM_FILE", path)
    monkeypatch.setattr(download_public, "INDIA_SPAM_SHA256",
                        download_public.sha256_of(path.read_bytes()))  # fmt: skip

    def no_network(*a: object, **k: object) -> None:
        raise AssertionError("must not download")

    monkeypatch.setattr(download_public.httpx, "get", no_network)
    download_public.download_india_spam(force=False)
    assert "checksum OK" in capsys.readouterr().out


# ----------------------------------------------------------------------------- review


def test_apply_review_merges_labels_and_reports_accuracy(tmp_path: Path) -> None:
    queue, store = tmp_path / "queue.csv", tmp_path / "reviewed.csv"
    rows = [
        {"id": "a", "text": "t", "auto_label": "scam", "auto_scam_type": "phishing_link",
         "top_signals": "", "my_label": "scam", "my_scam_type": ""},
        {"id": "b", "text": "t", "auto_label": "scam", "auto_scam_type": "phishing_link",
         "top_signals": "", "my_label": "promo", "my_scam_type": ""},
        {"id": "c", "text": "t", "auto_label": "promo_spam", "auto_scam_type": "",
         "top_signals": "", "my_label": "promo_spam", "my_scam_type": ""},
        {"id": "d", "text": "t", "auto_label": "uncertain", "auto_scam_type": "",
         "top_signals": "", "my_label": "scam", "my_scam_type": ""},
        {"id": "e", "text": "t", "auto_label": "uncertain", "auto_scam_type": "",
         "top_signals": "", "my_label": "", "my_scam_type": ""},
        {"id": "f", "text": "t", "auto_label": "uncertain", "auto_scam_type": "",
         "top_signals": "", "my_label": "maybe", "my_scam_type": ""},
    ]  # fmt: skip
    write_csv(queue, rows, REVIEW_COLUMNS)
    reviewed, new, problems = apply_review.apply(queue, store)
    assert new == 4 and len(problems) == 1 and "maybe" in problems[0]
    assert reviewed["a"]["scam_type"] == "phishing_link"  # empty: the auto type
    assert reviewed["b"]["label"] == "promo_spam"  # alias
    assert reviewed["d"]["scam_type"] == "other"
    assert load_reviewed(store) == reviewed

    report = "\n".join(apply_review.accuracy_report(list(reviewed.values())))
    assert "| scam | 2 | 1 | 50.0% | 1/1 |" in report
    assert "| promo_spam | 1 | 1 | 100.0% | – |" in report
    assert "| uncertain | 1 | 0 | 0 |" in report  # scam, genuine, promo_spam columns


def test_prepare_does_not_overwrite_a_filled_queue(tmp_path: Path) -> None:
    queue = tmp_path / "q.csv"
    write_csv(queue, [{"id": "x", "my_label": "scam"}, {"id": "y", "my_label": ""}],
              REVIEW_COLUMNS)  # fmt: skip
    assert prepare_dataset.unapplied_reviews(queue, {}) == 1
    assert prepare_dataset.unapplied_reviews(queue, {"x": {}}) == 0


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


def test_promo_spam_is_a_negative_with_its_own_group_and_uncertain_is_left_out(
    tmp_path: Path,
) -> None:
    path = tmp_path / "set.csv"
    write_csv(path, [
        {"id": "1", "text": "a", "label": "scam", "scam_type": "phishing_link"},
        {"id": "2", "text": "b", "label": "promo_spam", "label_source": "auto"},
        {"id": "3", "text": "c", "label": "genuine", "label_source": "dataset"},
        {"id": "4", "text": "d", "label": "uncertain", "label_source": "auto"},
    ], COLUMNS)  # fmt: skip
    items = load_csv_set(path, "x", "").items
    assert [(it.positive, it.group, it.label_source) for it in items] == [
        (True, "phishing_link", ""), (False, "promo_spam", "auto"), (False, "genuine", "dataset"),
    ]  # fmt: skip


def test_balanced_sample_is_fixed_and_balanced() -> None:
    items = [Item(str(i), "t", i < 10, "g", "en") for i in range(100)]
    sample = balanced_sample(items, 8)
    assert sum(it.positive for it in sample) == 4 and len(sample) == 8
    assert balanced_sample(items, 8) == sample


def test_reports_quoting_collected_messages_stay_out_of_git(tmp_path: Path) -> None:
    from ml import evaluate

    path = tmp_path / "set.csv"
    rows = [{"id": "1", "text": "a", "label": "genuine", "dataset": "india_spam_sms"}]
    write_csv(path, rows, COLUMNS)
    public = load_csv_set(path, "x", "")
    assert not public.private
    assert evaluate.report_path(public, "x", None).parent == evaluate.REPORTS_DIR

    write_csv(path, [*rows, {"id": "2", "text": "b", "label": "scam", "dataset": "collected"}],
              COLUMNS)  # fmt: skip
    mine = load_csv_set(path, "x", "")
    assert mine.private
    assert evaluate.report_path(mine, "x", None).parent == evaluate.PRIVATE_REPORTS_DIR
    assert evaluate.report_path(mine, "x", str(tmp_path / "r.md")) == tmp_path / "r.md"
    with pytest.raises(SystemExit):  # a path git would track
        evaluate.report_path(mine, "x", str(evaluate.REPORTS_DIR / "2026-01-01_x.md"))


def _queue_row(row_id: str, label: str, **extra: str) -> dict[str, str]:
    return {"id": row_id, "text": f"text {row_id}", "auto_label": "uncertain",
            "auto_scam_type": "", "top_signals": "", "my_label": label, "my_scam_type": "",
            **extra}  # fmt: skip


def test_assisted_labels_are_kept_apart_and_never_replace_yours(tmp_path: Path) -> None:
    queue, store = tmp_path / "queue.csv", tmp_path / "reviewed.csv"
    write_csv(queue, [_queue_row("a", "genuine")], REVIEW_COLUMNS)  # yours (no source)
    apply_review.apply(queue, store)
    write_csv(queue, [
        _queue_row("a", "promo_spam", label_source="assisted"),
        _queue_row("b", "scam", label_source="assisted", label_reason="fake prize",
                   confidence="high"),
        _queue_row("c", "promo", label_source="robot"),
    ], REVIEW_COLUMNS)  # fmt: skip
    reviewed, new, problems = apply_review.apply(queue, store)
    assert new == 1 and len(problems) == 1 and "robot" in problems[0]
    assert (reviewed["a"]["label"], reviewed["a"]["label_source"]) == ("genuine", "manual")
    assert reviewed["b"]["label_source"] == "assisted"
    assert reviewed["b"]["label_reason"] == "fake prize"
    assert load_reviewed(store) == reviewed


def test_low_confidence_edits_become_manual(tmp_path: Path) -> None:
    queue, store, low = tmp_path / "q.csv", tmp_path / "r.csv", tmp_path / "low.csv"
    write_csv(queue, [
        _queue_row(i, "promo_spam", label_source="assisted", confidence=c)
        for i, c in (("x", "low"), ("y", "low"), ("z", "low"), ("h", "high"))
    ], REVIEW_COLUMNS)  # fmt: skip
    reviewed, _, _ = apply_review.apply(queue, store)
    written = apply_review.write_low_confidence(low, queue, reviewed)
    assert [r["id"] for r in written] == ["x", "y", "z"]

    rows = {r["id"]: r for r in read_csv(low)}
    rows["x"]["my_label"] = "scam"  # you changed the label
    rows["y"]["label_source"] = "manual"  # you confirmed it as is
    write_csv(low, rows.values(), REVIEW_COLUMNS)
    changed, problems = apply_review.apply_low_confidence(low, store)
    assert (changed, problems) == (2, [])
    reviewed, _, _ = apply_review.apply(queue, store)  # re-applying the queue changes nothing
    assert (reviewed["x"]["label"], reviewed["x"]["label_source"]) == ("scam", "manual")
    assert reviewed["x"]["scam_type"] == "other"
    assert (reviewed["y"]["label"], reviewed["y"]["label_source"]) == ("promo_spam", "manual")
    assert reviewed["z"]["label_source"] == "assisted"
    after = {r["id"]: r for r in apply_review.write_low_confidence(low, queue, reviewed)}
    assert after["x"]["my_label"] == "scam" and after["z"]["label_source"] == "assisted"


def test_assisted_rows_may_enter_test_and_are_counted_apart() -> None:
    rows = [{"label_source": s} for s in ("manual", "assisted", "assisted", "dataset")]
    assert [prepare_dataset.test_eligible(r) for r in rows] == [True, True, True, False]
    assert prepare_dataset.label_note(rows[:3]) == "1 manual (author), 2 AI-assisted (Claude)"


def test_reports_state_label_sources_and_split_metrics() -> None:
    from ml import evaluate

    items = [Item("1", "t", True, "g", "en", label="scam", label_source="manual"),
             Item("2", "t", False, "g", "en", label="genuine", label_source="assisted"),
             Item("3", "t", True, "g", "en", label="scam", label_source="assisted")]  # fmt: skip
    es = evaluate.EvalSet("test", items, "", "")
    assert evaluate.label_note(es, "test") == (
        "Test labels: 1 manual (author), 2 AI-assisted (Claude)"
    )
    preds = [Prediction(it, AnalysisResult(risk_score=80, verdict=Verdict.SCAM), 1.0)
             for it in items]  # fmt: skip
    groups = evaluate.by_label_source("checks", preds)
    assert [(label, len(g)) for label, g in groups] == [
        ("checks · combined", 3), ("checks · manual labels", 1),
        ("checks · AI-assisted labels", 2),
    ]  # fmt: skip
    only_dataset = evaluate.EvalSet("india", [Item("4", "t", False, "g", "en",
                                                   label_source="dataset")], "", "")  # fmt: skip
    assert evaluate.label_note(only_dataset, "india") is None
