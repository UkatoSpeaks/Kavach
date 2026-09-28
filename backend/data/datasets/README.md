# Datasets

Everything here except this README, `collected_template.csv` and `processed/.gitkeep` is
gitignored. Scripts live in `backend/ml/`; run them from `backend/` with `uv run python -m ...`.

```
raw/                 public downloads            (ml/download_public.py)
collected/           YOUR messages, NOT anonymized — never share or commit
synthetic/           Groq variations + hard negatives, progress.json (ml/generate_synthetic.py)
review_queue.csv     India rows for you to label (ml/prepare_dataset.py) — real messages, gitignored
reviewed_labels.csv  your applied review labels (ml/apply_review.py) — gitignored
review_disagreements.csv  rules vs classifier disagreements (ml/disagreements.py) — gitignored
processed/           anonymized, unified CSVs only  (ml/prepare_dataset.py)
  ood_uci_sms_spam.csv all of UCI: out-of-domain, never training
  ood_uci_unseen.csv   the UCI rows sharing no template with train/val (see Mendeley below)
  india_spam_sms.csv   every India row after dedupe, uncertain ones included (evaluation)
  collected.csv        your collected messages (evaluation)
  train.csv val.csv    India + Mendeley + IMC25 (+ synthetic in train); never collected
  heldout.csv          held-out template groups of every source (evaluation)
  test.csv             frozen Indian test split (see below)
  split_manifest.json  the ids in test.csv and when it was created
```

## Pipeline

```
uv run python -m ml.download_public      # UCI, India Spam SMS, Mendeley, IMC25 (checksums)
uv run python -m ml.anonymize collected/my_sms.csv   # optional: preview anonymization
uv run python -m ml.prepare_dataset      # anonymize -> auto-label -> dedupe -> splits + review queue
# fill in my_label / my_scam_type in review_queue.csv, then:
uv run python -m ml.apply_review         # save your labels, report auto-label accuracy
uv run python -m ml.prepare_dataset      # again, to use them
uv run python -m ml.generate_synthetic --max-calls 60   # Groq free tier; resumable
uv run python -m ml.prepare_dataset      # again, to add the synthetic rows to train
uv run python -m ml.train_classifier     # TF-IDF + logistic regression -> models/classifier.json
uv run python -m ml.eval_classifier      # held-out metrics + ablation -> ml/reports/private/
uv run python -m ml.disagreements        # rules vs classifier -> review_disagreements.csv
uv run python -m ml.evaluate --dataset test     # the full pipeline: test | india | collected | uci | examples | val | a CSV
```

`ml/train_transformer.ipynb` fine-tunes MuRIL on the same splits in Google Colab (not used by
the backend).

## Labels

| label | meaning | counts as a scam in metrics |
|---|---|---|
| `scam` | fraud; `scam_type` is a v1 type or `other` (a scam outside v1, e.g. a fake loan) | yes |
| `genuine` | an ordinary message | no |
| `promo_spam` | a legitimate or grey-area promotion (brand sale, recharge plan, betting ad) that is not fraud | no, but reported separately (promo false-positive rate) |

`label_source` says who decided the label: `manual` (you: collected, or reviewed),
`assisted` (reviewed by an AI assistant, Claude, reading each message; not you), `dataset`
(the source's own label, e.g. India `ham`), `auto` (pre-classified by `ml/autolabel.py`,
not reviewed), `synthetic`.

## Public sources

| | UCI SMS Spam Collection | SMS Phishing Dataset for ML and Pattern Recognition (Mendeley) | Smishing Dataset IMC 2025 |
|---|---|---|---|
| Authors | T. A. Almeida, J. M. Gómez Hidalgo | Sandhya Mishra, Devpriya Soni | S. Agarwal, A. Papasavva, G. Suarez-Tangil, M. Vasek |
| Year | 2011 (published 2012) | 2022 | 2025 (reports from about 2019 to 2024) |
| Real / synthetic | real | real (text converted from screenshots found online) | real, user-reported smishing, anonymized by the authors |
| Size | 5,574 SMS: 4,827 ham, 747 spam | 5,971 SMS: 4,844 ham, 489 spam, 638 smishing | 33,869 reports, 70 languages; we use the 20,797 English/Hindi ones that are not IMC "spam" |
| Country | Mostly UK and Singapore | Mostly UK/Singapore: **about 85% is copied verbatim from UCI** (4,319 of the ham, 345 of the smishing); a few Indian property/loan ads | Many; 3,729 rows from Indian networks (`original_network_country=IND`, mostly SBI/HDFC/Paytm KYC-block and SIM/electricity lures); country unknown for 2/3 |
| Licence | CC BY 4.0 | CC BY 4.0 as shown on the Mendeley Data page (the public API does not return it: **please confirm**) | CC BY 4.0 (LICENSE.txt in the repository) |
| Where | https://archive.ics.uci.edu/dataset/228/sms+spam+collection | https://data.mendeley.com/datasets/f45bkkt8pr/1, downloaded through Mendeley Data's public API; zip sha256 `9bbf3188…233cc3` | https://github.com/reportsmishing/Smishing-Dataset-IMC25, `dataset/final_dataset_output.csv` at commit `a6175560` (branch `main`); sha256 `1bbd1e9e…37fa9a64` |
| File | `raw/uci_sms_spam/SMSSpamCollection` | `raw/mendeley_sms_phishing/Dataset_5971.csv` (columns `LABEL, TEXT, URL, EMAIL, PHONE`) | `raw/imc25_smishing/final_dataset_output.csv` |
| Our labels | `ham` → genuine; `spam` kept as `spam` (not our scam) | `ham` → genuine, `spam` → promo_spam, `smishing` → scam | every row → scam; `original_label` = `imc:<their scam_type>` |
| `is_indian` | false | false | true only for Indian networks |
| Used for | **evaluation only** (`ood_uci_unseen.csv`) | train / val / held-out | train / val / held-out |
| Cite | Almeida, Gómez Hidalgo, Yamakami. *Contributions to the Study of SMS Spam Filtering.* DocEng 2011 | Mishra, Soni. Mendeley Data, V1, 2022. doi:10.17632/f45bkkt8pr.1 | Agarwal et al. *Fishing for Smishing.* IMC 2025. doi:10.1145/3730567.3764431 |

Non-Indian rows (`is_indian=false`) go to train, val or `heldout.csv`, never to the frozen
Indian `test.csv`.

**Mendeley ⊃ UCI.** Because most of Mendeley is UCI, a model trained on Mendeley has seen
most of UCI. `ood_uci_unseen.csv` keeps only the UCI rows whose template group (see Splits)
has no train/val member, about 800 of 5,011: that is the out-of-domain UCI set for the
classifier. `ood_uci_sms_spam.csv` (all of UCI) is still fine for the rules-only
`ml/evaluate.py --dataset uci`, which learns nothing.

**Mendeley labels are noisy.** Its `spam` (checked on a sample: ringtone/premium-rate
subscriptions, property and product ads, adult chat, a few claims-farming lures) maps to
promo_spam; its `smishing` is mostly UK premium-rate prize lures ("You have WON £1000, call
0906…") plus some phishing. The same UCI "spam" messages were split between the two labels,
so the promo/scam boundary in Mendeley is fuzzy.

**IMC25 anonymization placeholders.** The authors replaced personal data with tokens
(`<URL>`, `<PHONE_NUMBER>`, `<NAMED_ENTITY>`, `<DATE_TIME>`, `<US_DRIVER_LICENSE>` …), sometimes
eating neighbouring letters (`<URL>ease click`). They only occur in scam rows, so a model
would learn them instead of the scam. `prepare_dataset.neutralize_imc_placeholders` turns
them into ordinary text first: `<URL>` → `https://link.example/masked` (or
`https://<shortener>/masked` when IMC's `url_shortener` column names one), phone → a 99999
number, number-like IDs → `123456`, names/places/dates → nothing. The real link domains are
gone, so **the rules' link checks (lookalike, risky TLD) cannot fire on IMC rows**: rules-only
recall on IMC is a lower bound. IMC labels are user reports: a few are genuine messages
(an SBI branch loan offer), and IMC "spam" (marketing mixed with lures) and unlabelled rows
are left out.

### India Spam SMS Classification (in-domain)

| | |
|---|---|
| Author | junioralive (GitHub) |
| Year | 2024 (messages date from about 2021 to Aug 2024) |
| Size | 2,267 SMS: 1,522 ham, 745 spam (2,053 unique texts). Columns `Msg`, `Label` |
| Country | **India, real (not synthetic)**: Indian telecom (Airtel, Vi, Jio), retail, bank and personal messages |
| Licence | MIT |
| Where | https://github.com/junioralive/india-spam-sms-classification, downloaded automatically from `https://raw.githubusercontent.com/junioralive/india-spam-sms-classification/main/dataset/spam_ham_india.csv` |
| File | `raw/india_spam_sms/spam_ham_india.csv`, sha256 `e6a28126d1c4ec9d805a10cd89f2de2bb63650532102e9f35ab05c909c3a79f3` (checked on every run; the download is skipped when it matches and stops if upstream changes) |

Imported with `source=india_spam_sms`, `is_indian=true`, `is_synthetic=false`,
`original_label` kept, and anonymized like your own messages.

- `ham` → `genuine` (`label_source=dataset`).
- `spam` is **not** automatically `scam`: most of it is promotional (recharge plans, store
  sales), and some is transactional (OTPs, e-bills, "data consumed" alerts) or official
  advisories (RBI, DoT, CERT-In). `ml/autolabel.py` pre-classifies each spam row as
  `promo_spam`, `scam` (with a v1 scam_type or `other`) or `uncertain`, using the offline
  rules pipeline plus labelling-only heuristics (promo wording, known brands, fake
  credit alerts, random short domains + leetspeak). `label_source=auto`.
- `uncertain` rows stay out of train/val/test until you review them.
- Caveats: the upstream file already lost its Devanagari text (it shows up as `????`), so the
  language heuristic finds no Hindi. Some "ham" rows are scam-like (e.g. a "stock community"
  daily check-in lure). Treat the dataset's labels as noisy.

### Reviewing auto labels

`review_queue.csv` holds every `uncertain` row plus a fixed random ~10% of the auto
`scam` and `promo_spam` rows (columns `id, text, auto_label, auto_scam_type, top_signals,
my_label, my_scam_type, label_reason, confidence, label_source`). Fill in `my_label`
(`scam`, `genuine`, `promo_spam`; `promo` and `ham` also work) and, for scams,
`my_scam_type` (empty: the auto type, or `other`), then run `ml.apply_review`. It saves
the labels to `reviewed_labels.csv` and reports the auto-labeller's accuracy per class on
the random sample (all reviews, manual only, AI-assisted only). An empty `label_source`
means you (`manual`); rows an AI assistant labelled say `assisted`, and a manual label is
never replaced by an assisted one. Low-confidence assisted rows are written to
`review_low_confidence.csv` (gitignored): change a label there, or set its `label_source`
to `manual` to confirm it, and the next `ml.apply_review` run makes it `manual`. `prepare_dataset` does not overwrite a queue with filled-in rows
you have not applied yet.

## Your collected messages

Copy `collected_template.csv` into `collected/` (any number of CSV files) and delete the
example rows. Columns:

| column | |
|---|---|
| `text` | the message, exactly as received |
| `label` | `scam`, `genuine` or `promo_spam` (see Labels above) |
| `scam_type` | for scams: `upi_receive_money`, `qr_code`, `sent_by_mistake`, `phishing_link`, `task_job`, `fake_customer_care`, `generic`, or `other` (outside v1); empty otherwise |
| `source` | e.g. `my SMS`, `family WhatsApp`, `news article`, `reddit` |
| `source_url` | where it came from, if public |
| `date_collected` | YYYY-MM-DD |
| `notes` | anything useful (how you know the label) |

All collected messages are treated as Indian (`is_indian=true`). Keep non-Indian ones out.
They are **for testing only**: they go to `test.csv` or `heldout.csv`, never to train or val
(see Splits), and no synthetic variation is made from them.

**Anonymization** (`ml/anonymize.py`) runs on every collected message before anything is
written to `processed/`. Mobile numbers become `99999xxxxx` in the same format, the name
after "Dear/Hi/प्रिय" a placeholder name, account/card numbers `XX1234`, personal emails a
fake local part. URLs, domains, UPI IDs and amounts are kept: they are what the detectors
look at. Not handled: names that don't follow a greeting (e.g. "from RAMESH KUMAR" in a
credit alert), addresses, Aadhaar/PAN numbers. Preview with
`uv run python -m ml.anonymize collected/<file>.csv` and remove anything it misses.

## Unified schema (processed/*.csv)

`id, text, label, original_label, scam_type, language, source, dataset, is_synthetic,
is_indian, label_source, parent_id, split, group`

- `group`: the template group (see Splits); a synthetic variation takes its parent's.

- `id`: hash of the normalized text (for collected rows: of the original text, so it
  survives changes to the anonymizer).
- `language`: `en | hi | hinglish`, a heuristic (Devanagari share, then common
  romanized-Hindi words). Good enough for a per-language breakdown, not more.
- `parent_id`: for synthetic rows, the train message they were generated from.

**Dedupe** (all trainable sources together; collected and India rows first): exact duplicates (same normalized text) and near-duplicates (token Jaccard ≥
0.8) collapse to one copy, the first unless a later one has a more authoritative label
(manual > assisted > dataset > auto). When the same text has two labels, the most authoritative label
wins if its copies agree; otherwise all copies are dropped.

## Splits

**Template groups.** Before splitting, messages are grouped into near-duplicate templates
(`prepare_dataset.template_groups`): the dedupe's near-duplicate search, run on the
classifier's masked text (links, amounts, phones and numbers already replaced by tokens) with
token Jaccard ≥ 0.7, and transitive (A~B and B~C: one group). The SBI YONO "update PAN"
family alone is one group of ~490 IMC25 reports. Every split below takes whole groups, so no
template is in train and in an evaluation set. The group id is in the `group` column.

- **test**: only reviewed messages (`label_source=manual`: collected or reviewed by you;
  `label_source=assisted`: reviewed by an AI assistant), ~20%, stratified by label and scam_type (groups with fewer than 3 messages
  stay in train). Auto-labelled and dataset-labelled rows never enter it. Created the first
  time there are at least **30** such messages, then **frozen** in
  `split_manifest.json`: new messages go to train/val only, and the same messages stay in
  test so results remain comparable over time. Every report on it says "Test labels: N
  manual (author), M AI-assisted (Claude)" and gives metrics for manual-only,
  assisted-only and combined. `--rebuild-test` re-draws it (old reports
  are then no longer comparable).
- **heldout**: ~15% of the template groups (by a hash of the group id, so it is stable),
  every source, plus every other message of a test message's group, plus every collected
  message not in test and the rest of its group. Evaluation only
  (`ml/eval_classifier.py`).
- **val**: ~15% of the groups: choosing C and calibrating the classifier.
- **train**: the rest, plus synthetic rows. A synthetic row is dropped if its parent is not
  in train or it is too similar (Jaccard ≥ 0.7) to any val/test/heldout message.

## Synthetic data (`ml/generate_synthetic.py`)

Train only. Parents are real train scams, one per template group, Indian first (India
Spam SMS, IMC25 from Indian networks, then the rest), never your collected messages; hard
negatives (bank alerts, OTPs, courier updates, KYC reminders, receipts, personal money chat,
fraud-awareness advisories → `genuine`; brand promotions → `promo_spam`) are interleaved.
`--only-negatives` and `--kinds awareness,...` restrict a run. The `awareness` kind rotates
the sender and topic per call (SBI, RBI, NPCI, TRAI, Jio, police cyber cells, UIDAI …).

So far (2026-09-28/29): 130 Groq calls → 688 messages, plus 23 Hinglish awareness advisories
written by hand (Groq produced almost no Hinglish ones; source `hand-written (Claude)`):
160 scam variations of 40 parents, 497 genuine hard negatives (173 of them awareness
advisories: 100 English, 47 Hindi, 26 Hinglish), 54 promotions. 688 are in train: the 8
variations of your collected messages are dropped (their parents are test-only), plus
duplicates.

## The classifier (`ml/train_classifier.py`, `app/services/classifier.py`)

TF-IDF on `features.preprocess` text (char 2-5 grams inside words + word 1-2 grams) →
3-class logistic regression, class-balanced weights, template groups capped at 10 messages,
Indian rows ×5. C chosen on val by macro-F1; one temperature fitted on val. Exported as JSON
(`models/classifier.json`, 4.1 MB, 80,000 features) and run with numpy in the service; the
export is checked against scikit-learn on 200 val messages at every training run (and by a
unit test). It adds about 14 MB to the service's RSS (31 MB at peak while loading), see
[docs/DEPLOYMENT.md](../../../docs/DEPLOYMENT.md#memory-measured-locally-windows-python-312-one-uvicorn-worker).

**Your collected messages never train it.** `prepare_dataset` puts every collected
message (and its template group) in `test.csv` or `heldout.csv`, `train_classifier` refuses
to run if one is in train/val, and `tests/test_classifier.py` fails if the model contains an
n-gram that only your messages have (it runs locally, where the data is).

In scoring it is the `classifier` signal (weight in `SIGNAL_WEIGHTS`): score = 100·P(scam),
counted only when P(scam) ≥ `CLASSIFIER_MIN_SCAM_PROBABILITY` (0.9), never a floor. 0.9 is
the lowest threshold at which, on **val**, all 36 built-in examples keep their verdicts (at
0.5-0.8 one genuine example still becomes suspicious). On a fraud-awareness notice
(`rules.advisory_evidence`: "never asks", "do not share", "beware", "1930", Hindi/Hinglish
forms, and no link, UPI ID, phone number, amount or request for money) its weight is
multiplied by `CLASSIFIER_ADVISORY_WEIGHT_FACTOR` (0.5).

### Results (held-out, 2026-09-29)

Every message below is outside train and val, and so is every near-duplicate of it (template
groups). Flagged = verdict suspicious or scam (rules, combined) or calibrated P(scam) ≥ 0.5
(classifier alone). Brackets: 95% Wilson intervals.

**India held-out** (447 messages: 155 scams, 206 ham, 86 promos):

| | precision | scam recall | FPR (not scam) | FPR at 90% recall |
|---|---:|---:|---:|---:|
| rules only | 98.8% | 52.9% (45–61%) | 0.3% (0–2%) | unreachable* |
| classifier only | 91.5% | 97.4% (94–99%) | 4.8% (3–8%) | 1.0% |
| rules + classifier | 97.3% | **93.5%** (89–96%) | 1.4% (1–3%) | 1.4% |

**False positives of the full pipeline (combined) on genuine messages:**

| | rules only | rules + classifier |
|---|---:|---:|
| India ham (held-out) | 1/206 | 1/206 |
| UCI ham (unseen) | 0/690 | 1/690 |
| Mendeley ham (held-out) | 0/697 | 0/697 |
| India promo (held-out) | 0/86 | 3/86 |

**All held-out pooled** (2,688: India, Mendeley, non-Indian IMC25): scam recall 15.0% →
86.5% combined, FPR 0.1% → 0.9%; classifier alone: AP 99.3%, FPR 1.2% at 90% recall.

**Per class (classifier alone), India held-out:** genuine P 98.1% / R 98.5%, promo_spam
P 98.6% / R 84.9%, scam P 91.0% / R 97.4% (macro-F1 94.5%). Pooled: macro-F1 90.7%, promo
recall only 75.4%.

\* The rules score most messages 0; below that there is no threshold, so reaching 90%
recall means flagging everything.

**What changed on 2026-09-29.** Collected messages left training, 173 awareness
advisories joined it, and the advisory guard was added. Same splits, same threshold rule.
India held-out combined: recall 94.8% → 93.5% (−2 of 155 scams), FPR 1.7% → 1.4%; India ham
false positives 2 → 1 (now equal to the rules alone), UCI unseen 2 → 1. The TRAI ("never sends
any message…"), SIB and Kotak ("never asks for sensitive information…") notices and the
Indian-test "Don't click on suspicious link…" are no longer flagged. The retrained model
alone fixes them; with it, the guard changes no false-positive count on val or held-out and
un-flags 7 of 1,619 val scams (13 of 1,643 held-out), mostly OTP/transaction notices that
IMC25 users reported as smishing. Still flagged: a UCI callertune confirmation.

### How much to trust these numbers

- **Held-out, not circular:** India held-out scam recall (155 real scams: 151 IMC25
  reports from Indian networks, 4 of yours) and the ham false-positive rates (206 India,
  690 UCI, 697 Mendeley messages). Nothing was tuned on them.
- **Small samples:** a false-positive rate of 1/206 has a 95% interval of 0–3%; 1/690 of
  0–1%. A difference of one message is noise. The frozen Indian test split has 29 messages
  and 2 scams (27 labels AI-assisted): a smoke test, not a metric.
- **Circular or biased:** India promos are mostly auto-labelled by `ml/autolabel.py`,
  which uses the same rules, so the rules' 0% promo FPR is flattering. IMC25 links are
  masked by the dataset, so the rules' link checks cannot fire on IMC rows and rules-only
  recall there is a lower bound. IMC25 and Mendeley labels are noisy (user reports; an
  OTP notice reported as smishing counts as a scam).
- **Not Indian in the way users are:** only 4 of the held-out scams are messages you
  received; the rest are public reports, mostly SBI/HDFC/Paytm KYC lures. v1's UPI tricks
  (collect requests, QR "scan to receive", "sent by mistake") are nearly absent from the
  public data: for those the rules, not the classifier, do the work.
- **Known fingerprints** the model still leans on (top n-grams in the report): plain
  `<url>` (IMC25 links can only be plain), `": "` and `" 's"` (placeholder residue) for scam;
  date formats of the India Spam SMS file for genuine.
- **Choices made on val and the 36 examples only:** C, calibration, the Indian weight
  (×5), the 0.9 threshold. The 0.5 guard factor was specified, not tuned.

Full report (quotes messages, gitignored): `ml/reports/private/<date>_classifier.md`.
