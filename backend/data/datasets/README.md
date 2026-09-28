# Datasets

Everything here except this README, `collected_template.csv` and `processed/.gitkeep` is
gitignored. Scripts live in `backend/ml/`; run them from `backend/` with `uv run python -m ...`.

```
raw/                 public downloads            (ml/download_public.py)
collected/           YOUR messages, NOT anonymized — never share or commit
synthetic/           Groq variations + hard negatives, progress.json (ml/generate_synthetic.py)
review_queue.csv     India rows for you to label (ml/prepare_dataset.py) — real messages, gitignored
reviewed_labels.csv  your applied review labels (ml/apply_review.py) — gitignored
processed/           anonymized, unified CSVs only  (ml/prepare_dataset.py)
  ood_<name>.csv       non-Indian public datasets: out-of-domain EVALUATION ONLY, never training
  india_spam_sms.csv   every India row after dedupe, uncertain ones included (evaluation)
  collected.csv        your collected messages (evaluation)
  train.csv val.csv    collected + India (+ synthetic in train)
  test.csv             frozen Indian test split (see below)
  split_manifest.json  the ids in test.csv and when it was created
```

## Pipeline

```
uv run python -m ml.download_public      # UCI + India Spam SMS; prints instructions for Mendeley
uv run python -m ml.anonymize collected/my_sms.csv   # optional: preview anonymization
uv run python -m ml.prepare_dataset      # anonymize -> auto-label -> dedupe -> splits + review queue
# fill in my_label / my_scam_type in review_queue.csv, then:
uv run python -m ml.apply_review         # save your labels, report auto-label accuracy
uv run python -m ml.prepare_dataset      # again, to use them
uv run python -m ml.generate_synthetic --max-calls 10   # needs collected scams
uv run python -m ml.prepare_dataset      # again, to add the synthetic rows to train
uv run python -m ml.evaluate --dataset test     # or india | collected | uci | examples | val | mendeley | a CSV
```

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

### Out-of-domain: UCI, Mendeley

Both are mostly non-Indian, with no UPI, and their "spam" label is not our
"scam" label. It mixes promotions, premium-rate prize lures and subscription services with
outright fraud. `label` keeps their own word (`spam`, `smishing`; `ham` → `genuine`),
`original_label` their exact label, `is_indian=false`. They are used only to measure how
often ordinary messages get flagged (false positive rate on ham) and as a rough baseline.

| | UCI SMS Spam Collection | SMS Phishing Dataset for Machine Learning and Pattern Recognition |
|---|---|---|
| Authors | T. A. Almeida, J. M. Gómez Hidalgo | Sandhya Mishra, Devpriya Soni |
| Year | 2011 (published 2012) | 2022 |
| Size | 5,574 SMS: 4,827 ham, 747 spam | 5,971 SMS: ham, spam, smishing |
| Country | Mostly UK (Grumbletext spam forum, a UK thesis corpus) and Singapore (NUS SMS Corpus ham) | Authors in India; the messages are largely drawn from existing public English corpora. Check the paper before treating any of it as Indian |
| Licence | CC BY 4.0 | CC BY 4.0 (as listed on Mendeley Data; check the dataset page) |
| Where | https://archive.ics.uci.edu/dataset/228/sms+spam+collection (downloaded automatically) | https://data.mendeley.com/datasets/f45bkkt8pr/1 (manual download, see below) |
| File | `raw/uci_sms_spam/SMSSpamCollection` | `raw/mendeley_sms_phishing/*.csv` |
| Cite | Almeida, Gómez Hidalgo, Yamakami. *Contributions to the Study of SMS Spam Filtering: New Collection and Results.* DocEng 2011 | Mishra, Soni. *SMS Phishing Dataset for Machine Learning and Pattern Recognition.* Mendeley Data, V1, 2022. doi:10.17632/f45bkkt8pr.1 |

**Mendeley manual download:** open the page, "Download All", unzip, and put the CSV
(columns `LABEL, TEXT, URL, EMAIL, PHONE`) in `raw/mendeley_sms_phishing/`. The scripts
skip it if it is missing.

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

**Anonymization** (`ml/anonymize.py`) runs on every collected message before anything is
written to `processed/`. Mobile numbers become `99999xxxxx` in the same format, the name
after "Dear/Hi/प्रिय" a placeholder name, account/card numbers `XX1234`, personal emails a
fake local part. URLs, domains, UPI IDs and amounts are kept: they are what the detectors
look at. Not handled: names that don't follow a greeting (e.g. "from RAMESH KUMAR" in a
credit alert), addresses, Aadhaar/PAN numbers. Preview with
`uv run python -m ml.anonymize collected/<file>.csv` and remove anything it misses.

## Unified schema (processed/*.csv)

`id, text, label, original_label, scam_type, language, source, dataset, is_synthetic,
is_indian, label_source, parent_id, split`

- `id`: hash of the normalized text (for collected rows: of the original text, so it
  survives changes to the anonymizer).
- `language`: `en | hi | hinglish`, a heuristic (Devanagari share, then common
  romanized-Hindi words). Good enough for a per-language breakdown, not more.
- `parent_id`: for synthetic rows, the train message they were generated from.

**Dedupe:** exact duplicates (same normalized text) and near-duplicates (token Jaccard ≥
0.8) collapse to one copy, the first unless a later one has a more authoritative label
(manual > assisted > dataset > auto). When the same text has two labels, the most authoritative label
wins if its copies agree; otherwise all copies are dropped.

## Splits

- **test**: only reviewed messages (`label_source=manual`: collected or reviewed by you;
  `label_source=assisted`: reviewed by an AI assistant), ~20%, stratified by label and scam_type (groups with fewer than 3 messages
  stay in train). Auto-labelled and dataset-labelled rows never enter it. Created the first
  time there are at least **30** such messages, then **frozen** in
  `split_manifest.json`: new messages go to train/val only, and the same messages stay in
  test so results remain comparable over time. Every report on it says "Test labels: N
  manual (author), M AI-assisted (Claude)" and gives metrics for manual-only,
  assisted-only and combined. `--rebuild-test` re-draws it (old reports
  are then no longer comparable).
- **val**: ~15% of the remaining real messages (auto and dataset labels included),
  stratified; recomputed on each run.
- **train**: the rest, plus synthetic rows. A synthetic row is dropped if its parent is not
  in train or it is too similar (Jaccard ≥ 0.7) to any val/test message.
