# Datasets

Everything here except this README, `collected_template.csv` and `processed/.gitkeep` is
gitignored. Scripts live in `backend/ml/`; run them from `backend/` with `uv run python -m ...`.

```
raw/                 public downloads            (ml/download_public.py)
collected/           YOUR messages, NOT anonymized — never share or commit
synthetic/           Groq variations + hard negatives, progress.json (ml/generate_synthetic.py)
processed/           anonymized, unified CSVs only  (ml/prepare_dataset.py)
  ood_<name>.csv       public datasets: out-of-domain EVALUATION ONLY, never training
  train.csv val.csv    collected (+ synthetic in train)
  test.csv             frozen Indian test split (see below)
  split_manifest.json  the ids in test.csv and when it was created
```

## Pipeline

```
uv run python -m ml.download_public      # UCI; prints instructions for Mendeley
uv run python -m ml.anonymize collected/my_sms.csv   # optional: preview anonymization
uv run python -m ml.prepare_dataset      # anonymize -> dedupe -> splits
uv run python -m ml.generate_synthetic --max-calls 10   # needs collected scams
uv run python -m ml.prepare_dataset      # again, to add the synthetic rows to train
uv run python -m ml.evaluate --dataset test     # or uci | examples | val | mendeley | a CSV
```

## Public sources

Both are **out-of-domain**: mostly non-Indian, no UPI, and their "spam" label is not our
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

## Your collected messages

Copy `collected_template.csv` into `collected/` (any number of CSV files) and delete the
example rows. Columns:

| column | |
|---|---|
| `text` | the message, exactly as received |
| `label` | `scam` or `genuine` |
| `scam_type` | for scams: `upi_receive_money`, `qr_code`, `sent_by_mistake`, `phishing_link`, `task_job`, `fake_customer_care`, or `generic`; empty for genuine |
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
is_indian, parent_id, split`

- `id`: hash of the normalized text (for collected rows: of the original text, so it
  survives changes to the anonymizer).
- `language`: `en | hi | hinglish`, a heuristic (Devanagari share, then common
  romanized-Hindi words). Good enough for a per-language breakdown, not more.
- `parent_id`: for synthetic rows, the train message they were generated from.

**Dedupe:** exact duplicates (same normalized text) and near-duplicates (token Jaccard ≥
0.8) collapse to the first copy. Messages that appear with two different labels are dropped.

## Splits

- **test**: only real, non-synthetic, Indian (collected) messages, ~20%, stratified by
  label and scam_type (groups with fewer than 3 messages stay in train). Created the first
  time there are at least **30** collected messages, then **frozen** in
  `split_manifest.json`: new messages go to train/val only, and the same messages stay in
  test so results remain comparable over time. `--rebuild-test` re-draws it (old reports
  are then no longer comparable).
- **val**: ~15% of the remaining real messages, stratified; recomputed on each run.
- **train**: the rest, plus synthetic rows. A synthetic row is dropped if its parent is not
  in train or it is too similar (Jaccard ≥ 0.7) to any val/test message.
