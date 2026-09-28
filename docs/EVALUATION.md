# Evaluation

How good the scam classifier is, how it was measured, and how much to trust the numbers.
Data sources, splits and training details: [backend/data/datasets/README.md](../backend/data/datasets/README.md).

## The classifier

A TF-IDF (character + word n-grams) logistic-regression model trained on public smishing
data (IMC 2025 reports, Mendeley, India Spam SMS) plus synthetic hard negatives, exported
to `backend/models/classifier.json` (4 MB) and run with numpy. It is the `classifier`
signal: 100 × P(scam), counted only when P(scam) ≥ 0.9, never setting a minimum score, and
with half its weight on fraud-awareness notices ("SBI never asks for your OTP"). Your own
collected messages are test-only: they never train it. Code: `ml/train_classifier.py`,
`ml/eval_classifier.py`, `app/services/classifier.py`.

Render needs `backend/models/classifier.json` committed; without it the signal is reported
unavailable and everything else works. In memory it costs about 14 MB (see
[DEPLOYMENT.md](DEPLOYMENT.md#memory-measured-locally-windows-python-312-one-uvicorn-worker)).

## Results

Held-out Indian messages (447: 155 scams, 206 genuine, 86 promotions), 95% intervals:

| | precision | scam recall | false-positive rate | FPR at 90% recall |
|---|---:|---:|---:|---:|
| rules only | 98.8% | 52.9% (45–61%) | 0.3% (0–2%) | unreachable |
| classifier only | 91.5% | 97.4% (94–99%) | 4.8% (3–8%) | 1.0% |
| rules + classifier (what the API does) | 97.3% | 93.5% (89–96%) | 1.4% (1–3%) | 1.4% |

"Unreachable": the rules score most messages 0, so there is no threshold below that; reaching
90% recall would mean flagging everything.

Genuine messages flagged by the API, rules only → with the classifier: Indian 1/206 →
1/206, UCI (UK/Singapore, never seen in training) 0/690 → 1/690. The 36 built-in examples
keep their verdicts.

The per-dataset breakdown (Mendeley, promotions, pooled results, per-class scores) and the
changelog of the latest retrain are in
[backend/data/datasets/README.md](../backend/data/datasets/README.md#results-held-out-2026-09-29).

## How much to trust these numbers

- Held-out means no message and no near-duplicate template of it was used for training or
  for choosing any setting; the threshold and model settings were chosen on a separate
  validation split.
- The samples are small where it matters most: 1/206 has an interval of 0–3%, so a
  one-message difference means nothing. The frozen Indian test split (29 messages, 2 scams,
  27 AI-assisted labels) is a smoke test, not a metric.
- 151 of the 155 Indian held-out scams are public user reports (mostly bank KYC lures);
  only 4 are messages the author received. v1's UPI tricks (collect requests, "scan to
  receive", "sent by mistake") are almost absent from public data, so for those the rules do
  the work, and the recall above says little about them.
- Some labels are circular or noisy: Indian promotions were largely labelled by a script
  built on the same rules (flattering the rules' 0% promo false-positive rate), and the
  public datasets' scam labels are user reports.

## Known weaknesses

The classifier learned mostly from public, largely non-Indian smishing reports. It still
rates some genuine Indian transactional messages as likely scams (a UPI debit alert 0.72, a
food-delivery update 0.68, an SBI "visit your branch for KYC" reminder 0.86), which is why it
only counts from 0.9.
