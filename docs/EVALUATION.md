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

Held-out Indian messages (447: 155 scams, 206 genuine, 86 promotions), 95% intervals,
model and rules of 2026-10-19:

| | precision | scam recall | false-positive rate | FPR at 90% recall |
|---|---:|---:|---:|---:|
| rules only | 98.7% | 50.3% (43–58%) | 0.3% (0–2%) | unreachable |
| classifier only | 91.5% | 96.8% (93–99%) | 4.8% (3–8%) | 1.0% |
| rules + classifier (what the API does) | 97.3% | 94.2% (89–97%) | 1.4% (1–3%) | 1.4% |

"Unreachable": the rules score most messages 0, so there is no threshold below that; reaching
90% recall would mean flagging everything.

Genuine messages flagged by the API, rules only → with the classifier: Indian 0/206 →
0/206, UCI (UK/Singapore, never seen in training) 0/690 → 1/690. The 36 built-in examples
keep their verdicts. Before 2026-10-19 (see "Polished scams" below): recall 93.5%, Indian
genuine 1/206.

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

## Polished scams (2026-10-19)

### What was pointed out

The concern raised in review: real campaigns are increasingly *polished*: correct
spelling, a real bank or brand name, a calm tone, no "URGENT!!!", no leetspeak. A detector
that learned sloppy scams may miss these, and may flag clean genuine messages about the same
topics (KYC, refunds, bills, parcels).

### What we found

We wrote 40 polished scams and 40 genuine messages in the same clean style
(`backend/data/datasets/polished_eval.csv`, evaluation only) plus a fake internet for the
links (`polished_eval_network.json`: redirect chains and domain ages), and ran the pipeline
on it. Full write-up: `backend/ml/reports/2026-10-19_polished_summary.md`.

- **False positives were the bigger problem:** 16 of 40 genuine messages were flagged, 9 of
  them by the classifier alone (clean bank, refund, bill and job wording looked like scams
  to it, whatever the link) and 7 by rules (KYC reminders with no link, "as requested, your
  card has been blocked", HDFC's real short domain hdfcbk.io treated as a lookalike).
- Scams were mostly caught, but often only because of the classifier or the network checks:
  bare `rb.gy` links were not recognised, a disabled bit.ly link was reported as "no issues
  found" (we were looking up bit.ly's own domain age), and a shortener hiding a days-old site
  scored just above the line.

### What changed

The 80 messages were split first (`ml/split_polished.py`, stratified, seed 20261019) into
`polished_dev` (fixes developed against it) and `polished_test` (looked at once, at the end).

- **Classifier:** retrained on the same template-grouped splits with 432 new hand-written
  training messages (`polished_train.csv`: 291 genuine hard negatives such as bank alerts,
  KYC reminders pointing to the app or branch, card-block confirmations, delivery OTPs,
  courier duty notices and brand short links, plus 141 polished scams). None is a
  near-duplicate of an evaluation message (checked by a test). Threshold unchanged at 0.9.
- **Rules:** bare `.gy`/`.to`/`.it` links are now recognised. A new rule,
  `account_action_link` (0.5), fires on "verify / restore / reactivate / re-KYC your account"
  plus a link that is not an official domain. `account_blocked` drops to 0.2 when the
  message gives no link, phone or UPI ID, or says "as requested". New task-job wording:
  "paying Rs.X … per day", Hindi "कमा", and "commission … next set of tasks"
  (`task_commission`). Hindi job words for Telegram links. "Relationship manager" is now a
  customer-care role. New brands: Bank of Baroda, DTDC, Income Tax, MSEDCL, Speed Post, and
  zoma.to / hdfcbk.io as official domains.
- **Link checks:** a shortener hiding a site under 30 days old sets a minimum score of 50.
  A link the shortener has disabled (HTTP 404/410) is a mild warning (0.3), and the
  shortener's own domain is never looked up.
- **Corroboration:** built and measured, but **off by default** (below).

### Results

Flagged = verdict suspicious or scam. "Mocked network" = link expansion and domain age from
the fixture; no Safe Browsing, no reputation, no LLM.

| | before | after |
|---|---:|---:|
| polished_test, offline: scam recall | 18/20 (90%) | 20/20 (100%) |
| polished_test, offline: genuine flagged | 6/20 (30%) | 2/20 (10%) |
| polished_test, mocked network: scam recall | 18/20 (90%) | 20/20 (100%) |
| polished_test, mocked network: genuine flagged | 6/20 (30%) | 2/20 (10%) |
| India held-out scam recall (155) | 145 (93.5%) | 146 (94.2%) |
| India held-out genuine flagged (206) | 1 | 0 |
| India held-out promotions flagged (86) | 3 | 4 |
| UCI unseen genuine flagged (690) | 1 | 1 |
| Mendeley held-out genuine flagged (697) | 0 | 1 |
| 36 built-in examples keeping their verdict | 36 | 36 |

On polished_dev the genuine false positives went from 10/20 to 1/20.

Still flagged on polished_test: a Flipkart message telling you to give the OTP to the
delivery agent (the `credential_request` rule; a delivery-OTP exception was judged too risky,
since "give the OTP to our agent" is also a scam script), and a Hindi electricity-bill
reminder (classifier 0.90). On polished_dev: a DHL customs-duty notice (`fee_to_release`,
DHL is not in the brand list). Offline, polished_dev still misses two scams whose only sign
is a shortened link; with the network checks it misses none.

Smaller costs, all on held-out data. Rules-only India recall fell from 82 to 78: four
public reports whose link the dataset had removed ("click here link"), so the down-weighted
`account_blocked` applies. The classifier still catches them. A Refyne "complete KYC" promo
with an unofficial link now trips `account_action_link`, hence the promotion count of 4.
Non-Indian IMC25 recall went from 86.4% to 85.3%.

### Corroboration: the trade-off

The idea: the classifier counts only next to independent evidence (a rule outside the
supporting-only ones, url_intel, upi_check, reputation or sender_check); alone it can raise
the score but not to "suspicious". It is implemented (`CLASSIFIER_REQUIRES_CORROBORATION`,
`CLASSIFIER_CORROBORATION_BYPASS` to let very confident predictions through) and measured
on val first (`ml/eval_corroboration.py`):

| | val Indian scam recall (156) | val genuine flagged (905) | India held-out recall (155) | India promos flagged (86) | polished_test genuine flagged (offline) |
|---|---:|---:|---:|---:|---:|
| off (default) | 135 (86.5%) | 5 | 146 (94.2%) | 4 | 2/20 |
| on, but P(scam) ≥ 0.98 counts alone | 125 (80.1%) | 1 | 135 (87.1%) | 4 | 1/20 |
| on | 76 (48.7%) | 1 | 105 (67.7%) | 1 | 1/20 |

Strict corroboration un-flags 1,045 of val's 1,619 scams (59 of the 156 Indian ones). Most
public scam reports have their links masked by the dataset, so the rules have nothing to
add. Even the bypass variant loses 7 points of India held-out recall, over the limit of
about 3, so corroboration ships **off**. After the retrain it would remove one polished
false positive (the Hindi bill reminder on polished_test) and none on polished_dev. If real
messages show classifier-only false positives that the retrain did not fix, the bypass
variant is the one to try.

### Caveats

- **Synthetic, written by us.** Both the polished evaluation set and the new training
  messages were written by the same author (Claude), in the same style. Real polished scams
  and real bank SMS will differ, and a classifier trained on our genuine messages will find
  our other genuine messages easier than real ones. The near-duplicate check prevents copies,
  not a shared style.
- **The split came after the write-up.** The rule ideas came from analysing all 80 messages
  before the split, so polished_test is held out for the retrained classifier and the
  settings, not fully for the rules.
- **Mocked network.** Domain ages and redirects are invented: 2–12 days for most scam
  domains, 21–110 days for five. Real campaigns also use aged or hijacked domains.
- **Small samples.** 20 per side: one message is 5 points, and a 95% interval on 2/20 is
  about 3–30%. The held-out changes (one scam, one genuine message) are within noise.

## Known weaknesses

The classifier learned mostly from public, largely non-Indian smishing reports. It still
rates some genuine Indian transactional messages as likely scams (a UPI debit alert 0.72, a
food-delivery update 0.68, an SBI "visit your branch for KYC" reminder 0.86), which is why it
only counts from 0.9. (Scores from the 2026-09 model; the 2026-10-19 retrain added hard
negatives of exactly these kinds.)
