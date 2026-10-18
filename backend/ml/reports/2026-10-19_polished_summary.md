# Polished scams: results, misses and proposed fixes (2026-10-19)

Set: `data/datasets/polished_eval.csv`: 40 polished scams and 40 clean genuine messages,
synthetic (hand-written by Claude) and evaluation only. Network fixture:
`data/datasets/polished_eval_network.json`. Detailed reports: `2026-10-19_polished_offline.md`,
`_offline_noclf.md`, `_mocknet.md`, `_mocknet_noclf.md` (every message, every signal).
Flagged = verdict suspicious or scam. No LLM, no Safe Browsing, no reputation reports.

## Results

| configuration | recall | precision | FPR (genuine) | F1 |
|---|---:|---:|---:|---:|
| offline, rules only (classifier off) | 21/40 = 52.5% | 75.0% | 7/40 = 17.5% | 61.8% |
| offline, rules + classifier + KB similarity | 37/40 = 92.5% | 69.8% | 16/40 = 40.0% | 79.6% |
| mocked network, classifier off | 30/40 = 75.0% | 81.1% | 7/40 = 17.5% | 77.9% |
| mocked network, everything | 38/40 = 95.0% | 70.4% | 16/40 = 40.0% | 80.9% |

- The network signals add 9 scams and no false positives.
- The classifier adds 7 to 8 scams but also 9 false positives. On this set its ROC AUC is
  0.80. At P(scam) ≥ 0.9 it flags 29/40 scams and 11/40 genuine messages; at 0.98, 15/40
  and 4/40. Clean bank, refund, bill and job wording is "scam" to it, whatever the link.
- n = 40 per side: a 95% interval is about ±15 points.

## What catches what (mocked network, classifier off)

| giveaway | scams | offline | with network |
|---|---|---|---|
| lookalike domain in the text | ps03 05 07 11 13 18 21 23 | all (lookalike_domain 0.6 → 60) | all, floor 75 (lookalike + new) |
| shortener → lookalike | ps01 02 06 10 19 22 24 | only with a wording rule (02, 06, 10); short_url alone is capped at 20 | all, floor 75 |
| shortener → new non-brand domain | ps04 12 15 17 27 | none (20) | all, but only just (37) |
| bare `rb.gy` link | ps08 20 | not extracted as a link | not extracted as a link |
| new/young non-brand domain | ps09 (75 d) 25 (110 d) 28 (21 d) 35 (45 d) | none | none (10–27) |
| shortener already disabled (404) | ps32 | no (29) | no (29) |
| personal mobile number | ps14 16 26 31 37 38 40 | helpline_personal_mobile → 40–47 (16: 84) | same |
| personal mobile, no "care" word | ps39 ("relationship manager") | no (0) | no |
| the request itself | ps29 30 34 | yes (sent_by_mistake, part_time_high_pay …) | same |
| the request itself | ps33 36 | no: "paying Rs.2,000 … per day", "कमा सकते" not matched | no |

## Misses

With every signal on, 2 are missed:

- **ps25** (10): "DTDC: Aapka parcel hamare warehouse mein hai … confirm karein:
  dtdc-track-delivery.in". 110-day-old domain (url_young_domain 0.3); DTDC is not in the
  brand list.
- **ps32** (29): Hindi gas-subsidy refund, `bit.ly/subsidy-refund` already disabled by the
  shortener (404). url_intel then runs RDAP on bit.ly itself and reports "no issues found".

Offline it also misses **ps15** (20): `cutt.ly/mseb-bill`, offline only short_url.

Without the classifier (it flags 11/40 genuine messages at the same threshold), these 8 are
also missed: **ps08** and **ps20** (rb.gy not extracted), **ps09** (Bank of Baroda, 75-day
domain), **ps28** (incometax-refund-status.in, 21 days: 27), **ps33** (rating job
"paying … per day", 14), **ps35** (trial task, commission, merchant portal; 45-day domain, 19),
**ps36** (Hindi review job, Telegram link, 14), **ps39** (SBI Card "relationship manager"
mobile number, 0).

Caught, but only just (37, threshold 35): ps04, ps12, ps15, ps17, ps27 (shortener → new domain).

## False positives (genuine)

- Driven by the rules (7):
  - pg07, pg09, pg10: KYC reminders with no link. account_blocked → 45.
  - pg11: "As requested, your debit card has been blocked". account_blocked plus the
    classifier → scam 70.
  - pg24: DHL customs duty at del.dhl.com. fee_to_release plus the classifier → scam 72.
  - pg25: Flipkart "Delivery agent OTP maangega, sirf delivery ke time share karein".
    credential_request → scam 85.
  - pg38: `hdfcbk.io`, HDFC's real short domain. lookalike_domain → 60.
- Driven by the classifier alone (9): pg02, pg17, pg18, pg27, pg29, pg31, pg32, pg34 and
  pg40 (pg40 also has short_url).

## Proposed fixes (not implemented)

Risk = false-positive risk, judged on the genuine half of this set and on what real SMS look like.

1. **Extract bare `rb.gy`, `zoma.to`, `fkrt.it`**: add `gy`, `to`, `it` to
   `BARE_DOMAIN_TLDS`. With the network this fixes ps08 and ps20 (floor 75). *Low risk*, but
   fkrt.it then also needs to be in `url_intel.OFFICIAL_DOMAINS` (only the rules' brand list
   has it), and zoma.to in both lists.
2. **Shortener → domain under 30 days old ⇒ floor about 50** in url_intel, next to
   `LOOKALIKE_CONFIRMED_FLOOR`. Makes ps04, 12, 15, 17 and 27 solid instead of 37. *Low risk*:
   no genuine shortener here leads to a new domain. In the wild, a brand campaign microsite
   behind bit.ly could.
3. **Disabled short link**: a shortener answering 404/410 (or its abuse warning page) becomes
   a finding of weight ≥ 0.5, and RDAP is skipped when the "final" domain is the shortener
   itself (today that prints "bit.ly registered 2008: no issues found"). Fixes ps32. *Medium
   risk*: old genuine campaign links expire too.
4. **"Official tone + link + account action"**: KYC/re-KYC/verify/restore/reactivate/"on
   hold"/"restricted"/"रोक दी" together with a link that is not an official domain, in the
   same message: a rule of about 0.5. Catches ps01, 04, 08, 09 and 12 on wording alone,
   offline. *Low risk here*: genuine KYC reminders point to the app or branch, or to
   hdfcbank.com. **Do not** widen `ACCOUNT_BLOCKED` to "KYC is due / periodic update" on its
   own: pg05, pg06 and pg08 say exactly that (3 new false positives).
   The flip side: account_blocked with no link, phone or UPI ID → lower weight (like the
   advisory guard), plus "as requested / aapke anurodh par" as a negation. Removes pg07,
   pg09, pg10 and pg11. *Low risk*: a scam needs a way to reach you.
5. **Brand named in the text, link to an unrelated domain** (`brand_link_mismatch`): "HDFC
   Bank", "Bank of Baroda", "Income Tax Department", "DTDC" … plus a final link domain that
   is not that brand's. Catches ps04, 09, 25 and 28. **High risk** unless the brand → domains
   map is complete. Genuine messages here use bsesdelhi.com, mahadiscom.in, dhl.com,
   zoma.to, hdfcbk.io, airtel.in and 1mg.com; any missing entry is a false positive. Offline,
   apply it only to links that are not shortened.
6. **New domain diluted by quiet rules**: url_new_domain alone gives url_intel 60 × 0.15
   against rules 0 × 0.30, a final score of about 20 (ps28 → 27). Proposal: under 30 days plus a
   link-action verb (verify, update, login, pay, confirm) ⇒ floor 35. *Low risk here* (no
   genuine message has a new domain), *medium in the wild* (new legitimate shops).
7. **Young domains (30–180 days)** get only 0.3 (ps09, 25, 35 → 10–19). Raise
   `NEW_DOMAIN_DAYS` to 60–90, or count "young" as "new" next to a brand or account action.
   *Medium risk*: check the promo FPR on `--dataset india` first.
8. **Brand list gaps**: bankofbaroda/bob, dtdc, incometax, mahavitaran/msedcl, speedpost,
   uppcl, airtel, irctc. ps09, 15, 25 and 28 would become lookalikes. Also add `hdfcbk.io` to
   HDFC's domains (fixes pg38) and `dhl.com` as a brand (pg24's fee_to_release). *Medium
   risk*: "bob" is a prefix of ordinary words, and each brand needs every official domain
   (MSEDCL is mahadiscom.in).
9. **Customer-care vocabulary**: add "relationship manager", "resolution desk", "manager"
   (ps39). *Low–medium risk*: private-banking SMS do name a relationship manager with a
   mobile number. Also, HDFC's real "SMS BLOCK to 7308080808" number is in mobile format, so
   any brand + mobile rule needs an allowlist of official numbers.
10. **Task-job vocabulary**: "paying Rs.X … per day", the Hindi stem "कमा", "commission … next
    set of tasks"; for messaging_link_job, a t.me link with Hindi job words ("नियुक्त", "रिव्यू").
    Fixes ps33, 35 and 36. *Low risk*: the genuine recruiter messages (pg31–33) mention no pay rate.
11. **Delivery-OTP exception** for credential_request: an OTP given to the delivery agent at
    the doorstep, with an official link (pg25, now verdict scam). *Medium risk*: "give the
    OTP to our agent" is also a scam script, so require an official link and "delivery".
12. **The classifier**: the largest source of false positives here. Retrain with clean,
    topic-matched hard negatives (credit alerts, refund initiated, bill due, recruiter,
    support replies) generated with `ml.generate_synthetic`, never from this set. Or let it
    count only next to at least one other signal. Doing that before fixes 1, 4, 5, 8 and 10
    loses ps08, 09, 20, 28, 33, 35, 36 and 39, so land those first.

## Caveats

- Both halves were written by the same author (Claude), and the classifier was trained
  partly on synthetic hard negatives. Real polished scams and real bank SMS will differ.
- The network results depend on the mocked infrastructure: domain ages of 2–12 days for most
  scam domains, 21–110 days for 5. Real campaigns also use aged or hijacked domains, which
  this set does not include.
- Not measured here: Safe Browsing, community reputation, the LLM step.
