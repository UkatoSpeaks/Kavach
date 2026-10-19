# Evaluation: polished_test

> **Synthetic, hand-written (Claude), never used for training.** 40 polished scams (perfect spelling, real bank/brand names, calm tone: the only giveaway is the link, a personal phone number or the request itself) and 40 genuine messages written the same clean way, across the v1 types, in English, Hinglish and Hindi. Scam domains are invented and were unregistered (RDAP 404) when written. Groups are categories (kyc, account, electricity, ...): each shows scam recall and genuine FPR side by side. A stress test of what the detector relies on, not a prevalence estimate: 50% scams. This is the held-out test half (ml/split_polished.py): not used to develop fixes.

- date: 2026-10-19 · code: `554da48 + uncommitted changes in app/`
- messages: 40 (20 positives = label scam; 20 negatives)
- network checks (url_intel, reputation): OFF (offline)
- classifier: on
- weights: `{'rules': 0.3, 'classifier': 0.25, 'url_intel': 0.15, 'upi_check': 0.15, 'reputation': 0.1, 'pattern_similarity': 0.05, 'llm': 0.15, 'sender_check': 0.15, 'fake_payment_proof': 0.15}` · thresholds: suspicious ≥ 35, scam ≥ 70
- flagged = verdict suspicious or scam. "scam-only" counts only verdict scam.

## Summary

| mode | n | precision | recall | F1 | FPR | scam-only P / R | p50 ms | p95 ms | errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rules | 40 | 90.9% | 100.0% | 95.2% | 10.0% | 93.8% / 75.0% | 3 | 4 | 0 |
| checks | 40 | 90.9% | 100.0% | 95.2% | 10.0% | 93.8% / 75.0% | 23 | 27 | 0 |

## Mode: rules

### Confusion matrix

| | flagged | not flagged |
|---|---:|---:|
| **positive** | TP 20 | FN 0 |
| **negative** | FP 2 | TN 18 |

### False-positive rate per not-scam label

| not-scam label | labelled by | n | flagged | FPR | of which verdict scam |
|---|---|---:|---:|---:|---:|
| genuine | synthetic | 20 | 2 | 10.0% | 1 |

### Every message

| # | expected | score | verdict | outcome | top signals | message |
|---:|---|---:|---|---|---|---|
| 1 | scam (phishing_link) | 82 | scam | ok | classifier 95 (w 0.45), rules 72 (w 0.55); flags: account_action_link, short_url | Dear Customer, as per RBI guidelines your HDFC Bank KYC is due for periodic update. Please complete re-KYC online to continue uninterrupted banking: bit.ly/3Kq… |
| 2 | scam (phishing_link) | 87 | scam | ok | rules 80 (w 0.55), classifier 96 (w 0.45); flags: lookalike_domain, account_action_link | Kotak Bank: Aapka Video KYC adhoora hai. Account active rakhne ke liye ise yahan poora karein: kotak-vkyc.co.in |
| 3 | scam (phishing_link) | 89 | scam | ok | classifier 99 (w 0.45), rules 80 (w 0.55); flags: lookalike_domain, account_action_link | Bank of Baroda: Your debit card has been put on hold following a routine security review. You can reactivate it securely at bob-card-services.in |
| 4 | scam (phishing_link) | 91 | scam | ok | rules 85 (w 0.55), classifier 97 (w 0.45); flags: account_action_link, short_url, account_blocked | SBI Alert: Aapka YONO account suraksha kaarano se band kar diya gaya hai. Dobara chalu karne ke liye login karein: bit.ly/3yonoSB |
| 5 | scam (phishing_link) | 89 | scam | ok | classifier 99 (w 0.45), rules 80 (w 0.55); flags: lookalike_domain, account_action_link | HDFC Bank: Aapke account par kuch transactions verify hone baaki hain. Account limit hatane ke liye apni details confirm karein: https://hdfc-netbanking-verify… |
| 6 | scam (phishing_link) | 84 | scam | ok | classifier 99 (w 0.45), rules 72 (w 0.55); flags: account_action_link, short_url | प्रिय ग्राहक, सुरक्षा समीक्षा के कारण आपकी नेट बैंकिंग सेवा अस्थायी रूप से रोक दी गई है। सेवा फिर से शुरू करने के लिए यहां लॉग इन करें: tinyurl.com/netbank-seva |
| 7 | scam (phishing_link) | 78 | scam | ok | classifier 99 (w 0.45), rules 60 (w 0.55); flags: lookalike_domain | Dear consumer, our records show your electricity bill for September is unpaid. To avoid interruption of supply, please clear it on the BSES payment page: bses-… |
| 8 | scam (fake_customer_care) | 89 | scam | ok | classifier 100 (w 0.45), rules 81 (w 0.55); flags: electricity_disconnection, helpline_personal_mobile, urgency | Electricity Dept: Aapka connection aaj raat 9:30 baje disconnect ho sakta hai kyunki pichhla bill system mein update nahi hua. Jankari ke liye officer se baat … |
| 9 | scam (phishing_link) | 78 | scam | ok | classifier 99 (w 0.45), rules 60 (w 0.55); flags: lookalike_domain | Traffic Police: A challan of Rs.500 has been issued against your vehicle for a signal violation. View the evidence and pay online at https://echallan-parivahan… |
| 10 | scam (phishing_link) | 54 | suspicious | ok | classifier 96 (w 0.45), rules 20 (w 0.55); flags: short_url | Your vehicle DL3CXX1234 has an unpaid e-challan of Rs.1,000. Please settle it to avoid it being forwarded to the virtual court: tinyurl.com/vcourt-challan |
| 11 | scam (phishing_link) | 77 | scam | ok | classifier 96 (w 0.45), rules 60 (w 0.55); flags: lookalike_domain | Parivahan Seva: Aapke vahan ka challan court mein bhejne se pehle online samadhan ka avsar hai. Yahan check karein: parivahan-samadhan.co.in |
| 12 | scam (phishing_link) | 89 | scam | ok | classifier 100 (w 0.45), rules 80 (w 0.55); flags: lookalike_domain, fee_to_release | India Post: Your parcel could not be delivered as the address was incomplete. Please confirm your address and a redelivery charge of Rs.25 at indiapost-redeliv… |
| 13 | scam (phishing_link) | 78 | scam | ok | classifier 100 (w 0.45), rules 60 (w 0.55); flags: lookalike_domain | DTDC: Aapka parcel hamare warehouse mein hai. Delivery schedule karne ke liye apna address yahan confirm karein: dtdc-track-delivery.in |
| 14 | scam (fake_customer_care) | 67 | suspicious | ok | classifier 100 (w 0.45), rules 40 (w 0.55); flags: helpline_personal_mobile | Customs Department, IGI Airport: A gift parcel addressed to you is awaiting clearance. For the duty amount and release process, contact the clearance officer o… |
| 15 | scam (sent_by_mistake) | 88 | scam | ok | classifier 99 (w 0.45), rules 78 (w 0.55); flags: sent_by_mistake, return_money | Hello, maine galti se aapke number par Rs.2,000 bhej diye. Aap please wapas kar dijiye 9999938807@paytm par. Thank you. |
| 16 | scam (phishing_link) | 55 | suspicious | ok | classifier 98 (w 0.45), rules 20 (w 0.55); flags: short_url | प्रिय ग्राहक, आपके गैस सब्सिडी रिफंड ₹1,240 की प्रक्रिया लंबित है। राशि प्राप्त करने के लिए अपना बैंक विवरण यहां सत्यापित करें: bit.ly/subsidy-refund |
| 17 | scam (task_job) | 73 | scam | ok | classifier 100 (w 0.45), rules 50 (w 0.55); flags: earn_per_task | Hello, I'm Riya from Talent Acquisition at Meridian Digital. We have a flexible remote role rating hotel listings, paying Rs.2,000 to Rs.5,000 per day. If inte… |
| 18 | scam (task_job) | 91 | scam | ok | rules 85 (w 0.55), classifier 98 (w 0.45); flags: earn_per_task, part_time_high_pay, messaging_link_job | Namaste, hum ek digital marketing company ke liye part-time associates hire kar rahe hain. Sirf YouTube videos like karke roz Rs.1,500 tak kama sakte hain. Det… |
| 19 | scam (fake_customer_care) | 64 | suspicious | ok | classifier 93 (w 0.45), rules 40 (w 0.55); flags: helpline_personal_mobile | PhonePe Support: We received your complaint about a failed transaction. To process the reversal, please speak to our resolution desk at 99999 85126. |
| 20 | scam (fake_customer_care) | 67 | suspicious | ok | classifier 99 (w 0.45), rules 40 (w 0.55); flags: helpline_personal_mobile | Thank you for contacting Flipkart. Your return request has been escalated. A senior support executive will assist you on +91 99999 30947; please keep your orde… |
| 21 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Dear SBI UPI User, your A/c X5123 is credited by Rs.12,000.00 on 17Oct26 by transfer from RAHUL S (Ref No 629011223344). -SBI |
| 22 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | आपके खाते XX7710 से ₹3,500.00 UPI द्वारा 15-10-26 को डेबिट किए गए। यदि यह लेनदेन आपने नहीं किया है तो 1800 1234 पर कॉल करें। - एसबीआई |
| 23 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Dear Customer, as per RBI guidelines, your account is due for periodic KYC updation. Please visit your nearest HDFC Bank branch with a valid ID proof, or updat… |
| 24 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Dear customer, aapke ICICI account ka re-KYC due hai. Kripya iMobile Pay app ya nazdeeki branch mein update karein. ICICI Bank kabhi bhi OTP ya password nahi m… |
| 25 | genuine | 20 | safe | ok | rules 20 (w 1.00); flags: account_blocked | Paytm Payments Bank: Your wallet KYC has expired under RBI's periodic review. Complete it in the Paytm app under Profile > KYC. We never share links for KYC ov… |
| 26 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | SBI: Aapka YONO login ek naye device par hua hai. Agar yeh aapne nahi kiya, toh 1800 1234 par call karein ya YONO app mein 'Block Access' chunein. |
| 27 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | प्रिय ग्राहक, आपके अनुरोध पर आपका डेबिट कार्ड ब्लॉक कर दिया गया है। नए कार्ड के लिए नजदीकी शाखा से संपर्क करें। - बैंक ऑफ बड़ौदा |
| 28 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | MSEDCL: Priya grahak, aapka bijli bill Rs.980 due date 30-10-2026 tak bhar dein. Online payment ke liye wss.mahadiscom.in par jaayein. |
| 29 | genuine | 41 | suspicious | **FALSE ALARM** | classifier 90 (w 0.45), rules 0 (w 0.55); flags: none | प्रिय उपभोक्ता, आपके बिजली बिल ₹1,420 का भुगतान नियत तिथि 20-10-2026 तक नहीं हुआ है। विच्छेदन से बचने के लिए कृपया भुगतान करें: uppcl.org - UPPCL |
| 30 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | A challan (No. DL116XXXX2611) of Rs.500 has been issued for vehicle DL3CXX1234 for over-speeding. Pay at echallan.parivahan.gov.in or at the nearest traffic po… |
| 31 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Aapke vahan MH12XX4521 par Rs.1,000 ka challan pending hai. Bhugtan sirf echallan.parivahan.gov.in ya Mahatraffic app par karein. - Maharashtra Traffic Police |
| 32 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Amazon: Delivery of your package with boAt Airdopes was attempted today but no one was available. We will try again tomorrow. Track: amzn.in/d/8xKp2Qr |
| 33 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | India Post: Article EE123456789IN booked on 14-10-2026 is out for delivery. Track at indiapost.gov.in |
| 34 | genuine | 85 | scam | **FALSE ALARM** | rules 85 (w 1.00); flags: credential_request | Flipkart: Aapka order 'Prestige Kettle' kal deliver hoga. Delivery agent OTP maangega, sirf delivery ke time share karein. Track: fkrt.it/Xq7PvRuuuN |
| 35 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Income Tax Department: A refund of Rs.15,490 for AY 2026-27 has been processed to your bank account ending XX4471. Check the status at incometax.gov.in. |
| 36 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | प्रिय ग्राहक, आपके रद्द किए गए ऑर्डर का ₹849 का रिफंड आपके खाते में भेज दिया गया है। - मिंत्रा |
| 37 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Namaste, aapka application Swiggy delivery partner ke liye approve ho gaya hai. Onboarding Swiggy Delivery Partner app mein complete karein. Koi joining fee na… |
| 38 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Thank you for contacting PhonePe Support. Your ticket CS-48213907 has been resolved. If you need more help, reply in the app under Help. PhonePe never asks for… |
| 39 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Airtel: Aapka Rs.349 ka plan 21-Oct ko khatam ho raha hai. Recharge ke liye: i.airtel.in/Recharge |
| 40 | genuine | 20 | safe | ok | rules 20 (w 1.00); flags: short_url | Tata 1mg: Your order #PO8XXXX21 has been shipped and will arrive by Tuesday. Track: bit.ly/1mgTrk82 |

### Per group (scam_type, or the dataset's own label)

| group | n | positives | flagged (TP) | recall | negatives | flagged (FP) | FPR | scam_type matches |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| account | 6 | 4 | 4 | 100.0% | 2 | 0 | 0.0% | 4/4 |
| bank_alert | 2 | 0 | 0 | – | 2 | 0 | 0.0% | – |
| brand_link | 2 | 0 | 0 | – | 2 | 0 | 0.0% | – |
| customer_care | 3 | 2 | 2 | 100.0% | 1 | 0 | 0.0% | 2/2 |
| e_challan | 5 | 3 | 3 | 100.0% | 2 | 0 | 0.0% | 3/3 |
| electricity | 4 | 2 | 2 | 100.0% | 2 | 1 | 50.0% | 1/2 |
| job | 3 | 2 | 2 | 100.0% | 1 | 0 | 0.0% | 2/2 |
| kyc | 5 | 2 | 2 | 100.0% | 3 | 0 | 0.0% | 2/2 |
| parcel_customs | 6 | 3 | 3 | 100.0% | 3 | 1 | 33.3% | 3/3 |
| refund | 4 | 2 | 2 | 100.0% | 2 | 0 | 0.0% | 2/2 |

### Per language (heuristic)

| language | n | positives | flagged (TP) | recall | negatives | flagged (FP) | FPR | scam_type matches |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| en | 19 | 10 | 10 | 100.0% | 9 | 0 | 0.0% | 10/10 |
| hi | 6 | 2 | 2 | 100.0% | 4 | 1 | 25.0% | 2/2 |
| hinglish | 15 | 8 | 8 | 100.0% | 7 | 1 | 14.3% | 7/8 |

### False positives (2, highest score first)

<details><summary>show all</summary>

- **85 scam** · group `parcel_customs` · lang hinglish · top: rules 85 (w 1.00) · flags: credential_request
  > Flipkart: Aapka order 'Prestige Kettle' kal deliver hoga. Delivery agent OTP maangega, sirf delivery ke time share karein. Track: fkrt.it/Xq7PvRuuuN
- **41 suspicious** · group `electricity` · lang hi · top: classifier 90 (w 0.45), rules 0 (w 0.55) · flags: none
  > प्रिय उपभोक्ता, आपके बिजली बिल ₹1,420 का भुगतान नियत तिथि 20-10-2026 तक नहीं हुआ है। विच्छेदन से बचने के लिए कृपया भुगतान करें: uppcl.org - UPPCL

</details>

### False negatives (0, lowest first)

None.


## Mode: checks

### Confusion matrix

| | flagged | not flagged |
|---|---:|---:|
| **positive** | TP 20 | FN 0 |
| **negative** | FP 2 | TN 18 |

### False-positive rate per not-scam label

| not-scam label | labelled by | n | flagged | FPR | of which verdict scam |
|---|---|---:|---:|---:|---:|
| genuine | synthetic | 20 | 2 | 10.0% | 1 |

### Every message

| # | expected | score | verdict | outcome | top signals | message |
|---:|---|---:|---|---|---|---|
| 1 | scam (phishing_link) | 82 | scam | ok | classifier 95 (w 0.45), rules 72 (w 0.55); flags: account_action_link, short_url | Dear Customer, as per RBI guidelines your HDFC Bank KYC is due for periodic update. Please complete re-KYC online to continue uninterrupted banking: bit.ly/3Kq… |
| 2 | scam (phishing_link) | 85 | scam | ok | rules 80 (w 0.50), classifier 96 (w 0.42), pattern_similarity 61 (w 0.08); flags: lookalike_domain, account_action_link | Kotak Bank: Aapka Video KYC adhoora hai. Account active rakhne ke liye ise yahan poora karein: kotak-vkyc.co.in |
| 3 | scam (phishing_link) | 89 | scam | ok | classifier 99 (w 0.45), rules 80 (w 0.55); flags: lookalike_domain, account_action_link | Bank of Baroda: Your debit card has been put on hold following a routine security review. You can reactivate it securely at bob-card-services.in |
| 4 | scam (phishing_link) | 91 | scam | ok | rules 85 (w 0.55), classifier 97 (w 0.45); flags: account_action_link, short_url, account_blocked | SBI Alert: Aapka YONO account suraksha kaarano se band kar diya gaya hai. Dobara chalu karne ke liye login karein: bit.ly/3yonoSB |
| 5 | scam (phishing_link) | 89 | scam | ok | classifier 99 (w 0.45), rules 80 (w 0.55); flags: lookalike_domain, account_action_link | HDFC Bank: Aapke account par kuch transactions verify hone baaki hain. Account limit hatane ke liye apni details confirm karein: https://hdfc-netbanking-verify… |
| 6 | scam (phishing_link) | 84 | scam | ok | classifier 99 (w 0.45), rules 72 (w 0.55); flags: account_action_link, short_url | प्रिय ग्राहक, सुरक्षा समीक्षा के कारण आपकी नेट बैंकिंग सेवा अस्थायी रूप से रोक दी गई है। सेवा फिर से शुरू करने के लिए यहां लॉग इन करें: tinyurl.com/netbank-seva |
| 7 | scam (phishing_link) | 80 | scam | ok | classifier 99 (w 0.42), rules 60 (w 0.50), pattern_similarity 100 (w 0.08); flags: lookalike_domain | Dear consumer, our records show your electricity bill for September is unpaid. To avoid interruption of supply, please clear it on the BSES payment page: bses-… |
| 8 | scam (fake_customer_care) | 90 | scam | ok | classifier 100 (w 0.42), rules 81 (w 0.50), pattern_similarity 100 (w 0.08); flags: electricity_disconnection, helpline_personal_mobile, urgency | Electricity Dept: Aapka connection aaj raat 9:30 baje disconnect ho sakta hai kyunki pichhla bill system mein update nahi hua. Jankari ke liye officer se baat … |
| 9 | scam (phishing_link) | 80 | scam | ok | classifier 99 (w 0.42), rules 60 (w 0.50), pattern_similarity 100 (w 0.08); flags: lookalike_domain | Traffic Police: A challan of Rs.500 has been issued against your vehicle for a signal violation. View the evidence and pay online at https://echallan-parivahan… |
| 10 | scam (phishing_link) | 58 | suspicious | ok | classifier 96 (w 0.42), rules 20 (w 0.50), pattern_similarity 100 (w 0.08); flags: short_url | Your vehicle DL3CXX1234 has an unpaid e-challan of Rs.1,000. Please settle it to avoid it being forwarded to the virtual court: tinyurl.com/vcourt-challan |
| 11 | scam (phishing_link) | 77 | scam | ok | classifier 96 (w 0.45), rules 60 (w 0.55); flags: lookalike_domain | Parivahan Seva: Aapke vahan ka challan court mein bhejne se pehle online samadhan ka avsar hai. Yahan check karein: parivahan-samadhan.co.in |
| 12 | scam (phishing_link) | 89 | scam | ok | classifier 100 (w 0.42), rules 80 (w 0.50), pattern_similarity 94 (w 0.08); flags: lookalike_domain, fee_to_release | India Post: Your parcel could not be delivered as the address was incomplete. Please confirm your address and a redelivery charge of Rs.25 at indiapost-redeliv… |
| 13 | scam (phishing_link) | 78 | scam | ok | classifier 100 (w 0.45), rules 60 (w 0.55); flags: lookalike_domain | DTDC: Aapka parcel hamare warehouse mein hai. Delivery schedule karne ke liye apna address yahan confirm karein: dtdc-track-delivery.in |
| 14 | scam (fake_customer_care) | 69 | suspicious | ok | classifier 100 (w 0.42), rules 40 (w 0.50), pattern_similarity 84 (w 0.08); flags: helpline_personal_mobile | Customs Department, IGI Airport: A gift parcel addressed to you is awaiting clearance. For the duty amount and release process, contact the clearance officer o… |
| 15 | scam (sent_by_mistake) | 88 | scam | ok | classifier 99 (w 0.45), rules 78 (w 0.55); flags: sent_by_mistake, return_money | Hello, maine galti se aapke number par Rs.2,000 bhej diye. Aap please wapas kar dijiye 9999938807@paytm par. Thank you. |
| 16 | scam (phishing_link) | 58 | suspicious | ok | classifier 98 (w 0.42), rules 20 (w 0.50), pattern_similarity 81 (w 0.08); flags: short_url | प्रिय ग्राहक, आपके गैस सब्सिडी रिफंड ₹1,240 की प्रक्रिया लंबित है। राशि प्राप्त करने के लिए अपना बैंक विवरण यहां सत्यापित करें: bit.ly/subsidy-refund |
| 17 | scam (task_job) | 75 | scam | ok | classifier 100 (w 0.42), rules 50 (w 0.50), pattern_similarity 100 (w 0.08); flags: earn_per_task | Hello, I'm Riya from Talent Acquisition at Meridian Digital. We have a flexible remote role rating hotel listings, paying Rs.2,000 to Rs.5,000 per day. If inte… |
| 18 | scam (task_job) | 91 | scam | ok | rules 85 (w 0.50), classifier 98 (w 0.42), pattern_similarity 98 (w 0.08); flags: earn_per_task, part_time_high_pay, messaging_link_job | Namaste, hum ek digital marketing company ke liye part-time associates hire kar rahe hain. Sirf YouTube videos like karke roz Rs.1,500 tak kama sakte hain. Det… |
| 19 | scam (fake_customer_care) | 65 | suspicious | ok | classifier 93 (w 0.42), rules 40 (w 0.50), pattern_similarity 72 (w 0.08); flags: helpline_personal_mobile | PhonePe Support: We received your complaint about a failed transaction. To process the reversal, please speak to our resolution desk at 99999 85126. |
| 20 | scam (fake_customer_care) | 69 | suspicious | ok | classifier 99 (w 0.42), rules 40 (w 0.50), pattern_similarity 87 (w 0.08); flags: helpline_personal_mobile | Thank you for contacting Flipkart. Your return request has been escalated. A senior support executive will assist you on +91 99999 30947; please keep your orde… |
| 21 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Dear SBI UPI User, your A/c X5123 is credited by Rs.12,000.00 on 17Oct26 by transfer from RAHUL S (Ref No 629011223344). -SBI |
| 22 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | आपके खाते XX7710 से ₹3,500.00 UPI द्वारा 15-10-26 को डेबिट किए गए। यदि यह लेनदेन आपने नहीं किया है तो 1800 1234 पर कॉल करें। - एसबीआई |
| 23 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Dear Customer, as per RBI guidelines, your account is due for periodic KYC updation. Please visit your nearest HDFC Bank branch with a valid ID proof, or updat… |
| 24 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Dear customer, aapke ICICI account ka re-KYC due hai. Kripya iMobile Pay app ya nazdeeki branch mein update karein. ICICI Bank kabhi bhi OTP ya password nahi m… |
| 25 | genuine | 20 | safe | ok | rules 20 (w 1.00); flags: account_blocked | Paytm Payments Bank: Your wallet KYC has expired under RBI's periodic review. Complete it in the Paytm app under Profile > KYC. We never share links for KYC ov… |
| 26 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | SBI: Aapka YONO login ek naye device par hua hai. Agar yeh aapne nahi kiya, toh 1800 1234 par call karein ya YONO app mein 'Block Access' chunein. |
| 27 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | प्रिय ग्राहक, आपके अनुरोध पर आपका डेबिट कार्ड ब्लॉक कर दिया गया है। नए कार्ड के लिए नजदीकी शाखा से संपर्क करें। - बैंक ऑफ बड़ौदा |
| 28 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | MSEDCL: Priya grahak, aapka bijli bill Rs.980 due date 30-10-2026 tak bhar dein. Online payment ke liye wss.mahadiscom.in par jaayein. |
| 29 | genuine | 46 | suspicious | **FALSE ALARM** | classifier 90 (w 0.42), pattern_similarity 100 (w 0.08), rules 0 (w 0.50); flags: none | प्रिय उपभोक्ता, आपके बिजली बिल ₹1,420 का भुगतान नियत तिथि 20-10-2026 तक नहीं हुआ है। विच्छेदन से बचने के लिए कृपया भुगतान करें: uppcl.org - UPPCL |
| 30 | genuine | 14 | safe | ok | pattern_similarity 100 (w 0.14), rules 0 (w 0.86); flags: none | A challan (No. DL116XXXX2611) of Rs.500 has been issued for vehicle DL3CXX1234 for over-speeding. Pay at echallan.parivahan.gov.in or at the nearest traffic po… |
| 31 | genuine | 13 | safe | ok | pattern_similarity 91 (w 0.14), rules 0 (w 0.86); flags: none | Aapke vahan MH12XX4521 par Rs.1,000 ka challan pending hai. Bhugtan sirf echallan.parivahan.gov.in ya Mahatraffic app par karein. - Maharashtra Traffic Police |
| 32 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Amazon: Delivery of your package with boAt Airdopes was attempted today but no one was available. We will try again tomorrow. Track: amzn.in/d/8xKp2Qr |
| 33 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | India Post: Article EE123456789IN booked on 14-10-2026 is out for delivery. Track at indiapost.gov.in |
| 34 | genuine | 85 | scam | **FALSE ALARM** | rules 85 (w 1.00); flags: credential_request | Flipkart: Aapka order 'Prestige Kettle' kal deliver hoga. Delivery agent OTP maangega, sirf delivery ke time share karein. Track: fkrt.it/Xq7PvRuuuN |
| 35 | genuine | 13 | safe | ok | pattern_similarity 93 (w 0.14), rules 0 (w 0.86); flags: none | Income Tax Department: A refund of Rs.15,490 for AY 2026-27 has been processed to your bank account ending XX4471. Check the status at incometax.gov.in. |
| 36 | genuine | 11 | safe | ok | pattern_similarity 76 (w 0.14), rules 0 (w 0.86); flags: none | प्रिय ग्राहक, आपके रद्द किए गए ऑर्डर का ₹849 का रिफंड आपके खाते में भेज दिया गया है। - मिंत्रा |
| 37 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Namaste, aapka application Swiggy delivery partner ke liye approve ho gaya hai. Onboarding Swiggy Delivery Partner app mein complete karein. Koi joining fee na… |
| 38 | genuine | 10 | safe | ok | pattern_similarity 71 (w 0.14), rules 0 (w 0.86); flags: none | Thank you for contacting PhonePe Support. Your ticket CS-48213907 has been resolved. If you need more help, reply in the app under Help. PhonePe never asks for… |
| 39 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Airtel: Aapka Rs.349 ka plan 21-Oct ko khatam ho raha hai. Recharge ke liye: i.airtel.in/Recharge |
| 40 | genuine | 20 | safe | ok | rules 20 (w 1.00); flags: short_url | Tata 1mg: Your order #PO8XXXX21 has been shipped and will arrive by Tuesday. Track: bit.ly/1mgTrk82 |

### Per group (scam_type, or the dataset's own label)

| group | n | positives | flagged (TP) | recall | negatives | flagged (FP) | FPR | scam_type matches |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| account | 6 | 4 | 4 | 100.0% | 2 | 0 | 0.0% | 4/4 |
| bank_alert | 2 | 0 | 0 | – | 2 | 0 | 0.0% | – |
| brand_link | 2 | 0 | 0 | – | 2 | 0 | 0.0% | – |
| customer_care | 3 | 2 | 2 | 100.0% | 1 | 0 | 0.0% | 2/2 |
| e_challan | 5 | 3 | 3 | 100.0% | 2 | 0 | 0.0% | 3/3 |
| electricity | 4 | 2 | 2 | 100.0% | 2 | 1 | 50.0% | 1/2 |
| job | 3 | 2 | 2 | 100.0% | 1 | 0 | 0.0% | 2/2 |
| kyc | 5 | 2 | 2 | 100.0% | 3 | 0 | 0.0% | 2/2 |
| parcel_customs | 6 | 3 | 3 | 100.0% | 3 | 1 | 33.3% | 3/3 |
| refund | 4 | 2 | 2 | 100.0% | 2 | 0 | 0.0% | 2/2 |

### Per language (heuristic)

| language | n | positives | flagged (TP) | recall | negatives | flagged (FP) | FPR | scam_type matches |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| en | 19 | 10 | 10 | 100.0% | 9 | 0 | 0.0% | 10/10 |
| hi | 6 | 2 | 2 | 100.0% | 4 | 1 | 25.0% | 2/2 |
| hinglish | 15 | 8 | 8 | 100.0% | 7 | 1 | 14.3% | 7/8 |

### False positives (2, highest score first)

<details><summary>show all</summary>

- **85 scam** · group `parcel_customs` · lang hinglish · top: rules 85 (w 1.00) · flags: credential_request
  > Flipkart: Aapka order 'Prestige Kettle' kal deliver hoga. Delivery agent OTP maangega, sirf delivery ke time share karein. Track: fkrt.it/Xq7PvRuuuN
- **46 suspicious** · group `electricity` · lang hi · top: classifier 90 (w 0.42), pattern_similarity 100 (w 0.08), rules 0 (w 0.50) · flags: none
  > प्रिय उपभोक्ता, आपके बिजली बिल ₹1,420 का भुगतान नियत तिथि 20-10-2026 तक नहीं हुआ है। विच्छेदन से बचने के लिए कृपया भुगतान करें: uppcl.org - UPPCL

</details>

### False negatives (0, lowest first)

None.
