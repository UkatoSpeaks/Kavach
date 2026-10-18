# Evaluation: polished_mocknet_noclf

> **Synthetic, hand-written (Claude), never used for training.** 40 polished scams (perfect spelling, real bank/brand names, calm tone: the only giveaway is the link, a personal phone number or the request itself) and 40 genuine messages written the same clean way, across the v1 types, in English, Hinglish and Hindi. Scam domains are invented and were unregistered (RDAP 404) when written. Groups are categories (kyc, account, electricity, ...): each shows scam recall and genuine FPR side by side. A stress test of what the detector relies on, not a prevalence estimate: 50% scams.

- date: 2026-10-19 · code: `a914451`
- messages: 80 (40 positives = label scam; 40 negatives)
- network checks (url_intel, reputation): MOCKED (polished_eval_network.json: url_intel on a fake internet, no reputation reports, no Safe Browsing)
- classifier: OFF (CLASSIFIER_ENABLED=false)
- weights: `{'rules': 0.3, 'classifier': 0.25, 'url_intel': 0.15, 'upi_check': 0.15, 'reputation': 0.1, 'pattern_similarity': 0.05, 'llm': 0.15, 'sender_check': 0.15, 'fake_payment_proof': 0.15}` · thresholds: suspicious ≥ 35, scam ≥ 70
- flagged = verdict suspicious or scam. "scam-only" counts only verdict scam.

## Summary

| mode | n | precision | recall | F1 | FPR | scam-only P / R | p50 ms | p95 ms | errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| checks | 80 | 81.1% | 75.0% | 77.9% | 17.5% | 95.0% / 47.5% | 29 | 37 | 0 |

## Mode: checks

### Confusion matrix

| | flagged | not flagged |
|---|---:|---:|
| **positive** | TP 30 | FN 10 |
| **negative** | FP 7 | TN 33 |

### False-positive rate per not-scam label

| not-scam label | labelled by | n | flagged | FPR | of which verdict scam |
|---|---|---:|---:|---:|---:|
| genuine | synthetic | 40 | 7 | 17.5% | 1 |

### Every message

| # | expected | score | verdict | outcome | top signals | message |
|---:|---|---:|---|---|---|---|
| 1 | scam (phishing_link) | 75 | scam | ok | url_intel 92 (w 0.33), rules 20 (w 0.67); flags: short_url, url_shortener_redirect, url_lookalike, url_new_domain | Dear Customer, as per RBI guidelines your HDFC Bank KYC is due for periodic update. Please complete re-KYC online to continue uninterrupted banking: bit.ly/3Kq… |
| 2 | scam (phishing_link) | 77 | scam | ok | rules 70 (w 0.67), url_intel 92 (w 0.33); flags: short_url, account_blocked, url_shortener_redirect, url_lookalike, url_new_domain | Your HDFC Bank KYC expires today. Update now to avoid account suspension: bit.ly/4mT2wQx |
| 3 | scam (phishing_link) | 75 | scam | ok | rules 60 (w 0.67), url_intel 88 (w 0.33); flags: lookalike_domain, url_new_domain | State Bank of India: Your PAN details are not linked to your YONO profile. Kindly update them at yono-sbi-profile.in to keep using mobile banking. |
| 4 | scam (phishing_link) | 37 | suspicious | ok | url_intel 72 (w 0.33), rules 20 (w 0.67); flags: short_url, url_shortener_redirect, url_new_domain | Dear customer, aapke ICICI Bank account ka KYC renewal baaki hai. Kripya apni details yahan update karein taaki services chalti rahein: tinyurl.com/icici-rekyc |
| 5 | scam (phishing_link) | 75 | scam | ok | rules 60 (w 0.60), url_intel 88 (w 0.30), pattern_similarity 61 (w 0.10); flags: lookalike_domain, url_new_domain | Kotak Bank: Aapka Video KYC adhoora hai. Account active rakhne ke liye ise yahan poora karein: kotak-vkyc.co.in |
| 6 | scam (phishing_link) | 77 | scam | ok | rules 70 (w 0.67), url_intel 92 (w 0.33); flags: short_url, account_blocked, url_shortener_redirect, url_lookalike, url_new_domain | प्रिय ग्राहक, आपके पंजाब नेशनल बैंक खाते का केवाईसी अपडेट होना है। सेवाएं जारी रखने के लिए यहां विवरण दर्ज करें: cutt.ly/pnbKyc7 |
| 7 | scam (phishing_link) | 75 | scam | ok | rules 60 (w 0.67), url_intel 88 (w 0.33); flags: lookalike_domain, url_new_domain | Axis Bank: We noticed a login to your net banking from a new device. If this wasn't you, please review your account activity here: https://axis-secure-review.c… |
| 8 | scam (phishing_link) | 11 | safe | **MISSED** | pattern_similarity 78 (w 0.14), rules 0 (w 0.86); flags: none | Your Paytm Payments wallet has been temporarily restricted due to incomplete verification. You can restore access here: rb.gy/k3v9qa |
| 9 | scam (phishing_link) | 10 | safe | **MISSED** | url_intel 30 (w 0.33), rules 0 (w 0.67); flags: url_young_domain | Bank of Baroda: Your debit card has been put on hold following a routine security review. You can reactivate it securely at bob-card-services.in |
| 10 | scam (phishing_link) | 77 | scam | ok | rules 70 (w 0.67), url_intel 92 (w 0.33); flags: short_url, account_blocked, url_shortener_redirect, url_lookalike, url_new_domain | SBI Alert: Aapka YONO account suraksha kaarano se band kar diya gaya hai. Dobara chalu karne ke liye login karein: bit.ly/3yonoSB |
| 11 | scam (phishing_link) | 75 | scam | ok | rules 60 (w 0.67), url_intel 88 (w 0.33); flags: lookalike_domain, url_new_domain | HDFC Bank: Aapke account par kuch transactions verify hone baaki hain. Account limit hatane ke liye apni details confirm karein: https://hdfc-netbanking-verify… |
| 12 | scam (phishing_link) | 37 | suspicious | ok | url_intel 72 (w 0.33), rules 20 (w 0.67); flags: short_url, url_shortener_redirect, url_new_domain | प्रिय ग्राहक, सुरक्षा समीक्षा के कारण आपकी नेट बैंकिंग सेवा अस्थायी रूप से रोक दी गई है। सेवा फिर से शुरू करने के लिए यहां लॉग इन करें: tinyurl.com/netbank-seva |
| 13 | scam (phishing_link) | 75 | scam | ok | rules 60 (w 0.60), url_intel 88 (w 0.30), pattern_similarity 100 (w 0.10); flags: lookalike_domain, url_new_domain | Dear consumer, our records show your electricity bill for September is unpaid. To avoid interruption of supply, please clear it on the BSES payment page: bses-… |
| 14 | scam (fake_customer_care) | 40 | suspicious | ok | rules 40 (w 1.00); flags: helpline_personal_mobile | Tata Power-DDL: Your meter details need to be updated for the new billing cycle. Please call our billing officer at 99999 41823 to avoid any service interrupti… |
| 15 | scam (phishing_link) | 37 | suspicious | ok | url_intel 72 (w 0.33), rules 20 (w 0.67); flags: short_url, url_shortener_redirect, url_new_domain | Priya upbhokta, aapka pichhle mahine ka bijli bill system mein update nahi hua hai. Connection chalu rakhne ke liye kripya bill yahan jama karein: cutt.ly/mseb… |
| 16 | scam (fake_customer_care) | 84 | scam | ok | rules 81 (w 0.86), pattern_similarity 100 (w 0.14); flags: electricity_disconnection, helpline_personal_mobile, urgency | Electricity Dept: Aapka connection aaj raat 9:30 baje disconnect ho sakta hai kyunki pichhla bill system mein update nahi hua. Jankari ke liye officer se baat … |
| 17 | scam (phishing_link) | 37 | suspicious | ok | url_intel 72 (w 0.33), rules 20 (w 0.67); flags: short_url, url_shortener_redirect, url_new_domain | प्रिय उपभोक्ता, आपके बिजली खाते में मोबाइल नंबर अपडेट नहीं है। बिल भुगतान जारी रखने के लिए विवरण यहां अपडेट करें: bit.ly/bijli-kyc |
| 18 | scam (phishing_link) | 75 | scam | ok | rules 60 (w 0.60), url_intel 88 (w 0.30), pattern_similarity 100 (w 0.10); flags: lookalike_domain, url_new_domain | Traffic Police: A challan of Rs.500 has been issued against your vehicle for a signal violation. View the evidence and pay online at https://echallan-parivahan… |
| 19 | scam (phishing_link) | 75 | scam | ok | url_intel 92 (w 0.30), rules 20 (w 0.60), pattern_similarity 100 (w 0.10); flags: short_url, url_shortener_redirect, url_lookalike, url_new_domain | Your vehicle DL3CXX1234 has an unpaid e-challan of Rs.1,000. Please settle it to avoid it being forwarded to the virtual court: tinyurl.com/vcourt-challan |
| 20 | scam (phishing_link) | 0 | safe | **MISSED** | rules 0 (w 1.00); flags: none | Aapki gaadi par Rs.500 ka e-challan pending hai. Details dekhne aur online bharne ke liye: rb.gy/echln5 |
| 21 | scam (phishing_link) | 75 | scam | ok | rules 60 (w 0.67), url_intel 88 (w 0.33); flags: lookalike_domain, url_new_domain | Parivahan Seva: Aapke vahan ka challan court mein bhejne se pehle online samadhan ka avsar hai. Yahan check karein: parivahan-samadhan.co.in |
| 22 | scam (phishing_link) | 75 | scam | ok | url_intel 92 (w 0.30), rules 20 (w 0.60), pattern_similarity 100 (w 0.10); flags: short_url, url_shortener_redirect, url_lookalike, url_new_domain | परिवहन विभाग: आपके वाहन पर ₹1,000 का ई-चालान दर्ज है। विवरण देखने और भुगतान के लिए यहां जाएं: cutt.ly/echallan-up |
| 23 | scam (phishing_link) | 84 | scam | ok | rules 80 (w 0.60), url_intel 88 (w 0.30), pattern_similarity 94 (w 0.10); flags: lookalike_domain, fee_to_release, url_new_domain | India Post: Your parcel could not be delivered as the address was incomplete. Please confirm your address and a redelivery charge of Rs.25 at indiapost-redeliv… |
| 24 | scam (phishing_link) | 75 | scam | ok | url_intel 92 (w 0.30), rules 20 (w 0.60), pattern_similarity 95 (w 0.10); flags: short_url, url_shortener_redirect, url_lookalike, url_new_domain | Blue Dart: Your international shipment is with customs. A clearance duty of Rs.1,850 applies before dispatch. You can complete the payment here: bit.ly/bd-cust… |
| 25 | scam (phishing_link) | 10 | safe | **MISSED** | url_intel 30 (w 0.33), rules 0 (w 0.67); flags: url_young_domain | DTDC: Aapka parcel hamare warehouse mein hai. Delivery schedule karne ke liye apna address yahan confirm karein: dtdc-track-delivery.in |
| 26 | scam (fake_customer_care) | 46 | suspicious | ok | rules 40 (w 0.86), pattern_similarity 84 (w 0.14); flags: helpline_personal_mobile | Customs Department, IGI Airport: A gift parcel addressed to you is awaiting clearance. For the duty amount and release process, contact the clearance officer o… |
| 27 | scam (phishing_link) | 37 | suspicious | ok | url_intel 72 (w 0.33), rules 20 (w 0.67); flags: short_url, url_shortener_redirect, url_new_domain | प्रिय ग्राहक, आपका पार्सल पता अधूरा होने के कारण रोका गया है। डिलीवरी के लिए अपना पता यहां अपडेट करें: tinyurl.com/parcel-pata |
| 28 | scam (phishing_link) | 27 | safe | **MISSED** | url_intel 60 (w 0.30), pattern_similarity 93 (w 0.10), rules 0 (w 0.60); flags: url_new_domain | Income Tax Department: You are eligible for a refund of Rs.15,490 for AY 2026-27. Please verify your bank account details to receive it: https://incometax-refu… |
| 29 | scam (sent_by_mistake) | 81 | scam | ok | rules 78 (w 0.86), pattern_similarity 97 (w 0.14); flags: sent_by_mistake, return_money | Hi, I accidentally transferred Rs.3,000 to your number while paying a friend. Could you please send it back to 9999951274@ybl? Sorry for the trouble. |
| 30 | scam (sent_by_mistake) | 78 | scam | ok | rules 78 (w 1.00); flags: sent_by_mistake, return_money | Hello, maine galti se aapke number par Rs.2,000 bhej diye. Aap please wapas kar dijiye 9999938807@paytm par. Thank you. |
| 31 | scam (fake_customer_care) | 45 | suspicious | ok | rules 40 (w 0.86), pattern_similarity 78 (w 0.14); flags: helpline_personal_mobile | Amazon: The refund of Rs.1,299 for your cancelled order could not be processed. Our refunds team will assist you at 99999 70452 between 9 AM and 6 PM. |
| 32 | scam (phishing_link) | 29 | safe | **MISSED** | rules 20 (w 0.86), pattern_similarity 81 (w 0.14); flags: short_url | प्रिय ग्राहक, आपके गैस सब्सिडी रिफंड ₹1,240 की प्रक्रिया लंबित है। राशि प्राप्त करने के लिए अपना बैंक विवरण यहां सत्यापित करें: bit.ly/subsidy-refund |
| 33 | scam (task_job) | 14 | safe | **MISSED** | pattern_similarity 100 (w 0.14), rules 0 (w 0.86); flags: none | Hello, I'm Riya from Talent Acquisition at Meridian Digital. We have a flexible remote role rating hotel listings, paying Rs.2,000 to Rs.5,000 per day. If inte… |
| 34 | scam (task_job) | 74 | scam | ok | rules 70 (w 0.86), pattern_similarity 98 (w 0.14); flags: part_time_high_pay, messaging_link_job | Namaste, hum ek digital marketing company ke liye part-time associates hire kar rahe hain. Sirf YouTube videos like karke roz Rs.1,500 tak kama sakte hain. Det… |
| 35 | scam (task_job) | 19 | safe | **MISSED** | pattern_similarity 100 (w 0.10), url_intel 30 (w 0.30), rules 0 (w 0.60); flags: url_young_domain | Thank you for completing the trial task. Your commission of Rs.150 has been added. To continue to the next set of tasks, please complete the registration on ou… |
| 36 | scam (task_job) | 14 | safe | **MISSED** | pattern_similarity 96 (w 0.14), rules 0 (w 0.86); flags: none | नमस्ते, हमारी कंपनी घर से काम करने के लिए लोगों को नियुक्त कर रही है। ऑनलाइन प्रोडक्ट रिव्यू देकर आप रोज़ ₹2,000 तक कमा सकते हैं। जुड़ने के लिए टेलीग्राम पर सं… |
| 37 | scam (fake_customer_care) | 45 | suspicious | ok | rules 40 (w 0.86), pattern_similarity 72 (w 0.14); flags: helpline_personal_mobile | PhonePe Support: We received your complaint about a failed transaction. To process the reversal, please speak to our resolution desk at 99999 85126. |
| 38 | scam (fake_customer_care) | 47 | suspicious | ok | rules 40 (w 0.86), pattern_similarity 87 (w 0.14); flags: helpline_personal_mobile | Thank you for contacting Flipkart. Your return request has been escalated. A senior support executive will assist you on +91 99999 30947; please keep your orde… |
| 39 | scam (fake_customer_care) | 0 | safe | **MISSED** | rules 0 (w 1.00); flags: none | SBI Card: Aapke card par annual charge waiver ke liye request mili hai. Process complete karne ke liye hamare relationship manager se baat karein: 99999 46381 |
| 40 | scam (fake_customer_care) | 44 | suspicious | ok | rules 40 (w 0.86), pattern_similarity 70 (w 0.14); flags: helpline_personal_mobile | Google Pay सहायता: आपके असफल लेनदेन की शिकायत दर्ज हो गई है। रिफंड प्रक्रिया के लिए हमारे सहायता अधिकारी से 99999 72815 पर संपर्क करें। |
| 41 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | HDFC Bank: Rs.2,450.00 debited from a/c **4821 on 18-10-26 to VPA swiggy@icici (UPI Ref 629184736512). Not you? Call 1800 202 6161. |
| 42 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Dear SBI UPI User, your A/c X5123 is credited by Rs.12,000.00 on 17Oct26 by transfer from RAHUL S (Ref No 629011223344). -SBI |
| 43 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | ICICI Bank Acct XX902 debited for Rs 1,180.00 on 16-Oct-26; Airtel credited. UPI Ref 629355120876. If not done by you, call 1800 1080. |
| 44 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | आपके खाते XX7710 से ₹3,500.00 UPI द्वारा 15-10-26 को डेबिट किए गए। यदि यह लेनदेन आपने नहीं किया है तो 1800 1234 पर कॉल करें। - एसबीआई |
| 45 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Dear Customer, as per RBI guidelines, your account is due for periodic KYC updation. Please visit your nearest HDFC Bank branch with a valid ID proof, or updat… |
| 46 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | SBI: Your KYC is due for periodic update. You can complete re-KYC through YONO SBI or at your home branch. Please ignore if already submitted. |
| 47 | genuine | 45 | suspicious | **FALSE ALARM** | rules 45 (w 1.00); flags: account_blocked | Kotak: Your KYC update is pending. Complete it in the Kotak811 app under Profile > KYC, or visit any branch. Kotak never calls to ask for KYC details. |
| 48 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Dear customer, aapke ICICI account ka re-KYC due hai. Kripya iMobile Pay app ya nazdeeki branch mein update karein. ICICI Bank kabhi bhi OTP ya password nahi m… |
| 49 | genuine | 45 | suspicious | **FALSE ALARM** | rules 45 (w 1.00); flags: account_blocked | प्रिय ग्राहक, आरबीआई के निर्देशानुसार आपके खाते का केवाईसी अपडेट किया जाना है। कृपया अपनी नजदीकी शाखा में पहचान पत्र के साथ जाएं। बैंक कभी भी ओटीपी नहीं मांगता… |
| 50 | genuine | 45 | suspicious | **FALSE ALARM** | rules 45 (w 1.00); flags: account_blocked | Paytm Payments Bank: Your wallet KYC has expired under RBI's periodic review. Complete it in the Paytm app under Profile > KYC. We never share links for KYC ov… |
| 51 | genuine | 45 | suspicious | **FALSE ALARM** | rules 45 (w 1.00); flags: account_blocked | Axis Bank: As requested, your debit card ending 4410 has been blocked. A new card will be dispatched to your registered address within 7 working days. For quer… |
| 52 | genuine | 0 | safe | ok | rules 0 (w 0.67), url_intel 0 (w 0.33); flags: none | HDFC Bank: For your security, NetBanking access was locked after 3 incorrect password attempts. You can reset your password at hdfcbank.com or in the HDFC Bank… |
| 53 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | SBI: Aapka YONO login ek naye device par hua hai. Agar yeh aapne nahi kiya, toh 1800 1234 par call karein ya YONO app mein 'Block Access' chunein. |
| 54 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | प्रिय ग्राहक, आपके अनुरोध पर आपका डेबिट कार्ड ब्लॉक कर दिया गया है। नए कार्ड के लिए नजदीकी शाखा से संपर्क करें। - बैंक ऑफ बड़ौदा |
| 55 | genuine | 10 | safe | ok | pattern_similarity 70 (w 0.14), rules 0 (w 0.86); flags: none | BSES Rajdhani: Your electricity bill of Rs.1,846 for CA No. 15XXXX902 is due on 25-10-2026. Pay at bsesdelhi.com or in the BSES BRPL app. Ignore if already pai… |
| 56 | genuine | 10 | safe | ok | pattern_similarity 69 (w 0.14), rules 0 (w 0.86); flags: none | Tata Power-DDL: Your bill of Rs.2,310 has been generated. Due date 28-Oct-26. Pay via tatapower-ddl.com, UPI or any bank app. Thank you. |
| 57 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | MSEDCL: Priya grahak, aapka bijli bill Rs.980 due date 30-10-2026 tak bhar dein. Online payment ke liye wss.mahadiscom.in par jaayein. |
| 58 | genuine | 14 | safe | ok | pattern_similarity 100 (w 0.14), rules 0 (w 0.86); flags: none | प्रिय उपभोक्ता, आपके बिजली बिल ₹1,420 का भुगतान नियत तिथि 20-10-2026 तक नहीं हुआ है। विच्छेदन से बचने के लिए कृपया भुगतान करें: uppcl.org - UPPCL |
| 59 | genuine | 10 | safe | ok | pattern_similarity 100 (w 0.10), rules 0 (w 0.60), url_intel 0 (w 0.30); flags: none | A challan (No. DL116XXXX2611) of Rs.500 has been issued for vehicle DL3CXX1234 for over-speeding. Pay at echallan.parivahan.gov.in or at the nearest traffic po… |
| 60 | genuine | 9 | safe | ok | pattern_similarity 91 (w 0.10), rules 0 (w 0.60), url_intel 0 (w 0.30); flags: none | Aapke vahan MH12XX4521 par Rs.1,000 ka challan pending hai. Bhugtan sirf echallan.parivahan.gov.in ya Mahatraffic app par karein. - Maharashtra Traffic Police |
| 61 | genuine | 10 | safe | ok | pattern_similarity 100 (w 0.10), rules 0 (w 0.60), url_intel 0 (w 0.30); flags: none | प्रिय वाहन स्वामी, आपके वाहन UP32XX7781 पर ₹500 का ई-चालान लंबित है। भुगतान केवल echallan.parivahan.gov.in पर करें। - यूपी ट्रैफिक पुलिस |
| 62 | genuine | 0 | safe | ok | rules 0 (w 0.67), url_intel 0 (w 0.33); flags: none | Amazon: Delivery of your package with boAt Airdopes was attempted today but no one was available. We will try again tomorrow. Track: amzn.in/d/8xKp2Qr |
| 63 | genuine | 0 | safe | ok | rules 0 (w 0.67), url_intel 0 (w 0.33); flags: none | India Post: Article EE123456789IN booked on 14-10-2026 is out for delivery. Track at indiapost.gov.in |
| 64 | genuine | 52 | suspicious | **FALSE ALARM** | rules 50 (w 0.86), pattern_similarity 66 (w 0.14); flags: fee_to_release | DHL Express: Your shipment 4821XXXX03 from the UK is held at customs. Import duty of Rs.2,140 is payable. Pay securely at del.dhl.com or in the MyDHL+ app. The… |
| 65 | genuine | 85 | scam | **FALSE ALARM** | rules 85 (w 1.00); flags: credential_request | Flipkart: Aapka order 'Prestige Kettle' kal deliver hoga. Delivery agent OTP maangega, sirf delivery ke time share karein. Track: fkrt.it/Xq7PvRuuuN |
| 66 | genuine | 0 | safe | ok | rules 0 (w 0.67), url_intel 0 (w 0.33); flags: none | ब्लू डार्ट: आपका शिपमेंट 7XXXXX1290 आज डिलीवर होगा। ट्रैक करें: bluedart.com |
| 67 | genuine | 9 | safe | ok | pattern_similarity 87 (w 0.10), rules 0 (w 0.60), url_intel 0 (w 0.30); flags: none | Amazon: Refund of Rs.1,299.00 for your returned item has been initiated to your original payment method. It should reflect in 3-5 business days. Details: amzn.… |
| 68 | genuine | 9 | safe | ok | pattern_similarity 93 (w 0.10), rules 0 (w 0.60), url_intel 0 (w 0.30); flags: none | Income Tax Department: A refund of Rs.15,490 for AY 2026-27 has been processed to your bank account ending XX4471. Check the status at incometax.gov.in. |
| 69 | genuine | 11 | safe | ok | pattern_similarity 78 (w 0.14), rules 0 (w 0.86); flags: none | IRCTC: Aapke cancelled ticket PNR 42XXXXX871 ka refund Rs.1,145 aapke original payment mode mein 5-7 din mein aa jayega. |
| 70 | genuine | 11 | safe | ok | pattern_similarity 76 (w 0.14), rules 0 (w 0.86); flags: none | प्रिय ग्राहक, आपके रद्द किए गए ऑर्डर का ₹849 का रिफंड आपके खाते में भेज दिया गया है। - मिंत्रा |
| 71 | genuine | 14 | safe | ok | pattern_similarity 99 (w 0.14), rules 0 (w 0.86); flags: none | Naukri: A recruiter from Infosys viewed your profile and invited you to apply for 'Data Analyst'. View the job at naukri.com/mnjuser/inbox |
| 72 | genuine | 14 | safe | ok | pattern_similarity 100 (w 0.14), rules 0 (w 0.86); flags: none | Hi, this is Ankita from the HR team at Persistent Systems. Your interview for the Java Developer role is scheduled on 22 Oct at 11:00 AM on Microsoft Teams. Th… |
| 73 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Namaste, aapka application Swiggy delivery partner ke liye approve ho gaya hai. Onboarding Swiggy Delivery Partner app mein complete karein. Koi joining fee na… |
| 74 | genuine | 14 | safe | ok | pattern_similarity 100 (w 0.14), rules 0 (w 0.86); flags: none | Swiggy: We're sorry about your order. A refund of Rs.320 has been initiated. For further help, chat with us in the app under Help > Order issues. |
| 75 | genuine | 10 | safe | ok | pattern_similarity 71 (w 0.14), rules 0 (w 0.86); flags: none | Thank you for contacting PhonePe Support. Your ticket CS-48213907 has been resolved. If you need more help, reply in the app under Help. PhonePe never asks for… |
| 76 | genuine | 12 | safe | ok | pattern_similarity 85 (w 0.14), rules 0 (w 0.86); flags: none | प्रिय ग्राहक, आपकी शिकायत संख्या 7XXXXX12 दर्ज कर ली गई है। हमारी टीम 48 घंटे में समाधान करेगी। सहायता के लिए 1800 1234 पर कॉल करें। - एसबीआई |
| 77 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Your Zomato order from Burger Singh is out for delivery. Track it live: zoma.to/r/8Kp3x |
| 78 | genuine | 63 | suspicious | **FALSE ALARM** | rules 60 (w 0.67), url_intel 70 (w 0.33); flags: lookalike_domain | HDFC Bank: Your credit card statement for October is ready. Total due Rs.8,214, minimum due Rs.420, due by 05-Nov. View: hdfcbk.io/HDFCBK/s/aQ9x2 |
| 79 | genuine | 0 | safe | ok | rules 0 (w 1.00); flags: none | Airtel: Aapka Rs.349 ka plan 21-Oct ko khatam ho raha hai. Recharge ke liye: i.airtel.in/Recharge |
| 80 | genuine | 17 | safe | ok | rules 20 (w 0.67), url_intel 10 (w 0.33); flags: short_url, url_shortener_redirect | Tata 1mg: Your order #PO8XXXX21 has been shipped and will arrive by Tuesday. Track: bit.ly/1mgTrk82 |

### Per group (scam_type, or the dataset's own label)

| group | n | positives | flagged (TP) | recall | negatives | flagged (FP) | FPR | scam_type matches |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| account | 10 | 6 | 4 | 66.7% | 4 | 1 | 25.0% | 4/4 |
| bank_alert | 4 | 0 | 0 | – | 4 | 0 | 0.0% | – |
| brand_link | 4 | 0 | 0 | – | 4 | 1 | 25.0% | – |
| customer_care | 7 | 4 | 3 | 75.0% | 3 | 0 | 0.0% | 3/3 |
| e_challan | 8 | 5 | 4 | 80.0% | 3 | 0 | 0.0% | 4/4 |
| electricity | 9 | 5 | 5 | 100.0% | 4 | 0 | 0.0% | 4/5 |
| job | 7 | 4 | 1 | 25.0% | 3 | 0 | 0.0% | 1/1 |
| kyc | 12 | 6 | 6 | 100.0% | 6 | 3 | 50.0% | 6/6 |
| parcel_customs | 10 | 5 | 4 | 80.0% | 5 | 2 | 40.0% | 4/4 |
| refund | 9 | 5 | 3 | 60.0% | 4 | 0 | 0.0% | 3/3 |

### Per language (heuristic)

| language | n | positives | flagged (TP) | recall | negatives | flagged (FP) | FPR | scam_type matches |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| en | 44 | 20 | 15 | 75.0% | 24 | 5 | 20.8% | 15/15 |
| hi | 16 | 8 | 6 | 75.0% | 8 | 1 | 12.5% | 6/6 |
| hinglish | 20 | 12 | 9 | 75.0% | 8 | 1 | 12.5% | 8/9 |

### False positives (7, highest score first)

<details><summary>show all</summary>

- **85 scam** · group `parcel_customs` · lang hinglish · top: rules 85 (w 1.00) · flags: credential_request
  > Flipkart: Aapka order 'Prestige Kettle' kal deliver hoga. Delivery agent OTP maangega, sirf delivery ke time share karein. Track: fkrt.it/Xq7PvRuuuN
- **63 suspicious** · group `brand_link` · lang en · top: rules 60 (w 0.67), url_intel 70 (w 0.33) · flags: lookalike_domain
  > HDFC Bank: Your credit card statement for October is ready. Total due Rs.8,214, minimum due Rs.420, due by 05-Nov. View: hdfcbk.io/HDFCBK/s/aQ9x2
- **52 suspicious** · group `parcel_customs` · lang en · top: rules 50 (w 0.86), pattern_similarity 66 (w 0.14) · flags: fee_to_release
  > DHL Express: Your shipment 4821XXXX03 from the UK is held at customs. Import duty of Rs.2,140 is payable. Pay securely at del.dhl.com or in the MyDHL+ app. The shipment will be delivered after payment.
- **45 suspicious** · group `kyc` · lang en · top: rules 45 (w 1.00) · flags: account_blocked
  > Kotak: Your KYC update is pending. Complete it in the Kotak811 app under Profile > KYC, or visit any branch. Kotak never calls to ask for KYC details.
- **45 suspicious** · group `kyc` · lang hi · top: rules 45 (w 1.00) · flags: account_blocked
  > प्रिय ग्राहक, आरबीआई के निर्देशानुसार आपके खाते का केवाईसी अपडेट किया जाना है। कृपया अपनी नजदीकी शाखा में पहचान पत्र के साथ जाएं। बैंक कभी भी ओटीपी नहीं मांगता। - पंजाब नेशनल बैंक
- **45 suspicious** · group `kyc` · lang en · top: rules 45 (w 1.00) · flags: account_blocked
  > Paytm Payments Bank: Your wallet KYC has expired under RBI's periodic review. Complete it in the Paytm app under Profile > KYC. We never share links for KYC over SMS.
- **45 suspicious** · group `account` · lang en · top: rules 45 (w 1.00) · flags: account_blocked
  > Axis Bank: As requested, your debit card ending 4410 has been blocked. A new card will be dispatched to your registered address within 7 working days. For queries call 1860 419 5555.

</details>

### False negatives (10, lowest first)

<details><summary>show all</summary>

- **0 safe** · group `e_challan` · lang hinglish · top: rules 0 (w 1.00) · flags: none
  > Aapki gaadi par Rs.500 ka e-challan pending hai. Details dekhne aur online bharne ke liye: rb.gy/echln5
- **0 safe** · group `customer_care` · lang hinglish · top: rules 0 (w 1.00) · flags: none
  > SBI Card: Aapke card par annual charge waiver ke liye request mili hai. Process complete karne ke liye hamare relationship manager se baat karein: 99999 46381
- **10 safe** · group `account` · lang en · top: url_intel 30 (w 0.33), rules 0 (w 0.67) · flags: url_young_domain
  > Bank of Baroda: Your debit card has been put on hold following a routine security review. You can reactivate it securely at bob-card-services.in
- **10 safe** · group `parcel_customs` · lang hinglish · top: url_intel 30 (w 0.33), rules 0 (w 0.67) · flags: url_young_domain
  > DTDC: Aapka parcel hamare warehouse mein hai. Delivery schedule karne ke liye apna address yahan confirm karein: dtdc-track-delivery.in
- **11 safe** · group `account` · lang en · top: pattern_similarity 78 (w 0.14), rules 0 (w 0.86) · flags: none
  > Your Paytm Payments wallet has been temporarily restricted due to incomplete verification. You can restore access here: rb.gy/k3v9qa
- **14 safe** · group `job` · lang en · top: pattern_similarity 100 (w 0.14), rules 0 (w 0.86) · flags: none
  > Hello, I'm Riya from Talent Acquisition at Meridian Digital. We have a flexible remote role rating hotel listings, paying Rs.2,000 to Rs.5,000 per day. If interested, reply YES and our coordinator will message you on WhatsApp.
- **14 safe** · group `job` · lang hi · top: pattern_similarity 96 (w 0.14), rules 0 (w 0.86) · flags: none
  > नमस्ते, हमारी कंपनी घर से काम करने के लिए लोगों को नियुक्त कर रही है। ऑनलाइन प्रोडक्ट रिव्यू देकर आप रोज़ ₹2,000 तक कमा सकते हैं। जुड़ने के लिए टेलीग्राम पर संपर्क करें: t.me/reviewdesk_hr
- **19 safe** · group `job` · lang en · top: pattern_similarity 100 (w 0.10), url_intel 30 (w 0.30), rules 0 (w 0.60) · flags: url_young_domain
  > Thank you for completing the trial task. Your commission of Rs.150 has been added. To continue to the next set of tasks, please complete the registration on our merchant portal: merchant-taskdesk.com
- **27 safe** · group `refund` · lang en · top: url_intel 60 (w 0.30), pattern_similarity 93 (w 0.10), rules 0 (w 0.60) · flags: url_new_domain
  > Income Tax Department: You are eligible for a refund of Rs.15,490 for AY 2026-27. Please verify your bank account details to receive it: https://incometax-refund-status.in
- **29 safe** · group `refund` · lang hi · top: rules 20 (w 0.86), pattern_similarity 81 (w 0.14) · flags: short_url
  > प्रिय ग्राहक, आपके गैस सब्सिडी रिफंड ₹1,240 की प्रक्रिया लंबित है। राशि प्राप्त करने के लिए अपना बैंक विवरण यहां सत्यापित करें: bit.ly/subsidy-refund

</details>
