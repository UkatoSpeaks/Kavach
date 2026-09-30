# Evaluation: screenshots (OCR)

> **Synthetic images.** 30 built-in messages (tests/examples.py) drawn as phone screenshots by tests/screenshots.py: clean fonts, no photos of screens, no compression artefacts. Real screenshots are harder. Devanagari is drawn without complex shaping (no libraqm on Windows), so its numbers are pessimistic.

- date: 2026-09-30 · code: `0f13c0c + uncommitted changes in app/`
- messages: 30 (18 scams from personal numbers, 12 genuine under a business header or a contact name); 4 in Devanagari
- vision model: `qwen/qwen3.8-27b` · local: RapidOCR PP-OCRv6 (+ PP-OCRv5 Devanagari for `local`), long side 1024 px
- verdicts: pipeline.analyze offline (no network checks, no LLM)

## Summary

| engine | CER all | CER Latin | CER Devanagari | identifiers kept | verdict = text | screenshot verdict ok | errors | median ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| groq_vision | 0.002 | 0.002 | 0.005 | 30/30 (100%) | 30/30 (100%) | 30/30 (100%) | 0 | 819 |
| local | 0.050 | 0.003 | 0.353 | 30/30 (100%) | 28/30 (93%) | 28/30 (93%) | 0 | 2312 |
| local_latin | 0.094 | 0.003 | 0.681 | 29/30 (97%) | 27/30 (90%) | 27/30 (90%) | 0 | 833 |

## Every message

| # | expected | text verdict | groq_vision CER / verdict / screenshot | local CER / verdict / screenshot | local_latin CER / verdict / screenshot | message |
|---:|---|---|---|---|---|---|
| 1 | scam | scam | 0.000 / scam / scam | 0.005 / scam / scam | 0.005 / scam / scam | `+91 97001 40001` Congratulations! You have won ₹5,000 cashback from PhonePe. To receive the money, enter yo… |
| 2 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 96002 40002` Aapke account me ₹2,000 cashback aaya hai. Paise receive karne ke liye PhonePe request acc… |
| 3 | scam | scam | 0.000 / scam / scam | 0.407 / safe / safe | 0.713 / safe / safe | `+91 98003 40003` बधाई हो! आपको ₹10,000 का इनाम मिला है। पैसे प्राप्त करने के लिए अपना UPI पिन डालें। |
| 4 | scam | scam | 0.047 / scam / scam | 0.055 / scam / scam | 0.055 / scam / scam | `+91 97004 40004` Scan this QR to get your Paytm cashback: upi://pay?pa=ramesh.k9@ybl&pn=Paytm%20Cashback&am… |
| 5 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 96005 40005` Sir main army se hoon, aapki bike kharidni hai. Advance payment bhej raha hoon, yeh QR sca… |
| 6 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 98006 40006` Hello sir, maine galti se aapke Paytm pe ₹3,000 bhej diye. Please wapas kar do, mera UPI I… |
| 7 | scam | scam | 0.022 / scam / scam | 0.500 / safe / safe | 0.685 / safe / safe | `+91 97007 40007` मैंने गलती से आपके खाते में ₹2000 भेज दिए हैं, कृपया वापस कर दीजिए। |
| 8 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 96008 40008` Dear Customer, your SBI YONO account will be blocked today due to KYC expiry. Update your … |
| 9 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 98009 40009` Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM because your… |
| 10 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 97010 40010` India Post: Your parcel is held at our warehouse due to incomplete address. Pay ₹25 redeli… |
| 11 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 96011 40011` Priya grahak, aapka bijli connection aaj raat 9:30 baje kat jayega kyunki pichle mahine ka… |
| 12 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 98012 40012` Hi, I'm Priya from Amazon HR. We are hiring part-time. Earn ₹3,000-₹8,000 daily by liking … |
| 13 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 97013 40013` Task 1-3 completed. To unlock the VIP prepaid task, recharge ₹1,000 and get ₹1,300 back in… |
| 14 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 96014 40014` Ghar baithe kamaye ₹2000-₹5000 roz, sirf YouTube videos like karke. Part time job, Telegra… |
| 15 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 98015 40015` Thank you for contacting Paytm customer care. To process your refund of ₹2,499, please ins… |
| 16 | scam | scam | 0.000 / scam / scam | 0.128 / scam / scam | 0.677 / safe / safe ⚠ id | `+91 97016 40016` आपकी शिकायत दर्ज हो गई है। रिफंड के लिए हमारे कस्टमर केयर 9812345678 पर कॉल करें और AnyDes… |
| 17 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 96017 40017` HDFC customer care: your credit card reward points expire today. Install the HDFC Rewards … |
| 18 | scam | scam | 0.000 / scam / scam | 0.000 / scam / scam | 0.000 / scam / scam | `+91 98018 40018` Sir aapke account me refund aa raha hai, jo OTP aaya hai woh bata dijiye. |
| 19 | safe | safe | 0.000 / safe / safe | 0.000 / safe / safe | 0.000 / safe / safe | `AX-ICICIT` 482913 is the OTP for your transaction of INR 3,250.00 at FLIPKART on ICICI Bank Credit Ca… |
| 20 | safe | safe | 0.000 / safe / safe | 0.379 / safe / safe | 0.650 / safe / safe | `VM-SBIINB` आपका ओटीपी 123456 है। इसे किसी के साथ शेयर न करें। SBI कभी भी OTP नहीं मांगता। - SBI |
| 21 | safe | safe | 0.000 / safe / safe | 0.000 / safe / safe | 0.000 / safe / safe | `JD-SBIINB` OTP to confirm your transaction of Rs 1,200 is 774411. SBI never asks you to share OTP. |
| 22 | safe | safe | 0.000 / safe / safe | 0.005 / safe / safe | 0.005 / safe / safe | `VM-CNRBNK` Dear Customer, Rs.500.00 has been debited from A/c XX1234 to VPA swiggy.stores@icici on 12… |
| 23 | safe | safe | 0.000 / safe / safe | 0.000 / safe / safe | 0.000 / safe / safe | `VK-SWIGGY` Your Swiggy order #174839201756 from Meghana Foods is out for delivery. Suresh will reach … |
| 24 | safe | safe | 0.000 / safe / safe | 0.000 / safe / safe | 0.000 / safe / safe | `AX-AMAZON` Delivered: Your package with boAt Airdopes 141 was delivered. Track at amzn.in/d/3xYz9Ab. … |
| 25 | safe | safe | 0.000 / safe / safe | 0.006 / safe / safe | 0.006 / safe / safe | `VM-SBIINB` Dear Customer, your account statement for August 2026 is ready. Login at https://www.onlin… |
| 26 | safe | safe | 0.000 / safe / safe | 0.000 / safe / safe | 0.000 / safe / safe | `VM-SBIINB` Your KYC update is due. Please visit your nearest branch with valid documents. -SBI |
| 27 | safe | safe | 0.000 / safe / safe | 0.000 / safe / safe | 0.000 / safe / safe | `Priya` Oops, sent that photo by mistake, please ignore! |
| 28 | safe | safe | 0.000 / safe / safe | 0.000 / safe / safe | 0.000 / safe / safe | `Rohit` Maa, bijli ka bill bhar diya ₹1,200. Receipt WhatsApp pe bhej raha hoon. |
| 29 | safe | safe | 0.000 / safe / safe | 0.010 / safe / safe | 0.010 / safe / safe | `VM-NPCIOR` Remember: you never need to enter your UPI PIN to receive money. Stay safe! -NPCI |
| 30 | safe | safe | 0.000 / safe / safe | 0.000 / safe / safe | 0.000 / safe / safe | `JD-DLHVRY` Your parcel could not be delivered today as you were unavailable. We will try again tomorr… |

## Worst read per engine

**groq_vision** (#4, CER 0.047)

```text
+91 97004 40004
Scan this QR to get your Paytm cashback:
upi://pay?pa=ramesh.k9@ybl&pn=Paytm%20Cashback&am=4999&
10:42 AM
```

**local** (#7, CER 0.500)

```text
+91 97007 40007
मैने से में र2000 1hh hle
कर
10:42 AM
```

**local_latin** (#3, CER 0.713)

```text
+91 98003 40003
可可10,000可取
10:42 AM
```

