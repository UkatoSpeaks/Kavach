"""Labelled example messages shared by the scoring tests and the API tests.

Numbers, UPI IDs and domains are made up.
"""

from app.core.enums import ScamType

T = ScamType

# (expected scam type, message). Every one must score >= 70 with that scam_type.
SCAM_EXAMPLES: list[tuple[ScamType, str]] = [
    # --- receive-money UPI
    (T.UPI_RECEIVE_MONEY,
     "Congratulations! You have won ₹5,000 cashback from PhonePe. To receive the money, enter "
     "your UPI PIN on the payment request sent to your number. Offer valid for 24 hours only."),
    (T.UPI_RECEIVE_MONEY,
     "Aapke account me ₹2,000 cashback aaya hai. Paise receive karne ke liye PhonePe request "
     "accept karein aur apna UPI PIN dalein."),
    (T.UPI_RECEIVE_MONEY,
     "बधाई हो! आपको ₹10,000 का इनाम मिला है। पैसे प्राप्त करने के लिए अपना UPI पिन डालें।"),
    # --- QR code
    (T.QR_CODE,
     "Hi, I am interested in buying your sofa listed on OLX. I am sending ₹5,000 advance. "
     "Please scan this QR code to receive the payment."),
    (T.QR_CODE,
     "Scan this QR to get your Paytm cashback: upi://pay?pa=ramesh.k9@ybl&pn=Paytm%20Cashback"
     "&am=4999&cu=INR"),
    (T.QR_CODE,
     "Sir main army se hoon, aapki bike kharidni hai. Advance payment bhej raha hoon, yeh QR "
     "scan karo paise aapke account me aa jayenge."),
    # --- sent by mistake
    (T.SENT_BY_MISTAKE,
     "Hello sir, maine galti se aapke Paytm pe ₹3,000 bhej diye. Please wapas kar do, mera UPI "
     "ID hai rohit.sharma@ybl"),
    (T.SENT_BY_MISTAKE,
     "Sorry, I sent ₹5,000 to your number by mistake. Kindly return it to 9123456780 on GPay, "
     "it was for my mother's hospital bill."),
    (T.SENT_BY_MISTAKE,
     "मैंने गलती से आपके खाते में ₹2000 भेज दिए हैं, कृपया वापस कर दीजिए।"),
    # --- phishing links / fake notices
    (T.PHISHING_LINK,
     "Dear Customer, your SBI YONO account will be blocked today due to KYC expiry. Update "
     "your PAN immediately: https://sbi-kyc-update.xyz/login"),
    (T.PHISHING_LINK,
     "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM because "
     "your previous month bill was not updated. Please immediately contact our electricity "
     "officer 8260612345."),
    (T.PHISHING_LINK,
     "Your vehicle e-challan of Rs 500 is pending. Pay within 24 hours to avoid court action: "
     "http://echallan-parivahan.top/pay"),
    (T.PHISHING_LINK,
     "India Post: Your parcel is held at our warehouse due to incomplete address. Pay ₹25 "
     "redelivery fee at https://bit.ly/ip-redeliver within 48 hours."),
    (T.PHISHING_LINK,
     "Priya grahak, aapka bijli connection aaj raat 9:30 baje kat jayega kyunki pichle mahine "
     "ka bill update nahi hua. Turant bijli adhikari se sampark karein 9123456789"),
    # --- task-based job
    (T.TASK_JOB,
     "Hi, I'm Priya from Amazon HR. We are hiring part-time. Earn ₹3,000-₹8,000 daily by "
     "liking YouTube videos. Contact on Telegram: t.me/amzn_jobs_hr"),
    (T.TASK_JOB,
     "Work from home job! Rate hotels on Google and earn ₹150 per review. Daily income ₹5000+. "
     "WhatsApp: wa.me/919876543210"),
    (T.TASK_JOB,
     "Task 1-3 completed. To unlock the VIP prepaid task, recharge ₹1,000 and get ₹1,300 back "
     "in 10 minutes."),
    (T.TASK_JOB,
     "Ghar baithe kamaye ₹2000-₹5000 roz, sirf YouTube videos like karke. Part time job, "
     "Telegram pe message karein @hr_neha"),
    # --- fake customer care
    (T.FAKE_CUSTOMER_CARE,
     "Thank you for contacting Paytm customer care. To process your refund of ₹2,499, please "
     "install AnyDesk from Play Store and share the 9-digit code. Call our executive at "
     "9876543210."),
    (T.FAKE_CUSTOMER_CARE,
     "Flipkart customer care: For refund of ₹1,299 download QuickSupport app and call our "
     "helpline 7003123456."),
    (T.FAKE_CUSTOMER_CARE,
     "आपकी शिकायत दर्ज हो गई है। रिफंड के लिए हमारे कस्टमर केयर 9812345678 पर कॉल करें और "
     "AnyDesk ऐप इंस्टॉल करें।"),
    (T.FAKE_CUSTOMER_CARE,
     "HDFC customer care: your credit card reward points expire today. Install the HDFC "
     "Rewards app from http://bit.ly/hdfc-rwd/HDFCRewards.apk"),
    # --- generic credential request
    (T.GENERIC,
     "Sir aapke account me refund aa raha hai, jo OTP aaya hai woh bata dijiye."),
    (T.GENERIC,
     "This is from SBI head office. Please share the OTP you just received to stop the "
     "unauthorised transaction."),
]  # fmt: skip

# (label, message). Every one must score < 35.
GENUINE_EXAMPLES: list[tuple[str, str]] = [
    ("bank OTP (do not share)",
     "482913 is the OTP for your transaction of INR 3,250.00 at FLIPKART on ICICI Bank Credit "
     "Card XX4321. Valid for 10 minutes. Do not share OTP with anyone for security reasons. "
     "-ICICI Bank"),
    ("bank OTP, Hindi",
     "आपका ओटीपी 123456 है। इसे किसी के साथ शेयर न करें। SBI कभी भी OTP नहीं मांगता। - SBI"),
    ("OTP to confirm txn",
     "OTP to confirm your transaction of Rs 1,200 is 774411. SBI never asks you to share OTP."),
    ("UPI debit alert",
     "Dear Customer, Rs.500.00 has been debited from A/c XX1234 to VPA swiggy.stores@icici on "
     "12-09-26. UPI Ref No 412345678901. Not you? Call 18002586161 to report. -Canara Bank"),
    ("Swiggy order",
     "Your Swiggy order #174839201756 from Meghana Foods is out for delivery. Suresh will "
     "reach in 12 mins. Total paid: ₹642."),
    ("Amazon delivery",
     "Delivered: Your package with boAt Airdopes 141 was delivered. Track at amzn.in/d/3xYz9Ab. "
     "Order #407-1234567-8901234"),
    ("genuine sbi.co.in link",
     "Dear Customer, your account statement for August 2026 is ready. Login at "
     "https://www.onlinesbi.sbi or visit sbi.co.in/web/personal-banking. -SBI"),
    ("KYC reminder, no link",
     "Your KYC update is due. Please visit your nearest branch with valid documents. -SBI"),
    ("sent a photo by mistake",
     "Oops, sent that photo by mistake, please ignore!"),
    ("family bill payment",
     "Maa, bijli ka bill bhar diya ₹1,200. Receipt WhatsApp pe bhej raha hoon."),
    ("UPI awareness message",
     "Remember: you never need to enter your UPI PIN to receive money. Stay safe! -NPCI"),
    ("real parcel update",
     "Your parcel could not be delivered today as you were unavailable. We will try again "
     "tomorrow. -Delhivery"),
]  # fmt: skip
