import pytest

from app.schemas.entities import SensitiveInfo as S
from app.services.extractors import (
    URL_SHORTENERS,
    detect_remote_access_apps,
    detect_sensitive_info,
    extract_amounts,
    extract_apk_files,
    extract_emails,
    extract_entities,
    extract_phones,
    extract_upi_ids,
    extract_upi_uris,
    extract_urls,
    normalize_text,
    parse_upi_uri,
    registered_domain,
)

# ----------------------------------------------------------------------------- normalize


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Share  your\n\tOTP   now", "share your otp now"),
        ("O​T‌P⁠ bhejo", "otp bhejo"),  # zero-width chars removed
        ("ＯＴＰ ｓｂｉ", "otp sbi"),  # fullwidth folded by NFKC
        ("call ९८७६५४३२१०", "call 9876543210"),  # Devanagari digits
        ("﻿KYC­ update", "kyc update"),  # BOM + soft hyphen
    ],
)
def test_normalize_text(raw: str, expected: str) -> None:
    assert normalize_text(raw) == expected


# ----------------------------------------------------------------------------- URLs


@pytest.mark.parametrize(
    ("text", "url", "domain"),
    [
        (
            "Update now: sbi-kyc-update.in/verify.",
            "http://sbi-kyc-update.in/verify",
            "sbi-kyc-update.in",
        ),
        ("visit www.xyz.top today", "http://www.xyz.top", "xyz.top"),
        (
            "(see https://secure.sbi.co.in/login?x=1),",
            "https://secure.sbi.co.in/login?x=1",
            "sbi.co.in",
        ),
        ("portal.uidai.gov.in pe jao", "http://portal.uidai.gov.in", "uidai.gov.in"),
        ("NGO site: help.seva.org.in!", "http://help.seva.org.in", "seva.org.in"),
        ("Click HTTPS://Rb.gy/AbC9!", "https://rb.gy/AbC9", "rb.gy"),  # path case kept
        ("pay at http://192.168.1.5:8080/pay", "http://192.168.1.5:8080/pay", "192.168.1.5"),
        ("Telegram: t.me/amzn_tasks_hr", "http://t.me/amzn_tasks_hr", "t.me"),
        ("इस लिंक पर क्लिक करें bit.ly/3xYz।", "http://bit.ly/3xYz", "bit.ly"),
    ],
)
def test_extract_urls(text: str, url: str, domain: str) -> None:
    urls = extract_urls(text)
    assert [u.url for u in urls] == [url]
    assert urls[0].registered_domain == domain


@pytest.mark.parametrize(
    "shortener",
    ["bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "rb.gy", "t.ly", "shorturl.at", "tiny.cc",
     "goo.gl", "ow.ly"],
)  # fmt: skip
def test_url_shorteners_flagged(shortener: str) -> None:
    assert shortener in URL_SHORTENERS
    (url,) = extract_urls(f"Claim reward: https://{shortener}/Xy12z")
    assert url.is_shortener


@pytest.mark.parametrize(
    "text",
    [
        "Hello Mr.Sharma, see invoice.pdf e.g. tomorrow",
        "Pay Rs.500 at 9.30pm",
        "write to support@flipkart.com",  # email domain is not a URL
        "ok.thanks bhai",
    ],
)
def test_no_false_urls(text: str) -> None:
    assert extract_urls(text) == []


@pytest.mark.parametrize(
    "text",
    [
        # UCI spam: a missing space after a full stop, not the domain quiz.win
        "Moby Pub Quiz.Win a £100 High Street prize if u know who the new Duchess of Cornwall "
        "will be? Txt her first name to 82277.unsub STOP £1.50 008704050406 SP Arrow",
        "Offer ends today.Call now",
        "Reached home.In the car now",
    ],
)
def test_missing_space_after_full_stop_is_not_a_url(text: str) -> None:
    assert extract_urls(text) == []


@pytest.mark.parametrize(
    ("text", "url"),
    [
        ("Update KYC at sbi-kyc.in/verify", "http://sbi-kyc.in/verify"),
        ("Visit xyz.top now", "http://xyz.top"),
        ("Visit Sbi-Kyc.Online now", "http://sbi-kyc.online"),  # hyphen: a real domain
        ("Claim at Free.Win/prize", "http://free.win/prize"),  # has a path
        ("Claim at https://Quiz.Win", "https://quiz.win"),  # has a scheme
    ],
)
def test_bare_domains_still_found(text: str, url: str) -> None:
    assert [u.url for u in extract_urls(text)] == [url]


def test_url_flags() -> None:
    by_host = {u.host: u for u in extract_urls("get http://10.0.0.7/a and x.xyz/app/Loan.APK")}
    assert by_host["10.0.0.7"].is_ip
    assert by_host["x.xyz"].is_apk
    assert not by_host["x.xyz"].is_shortener


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("a.b.sbi.co.in", "sbi.co.in"),
        ("www.incometax.gov.in", "incometax.gov.in"),
        ("paytm.com", "paytm.com"),
        ("login.icici.bank.in", "icici.bank.in"),  # RBI's .bank.in
    ],
)
def test_registered_domain(host: str, expected: str) -> None:
    assert registered_domain(host) == expected


# ----------------------------------------------------------------------------- UPI


@pytest.mark.parametrize(
    ("text", "value", "confidence"),
    [
        ("Mera UPI ID hai rahul.sharma99@ybl, bhej do", "rahul.sharma99@ybl", "high"),
        ("pay 9876543210@PAYTM", "9876543210@paytm", "high"),
        ("send to refund.desk@oksbi.", "refund.desk@oksbi", "high"),
        ("UPI: cashback-help@axisbank", "cashback-help@axisbank", "high"),
        ("pay on kbcwinner@fakebank now", "kbcwinner@fakebank", "low"),
    ],
)
def test_extract_upi_ids(text: str, value: str, confidence: str) -> None:
    (upi,) = extract_upi_ids(text)
    assert (upi.value, upi.confidence) == (value, confidence)


def test_email_is_not_upi() -> None:
    text = "For queries write to support@flipkart.com or care.team@hdfcbank.com"
    assert extract_upi_ids(text) == []
    assert extract_emails(text) == ["support@flipkart.com", "care.team@hdfcbank.com"]


def test_parse_upi_uri() -> None:
    uri = parse_upi_uri(
        "upi://pay?pa=CashBack.Reward@okaxis&pn=Paytm%20Cashback&am=4999.00"
        "&cu=INR&tn=Refund+Claim&mc=5411"
    )
    assert uri is not None
    assert uri.pa == "cashback.reward@okaxis"
    assert uri.pn == "Paytm Cashback"
    assert uri.am == 4999.0
    assert (uri.cu, uri.tn, uri.mc) == ("INR", "Refund Claim", "5411")


def test_upi_uri_in_text_and_bad_amount() -> None:
    (uri,) = extract_upi_uris("Scan: UPI://pay?pa=x@ybl&am=abc.")
    assert uri.pa == "x@ybl"
    assert uri.am is None
    assert parse_upi_uri("https://example.com") is None


def test_percent_encoded_payee_added_to_upi_ids() -> None:
    entities = extract_entities("upi://pay?pa=win%40ybl&pn=KBC")
    assert [u.value for u in entities.upi_ids] == ["win@ybl"]


# ----------------------------------------------------------------------------- phones


@pytest.mark.parametrize(
    ("text", "number"),
    [
        ("call +91 98765 43210 now", "+919876543210"),
        ("WhatsApp +91-9876543210", "+919876543210"),
        ("contact 919876543210", "+919876543210"),
        ("dial 09876543210", "+919876543210"),
        ("Mob: 98765-43210", "+919876543210"),
        ("ph 987-654-3210", "+919876543210"),
        ("officer 8260 123 456 se baat karo", "+918260123456"),
        ("इस नंबर पर कॉल करें 7012345678", "+917012345678"),
        ("𝟗𝟖𝟕𝟔𝟓𝟒𝟑𝟐𝟏𝟎 pe call karo", "+919876543210"),  # math-bold digits
        ("toll free 1800 425 3800", "18004253800"),
        ("helpline 1800-419-3522.", "18004193522"),
    ],
)
def test_extract_phones(text: str, number: str) -> None:
    assert [p.number for p in extract_phones(text)] == [number]


@pytest.mark.parametrize(
    "text",
    [
        "874512 is your OTP. Do not share it.",
        "Appointment on 12/09/2026 at 10:30 AM",
        "Order ID: 9876543210 confirmed",
        "Your Zomato order (ID: 6789012345) is delivered",
        "Txn ref no. 7654321098 successful",
        "Amount Rs 9876543210 debited",
        "Aadhaar 9876 5432 1098 linked",
        "Amazon order 407-1234567-8901234",
        "Swiggy order #162534987612 placed",
        "UTR 412345678901",
        "pay 9876543210@ybl",  # part of a UPI ID
    ],
)
def test_no_false_phones(text: str) -> None:
    assert extract_phones(text) == []


# ----------------------------------------------------------------------------- amounts


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("Pay ₹1,50,000 now", 150000),
        ("fee Rs. 5000 only", 5000),
        ("Rs.499 pending", 499),
        ("INR 25,000.50 credited", 25000.5),
        ("5000 rupees bheje", 5000),
        ("galti se 5000 rupaye bhej diye", 5000),
        ("maine 7000rs bheje", 7000),
        ("2 lakh ka loan", 200000),
        ("1.5 lac jeeto", 150000),
        ("Rs 3 crore prize", 30000000),
        ("10cr ki lottery", 100000000),
        ("earn 50k monthly", 50000),
        ("₹5L instant loan", 500000),
        ("आपने 25 लाख रुपये जीते", 2500000),
        ("रु 500 का रिचार्ज", 500),
        ("processing fee 1500/- only", 1500),
        ("5 हज़ार रुपये भेजें", 5000),
    ],
)
def test_extract_amounts(text: str, value: float) -> None:
    assert [a.value for a in extract_amounts(text)] == [value]


def test_numbers_inside_links_are_not_amounts_or_phones() -> None:
    text = "fee ₹1,499/- via upi://pay?pa=a@ybl&pn=Quick%20Rupee&am=1499 or x.xyz/p?m=9876543210"
    assert [a.value for a in extract_amounts(text)] == [1499]
    assert extract_phones(text) == []


def test_amount_range() -> None:
    assert [a.value for a in extract_amounts("earn ₹3,000-₹8,000 daily")] == [3000, 8000]


@pytest.mark.parametrize(
    "text",
    ["I'm 2 km away", "Mrs 500 people came", "Lottery number 8394", "OTP 482913",
     "on 12/09/2026", "call 9876543210", "5 thousand people", "buy 5l milk"],
)  # fmt: skip
def test_no_false_amounts(text: str) -> None:
    assert extract_amounts(text) == []


# ----------------------------------------------------------------------------- credentials


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Bhai jo OTP aaya hai woh bata do", [S.OTP]),
        ("ओटीपी बताइए जल्दी", [S.OTP]),
        ("share your O​T​P", [S.OTP]),  # zero-width dodge
        ("enter the one time password", [S.OTP]),
        ("enter UPI PIN to receive money", [S.UPI_PIN]),
        ("अपना यूपीआई पिन डालें", [S.UPI_PIN]),
        ("send your ATM pin", [S.PIN]),
        ("apna MPIN batao", [S.MPIN]),
        ("card ka CVV bhejo", [S.CVV]),
        ("net banking password reset karo", [S.PASSWORD]),
        ("Aadhar number aur PAN card bhejo", [S.AADHAAR, S.PAN]),
        ("आधार कार्ड और पैन कार्ड की फोटो भेजें", [S.AADHAAR, S.PAN]),
        ("Deliver to pincode 560034", []),
        ("pan me sabzi banao", []),
        ("यह योजना आय पर आधारित है", []),  # "आधारित" (based on) is not Aadhaar
    ],
)
def test_detect_sensitive_info(text: str, expected: list[S]) -> None:
    assert detect_sensitive_info(text) == expected


# ----------------------------------------------------------------------------- apps / APKs


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Please install AnyDesk and share the code", ["AnyDesk"]),
        ("Play Store se TeamViewer QuickSupport download karo", ["TeamViewer", "QuickSupport"]),
        ("rustdesk ya airdroid install karein", ["RustDesk", "AirDroid"]),
        ("एनीडेस्क ऐप डाउनलोड करें", ["AnyDesk"]),
        ("Thanks for the quick support! Is any desk free?", []),
    ],
)
def test_detect_remote_access_apps(text: str, expected: list[str]) -> None:
    assert detect_remote_access_apps(text) == expected


def test_extract_apk_files() -> None:
    text = "Install SBI_Rewards.apk or get it at https://x.xyz/dl/PM-Kisan.apk"
    assert extract_apk_files(text) == ["SBI_Rewards.apk", "PM-Kisan.apk"]


# ----------------------------------------------------------------------------- scam messages


def test_fake_kyc_update() -> None:
    e = extract_entities(
        "Dear Customer, your SBI YONO account will be BLOCKED today. Update PAN card KYC "
        "immediately: sbi-kyc-update.in/verify or call 9876543210. -SBI"
    )
    assert [u.registered_domain for u in e.urls] == ["sbi-kyc-update.in"]
    assert [p.number for p in e.phones] == ["+919876543210"]
    assert e.sensitive_info == [S.PAN]


def test_electricity_disconnection() -> None:
    e = extract_entities(
        "Dear consumer your electricity power will be disconnected tonight at 9.30pm because "
        "your previous month bill was not update. Pay Rs.1,250 at https://bit.ly/3Kx9Pq or "
        "contact electricity officer 8260 123 456."
    )
    assert e.urls[0].is_shortener
    assert [a.value for a in e.amounts] == [1250]
    assert [p.number for p in e.phones] == ["+918260123456"]


def test_parcel_customs() -> None:
    e = extract_entities(
        "India Post: Your parcel is on hold at customs due to incomplete address. Pay customs "
        "fee INR 25.50 at https://indiapost-redelivery.top/track?id=IN8826 within 24 hrs."
    )
    assert [u.url for u in e.urls] == ["https://indiapost-redelivery.top/track?id=IN8826"]
    assert [a.value for a in e.amounts] == [25.5]
    assert e.phones == []


def test_task_based_job() -> None:
    e = extract_entities(
        "Hi, I am Priya from Amazon HR. Part time job, earn ₹3,000-₹8,000 daily by liking "
        "YouTube videos. Contact on Telegram t.me/amzn_tasks_hr or WhatsApp +91 70123 45678"
    )
    assert [u.registered_domain for u in e.urls] == ["t.me"]
    assert [a.value for a in e.amounts] == [3000, 8000]
    assert [p.number for p in e.phones] == ["+917012345678"]


def test_money_sent_by_mistake() -> None:
    e = extract_entities(
        "Sir maine galti se aapke account me Rs 5,000 bhej diye, please wapas kar do. Mera "
        "UPI ID hai rahul.sharma99@ybl. Ya is number pe bhejo 9123456780"
    )
    assert [(u.value, u.confidence) for u in e.upi_ids] == [("rahul.sharma99@ybl", "high")]
    assert [a.value for a in e.amounts] == [5000]
    assert [p.number for p in e.phones] == ["+919123456780"]
    assert e.emails == []


def test_digital_arrest_hindi() -> None:
    e = extract_entities(
        "यह CBI मुंबई से है। आपके आधार कार्ड से जुड़ा पार्सल ड्रग्स के साथ पकड़ा गया है। आप "
        "डिजिटल अरेस्ट में हैं। तुरंत AnyDesk डाउनलोड करें और 2 लाख रुपये RBI खाते में "
        "ट्रांसफर करें।"
    )
    assert e.sensitive_info == [S.AADHAAR]
    assert e.remote_access_apps == ["AnyDesk"]
    assert [a.value for a in e.amounts] == [200000]


def test_loan_app() -> None:
    e = extract_entities(
        "Instant loan approved ₹50,000 without CIBIL! Download app: "
        "https://quickcash-loan.xyz/app/InstantLoan.apk . Share Aadhaar & PAN number."
    )
    assert e.apk_links == ["https://quickcash-loan.xyz/app/InstantLoan.apk"]
    assert e.apk_files == ["InstantLoan.apk"]
    assert [a.value for a in e.amounts] == [50000]
    assert e.sensitive_info == [S.AADHAAR, S.PAN]


def test_lottery_kbc() -> None:
    e = extract_entities(
        "KBC Jio Lottery: Aapne 25 lakh rupaye jeete hain! Lottery number 8394. Processing "
        "fee Rs 15,500 bhej ke claim karein. Rana Pratap ji ko WhatsApp karein +91-98765-43210"
    )
    assert [a.value for a in e.amounts] == [2500000, 15500]
    assert [p.number for p in e.phones] == ["+919876543210"]


def test_fake_customer_care() -> None:
    e = extract_entities(
        "Paytm customer care: Your refund of Rs.1,999 is pending. To receive, call toll-free "
        "1800-419-3522, install QuickSupport and share the OTP & UPI PIN."
    )
    assert [p.kind for p in e.phones] == ["toll_free"]
    assert e.remote_access_apps == ["QuickSupport"]
    assert e.sensitive_info == [S.OTP, S.UPI_PIN]
    assert [a.value for a in e.amounts] == [1999]


def test_upi_qr_cashback() -> None:
    e = extract_entities(
        "Scan to receive cashback: upi://pay?pa=cashback.reward@okaxis&pn=Paytm%20Cashback"
        "&am=4999.00&cu=INR&tn=Refund%20Claim&mc=5411"
    )
    assert e.upi_uris[0].am == 4999.0
    assert e.upi_ids[0].value == "cashback.reward@okaxis"
    assert e.urls == []


# ----------------------------------------------------------------------------- genuine messages


def test_genuine_bank_otp_sms() -> None:
    e = extract_entities(
        "123456 is your OTP for txn of INR 2,500.00 at AMAZON on HDFC Bank card xx1234. "
        "Valid for 10 mins. Do not share OTP with anyone. -HDFC Bank"
    )
    assert e.phones == [] and e.urls == [] and e.upi_ids == []
    assert [a.value for a in e.amounts] == [2500]
    assert e.sensitive_info == [S.OTP]  # mentioned, not requested; scoring decides


def test_genuine_swiggy_update() -> None:
    e = extract_entities(
        "Your Swiggy order #162534987612 from Behrouz Biryani is out for delivery. Ramesh "
        "will reach in 15 mins. Total paid: ₹486."
    )
    assert e.phones == [] and e.urls == []
    assert [a.value for a in e.amounts] == [486]


def test_genuine_amazon_delivery() -> None:
    e = extract_entities(
        "Delivered: Your Amazon package with boAt Airdopes was delivered. Order "
        "407-1234567-8901234. Track: amzn.in/d/abc123"
    )
    assert e.phones == [] and e.amounts == [] and e.sensitive_info == []
    assert [(u.registered_domain, u.is_shortener) for u in e.urls] == [("amzn.in", False)]


def test_extracted_entities_is_json_serializable() -> None:
    e = extract_entities("Pay ₹500 to x@ybl at bit.ly/x, call 9876543210, share OTP")
    dumped = e.model_dump(mode="json")
    assert dumped["sensitive_info"] == ["otp"]
    assert dumped["upi_ids"][0]["confidence"] == "high"
