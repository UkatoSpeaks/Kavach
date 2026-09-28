import pytest

from app.services.extractors import clean_text, extract_entities
from app.services.normalize import fold


def folded(text: str) -> str:
    return extract_entities(text).rule_texts[0]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Withdraw N0W", "withdraw now"),
        ("credited t0 your wallet 0n 29 Aug", "credited to your wallet on 29 aug"),
        ("Y0UR L0AN is Approve", "your loan is approve"),
        ("receive a B0nus, M0ve to Y0ur Bank", "receive a bonus, move to your bank"),
        ("Cl@im your reward", "claim your reward"),
        ("0nly for you", "only for you"),
        ("acc3ss y4ur acc0unt", "access yaur account"),
    ],
)
def test_leet_inside_words_is_folded(text: str, expected: str) -> None:
    assert folded(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "Open OI1.in/2vclen!8cpr814 or http://q4m2.com/zx0Nw3!51k9pq",  # URLs
        "Pay rahu1@ybl or write to r0hit@gmail.com",  # UPI IDs, emails
        "Call 9876543210 or 1800 425 3800",  # phones
        "Rs.500 credited, Rs 1,05,000 due, ₹30",  # amounts
        "Use code MY400, F10N5, ATV31M, OC10K, UL399, B1G1, BA1GA1, PAYTMVI20",  # codes
        "5G data, 4GB/day, 3D, 4K TV, 1st prize, 5pm, 3days, 1BHK, XX32, XXO2, XX11",
        "Open 11:00AM to 9:30PM",  # times
        "Wednesday Bonus@JioMart, FRESH WEDNESDAY@STAR, Special Offer@SMART",  # "at"
        "Code REBU1UUYSC, M-ticket WHSTD4K, Tide5kg Rs115OFF, Ghee1L",  # promo codes, sizes
        "Not gone 4the test yet, Only1more day, least5times, 4T&C",  # text-speak
    ],
)
def test_links_ids_amounts_and_codes_are_never_folded(text: str) -> None:
    e = extract_entities(text)
    assert e.rule_texts == [e.normalized_text]
    assert e.evasions == []


@pytest.mark.parametrize(
    ("text", "evasions"),
    [
        ("Credited to yOur A/c", ["yOur"]),
        ("Withdraw N0W, 0N 16 AUG", ["N0W", "0N"]),
        ("7 daysAlso get more, atHome, toClaim, moreFrmMob", []),  # missing spaces
        ("New iPhone, eKYC, mAadhaar, WhatsApp, JioMart, YouTube", []),  # brand spellings
        ("Visit http://x.com/yOurLink", []),  # URL slugs mix case anyway
    ],
)
def test_evasions(text: str, evasions: list[str]) -> None:
    assert extract_entities(text).evasions == evasions


def test_folding_keeps_positions() -> None:
    text = "Dear 90196xxxxx, Rs.38,OOO/- is Added t0 your wallet. Directly Withdraw N0w"
    e = extract_entities(text)
    for copy in e.rule_texts:
        assert len(copy) == len(e.normalized_text)
    assert [
        i for i, (a, b) in enumerate(zip(e.rule_texts[0], e.normalized_text, strict=True)) if a != b
    ] == [
        e.normalized_text.index("t0") + 1,
        e.normalized_text.index("n0w") + 1,
    ]


def test_one_gets_a_second_copy_with_l() -> None:
    result = fold(clean_text("P1ease c1ick"))
    assert result.texts == ("piease ciick", "please click")
    assert fold(clean_text("Withdraw N0W")).texts == ("withdraw now",)  # no 1: one copy


def test_protected_spans_are_left_alone() -> None:
    assert fold("N0W and N0W", [(0, 3)]).texts == ("n0w and now",)
