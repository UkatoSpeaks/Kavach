import pytest

from app.schemas.entities import ExtractedUPI
from app.services.extractors import extract_entities, parse_upi_uri
from app.services.upi import IMPERSONATION_WITH_PAYMENT_FLOOR, check_upi_id, upi_signal
from tests.conftest import ClientFactory


def upi(value: str) -> ExtractedUPI:
    return extract_entities(value).upi_ids[0]


def codes(findings: list) -> set[str]:
    return {f.code for f in findings}


@pytest.mark.parametrize(
    ("vpa", "impersonates"),
    [
        ("sbi-kyc@ybl", True),
        ("sbikyc@ybl", True),
        ("kycupdate@okaxis", True),
        ("refund.helpdesk@axl", True),
        ("customer.care@okicici", True),
        ("rbi.npci.cashback@ibl", True),
        ("demo-kyc-help@ybl", True),
        ("rohit.sharma@ybl", False),
        ("govind.k@ybl", False),  # "gov" only as a whole word
        ("sbin.patel@oksbi", False),  # "sbi" + "n" is not a keyword
        ("healthcare.clinic@okaxis", False),
        ("paytmqr2810050501@paytm", False),  # Paytm merchant on Paytm's own handle
        ("9876543210@ybl", False),
    ],
)
def test_upi_id_impersonation(vpa: str, impersonates: bool) -> None:
    assert ("upi_id_impersonation" in codes(check_upi_id(upi(vpa)))) is impersonates


def test_unknown_handle() -> None:
    assert codes(check_upi_id(upi("ravi@zzpay"))) == {"upi_unknown_handle"}
    assert check_upi_id(upi("ravi@ybl")) == []
    assert check_upi_id(upi("shop.123@fbpe")) == []  # BharatPe merchant handle


def test_clean_upi_id_is_not_informative() -> None:
    out = upi_signal([upi("rohit.sharma@ybl")], [])
    assert out is not None
    assert (out.score, out.informative) == (0, False)
    assert upi_signal([], []) is None


def test_fake_refund_uri_hits_every_check_and_sets_floor() -> None:
    uri = parse_upi_uri("upi://pay?pa=sbi-kyc@ybl&pn=SBI%20Refund&am=4999&tn=refund")
    assert uri is not None
    out = upi_signal([upi("sbi-kyc@ybl")], [uri])
    assert out is not None
    assert out.score >= 90
    assert out.floor == IMPERSONATION_WITH_PAYMENT_FLOOR
    assert {f.code for f in out.red_flags} == {
        "upi_id_impersonation", "upi_payee_impersonation", "upi_bait_note"
    }  # fmt: skip  # amount and name mismatch are already red flags from the rules


def test_payee_mismatch_and_amount_without_impersonation_has_no_floor() -> None:
    uri = parse_upi_uri("upi://pay?pa=ramesh.k9@ybl&pn=Suresh%20Traders&am=500")
    assert uri is not None
    out = upi_signal([], [uri])
    assert out is not None
    assert "upi_payee_mismatch" in out.detail and "upi_prefilled_amount" in out.detail
    assert out.floor is None


def test_genuine_merchant_uri_is_clean() -> None:
    uri = parse_upi_uri("upi://pay?pa=swiggy.stores@icici&pn=Swiggy%20Stores&mc=5812")
    assert uri is not None
    out = upi_signal([upi("swiggy.stores@icici")], [uri])
    assert out is not None and not out.informative


# ----------------------------------------------------------------------------- API


async def test_analyze_upi_id(make_client: ClientFactory) -> None:
    async with make_client() as client:
        resp = await client.post("/analyze/upi", json={"upi_id": "SBI-KYC@ybl"})
    body = resp.json()
    assert resp.status_code == 200
    upi_check = next(s for s in body["signal_breakdown"] if s["source"] == "upi_check")
    rules = next(s for s in body["signal_breakdown"] if s["source"] == "rules")
    assert rules["weight"] == 0  # no message text to read
    assert upi_check["weight"] == 1.0
    assert body["verdict"] == "suspicious"


async def test_analyze_upi_uri_scam(make_client: ClientFactory) -> None:
    uri = "upi://pay?pa=sbi-kyc@ybl&pn=SBI%20Refund&am=4999&tn=refund"
    async with make_client() as client:
        resp = await client.post("/analyze/upi", json={"upi_uri": uri})
    body = resp.json()
    assert (body["verdict"], body["scam_type"]) == ("scam", "qr_code")
    assert body["risk_score"] >= 75


async def test_analyze_plain_upi_id_is_safe(make_client: ClientFactory) -> None:
    async with make_client() as client:
        body = (await client.post("/analyze/upi", json={"upi_id": "rohit.sharma@ybl"})).json()
    assert body["verdict"] == "safe"


@pytest.mark.parametrize(
    "payload",
    [{}, {"upi_id": "a@ybl", "upi_uri": "upi://pay?pa=a@ybl"}, {"upi_id": "not-a-upi"},
     {"upi_id": "me@gmail.com"}, {"upi_uri": "https://example.com"}, {"upi_uri": "upi://pay?am=1"}],
)  # fmt: skip
async def test_analyze_upi_rejects_bad_input(make_client: ClientFactory, payload: dict) -> None:
    async with make_client() as client:
        assert (await client.post("/analyze/upi", json=payload)).status_code == 422
