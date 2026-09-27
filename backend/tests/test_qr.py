import io

import httpx
import pytest
import qrcode
import respx
from PIL import Image

from app.services.qr import (
    MAX_IMAGE_BYTES,
    ImageTooLargeError,
    NoQRCodeError,
    UnsupportedImageError,
    classify,
    decode_qr,
)
from tests.conftest import ClientFactory

FAKE_REFUND_QR = "upi://pay?pa=sbi-kyc@ybl&pn=SBI%20Refund&am=4999&tn=refund"


def qr_image(payload: str, fmt: str = "PNG") -> bytes:
    img = qrcode.make(payload).get_image().convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


def blank_png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (200, 200), "white").save(buf, format="PNG")
    return buf.getvalue()


# ----------------------------------------------------------------------------- decoding


@pytest.mark.parametrize("fmt", ["PNG", "JPEG"])
def test_decode_upi_qr(fmt: str) -> None:
    result = decode_qr(qr_image(FAKE_REFUND_QR, fmt))
    assert (result.payload, result.kind) == (FAKE_REFUND_QR, "upi")


@pytest.mark.parametrize(
    ("payload", "kind"),
    [("https://bit.ly/abc", "url"), ("example.com/pay", "url"), ("UPI://PAY?pa=x@ybl", "upi"),
     ("Wifi password is hunter2", "text"), ("visit https://a.com and https://b.com", "text")],
)  # fmt: skip
def test_classify(payload: str, kind: str) -> None:
    assert classify(payload) == kind


def test_rejects_non_images_and_other_formats() -> None:
    with pytest.raises(UnsupportedImageError):
        decode_qr(b"%PDF-1.7 not an image")
    gif = io.BytesIO()
    Image.new("RGB", (10, 10)).save(gif, format="GIF")
    with pytest.raises(UnsupportedImageError):
        decode_qr(gif.getvalue())


def test_rejects_oversized_upload() -> None:
    with pytest.raises(ImageTooLargeError):
        decode_qr(b"\x89PNG" + b"0" * MAX_IMAGE_BYTES)


def test_no_qr_code() -> None:
    with pytest.raises(NoQRCodeError):
        decode_qr(blank_png())


# ----------------------------------------------------------------------------- API


async def test_fake_refund_qr_is_a_scam(make_client: ClientFactory) -> None:
    files = {"image": ("qr.png", qr_image(FAKE_REFUND_QR), "image/png")}
    async with make_client() as client:
        resp = await client.post("/analyze/qr", files=files)
        assert resp.status_code == 200
        body = resp.json()
        saved = (await client.get(f"/analysis/{body['id']}")).json()

    assert body["verdict"] == "scam"
    assert body["risk_score"] >= 70
    assert body["scam_type"] == "qr_code"
    sources = {s["source"] for s in body["signal_breakdown"]}
    assert {"rules", "upi_check", "reputation"} <= sources
    assert {"upi_id_impersonation", "upi_payee_impersonation", "upi_bait_note"} <= {
        f["code"] for f in body["red_flags"]
    }
    assert saved == body


@respx.mock
async def test_url_qr_goes_to_url_intel(make_client: ClientFactory) -> None:
    respx.head("https://bit.ly/qr-pay").mock(
        return_value=httpx.Response(302, headers={"Location": "https://paytm-kyc-verify.top/"})
    )
    respx.head("https://paytm-kyc-verify.top/").mock(return_value=httpx.Response(200))
    respx.get("https://rdap.org/domain/paytm-kyc-verify.top").mock(return_value=httpx.Response(404))
    files = {"image": ("qr.jpg", qr_image("https://bit.ly/qr-pay", "JPEG"), "image/jpeg")}
    async with make_client() as client:
        body = (await client.post("/analyze/qr", files=files)).json()
    intel = next(s for s in body["signal_breakdown"] if s["source"] == "url_intel")
    assert "paytm-kyc-verify.top" in intel["detail"]
    assert body["verdict"] == "scam"


@pytest.mark.parametrize(
    ("content", "status"),
    [(blank_png(), 422), (b"just text", 415), (b"\x89PNG" + b"0" * MAX_IMAGE_BYTES, 413)],
    ids=["no-qr", "not-an-image", "too-large"],
)
async def test_qr_errors(make_client: ClientFactory, content: bytes, status: int) -> None:
    async with make_client() as client:
        resp = await client.post("/analyze/qr", files={"image": ("x.png", content, "image/png")})
    assert resp.status_code == status
    assert resp.json()["detail"]


async def test_qr_requires_file(make_client: ClientFactory) -> None:
    async with make_client() as client:
        assert (await client.post("/analyze/qr")).status_code == 422
