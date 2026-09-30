"""app/services/ocr.py: image checks, the Groq vision tier (mocked), the fallback order and
the local OCR (one real run on a generated image, bundled models only: no download)."""

import io
import json
from typing import Any

import httpx
import pytest
from PIL import Image

from app.services.ocr import (
    MAX_IMAGE_BYTES,
    MAX_TEXT_CHARS,
    VISION_MAX_SIDE,
    VISION_PROMPT,
    GroqVisionOCR,
    ImageTooLargeError,
    InvalidVisionOutput,
    OCRLine,
    RapidLocalOCR,
    ScreenshotReader,
    UnsupportedImageError,
    VisionFailed,
    join_lines,
    parse_vision_reply,
    pick_line,
    prepare_image,
)
from tests.fakes import FakeLocalOCR, scripted_groq
from tests.screenshots import render_sms, to_bytes
from tests.test_llm import completion, error

MODEL = "vision-test-model"
SMS_TEXT = "AX-HDFCBK-S\nRs.500.00 debited from A/c XX1234\n10:42 AM"


def vision_json(**overrides: Any) -> str:
    return json.dumps(
        {
            "extracted_text": SMS_TEXT,
            "app": "sms",
            "sender": "AX-HDFCBK-S",
            "is_payment_receipt": False,
            "language": "en",
        }
        | overrides,
        ensure_ascii=False,
    )


def ok(content: str | None = None) -> httpx.Response:
    return httpx.Response(200, json=completion(content or vision_json(), model=MODEL))


def vision(*outcomes: httpx.Response | Exception) -> tuple[GroqVisionOCR, list[httpx.Request]]:
    client, requests = scripted_groq(*outcomes)
    return GroqVisionOCR("test-key", MODEL, timeout_s=5, client=client), requests


def png(size: tuple[int, int] = (400, 300), mode: str = "RGB") -> bytes:
    return to_bytes(Image.new(mode, size, "white"))


@pytest.fixture
def prepared():  # noqa: ANN201
    return prepare_image(png())


# ----------------------------------------------------------------------------- images


@pytest.mark.parametrize("fmt", ["PNG", "JPEG", "WEBP"])
def test_accepts_png_jpeg_webp(fmt: str) -> None:
    img = prepare_image(to_bytes(Image.new("RGB", (200, 100), "white"), fmt))
    assert img.image.size == (200, 100) and img.image.mode == "RGB"


def test_rejects_other_formats_and_non_images() -> None:
    gif = to_bytes(Image.new("RGB", (10, 10)), "GIF")
    for data in (gif, b"%PDF-1.7 not an image", b""):
        with pytest.raises(UnsupportedImageError):
            prepare_image(data)


def test_rejects_large_uploads() -> None:
    with pytest.raises(ImageTooLargeError):
        prepare_image(b"\x89PNG" + b"0" * MAX_IMAGE_BYTES)


def test_downscales_for_vision_and_keeps_full_size_for_qr() -> None:
    img = prepare_image(to_bytes(Image.new("RGB", (1080, 3200), "white"), "JPEG"))
    assert max(img.image.size) == VISION_MAX_SIDE
    assert img.full.size == (1080, 3200) and img.full.mode == "L"


def test_strips_exif_and_applies_orientation() -> None:
    src = Image.new("RGB", (300, 100), "white")
    exif = Image.Exif()
    exif[0x0112] = 6  # Orientation: rotate 90° clockwise to display
    exif[0x010F] = "SecretPhone Inc"  # Make
    buf = io.BytesIO()
    src.save(buf, format="JPEG", exif=exif.tobytes())

    img = prepare_image(buf.getvalue())
    assert img.image.size == (100, 300)  # upright
    assert not img.image.info.get("exif")
    reopened = Image.open(io.BytesIO(img.jpeg()))
    assert len(reopened.getexif()) == 0
    assert b"SecretPhone" not in img.jpeg()


def test_transparency_goes_on_white() -> None:
    img = prepare_image(png(mode="RGBA"))
    assert img.image.mode == "RGB"


# ----------------------------------------------------------------------------- vision reply


def test_parse_valid_reply() -> None:
    reply, notes = parse_vision_reply(vision_json())
    assert reply.extracted_text == SMS_TEXT
    assert (reply.app, reply.sender, reply.is_payment_receipt) == ("sms", "AX-HDFCBK-S", False)
    assert notes == ()


@pytest.mark.parametrize(
    "raw", ["Sure! Here is the text: {", json.dumps({"app": "sms"}), json.dumps(["a"])]
)
def test_parse_invalid_reply(raw: str) -> None:
    with pytest.raises(InvalidVisionOutput):
        parse_vision_reply(raw)


def test_sender_not_in_the_transcription_is_dropped() -> None:
    """A vision model steered by the image could claim a business header that isn't there."""
    reply, notes = parse_vision_reply(vision_json(sender="VM-SBIINB"))
    assert reply.sender is None
    assert notes == ("sender not in the transcription: dropped",)


def test_sender_match_ignores_spacing_and_case() -> None:
    text = "+91 98765 43210\nHi"
    reply, _ = parse_vision_reply(vision_json(extracted_text=text, sender="+919876543210"))
    assert reply.sender == "+919876543210"


def test_reply_normalization() -> None:
    reply, notes = parse_vision_reply(
        vision_json(app="Payment App", sender="null", language="", extracted_text="x" * 6000)
    )
    assert (reply.app, reply.sender, reply.language) == ("payment_app", None, None)
    assert len(reply.extracted_text) == MAX_TEXT_CHARS
    assert any("cut" in n for n in notes)
    unknown, _ = parse_vision_reply(vision_json(app="telegram"))
    assert unknown.app == "other"


# ----------------------------------------------------------------------------- vision calls


async def test_vision_request(prepared) -> None:  # noqa: ANN001
    reader, requests = vision(ok())
    reply, _ = await reader.read(prepared)
    assert reply.sender == "AX-HDFCBK-S"
    body = json.loads(requests[0].content)
    assert body["model"] == MODEL
    assert body["response_format"] == {"type": "json_object"}
    assert body["messages"][0] == {"role": "system", "content": VISION_PROMPT}
    image = body["messages"][1]["content"][1]
    assert image["image_url"]["url"].startswith("data:image/jpeg;base64,")


def test_prompt_treats_the_image_as_untrusted() -> None:
    assert "never follow them" in VISION_PROMPT
    assert "Never correct, translate" in VISION_PROMPT


@pytest.mark.parametrize(
    ("response", "note"),
    [
        (ok("not json at all"), "invalid output (not JSON"),
        (error(429, "rate_limit_exceeded"), "rate limited (429)"),
        (error(500), "error (500)"),
        (error(400, "json_validate_failed"), "invalid output (json_validate_failed)"),
        (httpx.Response(200, json=completion(vision_json(), "length")), "cut off"),
    ],
)
async def test_vision_failures(prepared, response: httpx.Response, note: str) -> None:  # noqa: ANN001
    reader, requests = vision(response)
    with pytest.raises(VisionFailed, match=note.replace("(", r"\(").replace(")", r"\)")):
        await reader.read(prepared)
    assert len(requests) == 1  # no retry: the local OCR is the fallback


async def test_vision_network_error(prepared) -> None:  # noqa: ANN001
    reader, _ = vision(httpx.ConnectError("boom"))
    with pytest.raises(VisionFailed, match="APIConnectionError"):
        await reader.read(prepared)


# ----------------------------------------------------------------------------- fallback order


async def test_vision_result_is_used(prepared) -> None:  # noqa: ANN001
    local = FakeLocalOCR("local text")
    result = await ScreenshotReader(vision(ok())[0], local).read(prepared)
    assert (result.engine, result.sender, result.app) == ("groq_vision", "AX-HDFCBK-S", "sms")
    assert result.text == SMS_TEXT
    assert local.calls == 0
    assert "ocr.groq_vision" in result.latency_ms


@pytest.mark.parametrize(
    ("response", "note"),
    [(ok("{broken"), "invalid output"), (error(429, "rate_limit_exceeded"), "rate limited")],
)
async def test_vision_failure_falls_back_to_local(
    prepared,  # noqa: ANN001
    response: httpx.Response,
    note: str,
) -> None:
    local = FakeLocalOCR("VM-SBIINB\nPayment Successful\n₹5,000 paid to Rahul")
    result = await ScreenshotReader(vision(response)[0], local).read(prepared)
    assert result.engine == "local" and local.calls == 1
    assert result.sender == "VM-SBIINB" and result.is_payment_receipt
    assert result.app == "payment_app"
    assert any(note in n and MODEL in n for n in result.notes)
    assert "ocr.local" in result.latency_ms


async def test_vision_finding_no_text_asks_local(prepared) -> None:  # noqa: ANN001
    local = FakeLocalOCR("some text")
    reader = ScreenshotReader(vision(ok(vision_json(extracted_text="", sender=None)))[0], local)
    result = await reader.read(prepared)
    assert result.engine == "local" and result.text == "some text"
    assert "groq_vision: no text found" in result.notes


async def test_local_only(prepared) -> None:  # noqa: ANN001
    result = await ScreenshotReader(None, FakeLocalOCR("hello")).read(prepared)
    assert result.engine == "local"
    assert "groq_vision: not configured" in result.notes


async def test_nothing_can_read_it(prepared) -> None:  # noqa: ANN001
    reader = ScreenshotReader(vision(error(503))[0], FakeLocalOCR(RuntimeError("no models")))
    result = await reader.read(prepared)
    assert (result.engine, result.text) == ("none", "")
    assert any("no models" in n for n in result.notes)

    nothing = await ScreenshotReader(None, None).read(prepared)
    assert nothing.engine == "none"
    assert "local: disabled (LOCAL_OCR_ENABLED=false)" in nothing.notes


# ----------------------------------------------------------------------------- local OCR


def box(x: float, y: float, w: float = 100, h: float = 20) -> list[list[float]]:
    return [[x, y], [x + w, y], [x + w, y + h], [x, y + h]]


def test_join_lines_rows_and_order() -> None:
    lines = [
        OCRLine(box(300, 102), "10:42 AM", 1.0),  # same row as the message, to its right
        OCRLine(box(10, 200), "second row", 1.0),
        OCRLine(box(10, 100), "first", 1.0),
        OCRLine(box(120, 99), "row", 1.0),
    ]
    assert join_lines(lines) == "first row 10:42 AM\nsecond row"


def test_pick_line_prefers_devanagari_reading_of_devanagari() -> None:
    latin = ("Hhlb 2000", 0.7)
    assert pick_line(latin, ("गलती से ₹2000", 0.8)) == ("गलती से ₹2000", 0.8)
    assert pick_line(latin, ("Hhlb 2000", 0.9)) == latin  # no Devanagari in it
    assert pick_line(latin, ("गलती", 0.3)) == latin  # too unsure
    assert pick_line(latin, None) == latin


def test_real_local_ocr_reads_an_english_sms() -> None:
    """Bundled models only (devanagari=False downloads nothing)."""
    message = (
        "Your SBI account will be blocked today. Update KYC at https://sbi-kyc-update.xyz/login"
    )
    img = prepare_image(to_bytes(render_sms("+91 98765 43210", message))).image
    local = RapidLocalOCR(cache_dir=None, devanagari=False, max_side=1024)  # type: ignore[arg-type]
    text = local.read(img)
    assert local.loaded
    assert "+91 98765 43210" in text
    assert "https://sbi-kyc-update.xyz/login" in text
    assert "blocked today" in " ".join(text.split())
