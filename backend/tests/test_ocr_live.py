"""The real Groq vision model on generated screenshots. Deselected by default (uses quota,
~1.5k tokens per image); run with `pytest -m llm`."""

import pytest

from app.core.config import get_settings
from app.services.ocr import GroqVisionOCR, prepare_image
from tests.screenshots import render_sms, to_bytes
from tests.test_api_screenshot import INJECTION, PHISHING

pytestmark = pytest.mark.llm


@pytest.fixture
def vision() -> GroqVisionOCR:
    s = get_settings()
    if not s.GROQ_API_KEY or not s.GROQ_VISION_MODEL:
        pytest.skip("GROQ_API_KEY or GROQ_VISION_MODEL is not set")
    return GroqVisionOCR(s.GROQ_API_KEY, s.GROQ_VISION_MODEL, s.VISION_TIMEOUT_S)


async def test_real_vision_reads_an_sms_screenshot(vision: GroqVisionOCR) -> None:
    image = prepare_image(to_bytes(render_sms("+91 98765 43210", PHISHING)))
    reply, notes = await vision.read(image)
    text = " ".join(reply.extracted_text.split())
    assert "https://sbi-kyc-update.xyz/login" in text
    assert "SBI YONO account will be blocked" in text
    assert reply.sender is not None and "98765" in reply.sender, notes
    assert reply.app == "sms" and not reply.is_payment_receipt


async def test_real_vision_transcribes_injected_instructions(vision: GroqVisionOCR) -> None:
    """Instructions in the image are copied as text, not followed."""
    image = prepare_image(to_bytes(render_sms("+91 90000 11111", INJECTION)))
    reply, _ = await vision.read(image)
    text = " ".join(reply.extracted_text.split()).lower()
    assert "ignore previous instructions" in text
    assert "enter your upi pin" in text
