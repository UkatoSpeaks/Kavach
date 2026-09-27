"""Decode a QR code from an uploaded PNG/JPEG image (zxing-cpp + Pillow, no OpenCV)."""

import io
from dataclasses import dataclass
from typing import Literal

import zxingcpp
from PIL import Image, UnidentifiedImageError

from app.services.extractors import extract_urls

MAX_IMAGE_BYTES = 5 * 1024 * 1024
ALLOWED_FORMATS = {"PNG": "image/png", "JPEG": "image/jpeg"}
# Refuse decompression bombs: a tiny file that expands to a huge bitmap.
MAX_PIXELS = 40_000_000

QRKind = Literal["upi", "url", "text"]


class QRError(ValueError):
    """Base class; `str(exc)` is safe to show to the user."""


class UnsupportedImageError(QRError):
    pass


class ImageTooLargeError(QRError):
    pass


class NoQRCodeError(QRError):
    pass


@dataclass(frozen=True)
class QRPayload:
    payload: str
    kind: QRKind


def classify(payload: str) -> QRKind:
    stripped = payload.strip()
    if stripped.lower().startswith("upi://"):
        return "upi"
    urls = extract_urls(stripped)
    if len(urls) == 1 and urls[0].raw == stripped:
        return "url"
    return "text"


def decode_qr(data: bytes) -> QRPayload:
    """First QR code in the image. Raises a QRError subclass on bad input."""
    if len(data) > MAX_IMAGE_BYTES:
        raise ImageTooLargeError(f"image is larger than {MAX_IMAGE_BYTES // (1024 * 1024)} MB")
    try:
        with Image.open(io.BytesIO(data)) as img:
            if img.format not in ALLOWED_FORMATS:
                raise UnsupportedImageError("only PNG and JPEG images are supported")
            if img.width * img.height > MAX_PIXELS:
                raise ImageTooLargeError("image dimensions are too large")
            gray = img.convert("L")
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError) as exc:
        raise UnsupportedImageError("not a readable PNG or JPEG image") from exc

    results = zxingcpp.read_barcodes(gray, formats=zxingcpp.BarcodeFormat.QRCode)
    payload = next((r.text for r in results if r.text and r.text.strip()), None)
    if payload is None:
        raise NoQRCodeError("no QR code found in the image")
    payload = payload.strip()
    return QRPayload(payload=payload, kind=classify(payload))
