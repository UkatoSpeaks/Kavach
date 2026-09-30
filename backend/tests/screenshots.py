"""Synthetic phone screenshots rendered with Pillow, for the OCR tests and
ml/eval_screenshots.py. Every sender, number, UPI ID and amount is made up; no real
screenshots are used anywhere.

Fonts: the first installed font that covers the script (Nirmala UI on Windows, Noto /
Lohit / DejaVu on Linux), else Pillow's built-in Latin font. Without libraqm (Pillow's
Windows wheels) Devanagari is drawn without complex shaping, so vowel signs can sit in the
wrong place: Hindi OCR scores on these images are pessimistic.
"""

import io
from functools import lru_cache
from pathlib import Path

import qrcode
from PIL import Image, ImageDraw, ImageFont

WIDTH = 1080
FONT_SIZE = 34
LINE_GAP = 14

_LATIN_FONTS = [
    "C:/Windows/Fonts/Nirmala.ttc",
    "C:/Windows/Fonts/segoeui.ttf",
    "C:/Windows/Fonts/arial.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
]
_DEVANAGARI_FONTS = [
    "C:/Windows/Fonts/Nirmala.ttc",
    "C:/Windows/Fonts/mangal.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansDevanagari-Regular.ttf",
    "/usr/share/fonts/opentype/noto/NotoSansDevanagari-Regular.ttf",
    "/usr/share/fonts/truetype/lohit-devanagari/Lohit-Devanagari.ttf",
    "/System/Library/Fonts/Supplemental/Devanagari Sangam MN.ttc",
]

Font = ImageFont.FreeTypeFont | ImageFont.ImageFont


def _has_devanagari(text: str) -> bool:
    return any("\u0900" <= c <= "\u097f" for c in text)


@lru_cache
def font(size: int = FONT_SIZE, devanagari: bool = False) -> Font:
    for path in _DEVANAGARI_FONTS if devanagari else _LATIN_FONTS:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default(size)


def font_for(text: str, size: int = FONT_SIZE) -> Font:
    return font(size, _has_devanagari(text))


def has_devanagari_font() -> bool:
    return any(Path(p).exists() for p in _DEVANAGARI_FONTS)


def wrap(text: str, fnt: Font, max_width: int) -> list[str]:
    """Wrap each paragraph to max_width pixels."""
    lines: list[str] = []
    for paragraph in text.splitlines() or [""]:
        words = paragraph.split()
        line = ""
        for word in words:
            candidate = f"{line} {word}".strip()
            if line and fnt.getlength(candidate) > max_width:
                lines.append(line)
                line = word
            else:
                line = candidate
        lines.append(line)
    return lines


def to_bytes(img: Image.Image, fmt: str = "PNG", **save: object) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format=fmt, **save)
    return buf.getvalue()


def _line_height(fnt: Font) -> int:
    top, bottom = fnt.getbbox("Hgyक")[1::2]
    return int(bottom - top) + LINE_GAP


def render_sms(
    sender: str,
    message: str,
    *,
    time: str = "10:42 AM",
    bubble: tuple[int, int, int] = (233, 233, 238),
    header: tuple[int, int, int] = (245, 245, 245),
) -> Image.Image:
    """A messaging-app screenshot: the sender at the top, the message in a bubble."""
    fnt = font_for(message)
    head_fnt = font_for(sender, FONT_SIZE + 4)
    small = font(FONT_SIZE - 10)
    lines = wrap(message, fnt, WIDTH - 260)
    lh = _line_height(fnt)
    bubble_h = lh * len(lines) + 90
    height = max(1400, 260 + bubble_h + 200)
    img = Image.new("RGB", (WIDTH, height), "white")
    d = ImageDraw.Draw(img)
    d.rectangle((0, 0, WIDTH, 180), fill=header)
    d.text((110, 95), sender, fill="black", font=head_fnt)
    top = 260
    d.rounded_rectangle((40, top, WIDTH - 160, top + bubble_h), 36, fill=bubble)
    for i, line in enumerate(lines):
        d.text((80, top + 30 + i * lh), line, fill="black", font=fnt)
    d.text((80, top + bubble_h - 45), time, fill=(110, 110, 110), font=small)
    return img


def render_whatsapp(sender: str, message: str, **kw: object) -> Image.Image:
    return render_sms(sender, message, bubble=(220, 248, 198), header=(7, 94, 84), **kw)  # type: ignore[arg-type]


def render_receipt(
    amount: str = "₹5,000",
    payee: str = "Rahul Kumar",
    upi_id: str = "rahul.k1987@ybl",
    ref: str = "412345678901",
    *,
    title: str = "Payment Successful",
) -> Image.Image:
    """A UPI app's 'payment successful' screen (no real app's branding)."""
    big, mid = font(FONT_SIZE + 30), font(FONT_SIZE + 4)
    body = font(FONT_SIZE)
    img = Image.new("RGB", (WIDTH, 1500), (246, 250, 246))
    d = ImageDraw.Draw(img)
    d.ellipse((WIDTH // 2 - 90, 140, WIDTH // 2 + 90, 320), fill=(40, 170, 90))
    d.line((WIDTH // 2 - 45, 230, WIDTH // 2 - 10, 265, WIDTH // 2 + 50, 195), "white", 16)
    rows = [
        (title, mid, 400), (amount, big, 480), (f"Paid to {payee}", body, 620),
        (upi_id, body, 680), (f"UPI transaction ID: {ref}", body, 800),
        ("12 Sep 2026, 10:41 AM", body, 860),
    ]  # fmt: skip
    for text, fnt, y in rows:
        w = fnt.getlength(text)
        d.text(((WIDTH - w) / 2, y), text, fill="black", font=fnt)
    return img


def stack(*images: Image.Image, gap: int = 0) -> Image.Image:
    """Images one below the other (e.g. a receipt forwarded into a chat)."""
    width = max(i.width for i in images)
    height = sum(i.height for i in images) + gap * (len(images) - 1)
    out = Image.new("RGB", (width, height), "white")
    y = 0
    for i in images:
        out.paste(i, (0, y))
        y += i.height + gap
    return out


def render_with_qr(sender: str, message: str, payload: str) -> Image.Image:
    """A message screenshot with a QR code image below the text."""
    shot = render_sms(sender, message)
    code = qrcode.make(payload).get_image().convert("RGB").resize((500, 500))
    out = Image.new("RGB", (WIDTH, shot.height + 560), "white")
    out.paste(shot, (0, 0))
    out.paste(code, ((WIDTH - 500) // 2, shot.height + 20))
    return out


def reference_text(sender: str, message: str, time: str = "10:42 AM") -> str:
    """What a perfect OCR reads from render_sms, whitespace-joined."""
    return " ".join(f"{sender} {message} {time}".split())
