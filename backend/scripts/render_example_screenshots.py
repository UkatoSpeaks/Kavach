"""Render the web app's example screenshots into frontend/public/examples/.

Three synthetic phone screenshots for the checker's "Try an example" chips: a KYC scam SMS
from a personal mobile number, a "sent by mistake" chat with a fake payment receipt, and a
genuine bank alert under a DLT business header. Every name, number, UPI ID, account and
domain is made up; no app's branding is copied.

    uv run python -m scripts.render_example_screenshots
"""

from pathlib import Path

from PIL import Image, ImageDraw

from tests.screenshots import font, wrap

OUT = Path(__file__).resolve().parents[2] / "frontend" / "public" / "examples"

W, H = 720, 1480
TEXT = 30
Color = tuple[int, int, int]


def _status_bar(d: ImageDraw.ImageDraw, bg: Color, fg: Color) -> None:
    d.rectangle((0, 0, W, 48), fill=bg)
    d.text((28, 10), "10:42", fill=fg, font=font(24))
    d.rounded_rectangle((W - 78, 16, W - 36, 34), 4, outline=fg, width=2)
    d.rectangle((W - 74, 20, W - 48, 30), fill=fg)
    for i, h in enumerate((6, 10, 14, 18)):
        d.rectangle((W - 130 + i * 9, 34 - h, W - 124 + i * 9, 34), fill=fg)


def _header(
    d: ImageDraw.ImageDraw, title: str, subtitle: str, bg: Color, fg: Color, avatar: Color
) -> int:
    d.rectangle((0, 48, W, 168), fill=bg)
    d.text((22, 80), "‹", fill=fg, font=font(52))
    d.ellipse((66, 78, 126, 138), fill=avatar)
    initial = "#" if title[0] in "+0123456789" else title[0]
    iw = font(28).getlength(initial)
    d.text((96 - iw / 2, 90), initial, fill="white", font=font(28))
    d.text((144, 76), title, fill=fg, font=font(32))
    d.text((144, 120), subtitle, fill=fg if bg == (7, 94, 84) else (100, 100, 100), font=font(22))
    return 168


def _bubble(
    img: Image.Image, top: int, text: str, fill: Color, time: str, *, width: int = W - 150
) -> int:
    d = ImageDraw.Draw(img)
    f = font(TEXT)
    lines = wrap(text, f, width - 56)
    lh = TEXT + 12
    h = lh * len(lines) + 70
    d.rounded_rectangle((24, top, 24 + width, top + h), 26, fill=fill)
    for i, line in enumerate(lines):
        d.text((50, top + 22 + i * lh), line, fill=(20, 20, 20), font=f)
    tw = font(20).getlength(time)
    d.text((24 + width - 24 - tw, top + h - 36), time, fill=(120, 120, 120), font=font(20))
    return top + h


def _input_bar(d: ImageDraw.ImageDraw, placeholder: str, bg: Color) -> None:
    d.rectangle((0, H - 110, W, H), fill=bg)
    d.rounded_rectangle((20, H - 92, W - 110, H - 28), 32, fill="white", outline=(210, 210, 210))
    d.text((50, H - 76), placeholder, fill=(150, 150, 150), font=font(26))
    d.ellipse((W - 90, H - 94, W - 22, H - 26), fill=(60, 120, 90))


def sms_scam() -> Image.Image:
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    _status_bar(d, (245, 245, 247), (0, 0, 0))
    y = _header(d, "+91 98765 43210", "Not in your contacts", (245, 245, 247), (0, 0, 0),
                (120, 130, 150))  # fmt: skip
    d.text((W // 2 - 70, y + 30), "Today 10:41 AM", fill=(130, 130, 130), font=font(22))
    _bubble(
        img,
        y + 80,
        "Dear Customer, your SBI YONO account will be BLOCKED today. Update your PAN/KYC "
        "immediately to avoid suspension: http://sbi-kyc-verify.top/update -SBI",
        (233, 233, 238),
        "10:41 AM",
    )
    _input_bar(d, "Text message", (245, 245, 247))
    return img


def _receipt(width: int) -> Image.Image:
    """A generic UPI 'payment successful' screen (no real app's branding)."""
    h = int(width * 1.15)
    img = Image.new("RGB", (width, h), (246, 250, 246))
    d = ImageDraw.Draw(img)
    cx = width // 2
    d.ellipse((cx - 50, 40, cx + 50, 140), fill=(40, 170, 90))
    d.line((cx - 24, 92, cx - 6, 110, cx + 28, 70), "white", 10)
    rows = [
        ("Payment Successful", font(30), 170), ("₹5,000", font(56), 220),
        ("Paid to Priya Sharma", font(24), 310), ("priya.s1990@okicici", font(24), 346),
        ("UPI transaction ID: 412345678901", font(20), 410),
        ("12 Sep 2026, 10:38 AM", font(20), 442),
    ]  # fmt: skip
    for text, f, y in rows:
        d.text((cx - f.getlength(text) / 2, y), text, fill=(20, 20, 20), font=f)
    return img


def payment_proof() -> Image.Image:
    green, beige = (7, 94, 84), (236, 229, 221)
    img = Image.new("RGB", (W, H), beige)
    d = ImageDraw.Draw(img)
    _status_bar(d, green, (255, 255, 255))
    y = _header(d, "+91 87654 32109", "online", green, (255, 255, 255), (100, 160, 150))
    # The forwarded "proof": a receipt image in a chat bubble.
    rw = W - 170
    d.rounded_rectangle((24, y + 30, 24 + rw + 20, y + 30 + int(rw * 1.15) + 60), 22, fill="white")
    img.paste(_receipt(rw), (34, y + 40))
    top = y + 30 + int(rw * 1.15) + 60
    d.text((24 + rw - 70, top - 40), "10:39 AM", fill=(120, 120, 120), font=font(20))
    _bubble(
        img,
        top + 20,
        "Sorry sir, I sent ₹5,000 to your number by mistake, screenshot above. Please send it "
        "back to rahul.k1987@ybl, it is urgent, my son's hospital fees.",
        (255, 255, 255),
        "10:40 AM",
    )
    _input_bar(d, "Message", beige)
    return img


def bank_alert() -> Image.Image:
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    _status_bar(d, (245, 245, 247), (0, 0, 0))
    y = _header(d, "AX-HDFCBK-S", "Business message", (245, 245, 247), (0, 0, 0), (40, 80, 160))
    d.text((W // 2 - 70, y + 30), "Today 9:15 AM", fill=(130, 130, 130), font=font(22))
    _bubble(
        img,
        y + 80,
        "Sent Rs.642.00 from HDFC Bank A/c **4821 to SWIGGY on 12-09-26. UPI Ref 412398765432. "
        "Not you? Call the number on the back of your card.",
        (233, 233, 238),
        "9:15 AM",
    )
    _input_bar(d, "This sender does not accept replies", (245, 245, 247))
    return img


EXAMPLES = {
    "shot-sms-scam.png": sms_scam,
    "shot-payment-proof.png": payment_proof,
    "shot-bank-alert.png": bank_alert,
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, render in EXAMPLES.items():
        path = OUT / name
        render().save(path, optimize=True)
        print(f"{path} ({path.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
