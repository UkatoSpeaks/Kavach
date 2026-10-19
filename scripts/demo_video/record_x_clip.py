"""Record short vertical "Scam or Not?" clips of the live Kavach site for X.

Throwaway tooling, not part of the app. Run from the repo root with:

    uv run --no-project --with playwright --with imageio-ffmpeg python scripts/demo_video/record_x_clip.py \
        --message "<text>" --label "<episode title>" --out scripts/demo_video/out/x-clip.mp4

or `--all` to make the four preset clips (x-launch, x-ep1..3) with a pause between them.

A phone viewport (390 CSS px wide, 9:16) is captured with the CDP screencast at 1080x1920
device pixels; Playwright's own recorder encodes at ~1 Mbit/s, which blurs text at that size.
The take is one continuous run; the loading wait is cut when the MP4 is assembled. A take
that errors or whose typed text doesn't land is thrown away and recorded again.
"""

from __future__ import annotations

import argparse
import base64
import random
import shutil
import sys
import time
from pathlib import Path

from playwright.sync_api import Page, sync_playwright
from record_demo import FFMPEG, SITE, SMOOTH_SCROLL_JS, ffmpeg, probe_duration, wait_for_api

OUT = Path(__file__).resolve().parent / "out"
RAW = OUT / "raw"

# 9:16 at a phone width; 390 x 2.769 = 1080 device px.
VW, VH = 390, 693
OW, OH = 1080, 1920
DPR = OW / VW
FPS = 30

RESULT_TIMEOUT_S = 45
LOADING_SHOWN_S = 1.2  # how much of the scanning animation stays in the video
TYPING_TARGET_S = 4.0  # long messages type faster so the clip stays short
PAUSE_BETWEEN_CLIPS_S = 20
MAX_TAKES = 3

HOOK_TITLE = "Scam or not? 🤔"
END_CARD = ("Kavach 🛡️", "Free scam checker for India", "kavach-mu-blush.vercel.app")
VERDICT_CAPTION = {
    "SCAM": "SCAM — and exactly why",
    "SUSPICIOUS": "SUSPICIOUS — and exactly why",
    "SAFE": "SAFE ✅",
}

PRESETS = [
    ("x-launch.mp4", "Launch: the ₹45,000 Paytm credit",
     ("Dear User, Rs.45,OOO has been cr3dited to y0ur Paytm wallet. "
     "Transfer to bank N0W: http://q7x3.com/wx91!7ab3c2")),
    ("x-ep1-electricity.mp4", "Ep 1: The electricity cut-off",
     ("Dear consumer, your electricity will be disconnected tonight at 9:30 PM because your "
     "previous bill was not updated. Please contact electricity officer 98XXX-XXX45 immediately.")),
    ("x-ep2-qr.mp4", "Ep 2: The army buyer's QR code",
     ("Hi sir, I am from Army, posted in Jammu. I want to buy your sofa for 12,000. I am sending "
     "QR code, please scan it and enter UPI PIN to receive the advance payment.")),
    ("x-ep3-safe.mp4", "Ep 3: A real bank credit alert",
     ("Rs.1,500.00 credited to your A/c XX4521 on 28-09-26 by UPI Ref No 426789123456 from "
     "RAHUL SHARMA. Available balance: Rs.23,410.50 -HDFC Bank")),
]

# Caption, hook/end cards and a tap marker, in the site's neo-brutalist style.
OVERLAY_JS = """
(() => {
  const install = () => {
    if (document.getElementById('__x_style')) return;
    const style = document.createElement('style');
    style.id = '__x_style';
    style.textContent = `
      .__x_font { font-family: var(--font-bricolage), "Segoe UI", "Nirmala UI",
        "Segoe UI Emoji", system-ui, sans-serif; }
      #__x_caption { position: fixed; left: 14px; right: 14px; bottom: 54px;
        z-index: 2147483646; padding: 12px 16px; border: 3px solid #111; border-radius: 16px;
        background: #4338ca; color: #fff; box-shadow: 5px 5px 0 #111; pointer-events: none;
        font-size: 26px; line-height: 1.2; font-weight: 800; text-align: center;
        opacity: 0; transform: translateY(14px);
        transition: opacity .3s ease, transform .3s ease; }
      #__x_caption.on { opacity: 1; transform: none; }
      #__x_tap { position: fixed; z-index: 2147483647; width: 30px; height: 30px;
        margin: -15px 0 0 -15px; border-radius: 50%; pointer-events: none;
        background: rgba(67, 56, 202, 0.30); border: 3px solid #4338ca; opacity: 0;
        transition: transform .12s ease, opacity .2s ease; left: -60px; top: -60px; }
      #__x_tap.on { opacity: 1; }
      #__x_tap.down { transform: scale(0.7); background: rgba(67, 56, 202, 0.7); }
      .__x_card { position: fixed; inset: 0; z-index: 2147483647; display: flex;
        flex-direction: column; align-items: center; justify-content: center; gap: 22px;
        padding: 28px; background: #fbf8f1; color: #111; text-align: center;
        transition: opacity .35s ease; }
      .__x_card.off { opacity: 0; }
      .__x_box { border: 4px solid #111; border-radius: 22px; background: #fff;
        box-shadow: 8px 8px 0 #111; padding: 30px 22px; width: 100%; }
      .__x_chip { display: inline-block; border: 3px solid #111; border-radius: 999px;
        background: #e0e7ff; padding: 4px 16px; font-size: 20px; font-weight: 800; }
      .__x_hook { font-size: 52px; line-height: 1.05; font-weight: 800; letter-spacing: -1px;
        margin-top: 18px; }
      .__x_label { margin-top: 18px; font-size: 25px; line-height: 1.25; font-weight: 700;
        color: #3730a3; }
      .__x_end_t { white-space: nowrap; font-size: 50px; font-weight: 800; letter-spacing: -1px; }
      .__x_end_s { font-size: 26px; font-weight: 700; margin-top: 10px; }
      .__x_end_u { margin-top: 22px; display: inline-block; background: #4338ca; color: #fff;
        border: 3px solid #111; border-radius: 14px; box-shadow: 4px 4px 0 #111;
        padding: 8px 12px; font-size: 18px; font-weight: 800; white-space: nowrap; }
    `;
    document.head.appendChild(style);
    const cap = document.createElement('div'); cap.id = '__x_caption'; cap.className = '__x_font';
    const tap = document.createElement('div'); tap.id = '__x_tap';
    document.body.append(cap, tap);
    document.addEventListener('mousemove', e => {
      tap.style.left = e.clientX + 'px'; tap.style.top = e.clientY + 'px';
    }, true);
    document.addEventListener('mousedown', () => tap.classList.add('on', 'down'), true);
    document.addEventListener('mouseup', () => {
      tap.classList.remove('down'); setTimeout(() => tap.classList.remove('on'), 350);
    }, true);
  };
  const card = (html) => {
    install();
    const el = document.createElement('div');
    el.className = '__x_card __x_font';
    el.innerHTML = html;
    document.body.appendChild(el);
    return el;
  };
  const esc = s => s.replace(/[&<>]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;'}[c]));
  window.__xCaption = (text) => {
    install();
    const cap = document.getElementById('__x_caption');
    if (!text) { cap.classList.remove('on'); return; }
    cap.textContent = text; cap.classList.add('on');
  };
  window.__xHook = (title, label) => {
    window.__xHookEl = card(`<div class="__x_box"><span class="__x_chip">Kavach 🛡️</span>
      <div class="__x_hook">${esc(title)}</div><div class="__x_label">${esc(label)}</div></div>`);
  };
  window.__xHookHide = () => {
    const el = window.__xHookEl;
    el.style.pointerEvents = 'none';
    el.classList.add('off');
    setTimeout(() => el.remove(), 400);
  };
  window.__xEnd = (t, s, u) => {
    card(`<div class="__x_box"><div class="__x_end_t">${esc(t)}</div>
      <div class="__x_end_s">${esc(s)}</div><div class="__x_end_u">${esc(u)}</div></div>`);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', install);
  else install();
})();
"""


class TakeFailed(Exception):
    pass


class Screencast:
    """JPEG frames from the CDP screencast, with the browser's capture timestamps."""

    def __init__(self, page: Page, frame_dir: Path) -> None:
        self.dir = frame_dir
        self.frames: list[tuple[float, Path]] = []
        self.cdp = page.context.new_cdp_session(page)
        self.cdp.on("Page.screencastFrame", self._on_frame)

    def _on_frame(self, ev: dict) -> None:
        path = self.dir / f"{len(self.frames):05d}.jpg"
        path.write_bytes(base64.b64decode(ev["data"]))
        self.frames.append((ev["metadata"]["timestamp"], path))
        self.cdp.send("Page.screencastFrameAck", {"sessionId": ev["sessionId"]})

    def start(self) -> None:
        self.cdp.send("Page.startScreencast", {
            "format": "jpeg", "quality": 92, "maxWidth": OW, "maxHeight": OH, "everyNthFrame": 1,
        })

    def stop(self) -> None:
        self.cdp.send("Page.stopScreencast")


class Timeline:
    """Wall-clock stretches to keep (the screencast stamps frames with wall-clock time)."""

    def __init__(self) -> None:
        self.keep: list[list[float]] = []

    def start(self) -> None:
        self.keep.append([time.time(), -1.0])

    def stop(self) -> None:
        self.keep[-1][1] = time.time()


def wait(page: Page, s: float) -> None:
    # page.wait_for_timeout (not time.sleep) so screencast frames keep being acknowledged.
    page.wait_for_timeout(s * 1000)


def caption(page: Page, text: str | None) -> None:
    page.evaluate("t => window.__xCaption(t)", text)


def scroll_to(page: Page, y: float, ms: int) -> None:
    page.evaluate(SMOOTH_SCROLL_JS, [y, ms])


def scroll_into_view(page: Page, locator, ms: int, offset: int) -> None:
    y = locator.evaluate("(el, off) => el.getBoundingClientRect().top + window.scrollY - off",
                         offset)
    scroll_to(page, max(0, y), ms)


def tap(page: Page, locator) -> None:
    box = locator.bounding_box()
    if box["y"] < 70 or box["y"] + box["height"] > VH - 150:  # off screen or under the caption
        scroll_into_view(page, locator, 500, offset=VH // 2 - int(box["height"] // 2))
        wait(page, 0.15)
        box = locator.bounding_box()
    page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2, steps=12)
    wait(page, 0.2)
    page.mouse.down()
    wait(page, 0.1)
    page.mouse.up()


def type_text(page: Page, text: str) -> None:
    base = min(45.0, max(8.0, TYPING_TARGET_S * 1000 / (len(text) * 1.3)))
    for ch in text:
        page.keyboard.type(ch)
        delay = base * random.uniform(0.55, 1.45) + (base * 0.8 if ch in " .,:" else 0)
        page.wait_for_timeout(delay)


def read_verdict(page: Page) -> str:
    """Wait for the verdict heading; fail the take on an error or a slow result."""
    heading = page.locator("h2[tabindex='-1']")
    error = page.get_by_role("alert")
    deadline = time.time() + RESULT_TIMEOUT_S
    while time.time() < deadline:
        if heading.count() and heading.first.is_visible():
            text = heading.first.inner_text().upper()
            for v in VERDICT_CAPTION:
                if v in text:
                    return v
        if error.count() and error.first.is_visible() and error.first.inner_text().strip():
            raise TakeFailed(f"the check showed an error: {error.first.inner_text()[:120]!r}")
        wait(page, 0.25)
    page.screenshot(path=str(OUT / "slow_result.png"), full_page=True)
    raise TakeFailed(f"the result took too long (see {OUT / 'slow_result.png'})")


def record_take(browser, message: str, label: str, frame_dir: Path) -> tuple[Screencast, Timeline, str]:
    ctx = browser.new_context(
        viewport={"width": VW, "height": VH}, device_scale_factor=DPR,
        reduced_motion="no-preference",
    )
    try:
        ctx.add_init_script(OVERLAY_JS)
        page = ctx.new_page()
        page.set_default_timeout(20_000)
        page.goto(f"{SITE}/check", wait_until="networkidle")
        field = page.locator("textarea").first
        field.wait_for(state="visible")
        wait(page, 1.0)  # let React hydrate, or it resets what was typed
        page.evaluate("a => window.__xHook(...a)", [HOOK_TITLE, label])
        wait(page, 0.5)

        cast, tl = Screencast(page, frame_dir), Timeline()
        cast.start()
        wait(page, 0.4)

        # a) Hook card
        tl.start()
        wait(page, 2.0)
        page.evaluate("window.__xHookHide()")
        wait(page, 0.35)

        # b) Type the message
        caption(page, "Paste any suspicious message")
        scroll_into_view(page, field, 400, offset=120)
        tap(page, field)
        field.focus()
        type_text(page, message)
        wait(page, 0.5)
        if field.input_value() != message:
            raise TakeFailed("the typed text didn't land")

        # c) Check -> verdict (the wait is cut)
        tap(page, page.get_by_role("button", name="Check now"))
        wait(page, LOADING_SHOWN_S)
        tl.stop()
        caption(page, None)
        verdict = read_verdict(page)
        wait(page, 0.8)  # let the result animate in
        heading = page.locator("h2[tabindex='-1']").first
        scroll_into_view(page, heading, 1, offset=90)
        caption(page, VERDICT_CAPTION[verdict])
        wait(page, 0.35)
        tl.start()
        wait(page, 2.0)

        # d) The highlighted words, then हिंदी
        caption(page, "Explained in English + हिंदी")
        marks = page.locator("mark")
        if marks.count():
            scroll_into_view(page, marks.first, 1400, offset=170)
            for i in range(min(marks.count(), 4)):
                box = marks.nth(i).bounding_box()
                if box and 60 < box["y"] < VH - 160:
                    page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2,
                                    steps=14)
                    wait(page, 0.45)
        hindi = page.get_by_role("button", name="हिंदी")
        scroll_into_view(page, hindi, 1200, offset=150)
        wait(page, 0.3)
        tap(page, hindi)
        wait(page, 2.5)

        # e) End card
        caption(page, None)
        page.evaluate("a => window.__xEnd(...a)", list(END_CARD))
        wait(page, 2.3)
        tl.stop()
        wait(page, 0.2)
        cast.stop()
        return cast, tl, verdict
    finally:
        ctx.close()


def build_mp4(cast: Screencast, tl: Timeline, out: Path, list_file: Path) -> None:
    """Concatenate the kept stretches; each frame lasts until the next one (or the cut)."""
    frames = cast.frames
    if not frames:
        raise TakeFailed("no frames captured")
    lines: list[str] = []
    last = frames[0][1]
    for a, b in tl.keep:
        # The frame on screen at the cut-in, then every frame inside the stretch.
        shown = [f for t, f in frames if t <= a][-1:] or [frames[0][1]]
        seq = [(a, shown[0])] + [(t, f) for t, f in frames if a < t < b]
        for (t, f), nxt in zip(seq, [s[0] for s in seq[1:]] + [b]):
            lines += [f"file '{f.as_posix()}'", f"duration {nxt - t:.4f}"]
            last = f
    lines.append(f"file '{last.as_posix()}'")
    list_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ffmpeg("-f", "concat", "-safe", "0", "-i", str(list_file),
           "-vf", f"scale={OW}:{OH}:flags=lanczos:out_range=tv,setsar=1,fps={FPS},format=yuv420p",
           "-c:v", "libx264", "-preset", "slow", "-crf", "20", "-profile:v", "high",
           "-maxrate", "6M", "-bufsize", "12M", "-r", str(FPS),
           "-movflags", "+faststart", "-an", str(out))


def make_clip(browser, message: str, label: str, out: Path) -> str:
    frame_dir = RAW / out.stem
    for take in range(1, MAX_TAKES + 1):
        shutil.rmtree(frame_dir, ignore_errors=True)
        frame_dir.mkdir(parents=True)
        print(f"[{out.name}] take {take} ...", flush=True)
        try:
            cast, tl, verdict = record_take(browser, message, label, frame_dir)
            break
        except TakeFailed as e:
            print(f"  take {take} failed: {e}; retrying in {PAUSE_BETWEEN_CLIPS_S}s", flush=True)
            time.sleep(PAUSE_BETWEEN_CLIPS_S)
    else:
        sys.exit(f"{out.name}: every take failed")
    out.parent.mkdir(parents=True, exist_ok=True)
    build_mp4(cast, tl, out, frame_dir / "frames.txt")
    shutil.rmtree(frame_dir, ignore_errors=True)  # ~65 MB of JPEGs per clip
    size = out.stat().st_size / 1024 / 1024
    print(f"[{out.name}] {probe_duration(out):.1f}s, {size:.2f} MB, verdict {verdict}", flush=True)
    return verdict


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--message")
    ap.add_argument("--label")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--all", action="store_true", help="make the four preset clips into out/")
    args = ap.parse_args()
    if args.all:
        jobs = [(msg, label, OUT / name) for name, label, msg in PRESETS]
    elif args.message and args.label and args.out:
        jobs = [(args.message, args.label, args.out)]
    else:
        ap.error("give --message, --label and --out, or --all")

    print("ffmpeg:", FFMPEG, flush=True)
    wait_for_api()
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        for i, (msg, label, out) in enumerate(jobs):
            if i:
                print(f"Waiting {PAUSE_BETWEEN_CLIPS_S}s between clips ...", flush=True)
                time.sleep(PAUSE_BETWEEN_CLIPS_S)
            make_clip(browser, msg, label, out)
        browser.close()


if __name__ == "__main__":
    main()
