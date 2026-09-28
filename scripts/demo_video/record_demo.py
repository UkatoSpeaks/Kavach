"""Record a scripted demo video of the live Kavach site (LinkedIn post + README GIF).

Throwaway tooling, not part of the app. Run from the repo root with:

    uv run --no-project --with playwright --with imageio-ffmpeg python scripts/demo_video/record_demo.py

Uses the system Edge (channel="msedge"), so no Playwright browser download is needed.
Writes scripts/demo_video/out/kavach-demo.mp4 and docs/demo.gif.

The recording is one continuous take. Each scene logs the stretch of video worth keeping;
loading waits and the pause between the two checks are cut out when the MP4 is assembled.
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import imageio_ffmpeg
from playwright.sync_api import Page, TimeoutError as PWTimeout, sync_playwright

API_HEALTH = "https://kavach-api-mib4.onrender.com/health"
SITE = "https://kavach-mu-blush.vercel.app"

SCAM_MSG = (
    "Dear User, Rs.45,OOO has been cr3dited to y0ur Paytm wallet. "
    "Transfer to bank N0W: http://q7x3.com/wx91!7ab3c2"
)
SAFE_MSG = (
    "Rs.1,500.00 credited to your A/c XX4521 by UPI Ref No 426789123456 from RAHUL SHARMA. "
    "Available balance: Rs.23,410.50 -HDFC Bank"
)
END_CARD = ("Kavach 🛡️", "kavach-mu-blush.vercel.app", "github.com/UkatoSpeaks/Kavach")

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "out"
RAW = OUT / "raw"
MP4 = OUT / "kavach-demo.mp4"
GIF = ROOT / "docs" / "demo.gif"
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()

W, H = 1280, 720
RESULT_TIMEOUT_MS = 45_000
PAUSE_BETWEEN_CHECKS_S = 20
LOADING_SHOWN_S = 1.6  # how much of the scanning animation stays in the video

# Caption bar, end card and a visible cursor (headless recordings have none).
OVERLAY_JS = """
(() => {
  const install = () => {
    if (document.getElementById('__demo_style')) return;
    const style = document.createElement('style');
    style.id = '__demo_style';
    style.textContent = `
      #__demo_caption { position: fixed; left: 0; right: 0; bottom: 0; z-index: 2147483646;
        display: flex; justify-content: center; padding: 18px 40px 22px;
        background: rgba(10, 10, 20, 0.82); color: #fff; pointer-events: none;
        font: 700 34px/1.25 "Segoe UI", "Nirmala UI", system-ui, sans-serif; text-align: center;
        letter-spacing: 0.2px; opacity: 0; transform: translateY(12px);
        transition: opacity .35s ease, transform .35s ease; }
      #__demo_caption.on { opacity: 1; transform: none; }
      #__demo_cursor { position: fixed; z-index: 2147483647; width: 22px; height: 22px;
        margin: -11px 0 0 -11px; border-radius: 50%; pointer-events: none;
        background: rgba(79, 70, 229, 0.35); border: 3px solid #4f46e5;
        transition: transform .12s ease; left: -50px; top: -50px; }
      #__demo_cursor.down { transform: scale(0.7); background: rgba(79, 70, 229, 0.7); }
      #__demo_end { position: fixed; inset: 0; z-index: 2147483647; display: flex;
        flex-direction: column; align-items: center; justify-content: center; gap: 18px;
        background: #11111b; color: #fff; opacity: 0; transition: opacity .5s ease;
        font-family: "Segoe UI", "Segoe UI Emoji", system-ui, sans-serif; }
      #__demo_end.on { opacity: 1; }
      #__demo_end .t { font-size: 84px; font-weight: 800; }
      #__demo_end .u { font-size: 36px; font-weight: 600; color: #c7d2fe; }
      #__demo_end .g { font-size: 30px; font-weight: 500; color: #a1a1aa; }
    `;
    document.head.appendChild(style);
    const cap = document.createElement('div'); cap.id = '__demo_caption';
    const cur = document.createElement('div'); cur.id = '__demo_cursor';
    document.body.append(cap, cur);
    const pos = window.__demoCursor;
    if (pos) { cur.style.left = pos[0] + 'px'; cur.style.top = pos[1] + 'px'; }
    document.addEventListener('mousemove', e => {
      cur.style.left = e.clientX + 'px'; cur.style.top = e.clientY + 'px';
      window.__demoCursor = [e.clientX, e.clientY];
    }, true);
    document.addEventListener('mousedown', () => cur.classList.add('down'), true);
    document.addEventListener('mouseup', () => cur.classList.remove('down'), true);
  };
  window.__setCaption = (text) => {
    install();
    const cap = document.getElementById('__demo_caption');
    if (!text) { cap.classList.remove('on'); return; }
    cap.textContent = text; cap.classList.add('on');
  };
  window.__endCard = (t, u, g) => {
    install();
    const end = document.createElement('div'); end.id = '__demo_end';
    end.innerHTML = '<div class="t"></div><div class="u"></div><div class="g"></div>';
    end.querySelector('.t').textContent = t;
    end.querySelector('.u').textContent = u;
    end.querySelector('.g').textContent = g;
    document.body.appendChild(end);
    requestAnimationFrame(() => requestAnimationFrame(() => end.classList.add('on')));
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', install);
  else install();
})();
"""

SMOOTH_SCROLL_JS = """
([target, ms]) => new Promise(done => {
  const start = window.scrollY, dist = target - start, t0 = performance.now();
  const step = now => {
    const p = Math.min(1, (now - t0) / ms);
    const e = p < 0.5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2;
    window.scrollTo(0, start + dist * e);
    p < 1 ? requestAnimationFrame(step) : done();
  };
  requestAnimationFrame(step);
})
"""


class Timeline:
    """Seconds since recording started, and the stretches of it to keep."""

    def __init__(self) -> None:
        self.t0 = time.monotonic()
        self.keep: list[list[float]] = []
        self.labels: dict[str, float] = {}  # scene -> start in the *output* timeline

    def now(self) -> float:
        return time.monotonic() - self.t0

    def start(self, label: str | None = None) -> None:
        if label:
            self.labels[label] = sum(b - a for a, b in self.keep)
        self.keep.append([self.now(), -1.0])

    def stop(self) -> None:
        self.keep[-1][1] = self.now()


def wait_for_api() -> None:
    print("Waking the API ...", flush=True)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(API_HEALTH, timeout=20) as r:
                if r.status == 200:
                    print("API is up:", r.read()[:120].decode(errors="replace"), flush=True)
                    return
        except Exception as e:  # noqa: BLE001 - keep polling while the free dyno boots
            print("  not yet:", type(e).__name__, flush=True)
        time.sleep(4)
    sys.exit("API did not wake up within 3 minutes")


def caption(page: Page, text: str | None) -> None:
    page.evaluate("t => window.__setCaption(t)", text)


def pause(s: float) -> None:
    time.sleep(s)


def scroll_to(page: Page, y: float, ms: int) -> None:
    page.evaluate(SMOOTH_SCROLL_JS, [y, ms])


def scroll_into_view(page: Page, locator, ms: int, offset: int = 110) -> None:
    y = locator.evaluate(
        "(el, off) => el.getBoundingClientRect().top + window.scrollY - off", offset
    )
    scroll_to(page, max(0, y), ms)


def move_and_click(page: Page, locator) -> None:
    box = locator.bounding_box()
    x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
    page.mouse.move(x, y, steps=18)
    pause(0.25)
    page.mouse.down()
    pause(0.08)
    page.mouse.up()


def human_type(page: Page, text: str, base_ms: float) -> None:
    for ch in text:
        page.keyboard.type(ch)
        delay = base_ms * random.uniform(0.55, 1.45)
        if ch in " .,:":
            delay += base_ms * 0.8
        time.sleep(delay / 1000)


def run_check(page: Page, tl: Timeline, text: str, type_ms: float, label: str,
              cap_type: str, cap_result: str) -> None:
    """Type a message, check it, and keep only the start of the loading animation.

    Retries the check (cancel + resubmit) if the result is slow, so the video never
    shows a long wait. The keep-window is closed while waiting and reopened on the result.
    """
    field = page.locator("textarea").first
    field.wait_for(state="visible")
    page.wait_for_load_state("networkidle")
    pause(0.8)  # let React hydrate, or it resets what was typed
    scroll_into_view(page, field, 500, offset=200)
    for attempt in range(1, 4):
        tl.start(label if attempt == 1 else None)
        caption(page, cap_type)
        move_and_click(page, field)
        field.focus()
        human_type(page, text, type_ms)
        pause(0.6)
        if field.input_value() == text:
            break
        # Typing was lost: cut this take and type it again.
        tl.stop()
        print(f"  typed text didn't land (attempt {attempt}), retyping", flush=True)
        field.fill("")
        pause(0.5)
    else:
        sys.exit("Could not type into the message field")

    submit = page.get_by_role("button", name="Check now")
    caption(page, cap_result)
    for attempt in range(1, 4):
        move_and_click(page, submit)
        pause(LOADING_SHOWN_S)
        tl.stop()
        try:
            page.get_by_text("How we decided").first.wait_for(timeout=RESULT_TIMEOUT_MS)
            break
        except PWTimeout:
            print(f"  result slow (attempt {attempt}), retrying", flush=True)
            page.screenshot(path=str(OUT / f"slow_{label}_{attempt}.png"), full_page=True)
            cancel = page.get_by_role("button", name="Cancel")
            if cancel.count():
                cancel.first.click()
            pause(5)
            tl.start()
            continue
    else:
        sys.exit("The check never returned a result")
    pause(0.8)  # let the result animate in before the video resumes
    page.evaluate("window.scrollTo(0, 0)")  # the result card is at the top of its column
    pause(0.3)
    tl.start()


def record() -> tuple[Path, Timeline]:
    RAW.mkdir(parents=True, exist_ok=True)
    for old in RAW.glob("*.webm"):
        old.unlink()

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)

        # Unrecorded warm-up so Vercel's edge cache and fonts are hot.
        warm = browser.new_context(viewport={"width": W, "height": H})
        wp = warm.new_page()
        wp.goto(SITE, wait_until="networkidle")
        wp.goto(f"{SITE}/check", wait_until="networkidle")
        warm.close()

        ctx = browser.new_context(
            viewport={"width": W, "height": H},
            device_scale_factor=1,
            record_video_dir=str(RAW),
            record_video_size={"width": W, "height": H},
            reduced_motion="no-preference",
        )
        ctx.add_init_script(OVERLAY_JS)
        page = ctx.new_page()
        tl = Timeline()
        page.set_default_timeout(20_000)

        # a) Landing page
        page.goto(SITE, wait_until="networkidle")
        pause(1.0)
        page.mouse.move(640, 360)
        tl.start("a")
        caption(page, "Kavach: AI scam checker for India")
        pause(1.2)
        scroll_to(page, 520, 2600)
        pause(0.6)
        scroll_to(page, 0, 1200)
        pause(0.4)
        tl.stop()

        # b) + c) Scam message
        page.goto(f"{SITE}/check", wait_until="networkidle")
        pause(1.0)
        run_check(page, tl, SCAM_MSG, 38, "b", "Paste any suspicious message",
                  "Instant verdict with the exact red flags highlighted")
        pause(2.2)

        # d) Highlighted words, then हिंदी
        marks = page.locator("mark")
        if marks.count():
            first = marks.first
            scroll_into_view(page, first, 700, offset=260)
            box = first.bounding_box()
            page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2, steps=20)
            pause(1.6)
        tl.labels["d"] = sum(b - a for a, b in tl.keep[:-1]) + (tl.now() - tl.keep[-1][0])
        caption(page, "Explained in English and हिंदी")
        hindi = page.get_by_role("button", name="हिंदी")
        scroll_into_view(page, hindi, 600, offset=300)
        pause(0.4)
        move_and_click(page, hindi)
        pause(2.6)
        tl.labels["d_end"] = sum(b - a for a, b in tl.keep[:-1]) + (tl.now() - tl.keep[-1][0])

        # e) How we decided
        caption(page, "Every signal is explainable")
        scroll_into_view(page, page.get_by_text("How we decided").first, 1100, offset=90)
        pause(2.8)
        tl.stop()

        # Rate limit / Groq quota breather (cut from the video).
        english = page.get_by_role("button", name="English")
        if english.count():
            english.first.click()
        caption(page, None)
        print(f"Waiting {PAUSE_BETWEEN_CHECKS_S}s between checks ...", flush=True)
        pause(PAUSE_BETWEEN_CHECKS_S)
        page.get_by_role("button", name="Check another").first.click()
        pause(0.8)
        page.evaluate("window.scrollTo(0, 0)")
        pause(0.4)

        # f) Genuine bank alert
        run_check(page, tl, SAFE_MSG, 16, "f", "…and real bank alerts stay safe",
                  "…and real bank alerts stay safe")
        pause(3.0)
        tl.stop()

        # g) End card
        page.evaluate("window.__setCaption(null)")
        page.evaluate("a => window.__endCard(...a)", list(END_CARD))
        pause(0.3)
        tl.start("g")
        pause(3.2)
        tl.stop()

        video = page.video.path()
        ctx.close()
        browser.close()

    return Path(video), tl


def ffmpeg(*args: str) -> None:
    subprocess.run([FFMPEG, "-y", "-hide_banner", "-loglevel", "error", *args], check=True)


def probe_duration(path: Path) -> float:
    out = subprocess.run([FFMPEG, "-i", str(path)], capture_output=True, text=True).stderr
    hms = out.split("Duration: ")[1].split(",")[0]
    h, m, s = hms.split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


def build_mp4(raw: Path, tl: Timeline) -> None:
    parts = []
    for i, (a, b) in enumerate(tl.keep):
        parts.append(f"[0:v]trim=start={a:.3f}:end={b:.3f},setpts=PTS-STARTPTS[v{i}]")
    concat = "".join(f"[v{i}]" for i in range(len(tl.keep)))
    graph = ";".join(parts) + f";{concat}concat=n={len(tl.keep)}:v=1:a=0,fps=30,format=yuv420p[out]"
    ffmpeg("-i", str(raw), "-filter_complex", graph, "-map", "[out]",
           "-c:v", "libx264", "-preset", "slow", "-crf", "20", "-profile:v", "high",
           "-movflags", "+faststart", "-an", str(MP4))


def build_gif(tl: Timeline) -> None:
    start, end = tl.labels["b"], tl.labels["d_end"]
    dur = end - start
    speed = max(1.0, dur / 14.0)  # keep the GIF within 10-15 s
    GIF.parent.mkdir(parents=True, exist_ok=True)
    for width, fps in ((800, 12), (720, 10), (640, 10)):
        vf = (f"setpts=PTS/{speed:.3f},fps={fps},scale={width}:-1:flags=lanczos,"
              "split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];"
              "[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle")
        ffmpeg("-ss", f"{start:.3f}", "-t", f"{dur:.3f}", "-i", str(MP4), "-vf", vf,
               "-loop", "0", str(GIF))
        if GIF.stat().st_size < 5 * 1024 * 1024:
            break


def main() -> None:
    wait_for_api()
    raw, tl = record()
    print("Keep segments:", json.dumps(tl.keep), "labels:", json.dumps(tl.labels), flush=True)
    build_mp4(raw, tl)
    build_gif(tl)
    for f in (MP4, GIF):
        print(f"{f.relative_to(ROOT)}: {probe_duration(f):.1f}s, "
              f"{f.stat().st_size / 1024 / 1024:.2f} MB")


if __name__ == "__main__":
    main()
