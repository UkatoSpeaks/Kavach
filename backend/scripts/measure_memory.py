"""Resident memory (RSS) of the API after startup and after N analyses.

Starts the real app (create_app + lifespan) in this process and posts to
/analyze/text?explain=false through an in-process ASGI client. No database writes and no
outbound network: the session is a fake and the network checks are off, which leaves the
code that runs on every request (extractors, rules, classifier, scoring, templates).

    uv run python -m scripts.measure_memory                      # classifier on
    uv run python -m scripts.measure_memory --no-classifier
    uv run python -m scripts.measure_memory --model path/to/other.json
    uv run python -m scripts.measure_memory --screenshots          # local OCR (no Groq)
    uv run python -m scripts.measure_memory --screenshots --no-devanagari

--screenshots posts generated phone screenshots (tests/screenshots.py) to
/analyze/screenshot with the vision model off, so every one goes through the local OCR,
which loads on the first request. Needs the dev dependencies (qrcode).

Run each configuration in a fresh process: memory a process has touched is rarely returned.
RSS here is the working set on Windows and VmRSS on Linux.
"""

import argparse
import asyncio
import ctypes
import gc
import sys
from datetime import timedelta
from pathlib import Path

import httpx

TEXTS = [
    "Dear customer your SBI account will be blocked today, update PAN immediately",
    "Congratulations! You have won Rs 25,000. Enter your UPI PIN to receive the money",
    "Hi, I sent Rs 2000 to your number by mistake, please return it on PhonePe",
    "Work from home, earn 5000 daily by liking YouTube videos, join our Telegram group",
    "Your electricity will be disconnected tonight at 9.30 pm, call the officer now",
    "Kya aap aaj shaam ghar pe ho? Maa ne khana bheja hai",
    "Your OTP for login is 482913. Do not share it with anyone. -HDFC Bank",
    "Rs 500 debited from A/c XX1234 to swiggy on 12-09-26. Not you? Call the bank",
    "Beware of fake KYC calls. RBI never asks for your password. Report fraud at 1930.",
    "Aapka parcel customs mein ruka hai, fees bharein warna return ho jayega",
]


def rss_mb(peak: bool = False) -> float:
    """Current RSS in MB, or (Windows only) the peak so far."""
    if sys.platform == "win32":
        from ctypes import wintypes

        class Counters(ctypes.Structure):  # PROCESS_MEMORY_COUNTERS
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (n, ctypes.c_size_t) for n in (
                    "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                    "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage",
                )
            ]  # fmt: skip

        c = Counters()
        c.cb = ctypes.sizeof(c)
        get_info = ctypes.windll.psapi.GetProcessMemoryInfo
        get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        ctypes.windll.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        if not get_info(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(c), c.cb):
            raise ctypes.WinError()
        return (c.PeakWorkingSetSize if peak else c.WorkingSetSize) / 2**20
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024
    raise RuntimeError("no RSS source on this platform")


async def run(args: argparse.Namespace) -> None:
    from app.api.deps import get_reasoner, get_session, get_session_factory
    from app.api.routes.analyze import get_checks
    from app.core.config import get_settings
    from app.main import create_app
    from app.services.cache import LookupCache
    from app.services.pipeline import Checks
    from tests.fakes import FakeSession, session_factory

    update = {"PATTERN_SIGNAL_ENABLED": False, "CLASSIFIER_ENABLED": not args.no_classifier,
              "RATE_LIMIT_ENABLED": False, "GROQ_VISION_MODEL": "",
              "LOCAL_OCR_ENABLED": args.screenshots,
              "LOCAL_OCR_DEVANAGARI": not args.no_devanagari}  # fmt: skip
    if args.model:
        update["CLASSIFIER_MODEL_PATH"] = args.model
    settings = get_settings().model_copy(update=update)
    base = rss_mb()
    app = create_app(settings)

    session = FakeSession()  # the background save goes here, not to the database

    async def fake_session():  # noqa: ANN202
        yield session

    async with app.router.lifespan_context(app):
        client = app.state.http_client
        factory = session_factory(session)
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_session] = fake_session
        app.dependency_overrides[get_session_factory] = lambda: factory
        app.dependency_overrides[get_reasoner] = lambda: None  # explain=false anyway
        app.dependency_overrides[get_checks] = lambda: Checks(
            client, LookupCache(None, timedelta(hours=1)), None, None, network=False
        )
        gc.collect()
        started = rss_mb()
        transport = httpx.ASGITransport(app=app)
        images = screenshots() if args.screenshots else []
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            for i in range(args.n):
                if args.screenshots:
                    files = {"image": ("s.png", images[i % len(images)], "image/png")}
                    resp = await http.post("/analyze/screenshot?explain=false", files=files)
                else:
                    resp = await http.post("/analyze/text?explain=false",
                                           json={"text": TEXTS[i % len(TEXTS)]})  # fmt: skip
                resp.raise_for_status()
        gc.collect()
        after = rss_mb()
    label = "classifier OFF" if args.no_classifier else "classifier ON"
    if args.screenshots:
        label += ", local OCR" + ("" if args.no_devanagari else " + Devanagari")
    print(f"{label}: python+imports {base:.0f} MB -> after startup {started:.0f} MB -> "
          f"after {args.n} analyses {after:.0f} MB"
          + (f" (peak {rss_mb(peak=True):.0f} MB)" if sys.platform == "win32" else ""))  # fmt: skip


def screenshots() -> list[bytes]:
    """Phone-sized PNGs (1080 px wide), English and Hindi."""
    from tests.screenshots import render_sms, to_bytes

    return [to_bytes(render_sms(f"+91 98{i:03d} 43210", text)) for i, text in enumerate(TEXTS)] + [
        to_bytes(render_sms("+91 99887 76655", "मैंने गलती से आपके खाते में ₹2000 भेज दिए हैं"))
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-classifier", action="store_true")
    parser.add_argument("--model", help="classifier JSON to load instead of the configured one")
    parser.add_argument("-n", type=int, default=20)
    parser.add_argument("--screenshots", action="store_true", help="POST /analyze/screenshot")
    parser.add_argument("--no-devanagari", action="store_true", help="local OCR: Latin only")
    args = parser.parse_args()
    if args.model:
        args.model = Path(args.model).resolve()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
