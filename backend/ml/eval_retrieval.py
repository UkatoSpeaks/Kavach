"""Retrieval sanity check for the scam-pattern knowledge base.

For each test message: the top-3 scam patterns, the closest genuine pattern, and whether the
expected category is ranked first overall (scam and genuine matches together). Reports top-1
accuracy. Messages are written fresh for this eval; none is copied from the docs.

    uv run python -m ml.eval_retrieval          # retrieve from pgvector (run the ingest first)
    uv run python -m ml.eval_retrieval --local  # embed the docs in memory, no database
"""

import argparse
import asyncio
import sys
from contextlib import AsyncExitStack

from app.core.config import get_settings
from app.core.enums import ScamType
from app.db.session import create_engine, create_sessionmaker
from app.services import rag
from app.services.embeddings import FastEmbedder
from app.services.knowledge_base import GENUINE_CATEGORY, load_docs

T = ScamType
G = GENUINE_CATEGORY

# (expected category, message)
CASES: list[tuple[str, str]] = [
    (T.UPI_RECEIVE_MONEY,
     "Your wallet has received a ₹7,500 lucky reward. Tap the payment request and enter your "
     "UPI PIN to add it to your bank account."),
    (T.UPI_RECEIVE_MONEY,
     "Bhai tumhara paisa aa gaya hai, bas request approve karke PIN daalo, amount credit ho "
     "jayega."),
    (T.QR_CODE,
     "Hello, I saw your almirah on OLX and will pay the full amount. Scan the QR code I sent on "
     "WhatsApp to get the money."),
    (T.QR_CODE,
     "यह QR कोड स्कैन करें और ₹1,000 का कैशबैक तुरंत अपने खाते में पाएँ।"),
    (T.SENT_BY_MISTAKE,
     "Sir by mistake ₹6,000 transfer ho gaya aapke account me, please usi number pe return kar "
     "do, urgent hai."),
    (T.SENT_BY_MISTAKE,
     "I accidentally sent you Rs 3,500 through UPI. Kindly send it back, it was for my college "
     "fees."),
    (T.PHISHING_LINK,
     "Dear customer, your account will be blocked within 24 hours. Update your KYC now: "
     "http://bank-kyc-verify.top"),
    (T.PHISHING_LINK,
     "Your shipment is on hold due to unpaid customs charges. Pay Rs 49 now to release your "
     "package: https://post-track.xyz/pay"),
    (T.PHISHING_LINK,
     "Aapke vehicle par traffic challan pending hai, turant link se payment karo nahi to "
     "licence cancel ho jayega."),
    (T.TASK_JOB,
     "Earn money from home! Subscribe to YouTube channels and get ₹100 per task. Join our "
     "Telegram group for daily payments."),
    (T.TASK_JOB,
     "Aapka task complete ho gaya. Agla prepaid task ₹3,000 ka hai, deposit karo aur 30% "
     "profit ke saath wapas pao."),
    (T.FAKE_CUSTOMER_CARE,
     "Hello, I am calling from your bank's customer care. Please install AnyDesk so I can help "
     "you get your refund."),
    (T.FAKE_CUSTOMER_CARE,
     "Food delivery customer care helpline: for your refund call 9876501234 and share the "
     "details our executive asks for."),
    (G,
     "Rs.2,000.00 credited to A/c XX5566 on 20-09-26 by UPI from RAMESH KUMAR. UPI Ref "
     "426512341234. -Bank"),
    (G,
     "Your OTP for login is 918273. Valid for 3 minutes. Never share your OTP with anyone."),
    (G,
     "Your order has been delivered. Thank you for shopping with us. Rate your delivery "
     "experience in the app."),
]  # fmt: skip


def _short(text: str, n: int = 70) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


async def run(local: bool) -> None:
    settings = get_settings()
    embedder = FastEmbedder(
        settings.EMBEDDING_MODEL, settings.EMBEDDING_CACHE_DIR, settings.EMBEDDING_DIM
    )
    await embedder.load_async()
    params = rag.PatternParams.from_settings(settings)

    async with AsyncExitStack() as stack:
        if local:
            retriever: rag.Retriever = await rag.InMemoryRetriever.from_docs(load_docs(), embedder)
            print(f"retrieving from memory ({settings.EMBEDDING_MODEL})\n")
        else:
            engine = create_engine(settings.DATABASE_URL)
            stack.push_async_callback(engine.dispose)
            retriever = rag.retriever_in(create_sessionmaker(engine))
            print(f"retrieving from pgvector ({settings.EMBEDDING_MODEL})\n")
        search = rag.PatternSearch(embedder, retriever, params)

        hits = 0
        for i, (expected, text) in enumerate(CASES, 1):
            r = await rag.retrieve(text, search)
            ranked = sorted(
                [*r.scam, *([r.genuine] if r.genuine else [])],
                key=lambda m: m.similarity,
                reverse=True,
            )
            ok = bool(ranked) and ranked[0].category == expected
            hits += ok
            signal = rag.pattern_signal(r, params)
            score = f"{signal.score:.0f}" if signal.informative else "-"
            print(f"{i:2}. [{'OK' if ok else 'MISS'}] expected {expected}: {_short(text)}")
            for m in r.scam:
                print(f"      {m.similarity:.3f}  {m.category:<20} {m.slug}")
            if r.genuine:
                print(f"      {r.genuine.similarity:.3f}  {'genuine':<20} {r.genuine.slug}")
            print(f"      margin {r.margin:+.3f}  signal score {score}")

    print(f"\ntop-1 accuracy: {hits}/{len(CASES)} = {hits / len(CASES):.0%}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]  # ₹ and Hindi on Windows
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--local", action="store_true", help="embed docs in memory, no DB")
    asyncio.run(run(parser.parse_args().local))
