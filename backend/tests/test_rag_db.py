"""Pattern ingest + pgvector retrieval against the real database. All writes are rolled back."""

from datetime import timedelta

import httpx
import pytest
import respx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.enums import PatternKind, Verdict
from app.db.models import ScamPattern
from app.services import rag
from app.services.cache import LookupCache
from app.services.embeddings import EmbeddingUnavailable, FastEmbedder
from app.services.knowledge_base import PatternDoc, parse_doc
from app.services.pipeline import Checks, analyze
from scripts.ingest_patterns import ingest
from tests.conftest import SharedSessionFactory
from tests.examples import GENUINE_EXAMPLES, SCAM_EXAMPLES
from tests.fakes import FakeEmbedder
from tests.test_knowledge_base import GOOD

pytestmark = pytest.mark.db


def _doc(slug: str, title: str, kind: PatternKind = PatternKind.SCAM, **replace: str) -> PatternDoc:
    text = GOOD.replace("slug: demo", f"slug: {slug}").replace("Demo scam", title)
    if kind is PatternKind.GENUINE:
        text = text.replace("kind: scam", "kind: genuine").replace("qr_code", "genuine")
    for old, new in replace.items():
        text = text.replace(old, new)
    return parse_doc(text)


async def test_ingest_two_docs_and_retrieve_from_pgvector(db_session: AsyncSession) -> None:
    qr = _doc("test-qr-scan-to-receive", "Scan this QR code to receive money")
    otp = _doc("test-genuine-otp", "Your OTP is valid, do not share it", PatternKind.GENUINE)
    embedder = FakeEmbedder()

    # Inside the rolled-back transaction, the table ends up holding just these two docs.
    first = await ingest(db_session, [qr, otp], embedder)
    assert sorted(first.added) == sorted([qr.slug, otp.slug])
    assert sorted(first.reembedded) == sorted([qr.slug, otp.slug])
    assert await db_session.scalar(select(func.count()).select_from(ScamPattern)) == 2

    search = rag.PatternSearch(embedder, rag.retriever_in(SharedSessionFactory(db_session)))
    r = await rag.retrieve("please scan the qr code to receive the money", search)
    assert [m.slug for m in r.scam] == [qr.slug]
    assert r.scam[0].kind is PatternKind.SCAM and r.scam[0].category == "qr_code"
    assert r.genuine is not None and r.genuine.slug == otp.slug
    assert r.scam[0].similarity > r.genuine.similarity
    # pgvector's cosine distance agrees with the in-memory computation.
    expected = rag.cosine(embedder.vector("please scan the qr code to receive the money"),
                          embedder.vector(qr.embed_text))  # fmt: skip
    assert r.scam[0].similarity == pytest.approx(expected, abs=1e-5)

    # Idempotent: nothing changed, nothing re-embedded.
    calls = embedder.calls
    again = await ingest(db_session, [qr, otp], embedder)
    assert sorted(again.unchanged) == sorted([qr.slug, otp.slug]) and embedder.calls == calls

    # Metadata-only change: updated without re-embedding. Text change: re-embedded.
    sourced = _doc(qr.slug, qr.title, **{'source_url: ""': "source_url: https://example.org/a"})
    edited = _doc(otp.slug, "Genuine OTP message", PatternKind.GENUINE)
    third = await ingest(db_session, [sourced, edited], embedder)
    assert sorted(third.updated) == sorted([qr.slug, otp.slug])
    assert third.reembedded == [otp.slug]

    # A removed file deletes its row.
    fourth = await ingest(db_session, [sourced], embedder)
    assert fourth.deleted == [otp.slug]
    genuine = await rag.search_patterns(db_session, embedder.vector("otp"), PatternKind.GENUINE, 1)
    assert genuine == []


# ----------------------------------------------------------------------------- real model


@pytest.fixture(scope="module")
def real_embedder() -> FastEmbedder:
    s = get_settings()
    embedder = FastEmbedder(s.EMBEDDING_MODEL, s.EMBEDDING_CACHE_DIR, s.EMBEDDING_DIM)
    try:
        embedder.load()
    except EmbeddingUnavailable as exc:
        pytest.skip(f"embedding model unavailable: {exc}")
    return embedder


EXAMPLES = [(True, str(t), x) for t, x in SCAM_EXAMPLES] + [
    (False, label, x) for label, x in GENUINE_EXAMPLES
]


async def test_36_examples_keep_verdicts_with_real_patterns(
    db_session: AsyncSession, real_embedder: FastEmbedder
) -> None:
    """The ingested knowledge base + the real model must not change any example's verdict."""
    n = await db_session.scalar(select(func.count()).select_from(ScamPattern))
    assert n, "scam_patterns is empty: run `uv run python -m scripts.ingest_patterns`"
    settings = get_settings().model_copy(update={"SAFE_BROWSING_API_KEY": ""})
    search = rag.PatternSearch(
        real_embedder,
        rag.retriever_in(SharedSessionFactory(db_session)),
        rag.PatternParams.from_settings(settings),
    )
    failures = []
    with respx.mock as router:
        router.route().mock(side_effect=httpx.ConnectError("offline"))
        async with httpx.AsyncClient() as client:
            checks = Checks(client, LookupCache(None, timedelta(hours=1)), None, search)
            for is_scam, label, text in EXAMPLES:
                result = (await analyze(text, settings, checks=checks)).result
                pattern = next(s for s in result.signal_breakdown if s.source == rag.SOURCE)
                assert "unavailable" not in pattern.detail, pattern.detail
                want = Verdict.SCAM if is_scam else Verdict.SAFE
                if result.verdict is not want:
                    failures.append((label, result.risk_score, pattern.detail))
    assert not failures, failures
