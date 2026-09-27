"""Retrieval over the scam-pattern knowledge base -> the "pattern_similarity" signal.

The message is embedded and compared (cosine similarity, pgvector) with the knowledge-base
docs: the top-k scam patterns, and the single closest genuine-message pattern.

The signal is driven by the *margin* between the closest scam pattern and the closest
genuine pattern, not by raw similarity. Genuine bank alerts and OTP messages share most of
their vocabulary with scams ("account", "UPI", "OTP", "KYC"), so a genuine SMS can be very
similar to a scam pattern too. Only when a message is clearly closer to a scam than to any
genuine message does the signal count as evidence.

It is one-directional and deliberately weak:
- A small or negative margin is uninformative, never evidence of safety: a scam written to
  look like a bank alert must not be scored down for it.
- A clear margin scores 60-100, with a low weight in config (SIGNAL_WEIGHTS).
- It never sets a minimum score, and scoring.score() stops it from making a result a scam
  on its own (can_decide_scam=False).
"""

import asyncio
import math
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.enums import PatternKind, ScamType
from app.db.models import ScamPattern
from app.db.session import SessionFactory
from app.schemas.analysis import SimilarPattern
from app.services.embeddings import Embedder, EmbeddingUnavailable
from app.services.knowledge_base import PatternDoc
from app.services.scoring import SignalOutcome

SOURCE = "pattern_similarity"
# Score range for an informative match: a clear lean towards a known scam pattern is
# moderate evidence, not proof.
MIN_SCORE = 60
MAX_SCORE = 100


@dataclass(frozen=True)
class PatternMatch:
    slug: str
    title: str
    category: str
    kind: PatternKind
    similarity: float  # cosine similarity, -1..1
    source_url: str | None = None


# Returns the k patterns of one kind closest to an embedding, most similar first. The app
# uses pgvector (retriever_in); tests and offline evals use InMemoryRetriever.
Retriever = Callable[[Sequence[float], PatternKind, int], Awaitable[list[PatternMatch]]]


# --------------------------------------------------------------------------- pgvector


async def search_patterns(
    session: AsyncSession, embedding: Sequence[float], kind: PatternKind, k: int
) -> list[PatternMatch]:
    distance = ScamPattern.embedding.cosine_distance(list(embedding))
    stmt = (
        select(
            ScamPattern.slug,
            ScamPattern.title,
            ScamPattern.category,
            ScamPattern.kind,
            ScamPattern.source_url,
            distance.label("distance"),
        )
        .where(ScamPattern.kind == kind.value, ScamPattern.embedding.is_not(None))
        .order_by(distance)
        .limit(k)
    )
    return [
        PatternMatch(
            slug=r.slug,
            title=r.title,
            category=r.category,
            kind=PatternKind(r.kind),
            similarity=1 - r.distance,
            source_url=r.source_url,
        )
        for r in await session.execute(stmt)
    ]


def retriever_in(session_factory: SessionFactory) -> Retriever:
    """search_patterns on a short-lived session of its own."""

    async def retrieve(embedding: Sequence[float], kind: PatternKind, k: int) -> list[PatternMatch]:
        async with session_factory() as session:
            return await search_patterns(session, embedding, kind, k)

    return retrieve


# --------------------------------------------------------------------------- in memory


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b))
    return dot / norm if norm else 0.0


class InMemoryRetriever:
    """A Retriever over docs embedded in memory, for tests and offline evaluation."""

    def __init__(self, entries: Sequence[tuple[PatternDoc, Sequence[float]]]) -> None:
        self.entries = list(entries)

    @classmethod
    async def from_docs(cls, docs: Sequence[PatternDoc], embedder: Embedder) -> "InMemoryRetriever":
        vectors = await embedder.embed([d.embed_text for d in docs])
        return cls(list(zip(docs, vectors, strict=True)))

    async def __call__(
        self, embedding: Sequence[float], kind: PatternKind, k: int
    ) -> list[PatternMatch]:
        matches = [
            PatternMatch(d.slug, d.title, d.category, d.kind, cosine(embedding, vec), d.source_url)
            for d, vec in self.entries
            if d.kind is kind
        ]
        return sorted(matches, key=lambda m: m.similarity, reverse=True)[:k]


# --------------------------------------------------------------------------- signal


@dataclass(frozen=True)
class PatternParams:
    top_k: int = 3
    min_margin: float = 0.05
    full_margin: float = 0.20
    min_similarity: float = 0.35
    min_words: int = 0  # shorter messages skip the signal

    @classmethod
    def from_settings(cls, settings: Settings) -> "PatternParams":
        return cls(
            top_k=settings.PATTERN_TOP_K,
            min_margin=settings.PATTERN_MIN_MARGIN,
            full_margin=settings.PATTERN_FULL_MARGIN,
            min_similarity=settings.PATTERN_MIN_SIMILARITY,
            min_words=settings.PATTERN_MIN_WORDS,
        )


@dataclass(frozen=True)
class PatternSearch:
    """What the pattern signal needs: an embedder and a retriever."""

    embedder: Embedder
    retrieve: Retriever
    params: PatternParams = PatternParams()


@dataclass(frozen=True)
class Retrieval:
    scam: list[PatternMatch]  # top-k, most similar first
    genuine: PatternMatch | None  # the closest genuine-message pattern

    @property
    def margin(self) -> float | None:
        if not self.scam or self.genuine is None:
            return None
        return self.scam[0].similarity - self.genuine.similarity


async def retrieve(text: str, search: PatternSearch) -> Retrieval:
    [embedding] = await search.embedder.embed([text])
    scam, genuine = await asyncio.gather(
        search.retrieve(embedding, PatternKind.SCAM, search.params.top_k),
        search.retrieve(embedding, PatternKind.GENUINE, 1),
    )
    return Retrieval(scam=scam, genuine=genuine[0] if genuine else None)


def similar_patterns(retrieval: Retrieval, params: PatternParams) -> list[SimilarPattern]:
    return [
        SimilarPattern(
            slug=m.slug,
            title=m.title,
            category=m.category,
            similarity=round(min(max(m.similarity, 0.0), 1.0), 4),
            source_url=m.source_url,
        )
        for m in retrieval.scam
        if m.similarity >= params.min_similarity
    ]


def pattern_score(margin: float, params: PatternParams) -> float | None:
    """0-100 score for a margin, or None if the margin is too small to count."""
    if margin < params.min_margin:
        return None
    strength = min(1.0, (margin - params.min_margin) / (params.full_margin - params.min_margin))
    return round(MIN_SCORE + (MAX_SCORE - MIN_SCORE) * strength, 1)


def pattern_signal(retrieval: Retrieval, params: PatternParams) -> SignalOutcome:
    """Pure. Only informative when the message is clearly closer to a scam pattern."""
    similar = tuple(similar_patterns(retrieval, params))
    if not retrieval.scam:
        return SignalOutcome(SOURCE, 0, "knowledge base is empty", informative=False)
    top = retrieval.scam[0]
    if retrieval.genuine is None:
        return SignalOutcome(
            SOURCE,
            0,
            f"closest scam pattern {top.slug} ({top.similarity:.2f}); no genuine patterns to "
            "compare against",
            informative=False,
            similar_patterns=similar,
        )
    margin = top.similarity - retrieval.genuine.similarity
    compared = (
        f"closest scam pattern {top.slug} ({top.similarity:.2f}) vs closest genuine "
        f"{retrieval.genuine.slug} ({retrieval.genuine.similarity:.2f}), margin {margin:+.2f}"
    )
    score = pattern_score(margin, params)
    if score is None or top.similarity < params.min_similarity:
        return SignalOutcome(
            SOURCE,
            0,
            f"{compared}: not clearly closer to a scam",
            informative=False,
            similar_patterns=similar,
            can_decide_scam=False,
        )
    return SignalOutcome(
        SOURCE,
        score,
        compared,
        scam_type=ScamType(top.category),
        similar_patterns=similar,
        can_decide_scam=False,
    )


SKIPPED_SHORT = "skipped: message too short for reliable similarity"


async def pattern_similarity(text: str, search: PatternSearch) -> SignalOutcome:
    if len(text.split()) < search.params.min_words:
        return SignalOutcome(SOURCE, 0, SKIPPED_SHORT, informative=False)
    try:
        retrieval = await retrieve(text, search)
    except EmbeddingUnavailable as exc:
        return SignalOutcome(SOURCE, None, f"embedding {exc}")
    return pattern_signal(retrieval, search.params)
