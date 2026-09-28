"""In-memory stand-ins for the database, so API tests that only exercise the pipeline and
routes don't round-trip to Supabase. Real persistence is covered by the @pytest.mark.db tests.
"""

import hashlib
import re
import uuid
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

import groq
import httpx

from app.core.enums import EntityType
from app.db.models import ReportedEntity
from app.services import rag
from app.services.agent.llm import Evidence, LLMAssessment, ReasonResult
from app.services.embeddings import EmbeddingUnavailable, unit
from app.services.knowledge_base import PatternDoc, load_docs
from app.services.reputation import normalize
from scripts.seed_reported import DEMO_ENTITIES


def scripted_groq(
    *outcomes: httpx.Response | Exception, api_key: str = "test-key"
) -> tuple[groq.AsyncGroq, list[httpx.Request]]:
    """A real Groq SDK client whose transport returns or raises `outcomes` in order (the
    last one repeats), plus the requests it received. Unlike respx, a raised exception
    reaches the SDK as is, so error cause chains look like production's."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        outcome = outcomes[min(len(requests), len(outcomes)) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return groq.AsyncGroq(api_key=api_key, max_retries=0, http_client=http), requests


class FakeSession:
    """The part of AsyncSession the analyze routes use: add, commit, rollback, get.

    commit() fills in what the database would (id, created_at) and keeps the rows in memory.
    Anything else (e.g. execute) raises AttributeError, so a test that really needs SQL
    fails loudly instead of passing against the fake.
    """

    def __init__(self) -> None:
        self.rows: dict[tuple[type, uuid.UUID], Any] = {}
        self._pending: list[Any] = []

    def add(self, obj: Any) -> None:
        self._pending.append(obj)

    async def commit(self) -> None:
        for obj in self._pending:
            if obj.id is None:
                obj.id = uuid.uuid4()
            if hasattr(obj, "created_at") and obj.created_at is None:
                obj.created_at = datetime.now(UTC)
            self.rows[(type(obj), obj.id)] = obj
        self._pending.clear()

    async def rollback(self) -> None:
        self._pending.clear()

    async def get(self, model: type, key: uuid.UUID) -> Any:
        return self.rows.get((model, key))

    def all(self, model: type) -> list[Any]:
        return [row for (m, _), row in self.rows.items() if m is model]


def session_factory(session: Any) -> Callable[[], AbstractAsyncContextManager[Any]]:
    """A SessionFactory that always hands out `session` (e.g. a FakeSession)."""

    @asynccontextmanager
    async def factory() -> AsyncIterator[Any]:
        yield session

    return factory


class InMemoryReputation:
    """A reputation.FindReported backed by a dict instead of reported_entities."""

    def __init__(self) -> None:
        self.entities: dict[tuple[str, str], ReportedEntity] = {}

    def add(self, entity_type: EntityType, value: str, count: int, verified: bool) -> None:
        value = normalize(entity_type, value)
        self.entities[(entity_type.value, value)] = ReportedEntity(
            id=uuid.uuid4(),
            entity_type=entity_type.value,
            value=value,
            report_count=count,
            is_verified_scam=verified,
        )

    def seed_demo(self) -> None:
        """The same rows scripts/seed_reported.py writes."""
        for entity_type, value, count, verified, _ in DEMO_ENTITIES:
            self.add(entity_type, value, count, verified)

    async def __call__(self, keys: Sequence[tuple[EntityType, str]]) -> list[ReportedEntity]:
        return [self.entities[(t.value, v)] for t, v in keys if (t.value, v) in self.entities]


class FakeEmbedder:
    """Deterministic, instant stand-in for the embedding model: a hashed bag of words, so
    texts that share words are similar. Good enough to exercise retrieval and the signal."""

    model_name = "fake-hashed-bag-of-words"

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim
        self.calls = 0

    def vector(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for token in re.findall(r"\w+", text.lower()):
            digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
            vec[int.from_bytes(digest, "big") % self.dim] += 1.0
        return unit(vec)

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self.calls += 1
        return [self.vector(t) for t in texts]


class UnavailableEmbedder:
    """An embedder whose model never loaded."""

    model_name = "unavailable"

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        raise EmbeddingUnavailable("model is still loading")


@lru_cache
def _kb_docs() -> tuple[PatternDoc, ...]:
    return tuple(load_docs())


def fake_pattern_search(docs: Sequence[PatternDoc] | None = None) -> rag.PatternSearch:
    """Pattern search over the real knowledge-base docs (or `docs`), embedded with
    FakeEmbedder and retrieved in memory."""
    embedder = FakeEmbedder()
    docs = _kb_docs() if docs is None else docs
    retriever = rag.InMemoryRetriever([(d, embedder.vector(d.embed_text)) for d in docs])
    return rag.PatternSearch(embedder, retriever)


def assessment(risk: int, scam_type: str = "none", **overrides: Any) -> LLMAssessment:
    """A valid LLM assessment."""
    fields: dict[str, Any] = {
        "scam_type": scam_type,
        "llm_risk": risk,
        "explanation_en": f"LLM explanation (risk {risk}).",
        "explanation_hi": "यह संदेश एलएलएम ने समझाया है, ध्यान से पढ़ें।",
        "advice": ["Do not reply.", "Block the sender.", "Check in the official app."],
        "cited_flags": [],
        "confidence": "high",
    }
    return LLMAssessment.model_validate(fields | overrides)


class FakeReasoner:
    """Stands in for GroqReasoner. `respond` maps the evidence to an assessment (None: the
    LLM failed and templates are used), or raises to simulate a bug."""

    def __init__(
        self, respond: Callable[[Evidence], LLMAssessment | None] | LLMAssessment | None
    ) -> None:
        self._respond = respond
        self.calls: list[Evidence] = []

    async def reason(self, evidence: Evidence) -> ReasonResult:
        self.calls.append(evidence)
        a = self._respond(evidence) if callable(self._respond) else self._respond
        if a is None:
            return ReasonResult(None, None, ("fake-model: rate limited (429)",))
        return ReasonResult(a, "fake-model")
