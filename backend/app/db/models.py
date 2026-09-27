import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.config import get_settings
from app.core.enums import EntityType, InputType, Verdict
from app.db.base import Base

EMBEDDING_DIM = get_settings().EMBEDDING_DIM


def _one_of(column: str, enum: type[StrEnum], name: str) -> CheckConstraint:
    """CHECK constraint restricting a text column to an enum's values.

    Text + CHECK is used instead of native Postgres ENUMs, which are painful to alter.
    """
    values = ", ".join(f"'{member.value}'" for member in enum)
    return CheckConstraint(f"{column} IN ({values})", name=name)


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )


def _now(*, onupdate: bool = False) -> Mapped[datetime]:
    return mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now() if onupdate else None,
    )


class Analysis(Base):
    __tablename__ = "analyses"
    # Fetch server-generated id/created_at via RETURNING on insert.
    __mapper_args__ = {"eager_defaults": True}
    __table_args__ = (
        _one_of("input_type", InputType, "input_type"),
        _one_of("verdict", Verdict, "verdict"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score_range"),
        Index("ix_analyses_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    input_type: Mapped[str] = mapped_column(Text, nullable=False)
    raw_input: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_text: Mapped[str | None] = mapped_column(Text)
    extracted_entities: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    verdict: Mapped[str] = mapped_column(Text, nullable=False)
    scam_type: Mapped[str | None] = mapped_column(Text)
    red_flags: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    signal_breakdown: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    explanation_en: Mapped[str | None] = mapped_column(Text)
    explanation_hi: Mapped[str | None] = mapped_column(Text)
    advice: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    similar_patterns: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    language_hint: Mapped[str | None] = mapped_column(Text)
    # Per-layer timings, e.g. {"rules": 3, "classifier": 41, "llm": 820}.
    latency_ms: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = _now()


class ReportedEntity(Base):
    __tablename__ = "reported_entities"
    __table_args__ = (
        UniqueConstraint("entity_type", "value"),
        _one_of("entity_type", EntityType, "entity_type"),
        CheckConstraint("report_count >= 0", name="report_count_non_negative"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    # Normalized form (lower-cased UPI ID, E.164 phone, canonical URL/domain).
    value: Mapped[str] = mapped_column(Text, nullable=False)
    report_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    first_seen: Mapped[datetime] = _now()
    last_seen: Mapped[datetime] = _now()
    is_verified_scam: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    notes: Mapped[str | None] = mapped_column(Text)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = _uuid_pk()
    entity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reported_entities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    analysis_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="SET NULL"), index=True
    )
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()


class ScamPattern(Base):
    __tablename__ = "scam_patterns"
    __table_args__ = (
        Index(
            "ix_scam_patterns_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    slug: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str | None] = mapped_column(Text)
    # sha256 of content; lets the ingest script skip re-embedding unchanged docs.
    content_hash: Mapped[str] = mapped_column(Text, nullable=False)
    # Nullable so a doc can be stored before its embedding is computed.
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBEDDING_DIM))
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = _now(onupdate=True)


class UrlCache(Base):
    __tablename__ = "url_cache"

    url: Mapped[str] = mapped_column(Text, primary_key=True)
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    checked_at: Mapped[datetime] = _now()
