"""The AnalysisResult contract returned by every analysis endpoint (see CLAUDE.md)."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import Severity, Verdict


class RedFlag(BaseModel):
    """A human-readable warning sign found in the input."""

    code: str = Field(description="Stable machine id, e.g. 'otp_request', 'urgency'.")
    message: str = Field(description="Short explanation shown to the user.")
    message_hi: str | None = Field(default=None, description="The same in simple Hindi.")
    severity: Severity = Severity.MEDIUM
    evidence: str | None = Field(
        default=None, description="The matched text/entity, e.g. the suspicious URL."
    )


class Signal(BaseModel):
    """One scoring layer's contribution to the final risk score."""

    source: str = Field(description="Layer name: rules, classifier, url_intel, llm, ...")
    score: float = Field(ge=0, le=100, description="This layer's risk score, 0-100.")
    weight: float = Field(ge=0, le=1, description="Weight applied in the final combination.")
    detail: str = Field(default="", description="Why this score; notes if the layer failed.")


class SimilarPattern(BaseModel):
    """A knowledge-base scam pattern retrieved via RAG."""

    slug: str
    title: str
    category: str | None = Field(default=None, description="The v1 scam type it illustrates.")
    similarity: float = Field(ge=0, le=1, description="Cosine similarity to the input.")
    source_url: str | None = None


class AnalysisResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID | None = Field(default=None, description="Set once saved; None if saving failed.")
    created_at: datetime | None = None
    risk_score: int = Field(ge=0, le=100)
    verdict: Verdict
    scam_type: str | None = None
    red_flags: list[RedFlag] = Field(default_factory=list)
    signal_breakdown: list[Signal] = Field(default_factory=list)
    explanation_en: str = ""
    explanation_hi: str = ""
    advice: list[str] = Field(default_factory=list)
    similar_patterns: list[SimilarPattern] = Field(default_factory=list)
