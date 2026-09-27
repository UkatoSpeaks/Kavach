"""The LLM reasoning step: Groq chat completions in JSON mode, validated with Pydantic.

Call policy (at most two calls per analysis, each with an LLM_TIMEOUT_S timeout):
- GROQ_MODEL first.
- Invalid output (bad JSON, schema errors, invented contact details, or Groq's own
  json_validate_failed): retry once with the same model.
- Rate limit (429) or any other API error: retry once with GROQ_FALLBACK_MODEL.
- Timeout: no retry; a second slow call would double the wait.
- Anything left over: no assessment, and the caller uses the template explanations.

Successful results are cached in-process (LRU + TTL) to protect the free-tier quota. The
cache key is a hash of the normalized text plus a summary of the signals, flags and patterns
the prompt is built from.
"""

import asyncio
import hashlib
import json
import logging
import re
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Generic, Literal, Protocol, TypeVar

import groq
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.schemas.analysis import RedFlag, SimilarPattern
from app.schemas.entities import ExtractedEntities
from app.services.agent import prompts
from app.services.extractors import extract_phones, extract_urls
from app.services.scoring import SignalOutcome

logger = logging.getLogger(__name__)

# Explanations are asked for in at most 60 words; anything far beyond that means the model
# ignored the format, and is rejected.
MAX_EXPLANATION_WORDS = 90
MAX_ADVICE_WORDS = 30
MAX_TOKENS = 900
TEMPERATURE = 0.2
# Contact details the model may always mention (see prompts.SYSTEM_PROMPT).
ALLOWED_DOMAINS = frozenset({"cybercrime.gov.in"})
_DEVANAGARI = re.compile(r"[ऀ-ॿ]")

LLMScamType = Literal[
    "upi_receive_money",
    "qr_code",
    "sent_by_mistake",
    "phishing_link",
    "task_job",
    "fake_customer_care",
    "other",
    "none",
]
Confidence = Literal["low", "medium", "high"]
V = TypeVar("V")


class InvalidOutput(ValueError):
    """The model's reply can't be used."""


class LLMAssessment(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    scam_type: LLMScamType
    llm_risk: int = Field(ge=0, le=100)
    explanation_en: str = Field(min_length=1)
    explanation_hi: str = Field(min_length=1)
    advice: list[str] = Field(min_length=3, max_length=5)
    cited_flags: list[str] = Field(default_factory=list)
    confidence: Confidence

    @field_validator("scam_type", "confidence", mode="before")
    @classmethod
    def _lower(cls, v: Any) -> Any:
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("explanation_en", "explanation_hi")
    @classmethod
    def _short(cls, v: str) -> str:
        if len(v.split()) > MAX_EXPLANATION_WORDS:
            raise ValueError(f"longer than {MAX_EXPLANATION_WORDS} words")
        return v

    @field_validator("explanation_hi")
    @classmethod
    def _devanagari(cls, v: str) -> str:
        if len(_DEVANAGARI.findall(v)) < 10:
            raise ValueError("not written in Devanagari")
        return v

    @field_validator("advice")
    @classmethod
    def _advice_items(cls, v: list[str]) -> list[str]:
        items = [a.strip() for a in v]
        if any(not a or len(a.split()) > MAX_ADVICE_WORDS for a in items):
            raise ValueError(f"advice items must be 1-{MAX_ADVICE_WORDS} words")
        return items


# --------------------------------------------------------------------------- evidence


@dataclass(frozen=True)
class Evidence:
    """Everything the prompt is built from. `payload` is the EVIDENCE JSON."""

    message: str
    payload: dict[str, Any]
    flag_codes: frozenset[str]
    message_phones: frozenset[str]  # normalized numbers found in the message
    message_domains: frozenset[str]  # registered domains found in the message
    cache_key: str


def _entities_summary(e: ExtractedEntities) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "urls": [
            {"url": u.url, "domain": u.registered_domain, "shortener": u.is_shortener,
             "apk": u.is_apk}
            for u in e.urls
        ],
        "upi_ids": [u.value for u in e.upi_ids],
        "upi_payment_links": [
            {"payee": u.pa, "payee_name": u.pn, "amount": u.am} for u in e.upi_uris
        ],
        "phones": [{"number": p.number, "kind": p.kind} for p in e.phones],
        "amounts_inr": [a.value for a in e.amounts],
        "sensitive_info_mentioned": [s.value for s in e.sensitive_info],
        "remote_access_apps": e.remote_access_apps,
        "apk_files": e.apk_files,
    }  # fmt: skip
    return {k: v for k, v in summary.items() if v}


def _signal_summary(o: SignalOutcome) -> dict[str, Any]:
    if o.score is None:
        return {"source": o.source, "status": "unavailable", "detail": o.detail}
    return {
        "source": o.source,
        "score": o.score,
        "counts_in_score": o.informative,
        "detail": o.detail,
    }


def build_evidence(
    message: str,
    entities: ExtractedEntities,
    flags: Sequence[RedFlag],
    signals: Sequence[SignalOutcome],
    patterns: Sequence[SimilarPattern],
    advice_language: Literal["en", "hi"] = "en",
) -> Evidence:
    payload = {
        "advice_language": "Hindi (Devanagari)" if advice_language == "hi" else "English",
        "entities": _entities_summary(entities),
        "red_flags": [
            {"code": f.code, "severity": f.severity.value, "meaning": f.message,
             "evidence": f.evidence}
            for f in flags
        ],
        "signals": [_signal_summary(o) for o in signals],
        "similar_known_scam_patterns": [
            {"title": p.title, "category": p.category, "similarity": p.similarity}
            for p in patterns
        ],
    }  # fmt: skip
    key_parts = {
        "text": entities.normalized_text,
        "signals": sorted((o.source, o.score, o.informative) for o in signals),
        "flags": sorted(f.code for f in flags),
        "patterns": [p.slug for p in patterns],
        "lang": advice_language,
    }
    key = hashlib.sha256(json.dumps(key_parts, default=str).encode()).hexdigest()
    return Evidence(
        message=message,
        payload=payload,
        flag_codes=frozenset(f.code for f in flags),
        message_phones=frozenset(p.number for p in entities.phones),
        message_domains=frozenset(u.registered_domain for u in entities.urls),
        cache_key=key,
    )


# --------------------------------------------------------------------------- output


def _invented_contacts(a: LLMAssessment, evidence: Evidence) -> list[str]:
    """Phone numbers and URLs in the output that neither the message nor the allowed list has."""
    text = "\n".join([a.explanation_en, a.explanation_hi, *a.advice])
    invented = [
        u.raw
        for u in extract_urls(text)
        if u.registered_domain not in ALLOWED_DOMAINS | evidence.message_domains
    ]
    invented += [p.raw for p in extract_phones(text) if p.number not in evidence.message_phones]
    return invented


def parse_assessment(raw: str, evidence: Evidence) -> LLMAssessment:
    """Validate the model's JSON reply. Drops cited_flags that were not provided."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InvalidOutput(f"not JSON: {exc.msg}") from exc
    try:
        a = LLMAssessment.model_validate(data)
    except ValidationError as exc:
        fields = ", ".join(".".join(map(str, e["loc"])) or "root" for e in exc.errors())
        raise InvalidOutput(f"schema errors in {fields}") from exc
    if invented := _invented_contacts(a, evidence):
        raise InvalidOutput(f"mentions contact details not in the evidence: {invented}")
    cited = [c for c in dict.fromkeys(a.cited_flags) if c in evidence.flag_codes]
    return a.model_copy(update={"cited_flags": cited})


# --------------------------------------------------------------------------- cache


class LRUTTLCache(Generic[V]):
    """Small in-process LRU cache whose entries also expire after `ttl_s`."""

    def __init__(
        self, maxsize: int, ttl_s: float, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.maxsize, self.ttl_s, self._clock = maxsize, ttl_s, clock
        self._data: OrderedDict[str, tuple[float, V]] = OrderedDict()

    def get(self, key: str) -> V | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires, value = item
        if self._clock() >= expires:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: str, value: V) -> None:
        self._data[key] = (self._clock() + self.ttl_s, value)
        self._data.move_to_end(key)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)


# --------------------------------------------------------------------------- reasoner


@dataclass(frozen=True)
class ReasonResult:
    assessment: LLMAssessment | None  # None: use the template explanations
    model: str | None = None
    notes: tuple[str, ...] = ()  # failed attempts before the result
    cached: bool = False

    @property
    def detail(self) -> str:
        parts = list(self.notes)
        if self.assessment is None:
            parts.append("using template explanations")
        return "; ".join(parts)


class Reasoner(Protocol):
    async def reason(self, evidence: Evidence) -> ReasonResult: ...


def _is_json_mode_failure(exc: groq.APIStatusError) -> bool:
    return exc.status_code == 400 and "json_validate_failed" in str(exc.body or exc)


@dataclass
class GroqReasoner:
    api_key: str
    model: str
    fallback_model: str
    timeout_s: float = 8.0
    cache: LRUTTLCache[ReasonResult] = field(default_factory=lambda: LRUTTLCache(500, 3600))
    client: groq.AsyncGroq | None = None

    def __post_init__(self) -> None:
        if self.client is None:
            # Retries are ours (see module docstring), not the SDK's.
            self.client = groq.AsyncGroq(
                api_key=self.api_key, max_retries=0, timeout=self.timeout_s
            )

    async def reason(self, evidence: Evidence) -> ReasonResult:
        if (hit := self.cache.get(evidence.cache_key)) is not None:
            return replace(hit, cached=True)
        result = await self._reason(evidence)
        if result.assessment is not None:
            self.cache.set(evidence.cache_key, result)
        return result

    async def _complete(self, model: str, messages: list[dict[str, str]]) -> str:
        assert self.client is not None
        async with asyncio.timeout(self.timeout_s + 1):  # guard on top of the SDK timeout
            resp = await self.client.chat.completions.create(
                model=model,
                messages=messages,  # type: ignore[arg-type]
                response_format={"type": "json_object"},
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
                timeout=self.timeout_s,
            )
        choice = resp.choices[0]
        if choice.finish_reason == "length":
            raise InvalidOutput("reply was cut off")
        return choice.message.content or ""

    async def _reason(self, evidence: Evidence) -> ReasonResult:
        messages = prompts.messages(evidence.payload, evidence.message)
        model = self.model
        notes: list[str] = []
        for _ in range(2):
            try:
                raw = await self._complete(model, messages)
                return ReasonResult(parse_assessment(raw, evidence), model, tuple(notes))
            except InvalidOutput as exc:
                notes.append(f"{model}: invalid output ({exc})")
            except (TimeoutError, groq.APITimeoutError):
                notes.append(f"{model}: timed out after {self.timeout_s:g}s")
                break
            except groq.APIStatusError as exc:
                if _is_json_mode_failure(exc):
                    notes.append(f"{model}: invalid output (json_validate_failed)")
                    continue
                kind = "rate limited" if isinstance(exc, groq.RateLimitError) else "error"
                notes.append(f"{model}: {kind} ({exc.status_code})")
                model = self.fallback_model
            except groq.APIError as exc:
                notes.append(f"{model}: {type(exc).__name__}")
                model = self.fallback_model
        logger.warning("llm step fell back to templates: %s", "; ".join(notes))
        return ReasonResult(None, None, tuple(notes))
