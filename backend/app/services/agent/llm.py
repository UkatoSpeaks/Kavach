"""The LLM reasoning step: Groq chat completions in JSON mode, validated with Pydantic.

Call policy (at most two calls per analysis, each with an LLM_TIMEOUT_S timeout):
- GROQ_MODEL first.
- Invalid output (bad JSON, schema errors, invented contact details, or Groq's own
  json_validate_failed): retry once with the same model. If explanation_hi altered an
  identifier from the message (a transliterated UPI ID, say), the retry adds a reminder.
- Rate limit (429) or any other API error: retry once with GROQ_FALLBACK_MODEL.
- Timeout: no retry; a second slow call would double the wait.
- Anything left over: no assessment, and the caller uses the template explanations.

Successful results are cached in-process (LRU + TTL) to protect the free-tier quota. The
cache key is a hash of the normalized text plus a summary of the signals, flags and patterns
the prompt is built from.

Network errors are noted with their underlying cause (the SDK wraps every transport failure,
even a malformed request header, in APIConnectionError) and logged with the sanitized cause
chain, e.g. "APIConnectionError <- httpx.ConnectError <- ssl.SSLCertVerificationError: ...".
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
from app.services.extractors import extract_phones, extract_upi_ids, extract_urls
from app.services.scoring import SignalOutcome

logger = logging.getLogger(__name__)

# Explanations are asked for in at most 60 words; anything far beyond that means the model
# ignored the format, and is rejected.
MAX_EXPLANATION_WORDS = 90
MAX_ADVICE_WORDS = 30
MAX_TOKENS = 900
TEMPERATURE = 0.2
# /health/llm's connectivity check: a reply this short is enough (it may be cut off).
PING_MAX_TOKENS = 16
MAX_ERROR_MESSAGE_CHARS = 200
# Groq keys and bearer tokens, should an error message quote a request header.
_SECRET = re.compile(r"gsk_[A-Za-z0-9]+|Bearer\s+\S+", re.IGNORECASE)
# Contact details the model may always mention (see prompts.SYSTEM_PROMPT).
ALLOWED_DOMAINS = frozenset({"cybercrime.gov.in"})
_DEVANAGARI = re.compile(r"[ऀ-ॿ]")
# Devanagari letters and signs, without the danda (।॥) and the digits (०-९).
_DEVANAGARI_LETTER = re.compile(r"[ऀ-ॣ॰-ॿ]")
_DEVANAGARI_DIGITS = re.compile(r"[०-९](?:[\s-]?[०-९]){4,}")
# Parts of a token that only an identifier has: user@handle, a scheme, www., a Latin TLD.
_IDENTIFIER_PART = re.compile(r"@|://|www\.|\.[a-z]{2,}\b", re.IGNORECASE)

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


class AlteredIdentifiers(InvalidOutput):
    """explanation_hi translated, transliterated or respelled a UPI ID, URL or phone number."""


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
    message_upi_ids: frozenset[str]  # lowercased UPI IDs (and upi:// payees) in the message
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
        message_upi_ids=frozenset(
            [u.value for u in entities.upi_ids] + [u.pa.lower() for u in entities.upi_uris if u.pa]
        ),
        cache_key=key,
    )


# --------------------------------------------------------------------------- output


def _unknown_contacts(text: str, evidence: Evidence) -> list[str]:
    """URLs, phone numbers and UPI IDs in `text` that neither the message nor the allowed
    list has (after normalization: case, spacing, URL form)."""
    unknown = [
        u.raw
        for u in extract_urls(text)
        if u.registered_domain not in ALLOWED_DOMAINS | evidence.message_domains
    ]
    unknown += [p.raw for p in extract_phones(text) if p.number not in evidence.message_phones]
    unknown += [u.value for u in extract_upi_ids(text) if u.value not in evidence.message_upi_ids]
    return unknown


def altered_identifiers(text: str, evidence: Evidence) -> list[str]:
    """UPI IDs, URLs and phone numbers in `text` (explanation_hi) that are not written as
    in the message: transliterated into Devanagari (बिगबास्केट@okhdfc, https://एसबीआई.xyz),
    written in Devanagari digits (९८७६५४३२१०), or respelled (bigbasket@hdfc when the message
    had bigbasket@okhdfc). Pure."""
    altered = [
        token
        for token in text.split()
        if _DEVANAGARI_LETTER.search(token) and _IDENTIFIER_PART.search(token)
    ]
    altered += [
        m.group() for m in _DEVANAGARI_DIGITS.finditer(text) if m.group() not in evidence.message
    ]
    return list(dict.fromkeys(altered + _unknown_contacts(text, evidence)))


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
    if altered := altered_identifiers(a.explanation_hi, evidence):
        raise AlteredIdentifiers(f"explanation_hi altered identifiers: {altered}")
    if invented := _unknown_contacts("\n".join([a.explanation_en, *a.advice]), evidence):
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


# --------------------------------------------------------------------------- errors


@dataclass(frozen=True)
class ErrorInfo:
    """An exception and the exceptions it wraps, safe to log or return."""

    error_class: str  # e.g. APIConnectionError
    causes: tuple[str, ...]  # wrapped classes, outermost first, e.g. ("httpx.ConnectError", ...)
    message: str  # the innermost non-empty message, secrets removed

    @property
    def root_class(self) -> str:
        return self.causes[-1] if self.causes else self.error_class

    def __str__(self) -> str:
        chain = " <- ".join((self.error_class, *self.causes))
        return f"{chain}: {self.message}" if self.message else chain


def _qualified_name(exc: BaseException) -> str:
    cls = type(exc)
    package = cls.__module__.split(".")[0]
    return cls.__name__ if package == "builtins" else f"{package}.{cls.__name__}"


def sanitize(text: str, secrets: Sequence[str] = ()) -> str:
    """One line, at most MAX_ERROR_MESSAGE_CHARS, with the given secrets and anything that
    looks like a Groq key or bearer token replaced. Pure."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    text = " ".join(_SECRET.sub("[redacted]", text).split())
    if len(text) > MAX_ERROR_MESSAGE_CHARS:
        text = text[: MAX_ERROR_MESSAGE_CHARS - 1] + "…"
    return text


def describe_error(exc: BaseException, secrets: Sequence[str] = ()) -> ErrorInfo:
    """Follows __cause__ (or the implicit __context__) down to the root: that is where the
    real reason is (ConnectTimeout vs ConnectError vs an SSL or DNS error). Pure."""
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and current not in chain and len(chain) < 8:
        chain.append(current)
        current = current.__cause__ or (
            None if current.__suppress_context__ else current.__context__
        )
    messages = [str(e) for e in chain if str(e)]
    return ErrorInfo(
        error_class=type(exc).__name__,
        causes=tuple(_qualified_name(e) for e in chain[1:]),
        message=sanitize(messages[-1], secrets) if messages else "",
    )


# --------------------------------------------------------------------------- reasoner


@dataclass(frozen=True)
class PingResult:
    """One connectivity check (see GroqReasoner.ping)."""

    ok: bool
    model: str
    elapsed_ms: float
    reachable: bool  # Groq answered at all, even with an error status
    status_code: int | None = None
    error: ErrorInfo | None = None


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
    reasoning_effort: Literal["low", "medium", "high"] | None = None
    cache: LRUTTLCache[ReasonResult] = field(default_factory=lambda: LRUTTLCache(500, 3600))
    client: groq.AsyncGroq | None = None
    base_url: str | None = None  # None: the SDK's default (or GROQ_BASE_URL from the env)

    def __post_init__(self) -> None:
        if self.client is None:
            # Created once per process and shared, so its connection pool is reused.
            # Retries are ours (see module docstring), not the SDK's. The httpx timeout is
            # per phase (connect incl. TLS, each read, ...); _complete caps the whole call.
            self.client = groq.AsyncGroq(
                api_key=self.api_key,
                base_url=self.base_url,
                max_retries=0,
                timeout=self.timeout_s,
            )

    def describe(self, exc: BaseException) -> ErrorInfo:
        return describe_error(exc, secrets=[self.api_key])

    def _extra(self) -> dict[str, Any]:
        return {"reasoning_effort": self.reasoning_effort} if self.reasoning_effort else {}

    async def ping(self) -> PingResult:
        """One tiny completion with GROQ_MODEL through the same client the analyses use, for
        /health/llm. Never raises."""
        assert self.client is not None
        start = time.perf_counter()

        def done(ok: bool, reachable: bool, **kw: Any) -> PingResult:
            elapsed = round((time.perf_counter() - start) * 1000, 1)
            return PingResult(ok, self.model, elapsed, reachable, **kw)

        try:
            async with asyncio.timeout(self.timeout_s + 1):
                await self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": "Reply with: ok"}],
                    max_tokens=PING_MAX_TOKENS,
                    timeout=self.timeout_s,
                    **self._extra(),
                )
        except groq.APIStatusError as exc:
            return done(False, True, status_code=exc.status_code, error=self.describe(exc))
        except Exception as exc:  # fail soft: the error is the result
            return done(False, False, error=self.describe(exc))
        return done(True, True, status_code=200)

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
                **self._extra(),
            )
        choice = resp.choices[0]
        if choice.finish_reason == "length":
            raise InvalidOutput("reply was cut off")
        return choice.message.content or ""

    async def _reason(self, evidence: Evidence) -> ReasonResult:
        messages = prompts.messages(evidence.payload, evidence.message)
        model = self.model
        notes: list[str] = []
        errors: list[str] = []  # full sanitized cause chains of network errors, for the log
        for _ in range(2):
            try:
                raw = await self._complete(model, messages)
                return ReasonResult(parse_assessment(raw, evidence), model, tuple(notes))
            except AlteredIdentifiers as exc:
                notes.append(f"{model}: invalid output ({exc})")
                messages = [*messages, {"role": "user", "content": prompts.IDENTIFIER_RETRY_NOTE}]
            except InvalidOutput as exc:
                notes.append(f"{model}: invalid output ({exc})")
            except (TimeoutError, groq.APITimeoutError) as exc:
                err = self.describe(exc)
                # ConnectTimeout (never connected) vs ReadTimeout (slow reply); asyncio's own
                # TimeoutError (the overall cap in _complete) has no useful cause.
                sdk_timeout = isinstance(exc, groq.APITimeoutError) and err.causes
                cause = f" ({err.root_class})" if sdk_timeout else ""
                notes.append(f"{model}: timed out after {self.timeout_s:g}s{cause}")
                errors.append(f"{model}: {err}")
                break
            except groq.APIStatusError as exc:
                if _is_json_mode_failure(exc):
                    notes.append(f"{model}: invalid output (json_validate_failed)")
                    continue
                kind = "rate limited" if isinstance(exc, groq.RateLimitError) else "error"
                notes.append(f"{model}: {kind} ({exc.status_code})")
                model = self.fallback_model
            except groq.APIError as exc:
                err = self.describe(exc)
                cause = f" ({err.root_class})" if err.causes else ""
                notes.append(f"{model}: {type(exc).__name__}{cause}")
                errors.append(f"{model}: {err}")
                model = self.fallback_model
        logger.warning(
            "llm step fell back to templates: %s%s",
            "; ".join(notes),
            f" | causes: {' ; '.join(errors)}" if errors else "",
        )
        return ReasonResult(None, None, tuple(notes))
