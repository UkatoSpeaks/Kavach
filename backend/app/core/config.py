from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import quote, unquote

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


def _normalize_database_url(url: str) -> str:
    """Force the asyncpg driver and percent-encode the password.

    Supabase passwords often contain characters like '@', '#' or '$' that break URL
    parsing. The password is taken as everything between the first ':' after the scheme
    and the *last* '@', so unencoded passwords still parse correctly.
    """
    url = url.strip()
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            url = "postgresql+asyncpg://" + url[len(prefix) :]
            break

    scheme, sep, rest = url.partition("://")
    if not sep or "@" not in rest:
        return url
    creds, _, host_part = rest.rpartition("@")
    user, has_pw, password = creds.partition(":")
    if not has_pw:
        return url
    password = quote(unquote(password), safe="")
    return f"{scheme}://{user}:{password}@{host_part}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    DATABASE_URL: str
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "openai/gpt-oss-120b"
    # Used when GROQ_MODEL is rate limited (429) or errors; after that, template explanations.
    GROQ_FALLBACK_MODEL: str = "openai/gpt-oss-20b"
    # Reasoning effort for reasoning models (gpt-oss). Their reasoning tokens count toward
    # the reply's token limit and the free tier's tokens-per-minute; "medium" often runs out
    # before the JSON is written. Empty/None: not sent (for non-reasoning models).
    GROQ_REASONING_EFFORT: Literal["low", "medium", "high"] | None = "low"
    LLM_TIMEOUT_S: float = 8.0
    # In-process cache of LLM results, to protect the free-tier quota.
    LLM_CACHE_SIZE: int = 500
    LLM_CACHE_TTL_S: int = 3600
    # If the LLM's risk differs from the other signals' score by more than this, it is left
    # out of the score and the response confidence is "low" (see app/services/scoring.py).
    LLM_MAX_DISAGREEMENT: float = 50
    ENV: Literal["dev", "test", "prod"] = "dev"
    LOG_LEVEL: str = "INFO"
    # Local embedding model (fastembed/ONNX) for scam-pattern retrieval. Must be multilingual
    # and output EMBEDDING_DIM dims; changing the dim needs a migration, changing the model
    # needs a re-run of scripts/ingest_patterns.py.
    EMBEDDING_MODEL: str = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
    EMBEDDING_DIM: int = 384
    # Where the model files are downloaded (~220 MB). Gitignored.
    EMBEDDING_CACHE_DIR: Path = BACKEND_DIR / ".cache" / "fastembed"

    # Pattern retrieval (see app/services/rag.py). The signal is driven by the margin
    # between the closest scam pattern and the closest genuine-message pattern.
    PATTERN_TOP_K: int = 3
    # Margins below this are uninformative (no closer to a scam than to a genuine message).
    PATTERN_MIN_MARGIN: float = 0.05
    # Margin at which the signal reaches its maximum score.
    PATTERN_FULL_MARGIN: float = 0.20
    # Scam patterns less similar than this are not listed in similar_patterns.
    PATTERN_MIN_SIMILARITY: float = 0.35
    # Messages with fewer words than this skip the signal: a short chat line ("text me
    # tonight") embeds close to anything. Chosen on tests/examples.py and UCI (ml/evaluate.py).
    PATTERN_MIN_WORDS: int = 12

    # Real-world checks. Safe Browsing is skipped when no key is set.
    SAFE_BROWSING_API_KEY: str = ""
    HTTP_TIMEOUT_S: float = 5.0
    URL_CACHE_TTL_HOURS: int = 24

    # Scoring. Relative weight of each signal in the final score; signals that are missing
    # for a request are skipped and the remaining weights renormalize to 1. Override in
    # .env as JSON, e.g. SIGNAL_WEIGHTS='{"rules": 0.5, "classifier": 0.5}'.
    SIGNAL_WEIGHTS: dict[str, float] = {
        "rules": 0.30,
        "classifier": 0.25,
        "url_intel": 0.15,
        "upi_check": 0.15,
        "reputation": 0.10,
        "pattern_similarity": 0.05,
        "llm": 0.15,
    }
    # risk_score < SUSPICIOUS_MIN -> safe; < SCAM_MIN -> suspicious; else scam.
    VERDICT_SUSPICIOUS_MIN: int = 35
    VERDICT_SCAM_MIN: int = 70
    # A single rule at least this strong makes the verdict at least "suspicious".
    STRONG_RULE_WEIGHT: float = 0.8

    @field_validator("DATABASE_URL")
    @classmethod
    def _async_driver(cls, v: str) -> str:
        return _normalize_database_url(v)

    @model_validator(mode="after")
    def _thresholds_ordered(self) -> "Settings":
        if not 0 < self.VERDICT_SUSPICIOUS_MIN < self.VERDICT_SCAM_MIN <= 100:
            raise ValueError("need 0 < VERDICT_SUSPICIOUS_MIN < VERDICT_SCAM_MIN <= 100")
        return self

    @model_validator(mode="after")
    def _pattern_margins_ordered(self) -> "Settings":
        if not 0 <= self.PATTERN_MIN_MARGIN < self.PATTERN_FULL_MARGIN <= 1:
            raise ValueError("need 0 <= PATTERN_MIN_MARGIN < PATTERN_FULL_MARGIN <= 1")
        return self

    @field_validator("GROQ_REASONING_EFFORT", mode="before")
    @classmethod
    def _empty_is_none(cls, v: object) -> object:
        return None if isinstance(v, str) and not v.strip() else v

    @field_validator("EMBEDDING_CACHE_DIR")
    @classmethod
    def _relative_to_backend(cls, v: Path) -> Path:
        return v if v.is_absolute() else BACKEND_DIR / v

    @field_validator("LOG_LEVEL")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()


@lru_cache
def get_settings() -> Settings:
    return Settings()
