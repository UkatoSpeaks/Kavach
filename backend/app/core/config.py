import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import quote, unquote

from limits import parse_many
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]

# Rule weights (0-1) for the link and filter-evasion rules; the other rules keep theirs next
# to their checks in app/services/rules.py. Rule scores combine as 1 - prod(1 - w).
RULE_WEIGHTS: dict[str, float] = {
    # "Rs.82,850 credited ... GET Cash NOW <link>": a big fake credit with a cash-out link.
    "fake_credit_alert": 0.75,
    "short_url": 0.45,
    # "9lp7.com/tul8vf!88a6j7d": a per-recipient code after "!". Alone it stays below
    # "suspicious" (35); with a throwaway domain it does not.
    "tracking_suffix_link": 0.30,
    # Below 0.35 on purpose: only meaningful together with other signs.
    "throwaway_domain": 0.25,
    "filter_evasion": 0.15,
}
# Signs that are common in ordinary promotions too (short links, odd spellings). When only
# these fire, the rules score is capped at SUPPORTING_ONLY_MAX_SCORE, low enough that even a
# full pattern-similarity match stays below "suspicious"; next to any other rule they count
# with their full weight.
SUPPORTING_RULES = frozenset({"short_url", "throwaway_domain", "filter_evasion"})
SUPPORTING_ONLY_MAX_SCORE = 20


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
    # Passed to the SDK explicitly (it would otherwise read GROQ_BASE_URL from the
    # environment itself), so /health/llm can show which host is called.
    GROQ_BASE_URL: str = "https://api.groq.com"
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
    # "production" and "development" are accepted as aliases of prod and dev.
    ENV: Literal["dev", "test", "prod"] = "dev"
    LOG_LEVEL: str = "INFO"

    # API protection. Rate limits are per client IP, in memory (per process), in the
    # `limits` notation: "10/minute", "100/hour", "5/minute;50/day". All /analyze/* routes
    # share one budget.
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_ANALYZE: str = "10/minute"
    RATE_LIMIT_REPORT: str = "5/minute"
    # /health/llm makes a real (tiny, cached for 60 s) Groq call.
    RATE_LIMIT_HEALTH_LLM: str = "6/minute"
    # How many proxies in front of the app append to X-Forwarded-For. The header is only
    # used when the direct peer is an internal (non-global) address, i.e. the platform's
    # proxy; trailing internal addresses are dropped and the client IP is the entry this
    # many places from the right. 0: ignore the header. On Render it is 2: the header
    # arrives as "<client>, <Cloudflare edge>" and Render's proxy appends instead of
    # replacing, so anything further left may be forged by the client.
    TRUSTED_PROXY_HOPS: int = 0
    # Temporary diagnostic: GET /debug/client-ip (resolved IP, X-Forwarded-For hop count,
    # worker PID). Leave off except while checking the proxy setup.
    DEBUG_IP_ENDPOINT: bool = False
    # Request body limits: JSON bodies, and multipart uploads (the QR image plus form overhead).
    MAX_JSON_BODY_BYTES: int = 64 * 1024
    MAX_UPLOAD_BODY_BYTES: int = 5 * 1024 * 1024 + 64 * 1024
    # Origins allowed to call the API from a browser, as JSON or comma-separated. Empty:
    # no CORS headers (in dev, http://localhost:3000 is allowed instead).
    CORS_ORIGINS: Annotated[list[str], NoDecode] = []
    # /docs, /redoc and /openapi.json. Default: on, except in prod.
    ENABLE_DOCS: bool | None = None

    # The pattern-similarity signal loads a ~525 MB (RSS) embedding model. Turn it off on
    # small instances (Render free: 512 MB); the signal is then reported unavailable.
    PATTERN_SIGNAL_ENABLED: bool = True
    # Local embedding model (fastembed/ONNX) for scam-pattern retrieval. Must be multilingual
    # and output EMBEDDING_DIM dims; changing the dim needs a migration, changing the model
    # needs a re-run of scripts/ingest_patterns.py.
    EMBEDDING_MODEL: str = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
    EMBEDDING_DIM: int = 384
    # Where the model files are downloaded (~240 MB). Gitignored. Inside the project so a
    # build-time download (scripts/download_model.py) ships with the deploy.
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

    @field_validator("ENV", mode="before")
    @classmethod
    def _env_aliases(cls, v: object) -> object:
        if isinstance(v, str):
            v = v.strip().lower()
            return {"production": "prod", "development": "dev"}.get(v, v)
        return v

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                return json.loads(v)
            return [o.strip().rstrip("/") for o in v.split(",") if o.strip()]
        return v

    @field_validator(
        "GROQ_API_KEY",
        "GROQ_BASE_URL",
        "GROQ_MODEL",
        "GROQ_FALLBACK_MODEL",
        "SAFE_BROWSING_API_KEY",
        mode="before",
    )
    @classmethod
    def _strip(cls, v: object) -> object:
        # Values pasted into a dashboard often carry a trailing newline or space. In an API
        # key that makes the Authorization header illegal, which httpx rejects before
        # sending and the Groq SDK reports as APIConnectionError, not as a bad key.
        return v.strip() if isinstance(v, str) else v

    @field_validator("RATE_LIMIT_ANALYZE", "RATE_LIMIT_REPORT", "RATE_LIMIT_HEALTH_LLM")
    @classmethod
    def _valid_rate(cls, v: str) -> str:
        parse_many(v)  # ValueError on bad notation: fail at startup, not on the first request
        return v

    @property
    def is_prod(self) -> bool:
        return self.ENV == "prod"

    @property
    def docs_enabled(self) -> bool:
        return self.ENABLE_DOCS if self.ENABLE_DOCS is not None else not self.is_prod

    @property
    def cors_origins(self) -> list[str]:
        if not self.CORS_ORIGINS and self.ENV == "dev":
            return ["http://localhost:3000"]
        return self.CORS_ORIGINS

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
