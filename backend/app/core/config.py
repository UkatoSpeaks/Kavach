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
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    ENV: Literal["dev", "test", "prod"] = "dev"
    LOG_LEVEL: str = "INFO"
    # Must match the embedding model's output size. Changing it needs a migration.
    EMBEDDING_DIM: int = 384

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

    @field_validator("LOG_LEVEL")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()


@lru_cache
def get_settings() -> Settings:
    return Settings()
