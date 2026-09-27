from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import quote, unquote

from pydantic import field_validator
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

    @field_validator("DATABASE_URL")
    @classmethod
    def _async_driver(cls, v: str) -> str:
        return _normalize_database_url(v)

    @field_validator("LOG_LEVEL")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()


@lru_cache
def get_settings() -> Settings:
    return Settings()
