import pytest

from app.core.config import BACKEND_DIR, Settings, _normalize_database_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            "postgresql://u:pw@host:5432/db",
            "postgresql+asyncpg://u:pw@host:5432/db",
        ),
        (
            "postgres://u:pw@host:5432/db",
            "postgresql+asyncpg://u:pw@host:5432/db",
        ),
        (
            "postgresql+asyncpg://u:pw@host:5432/db",
            "postgresql+asyncpg://u:pw@host:5432/db",
        ),
        # special characters in the password get percent-encoded
        (
            "postgresql://u.ref:p@#$1@host:5432/db",
            "postgresql+asyncpg://u.ref:p%40%23%241@host:5432/db",
        ),
        # already-encoded passwords are not double-encoded
        (
            "postgresql://u:p%40%23@host:5432/db",
            "postgresql+asyncpg://u:p%40%23@host:5432/db",
        ),
    ],
)
def test_normalize_database_url(raw: str, expected: str) -> None:
    assert _normalize_database_url(raw) == expected


def test_relative_embedding_cache_dir_is_under_backend() -> None:
    settings = Settings(DATABASE_URL="postgresql://u:p@h/db", EMBEDDING_CACHE_DIR="models/fe")
    assert settings.EMBEDDING_CACHE_DIR == BACKEND_DIR / "models" / "fe"
