"""Download the embedding model into EMBEDDING_CACHE_DIR (and check it loads).

Run at build time (render.yaml) so a cold start doesn't download ~240 MB. The cache dir is
inside the project (backend/.cache/fastembed by default), which the platform ships with the
build. Skipped when PATTERN_SIGNAL_ENABLED=false: the app never loads the model then.

    python -m scripts.download_model [--force]   # --force: download even if the flag is off

Needs no database: DATABASE_URL is not read.
"""

import argparse
import asyncio
import logging
import sys

from app.core.config import Settings
from app.core.logging import setup_logging
from app.services.embeddings import EmbeddingUnavailable, FastEmbedder

logger = logging.getLogger("scripts.download_model")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="download even if the flag is off")
    args = parser.parse_args()

    settings = Settings(DATABASE_URL="postgresql://unused@localhost/unused")
    setup_logging(settings.LOG_LEVEL)
    if not settings.PATTERN_SIGNAL_ENABLED and not args.force:
        logger.info("PATTERN_SIGNAL_ENABLED=false: skipping the embedding model download")
        return 0
    embedder = FastEmbedder(
        settings.EMBEDDING_MODEL, settings.EMBEDDING_CACHE_DIR, settings.EMBEDDING_DIM
    )
    try:
        asyncio.run(embedder.load_async())
    except EmbeddingUnavailable as exc:
        logger.error("could not download the embedding model: %s", exc)
        return 1
    logger.info(
        "embedding model ready",
        extra={"extra_fields": {"cache_dir": str(settings.EMBEDDING_CACHE_DIR)}},
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
