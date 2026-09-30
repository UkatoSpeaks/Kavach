"""Download the models the app loads at runtime, and check they load:

- the embedding model into EMBEDDING_CACHE_DIR (~240 MB). Skipped when
  PATTERN_SIGNAL_ENABLED=false: the app never loads it then.
- the local OCR's Devanagari models into LOCAL_OCR_CACHE_DIR (~10 MB; the Latin ones ship
  with the rapidocr wheel). Skipped unless LOCAL_OCR_ENABLED and LOCAL_OCR_DEVANAGARI.

Run at build time (render.yaml) so a cold start or the first screenshot doesn't download
them. The cache dirs are inside the project (backend/.cache/), which the platform ships with
the build.

    python -m scripts.download_model [--force]   # --force: download even if the flags are off

Needs no database: DATABASE_URL is not read.
"""

import argparse
import asyncio
import logging
import sys

from app.core.config import Settings
from app.core.logging import setup_logging
from app.services.embeddings import EmbeddingUnavailable, FastEmbedder
from app.services.ocr import LocalOCRUnavailable, RapidLocalOCR

logger = logging.getLogger("scripts.download_model")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="download even if the flags are off")
    args = parser.parse_args()

    settings = Settings(DATABASE_URL="postgresql://unused@localhost/unused")
    setup_logging(settings.LOG_LEVEL)
    return download_embedding_model(settings, args.force) or download_ocr_models(
        settings, args.force
    )


def download_embedding_model(settings: Settings, force: bool) -> int:
    if not settings.PATTERN_SIGNAL_ENABLED and not force:
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


def download_ocr_models(settings: Settings, force: bool) -> int:
    wanted = settings.LOCAL_OCR_ENABLED and settings.LOCAL_OCR_DEVANAGARI
    if not wanted and not force:
        logger.info("local Devanagari OCR is off: skipping the OCR model download")
        return 0
    ocr = RapidLocalOCR(settings.LOCAL_OCR_CACHE_DIR, True, settings.LOCAL_OCR_MAX_SIDE)
    try:
        ocr.load()
    except LocalOCRUnavailable as exc:
        logger.error("could not load the local OCR: %s", exc)
        return 1
    if not ocr.devanagari_loaded:
        logger.error("could not download the Devanagari OCR models (see the warning above)")
        return 1
    logger.info(
        "OCR models ready", extra={"extra_fields": {"cache_dir": str(settings.LOCAL_OCR_CACHE_DIR)}}
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
