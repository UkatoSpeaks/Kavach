"""Text embeddings for scam-pattern retrieval, computed locally with fastembed (ONNX, no torch).

Default model: sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2. Multilingual
(English, Hindi and ~50 more; it also copes with romanized Hinglish), 384 dimensions, ~220 MB.
It is the only model in fastembed's catalogue that is multilingual, 384-dim and under
~300 MB. The model is symmetric: queries and documents need no prefixes.

The model loads once per process, in a worker thread: in the background at app startup, or
again after a failed load. Embedding also runs in a worker thread, so the event loop is never
blocked. Until the model is ready (or if it can't load: no network for the first download,
disk full, corrupt cache), `embed` raises EmbeddingUnavailable and callers mark the pattern
signal unavailable. Scripts that need the model call `load_async()` first.
"""

import asyncio
import logging
import math
import os
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)

# After a failed load, wait this long before trying again.
RETRY_AFTER_S = 300.0


class EmbeddingUnavailable(RuntimeError):
    """The embedding model isn't loaded: still loading, or it failed to load."""


class Embedder(Protocol):
    model_name: str

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """One unit-length vector per text."""
        ...


def unit(vec: Sequence[float]) -> list[float]:
    norm = math.sqrt(sum(x * x for x in vec))
    return [x / norm for x in vec] if norm else list(vec)


class FastEmbedder:
    def __init__(
        self, model_name: str, cache_dir: Path, dim: int, retry_after_s: float = RETRY_AFTER_S
    ) -> None:
        self.model_name = model_name
        self.dim = dim
        self._cache_dir = cache_dir
        self._retry_after_s = retry_after_s
        self._lock = threading.Lock()
        self._model: Any = None  # fastembed.TextEmbedding once loaded
        self._error: str | None = None
        self._failed_at = -math.inf
        self._background: asyncio.Future[None] | None = None

    @property
    def ready(self) -> bool:
        return self._model is not None

    def _in_retry_wait(self) -> bool:
        return time.monotonic() - self._failed_at < self._retry_after_s

    def load(self) -> None:
        """Blocking; thread-safe. Loads the model unless it is already loaded."""
        if self._model is not None:
            return
        with self._lock:
            if self._model is not None:
                return
            if self._in_retry_wait():
                raise EmbeddingUnavailable(f"model failed to load: {self._error}")
            start = time.perf_counter()
            try:
                # Windows without Developer Mode can't symlink; the cache still works.
                os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
                # Imported here: onnxruntime and friends are only paid for when needed.
                from fastembed import TextEmbedding

                self._cache_dir.mkdir(parents=True, exist_ok=True)
                model = TextEmbedding(self.model_name, cache_dir=str(self._cache_dir))
                probe = next(iter(model.embed(["probe"])))
                if len(probe) != self.dim:
                    raise ValueError(f"model outputs {len(probe)} dims, expected {self.dim}")
            except Exception as exc:
                self._failed_at = time.monotonic()
                self._error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "embedding model %s failed to load: %s", self.model_name, self._error
                )
                raise EmbeddingUnavailable(f"model failed to load: {self._error}") from exc
            self._model, self._error = model, None
            logger.info(
                "embedding model loaded",
                extra={
                    "extra_fields": {
                        "model": self.model_name,
                        "load_ms": round((time.perf_counter() - start) * 1000),
                    }
                },
            )

    async def load_async(self) -> None:
        await asyncio.to_thread(self.load)

    def start_loading(self) -> None:
        """Start loading in a worker thread without waiting. Call from the event loop.

        No-op if the model is loaded, already loading, or waiting to retry a failed load.
        """
        if self._model is not None or self._in_retry_wait():
            return
        if self._background is not None and not self._background.done():
            return
        self._background = asyncio.get_running_loop().run_in_executor(None, self._load_quietly)

    def _load_quietly(self) -> None:
        try:
            self.load()
        except EmbeddingUnavailable:
            pass  # logged in load()

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if self._model is None:
            self.start_loading()
            if self._error is not None:
                raise EmbeddingUnavailable(f"model failed to load: {self._error}")
            raise EmbeddingUnavailable("model is still loading")
        return await asyncio.to_thread(self._embed_sync, list(texts))

    def _embed_sync(self, texts: list[str]) -> list[list[float]]:
        return [unit(v.tolist()) for v in self._model.embed(texts)]
