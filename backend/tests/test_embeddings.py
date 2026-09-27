"""FastEmbedder's loading behaviour, with fastembed replaced by an instant fake module."""

import sys
import threading
import time
import types
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.services.embeddings import EmbeddingUnavailable, FastEmbedder


class _Vec(list[float]):
    def tolist(self) -> list[float]:
        return list(self)


class FakeTextEmbedding:
    instances = 0
    dim = 4
    fail: Exception | None = None
    load_s = 0.0

    def __init__(self, model_name: str, cache_dir: str) -> None:
        time.sleep(self.load_s)
        if FakeTextEmbedding.fail is not None:
            raise FakeTextEmbedding.fail
        FakeTextEmbedding.instances += 1

    def embed(self, texts: list[str]) -> Iterator[_Vec]:
        for t in texts:
            yield _Vec([float(len(t)), 0.0, 0.0, 0.0][: self.dim] + [0.0] * (self.dim - 4))


@pytest.fixture(autouse=True)
def fake_fastembed(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeTextEmbedding.instances, FakeTextEmbedding.dim = 0, 4
    FakeTextEmbedding.fail, FakeTextEmbedding.load_s = None, 0.0
    module = types.ModuleType("fastembed")
    module.TextEmbedding = FakeTextEmbedding  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fastembed", module)


def _embedder(tmp_path: Path, **kw: float) -> FastEmbedder:
    return FastEmbedder("fake/model", tmp_path / "cache", dim=4, **kw)


async def test_embed_after_load_returns_unit_vectors(tmp_path: Path) -> None:
    e = _embedder(tmp_path)
    await e.load_async()
    assert e.ready and (tmp_path / "cache").is_dir()
    assert await e.embed(["abc", "de"]) == [[1.0, 0.0, 0.0, 0.0], [1.0, 0.0, 0.0, 0.0]]


def test_concurrent_loads_load_once(tmp_path: Path) -> None:
    FakeTextEmbedding.load_s = 0.05
    e = _embedder(tmp_path)
    threads = [threading.Thread(target=e.load) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert FakeTextEmbedding.instances == 1


async def test_embed_fails_fast_while_loading_in_background(tmp_path: Path) -> None:
    FakeTextEmbedding.load_s = 0.2
    e = _embedder(tmp_path)
    start = time.perf_counter()
    with pytest.raises(EmbeddingUnavailable, match="still loading"):
        await e.embed(["hi"])  # kicks off the background load, doesn't wait for it
    assert time.perf_counter() - start < 0.1
    assert e._background is not None
    await e._background
    assert e.ready and await e.embed(["hi"])


async def test_failed_load_is_unavailable_and_retried_later(tmp_path: Path) -> None:
    FakeTextEmbedding.fail = OSError("no space left on device")
    e = _embedder(tmp_path, retry_after_s=60)
    with pytest.raises(EmbeddingUnavailable, match="no space left"):
        await e.load_async()
    with pytest.raises(EmbeddingUnavailable, match="failed to load: OSError"):
        await e.embed(["hi"])  # within the retry wait: no new attempt
    assert e._background is None

    FakeTextEmbedding.fail = None
    e._failed_at -= 61  # the retry wait is over
    await e.load_async()
    assert e.ready


async def test_wrong_dimension_is_a_load_failure(tmp_path: Path) -> None:
    FakeTextEmbedding.dim = 8
    with pytest.raises(EmbeddingUnavailable, match="outputs 8 dims, expected 4"):
        await _embedder(tmp_path).load_async()
