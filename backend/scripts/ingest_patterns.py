"""Embed the knowledge-base docs (data/scam_patterns/*.md) and upsert them into scam_patterns.

Idempotent: rows are matched by slug, and a doc is only re-embedded when its content_hash
(embedding model + title + content) changed. Metadata-only changes (category, kind,
source_url) update the row without re-embedding. Rows whose doc file was removed are deleted.

    uv run python -m scripts.ingest_patterns            # apply
    uv run python -m scripts.ingest_patterns --dry-run  # only print what would change

The first run downloads the embedding model (~220 MB) into EMBEDDING_CACHE_DIR.
"""

import argparse
import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.models import ScamPattern
from app.db.session import create_engine, create_sessionmaker
from app.services.embeddings import Embedder, FastEmbedder
from app.services.knowledge_base import PATTERNS_DIR, PatternDoc, load_docs


@dataclass
class Summary:
    added: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)  # re-embedded or metadata changed
    reembedded: list[str] = field(default_factory=list)  # subset of added + updated
    unchanged: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [
            f"added={len(self.added)} updated={len(self.updated)} "
            f"unchanged={len(self.unchanged)} deleted={len(self.deleted)} "
            f"(embedded {len(self.reembedded)})"
        ]
        for label, slugs in (
            ("added", self.added),
            ("updated", self.updated),
            ("deleted", self.deleted),
        ):
            lines += [f"  {label}: {s}" for s in slugs]
        return "\n".join(lines)


def _metadata(doc: PatternDoc) -> dict[str, str | None]:
    return {
        "title": doc.title,
        "category": doc.category,
        "kind": doc.kind.value,
        "content": doc.content,
        "source_url": doc.source_url,
    }


async def ingest(
    session: AsyncSession,
    docs: Sequence[PatternDoc],
    embedder: Embedder,
    *,
    dry_run: bool = False,
) -> Summary:
    """Sync scam_patterns with `docs`. Commits unless dry_run."""
    summary = Summary()
    existing = {row.slug: row for row in (await session.scalars(select(ScamPattern))).all()}

    to_embed: list[tuple[PatternDoc, ScamPattern]] = []
    for doc in docs:
        content_hash = doc.content_hash(embedder.model_name)
        row = existing.get(doc.slug)
        if row is None:
            row = ScamPattern(slug=doc.slug, content_hash=content_hash, **_metadata(doc))
            session.add(row)
            summary.added.append(doc.slug)
            to_embed.append((doc, row))
            continue
        needs_embedding = row.content_hash != content_hash or row.embedding is None
        changed = needs_embedding or any(getattr(row, k) != v for k, v in _metadata(doc).items())
        if not changed:
            summary.unchanged.append(doc.slug)
            continue
        for k, v in _metadata(doc).items():
            setattr(row, k, v)
        row.content_hash = content_hash
        summary.updated.append(doc.slug)
        if needs_embedding:
            to_embed.append((doc, row))

    if to_embed and not dry_run:
        vectors = await embedder.embed([doc.embed_text for doc, _ in to_embed])
        for (_, row), vector in zip(to_embed, vectors, strict=True):
            row.embedding = vector
    summary.reembedded = [doc.slug for doc, _ in to_embed]

    removed = sorted(set(existing) - {d.slug for d in docs})
    if removed:
        await session.execute(delete(ScamPattern).where(ScamPattern.slug.in_(removed)))
    summary.deleted = removed

    if dry_run:
        await session.rollback()
    else:
        await session.commit()
    return summary


async def main(directory: Path, dry_run: bool) -> None:
    settings = get_settings()
    docs = load_docs(directory)  # validate every doc before touching the database
    print(f"{len(docs)} docs in {directory}")
    embedder = FastEmbedder(
        settings.EMBEDDING_MODEL, settings.EMBEDDING_CACHE_DIR, settings.EMBEDDING_DIM
    )
    if not dry_run:
        print(f"loading {settings.EMBEDDING_MODEL} ...")
        await embedder.load_async()
    engine = create_engine(settings.DATABASE_URL)
    try:
        async with create_sessionmaker(engine)() as session:
            summary = await ingest(session, docs, embedder, dry_run=dry_run)
    finally:
        await engine.dispose()
    print(("DRY RUN: " if dry_run else "") + str(summary))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, default=PATTERNS_DIR, help="docs directory")
    parser.add_argument("--dry-run", action="store_true", help="don't write anything")
    args = parser.parse_args()
    asyncio.run(main(args.dir, args.dry_run))
