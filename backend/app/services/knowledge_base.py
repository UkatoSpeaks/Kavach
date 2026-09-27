"""The scam-pattern knowledge base: markdown docs in data/scam_patterns/.

Each doc has YAML frontmatter and markdown sections:

    ---
    slug: phishing-e-challan          # must equal the file name without .md
    title: Fake traffic e-challan payment link
    category: phishing_link           # a v1 scam type; "genuine" for kind: genuine
    kind: scam                        # scam | genuine
    source_url: ""                    # advisory the doc is based on, once verified
    needs_source_check: true
    ---

    ## How it works
    ...

Parsing is pure; scripts/ingest_patterns.py embeds the docs and stores them.
"""

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from app.core.config import BACKEND_DIR
from app.core.enums import PatternKind, ScamType

PATTERNS_DIR = BACKEND_DIR / "data" / "scam_patterns"

GENUINE_CATEGORY = "genuine"
SCAM_CATEGORIES = frozenset(t.value for t in ScamType if t is not ScamType.GENERIC)
SCAM_SECTIONS = ("How it works", "Red flags", "Example messages", "What to do", "Where to report")

_FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n(.*)\Z", re.DOTALL)
_HEADING_RE = re.compile(r"^## +(.+?)\s*$", re.MULTILINE)
_REQUIRED_KEYS = ("slug", "title", "category", "kind")


class DocError(ValueError):
    """A knowledge-base doc is malformed."""


@dataclass(frozen=True)
class PatternDoc:
    slug: str
    title: str
    category: str
    kind: PatternKind
    content: str  # markdown body, without the frontmatter
    source_url: str | None
    needs_source_check: bool

    @property
    def embed_text(self) -> str:
        return f"{self.title}\n\n{self.content}"

    def content_hash(self, model_name: str) -> str:
        """Changes whenever the stored embedding would: new text or a different model."""
        return hashlib.sha256(f"{model_name}\n{self.embed_text}".encode()).hexdigest()


def sections(content: str) -> list[str]:
    return _HEADING_RE.findall(content)


def parse_doc(text: str, expected_slug: str | None = None) -> PatternDoc:
    """Parse one doc. Raises DocError if it is malformed."""
    m = _FRONTMATTER_RE.match(text.lstrip("﻿"))
    if not m:
        raise DocError("missing YAML frontmatter (--- ... ---)")
    try:
        meta = yaml.safe_load(m.group(1))
    except yaml.YAMLError as exc:
        raise DocError(f"invalid YAML frontmatter: {exc}") from exc
    if not isinstance(meta, dict):
        raise DocError("frontmatter must be a mapping")
    missing = [k for k in _REQUIRED_KEYS if not str(meta.get(k) or "").strip()]
    if missing:
        raise DocError(f"missing frontmatter keys: {', '.join(missing)}")

    slug, category = str(meta["slug"]).strip(), str(meta["category"]).strip()
    if expected_slug is not None and slug != expected_slug:
        raise DocError(f"slug {slug!r} does not match the file name {expected_slug!r}")
    try:
        kind = PatternKind(str(meta["kind"]).strip())
    except ValueError:
        raise DocError(f"kind must be one of {[k.value for k in PatternKind]}") from None
    if kind is PatternKind.SCAM and category not in SCAM_CATEGORIES:
        raise DocError(f"category {category!r} is not a v1 scam type: {sorted(SCAM_CATEGORIES)}")
    if kind is PatternKind.GENUINE and category != GENUINE_CATEGORY:
        raise DocError(f"genuine docs must have category {GENUINE_CATEGORY!r}")

    content = m.group(2).strip()
    if kind is PatternKind.SCAM:
        absent = [s for s in SCAM_SECTIONS if s not in sections(content)]
        if absent:
            raise DocError(f"missing sections: {', '.join(absent)}")
    elif not content:
        raise DocError("empty doc")

    return PatternDoc(
        slug=slug,
        title=str(meta["title"]).strip(),
        category=category,
        kind=kind,
        content=content,
        source_url=str(meta.get("source_url") or "").strip() or None,
        needs_source_check=bool(meta.get("needs_source_check", True)),
    )


def load_docs(directory: Path = PATTERNS_DIR) -> list[PatternDoc]:
    """Every *.md doc in `directory`, sorted by slug. Raises DocError naming the bad file."""
    docs = []
    for path in sorted(directory.glob("*.md")):
        try:
            docs.append(parse_doc(path.read_text(encoding="utf-8"), expected_slug=path.stem))
        except DocError as exc:
            raise DocError(f"{path.name}: {exc}") from exc
    return docs
