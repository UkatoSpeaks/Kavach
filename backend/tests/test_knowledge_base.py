"""The knowledge-base docs themselves, and the parser."""

import re
from collections import Counter

import pytest

from app.core.enums import PatternKind
from app.services.knowledge_base import (
    GENUINE_CATEGORY,
    SCAM_CATEGORIES,
    DocError,
    PatternDoc,
    load_docs,
    parse_doc,
    sections,
)

DOCS = load_docs()
SCAM_DOCS = [d for d in DOCS if d.kind is PatternKind.SCAM]
GENUINE_DOCS = [d for d in DOCS if d.kind is PatternKind.GENUINE]


def test_scam_docs_cover_every_v1_type_with_3_to_4_variants() -> None:
    per_category = Counter(d.category for d in SCAM_DOCS)
    assert set(per_category) == SCAM_CATEGORIES
    assert all(3 <= n <= 4 for n in per_category.values()), per_category


def test_genuine_docs() -> None:
    assert len(GENUINE_DOCS) == 5
    assert {d.category for d in GENUINE_DOCS} == {GENUINE_CATEGORY}


@pytest.mark.parametrize("doc", DOCS, ids=[d.slug for d in DOCS])
def test_doc_awaits_source_check_and_invents_no_urls(doc: PatternDoc) -> None:
    assert doc.source_url is None and doc.needs_source_check
    # Only cybercrime.gov.in may be named; everything else waits for the source check.
    domains = set(re.findall(r"\b[\w-]+(?:\.[\w-]+)*\.(?:in|com|org|net|gov)\b", doc.content))
    assert domains <= {"cybercrime.gov.in"}, domains
    assert "http" not in doc.content


@pytest.mark.parametrize("doc", SCAM_DOCS, ids=[d.slug for d in SCAM_DOCS])
def test_scam_doc_examples_and_reporting(doc: PatternDoc) -> None:
    examples = doc.content.split("## Example messages")[1].split("## ")[0]
    for label in ("- English:", "- Hinglish:", "- Hindi:"):
        assert label in examples
    assert re.search(r"[ऀ-ॿ]", examples), "needs a Hindi (Devanagari) example"
    report = doc.content.split("## Where to report")[1]
    for where in ("1930", "cybercrime.gov.in", "Chakshu"):
        assert where in report


GOOD = """---
slug: demo
title: Demo scam
category: qr_code
kind: scam
source_url: ""
needs_source_check: true
---

## How it works
x
## Red flags
x
## Example messages
x
## What to do
x
## Where to report
x
"""


def test_parse_doc() -> None:
    doc = parse_doc(GOOD, expected_slug="demo")
    assert (doc.slug, doc.category, doc.kind, doc.source_url) == (
        "demo",
        "qr_code",
        PatternKind.SCAM,
        None,
    )
    assert sections(doc.content)[0] == "How it works"
    assert doc.embed_text.startswith("Demo scam\n\n## How it works")


def test_content_hash_tracks_text_and_model() -> None:
    doc = parse_doc(GOOD)
    edited = parse_doc(GOOD.replace("## Red flags\nx", "## Red flags\ny"))
    assert doc.content_hash("m1") == parse_doc(GOOD).content_hash("m1")
    assert doc.content_hash("m1") != edited.content_hash("m1")
    assert doc.content_hash("m1") != doc.content_hash("m2")


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("no frontmatter", "missing YAML frontmatter"),
        (GOOD.replace("slug: demo\n", ""), "missing frontmatter keys: slug"),
        (GOOD.replace("kind: scam", "kind: maybe"), "kind must be one of"),
        (GOOD.replace("qr_code", "digital_arrest"), "not a v1 scam type"),
        (GOOD.replace("qr_code", "generic"), "not a v1 scam type"),
        (GOOD.replace("kind: scam", "kind: genuine"), "genuine docs must have category"),
        (GOOD.replace("## Where to report\n", ""), "missing sections: Where to report"),
        (GOOD.replace("title: Demo scam", "title: [unclosed"), "invalid YAML"),
    ],
)
def test_parse_doc_rejects(text: str, error: str) -> None:
    with pytest.raises(DocError, match=re.escape(error)):
        parse_doc(text)


def test_slug_must_match_file_name() -> None:
    with pytest.raises(DocError, match="does not match the file name"):
        parse_doc(GOOD, expected_slug="other")
