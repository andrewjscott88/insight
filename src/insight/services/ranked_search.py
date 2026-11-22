"""Relevance-ranked report search (TIP 3.2, ADR 0027): the same ranking on SQLite and PostgreSQL.

A query is words in any order, with "quoted phrases" kept together, matched against the folded copy of each
report's title, publisher and text (``documents.search_text``, so case, accents and width never matter).
Every word must match. The database counts each word's occurrences with plain ``length``/``replace``
arithmetic, which both databases compute identically, and Python scores the counts with BM25 plus a title
boost. No full-text index or extension is needed, and a ranking never depends on the database in use.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Final

from sqlalchemy import ColumnElement, Integer, cast, func, select
from sqlalchemy.orm import Session

from ..models import Document
from .common import fold, like_pattern
from .search import MAX_PAGE_SIZE, MAX_QUERY_LENGTH, _document_conditions

MAX_TERMS: Final = 8
#: Only the newest this-many matching reports are ranked; ``RankedPage.capped`` says when more matched.
MAX_CANDIDATES: Final = 5_000
#: BM25 constants (the usual defaults) and the extra weight of a word that is also in the title.
K1: Final = 1.2
B: Final = 0.75
TITLE_BOOST: Final = 2.0
SNIPPET: Final = 220
_TOKENS = re.compile(r'"([^"]+)"|(\S+)')


def search_terms(query: str) -> list[str]:
    """Folded words and quoted phrases, deduplicated, in query order (at most ``MAX_TERMS``)."""
    found: list[str] = []
    for phrase, word in _TOKENS.findall(fold(query[:MAX_QUERY_LENGTH])):
        term = ' '.join((phrase or word).split())
        if term and term not in found:
            found.append(term)
    return found[:MAX_TERMS]


@dataclass(frozen=True)
class RankedHit:
    document: Document
    score: float
    matched_in_title: tuple[str, ...]
    snippet: str


@dataclass(frozen=True)
class RankedPage:
    hits: list[RankedHit]
    total: int
    capped: bool
    terms: tuple[str, ...]


def _occurrences(term: str) -> ColumnElement[int]:
    """How often ``term`` occurs in the folded text, counted the same way by SQLite and PostgreSQL."""
    removed = func.length(Document.search_text) - func.length(func.replace(Document.search_text, term, ''))
    return cast(removed / len(term), Integer)


def _snippet(body: str, words: list[str]) -> str:
    """Report text around the first word found (case-insensitive), or its start."""
    lowered = body.casefold()
    hits = [i for i in (lowered.find(w) for w in words) if i >= 0]
    if not hits:
        return body[:SNIPPET]
    start = max(0, min(hits) - SNIPPET // 3)
    text = body[start : start + SNIPPET]
    return ('…' if start else '') + text + ('…' if start + SNIPPET < len(body) else '')


def ranked_search(
    db: Session,
    q: str,
    *,
    status: str | None = None,
    tlp: str | None = None,
    include_superseded: bool = False,
    max_tlp: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> RankedPage:
    """Reports matching every word of ``q``, best first; ties go to the newer report.

    The visibility rules are the inbox's (``_document_conditions``): the caller's TLP limit, current
    revisions unless asked otherwise, and the status and TLP filters.
    """
    words = search_terms(q)
    base = _document_conditions(
        q='', status=status, tlp=tlp, include_superseded=include_superseded, max_tlp=max_tlp
    )
    if not words:
        return RankedPage([], 0, False, ())
    matches = [Document.search_text.like(like_pattern(w), escape='\\') for w in words]
    rows = db.execute(
        select(
            Document.id,
            Document.title,
            func.length(Document.search_text),
            *(_occurrences(w) for w in words),
        )
        .where(*base, *matches)
        .order_by(Document.created_at.desc(), Document.id)
        .limit(MAX_CANDIDATES + 1)
    ).all()
    capped = len(rows) > MAX_CANDIDATES
    rows = rows[:MAX_CANDIDATES]
    if not rows:
        return RankedPage([], 0, False, tuple(words))
    # Collection statistics over the reports the caller may search, not only the matches.
    total_docs, average = db.execute(
        select(func.count(), func.coalesce(func.avg(func.length(Document.search_text)), 1)).where(*base)
    ).one()
    frequency = [
        db.scalar(select(func.count()).select_from(Document).where(*base, match)) or 0 for match in matches
    ]
    idf = [math.log(1 + (total_docs - df + 0.5) / (df + 0.5)) for df in frequency]
    avg_length = max(float(average), 1.0)
    scored: list[tuple[float, int, str, tuple[str, ...]]] = []
    for position, (doc_id, title, length, *counts) in enumerate(rows):
        norm = K1 * (1 - B + B * (length or 0) / avg_length)
        score = sum(w * tf * (K1 + 1) / (tf + norm) for w, tf in zip(idf, counts, strict=True) if tf)
        folded_title = fold(title)
        in_title = tuple(word for word in words if word in folded_title)
        score += TITLE_BOOST * sum(idf[words.index(word)] for word in in_title)
        # Rows arrive newest first, so the position breaks ties in favour of newer reports.
        scored.append((round(score, 9), position, doc_id, in_title))
    scored.sort(key=lambda item: (-item[0], item[1]))
    page = scored[max(0, offset) : max(0, offset) + min(max(1, limit), MAX_PAGE_SIZE)]
    documents = {d.id: d for d in db.scalars(select(Document).where(Document.id.in_([p[2] for p in page])))}
    plain = [w for w in words if w.isascii()] or words
    hits = [
        RankedHit(documents[doc_id], score, in_title, _snippet(documents[doc_id].body, plain))
        for score, _, doc_id, in_title in page
    ]
    return RankedPage(hits, len(scored), capped, tuple(words))
