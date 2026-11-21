"""The rows the threat landscape is built from (composed in ``insight.landscape``).

One read covers the period the analyst asked about and the comparison periods before it, so trends
compare like with like. Everything honours the reader's TLP limit: a report above it adds nothing, not even
to a count.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from typing import Final

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from ..models import Document, DocumentTechnique, KEVRecord
from ..themes import THEMES
from .brief import KEV_SOURCE, SCORED_SOURCES, BriefDocument, BriefKev
from .common import fold, like_pattern
from .techniques import TAGGED
from .tlp import _visible
from .triage import list_watch_terms

#: At most this many reports are read; the landscape says so when it reached the limit.
MAX_LANDSCAPE_DOCUMENTS: Final = 10_000


@dataclass(frozen=True, slots=True)
class LandscapeData:
    """Raw facts for the threat landscape; ``landscape.compose`` decides what counts and words it."""

    #: Start of the earliest comparison period (ISO-8601 UTC); every row below is from on or after it.
    start: str
    #: Current reports Insight received at or after ``start``, newest first.
    documents: list[BriefDocument]
    #: The TLP label of each report in ``documents``.
    tlp: dict[str, str]
    #: Theme key -> IDs of the reports in ``documents`` whose text contains one of its words.
    theme_words: dict[str, set[str]]
    #: ``(document_id, technique_id)`` for ATT&CK techniques tagged on reports in ``documents``.
    techniques: list[tuple[str, str]]
    #: KEV entries CISA added on or after ``start``'s date.
    kev: list[BriefKev]
    #: Each watch term, with the IDs of the reports in ``documents`` that mention it.
    watch: dict[str, set[str]]
    #: When the oldest current report Insight holds arrived, leaving out ``ignore`` (``''`` when there are
    #: none): before it, Insight has nothing to compare with.
    first_received: str
    #: ``documents`` stopped at :data:`MAX_LANDSCAPE_DOCUMENTS`.
    truncated: bool


def landscape_data(
    db: Session, *, start: str, max_tlp: str | None = None, ignore: Collection[tuple[str, str]] = ()
) -> LandscapeData:
    """Facts for the threat landscape from reports Insight received at or after ``start`` (ISO-8601 UTC).

    ``ignore`` lists ``(title, source name)`` pairs that do not count as the start of Insight's history (the
    synthetic demo reports, which ``landscape.compose`` also leaves out).
    """
    window = [Document.is_current.is_(True), Document.created_at >= start, *_visible(max_tlp)]
    kev_report = and_(Document.source_key == KEV_SOURCE, Document.external_id == KEVRecord.cve)
    rows = db.execute(
        select(
            Document.id,
            Document.title,
            Document.source_name,
            Document.source_key,
            Document.created_at,
            func.coalesce(KEVRecord.date_added, ''),
            Document.tlp,
        )
        .outerjoin(KEVRecord, kev_report)
        .where(*window)
        .order_by(Document.created_at.desc(), Document.id)
        .limit(MAX_LANDSCAPE_DOCUMENTS + 1)
    ).all()
    truncated = len(rows) > MAX_LANDSCAPE_DOCUMENTS
    rows = rows[:MAX_LANDSCAPE_DOCUMENTS]
    ids = {r[0] for r in rows}
    # The bodies of CISA advisories carry their release dates (``brief.published``); no other body is read.
    bodies = dict(
        db.execute(
            select(Document.id, Document.body).where(*window, Document.source_key.in_(SCORED_SOURCES))
        ).all()
    )
    documents = [
        BriefDocument(i, title, source, key, created, published[:10], bodies.get(i, ''))
        for i, title, source, key, created, published, _ in rows
    ]

    def matching(words: tuple[str, ...]) -> set[str]:
        found = db.scalars(
            select(Document.id).where(
                *window, or_(*(Document.search_text.like(like_pattern(fold(w)), escape='\\') for w in words))
            )
        )
        return set(found) & ids

    theme_words = {theme.key: matching(theme.words) for theme in THEMES}
    techniques = [
        (doc_id, technique_id)
        for doc_id, technique_id in db.execute(
            select(DocumentTechnique.document_id, DocumentTechnique.technique_id)
            .join(Document, DocumentTechnique.document_id == Document.id)
            .where(*window, DocumentTechnique.status == TAGGED)
        )
        if doc_id in ids
    ]
    records = db.scalars(select(KEVRecord).where(KEVRecord.date_added >= start[:10])).all()
    kev_reports = dict(
        db.execute(
            select(Document.external_id, Document.id).where(
                Document.source_key == KEV_SOURCE,
                Document.external_id.in_([k.cve for k in records]),
                Document.is_current.is_(True),
                *_visible(max_tlp),
            )
        ).all()
    )
    kev = [
        BriefKev(
            k.cve,
            k.vendor,
            k.product,
            k.date_added,
            k.due_date,
            kev_reports.get(k.cve) or '',
            ransomware=k.ransomware,
            name=k.vulnerability_name,
        )
        for k in records
    ]
    watch = {term.term: matching((fold(term.term),)) for term in list_watch_terms(db)}
    oldest = db.execute(
        select(Document.created_at, Document.title, Document.source_name)
        .where(Document.is_current.is_(True), *_visible(max_tlp))
        .order_by(Document.created_at, Document.id)
        .limit(len(ignore) + 1)
    ).all()
    first = next((created for created, title, source in oldest if (title, source) not in ignore), '')
    return LandscapeData(
        start=start,
        documents=documents,
        tlp={r[0]: r[6] for r in rows},
        theme_words=theme_words,
        techniques=techniques,
        kev=kev,
        watch=watch,
        first_received=first,
        truncated=truncated,
    )
