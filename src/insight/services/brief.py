"""The rows the landing-page intel brief is built from (composed in insight.brief)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from ..models import (
    Document,
    Entity,
    KEVRecord,
    Observation,
)
from .common import fold, like_pattern
from .tlp import _visible
from .triage import list_watch_terms

#: Sources whose report bodies the brief reads: CVSS scores, vendors and release dates in the CSAF connector's
#: lines (``brief.py``). Bodies of other reports are not loaded for the brief.
SCORED_SOURCES: Final = ('cisa-csaf',)

KEV_SOURCE: Final = 'cisa-kev'

MAX_BRIEF_DOCUMENTS: Final = 2_000


@dataclass(frozen=True, slots=True)
class BriefDocument:
    """A current report that Insight received in the brief's window.

    ``published`` is the publisher's date (``YYYY-MM-DD``) when the database knows it (a KEV report: the day
    CISA added the CVE), else ``''``. ``body`` is loaded for :data:`SCORED_SOURCES` only.
    """

    id: str
    title: str
    source_name: str
    source_key: str | None
    created_at: str
    published: str
    body: str


@dataclass(frozen=True, slots=True)
class BriefKev:
    """A CVE on CISA's Known Exploited Vulnerabilities list, and its KEV report.

    ``document_id`` is ``''`` when there is no KEV report the reader may see.
    """

    cve: str
    vendor: str
    product: str
    date_added: str
    due_date: str
    document_id: str


@dataclass(frozen=True, slots=True)
class BriefData:
    """The raw facts the intel brief is built from; ``brief.compose`` decides what counts and words it."""

    since: str
    documents: list[BriefDocument]
    #: ``(document_id, kind, value)`` for every indicator in ``documents``.
    mentions: list[tuple[str, str, str]]
    #: KEV entries added on or after ``since``'s date, and those of every CVE that ``documents`` mention.
    kev: dict[str, BriefKev]
    #: Each watch term, with the IDs of the reports in ``documents`` that mention it.
    watch: dict[str, set[str]]


def brief_data(db: Session, *, since: str, max_tlp: str | None = None) -> BriefData:
    """Facts for the intel brief: current reports Insight received at or after ``since`` (ISO-8601 UTC).

    ``max_tlp`` leaves out reports above the reader's limit, so nothing in the brief comes from them (the KEV
    list itself is public).
    """
    window = [Document.is_current.is_(True), Document.created_at >= since, *_visible(max_tlp)]
    kev_report = and_(Document.source_key == KEV_SOURCE, Document.external_id == KEVRecord.cve)
    rows = db.execute(
        select(
            Document.id,
            Document.title,
            Document.source_name,
            Document.source_key,
            Document.created_at,
            func.coalesce(KEVRecord.date_added, ''),
            Document.source_key.in_(SCORED_SOURCES),
        )
        .outerjoin(KEVRecord, kev_report)
        .where(*window)
        .order_by(Document.created_at.desc(), Document.id)
        .limit(MAX_BRIEF_DOCUMENTS)
    ).all()
    ids = [r[0] for r in rows]
    bodies = dict(
        db.execute(
            select(Document.id, Document.body).where(Document.id.in_([r[0] for r in rows if r[6]]))
        ).all()
    )
    documents = [BriefDocument(i, t, n, k, c, p[:10], bodies.get(i, '')) for i, t, n, k, c, p, _ in rows]
    mentions = [
        (doc_id, kind, value)
        for doc_id, kind, value in db.execute(
            select(Observation.document_id, Entity.kind, Entity.value)
            .join(Entity, Observation.entity_id == Entity.id)
            .where(Observation.document_id.in_(ids))
            .distinct()
        )
    ]
    cves = {value for _, kind, value in mentions if kind == 'cve'}
    records = db.scalars(
        select(KEVRecord).where(or_(KEVRecord.date_added >= since[:10], KEVRecord.cve.in_(cves)))
    ).all()
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
    kev = {
        k.cve: BriefKev(k.cve, k.vendor, k.product, k.date_added, k.due_date, kev_reports.get(k.cve) or '')
        for k in records
    }
    watch: dict[str, set[str]] = {}
    for term in [w.term for w in list_watch_terms(db)]:
        pattern = like_pattern(fold(term))
        matched = db.scalars(
            select(Document.id).where(Document.id.in_(ids), Document.search_text.like(pattern, escape='\\'))
        )
        watch[term] = set(matched)
    return BriefData(since=since, documents=documents, mentions=mentions, kev=kev, watch=watch)
