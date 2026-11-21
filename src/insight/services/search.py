"""Search, summaries, the reader detail view and workspace statistics."""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session

from ..models import (
    Document,
    Entity,
    KEVRecord,
    Note,
    Observation,
)
from .common import fold, like_pattern
from .documents import revisions
from .tlp import _visible

SUMMARY_LENGTH: Final = 220

MAX_PAGE_SIZE: Final = 200

MAX_QUERY_LENGTH: Final = 200


@dataclass(frozen=True, slots=True)
class DocumentQuery:
    """Inbox search. ``q`` is a literal, case-insensitive substring of title, body or source name."""

    q: str = ''
    status: str | None = None
    tlp: str | None = None
    include_superseded: bool = False
    offset: int = 0
    limit: int = 100
    #: Reader's TLP limit (a TLP-limited API key): more restrictive reports are invisible.
    max_tlp: str | None = None


def _document_conditions(
    *, q: str, status: str | None, tlp: str | None, include_superseded: bool, max_tlp: str | None = None
) -> list[ColumnElement[bool]]:
    """Report selection shared by the inbox search and the IOC export, so both pick the same reports."""
    conditions: list[ColumnElement[bool]] = _visible(max_tlp)
    if not include_superseded:
        conditions.append(Document.is_current.is_(True))
    if term := fold(q.strip()[:MAX_QUERY_LENGTH]).strip():
        conditions.append(Document.search_text.like(like_pattern(term), escape='\\'))
    if status:
        conditions.append(Document.status == status)
    if tlp:
        conditions.append(Document.tlp == tlp)
    return conditions


def search_documents(db: Session, query: DocumentQuery) -> list[Document]:
    """Inbox search shared by the API and UI (newest first, bounded page size)."""
    stmt = select(Document)
    conditions = _document_conditions(
        q=query.q,
        status=query.status,
        tlp=query.tlp,
        include_superseded=query.include_superseded,
        max_tlp=query.max_tlp,
    )
    if conditions:
        stmt = stmt.where(*conditions)
    limit = min(max(1, query.limit), MAX_PAGE_SIZE)
    stmt = stmt.order_by(Document.created_at.desc(), Document.id).offset(max(0, query.offset)).limit(limit)
    return list(db.scalars(stmt))


def summaries(db: Session, docs: Sequence[Document]) -> list[dict[str, Any]]:
    """List-view representations. Uses one grouped query for all entity counts (no N+1)."""
    ids = [d.id for d in docs]
    counts: dict[str, int] = {}
    if ids:
        rows = db.execute(
            select(Observation.document_id, func.count(func.distinct(Observation.entity_id)))
            .where(Observation.document_id.in_(ids))
            .group_by(Observation.document_id)
        )
        counts = {row[0]: row[1] for row in rows}
    return [
        {
            'id': doc.id,
            'title': doc.title,
            'source_name': doc.source_name,
            'source_url': doc.source_url,
            'tlp': doc.tlp,
            'status': doc.status,
            'created_at': doc.created_at,
            'summary': doc.body[:SUMMARY_LENGTH],
            'entity_count': counts.get(doc.id, 0),
            'is_current': doc.is_current,
            'truncated': doc.truncated,
        }
        for doc in docs
    ]


def summary(db: Session, doc: Document) -> dict[str, Any]:
    return summaries(db, [doc])[0]


def _kev_view(kev: KEVRecord | None) -> dict[str, str] | None:
    if kev is None:
        return None
    return {
        'date_added': kev.date_added,
        'due_date': kev.due_date,
        'required_action': kev.required_action,
        'vendor': kev.vendor,
        'product': kev.product,
        'imported_at': kev.imported_at,
        'vulnerability_name': kev.vulnerability_name,
        'ransomware_use': kev.ransomware_use,
        'notes': kev.notes,
        'cwes': kev.cwes,
    }


def _utf16_offsets(text: str) -> Callable[[int], int]:
    """Map code-point offsets (Python) to UTF-16 code-unit offsets (JavaScript ``String.slice``)."""
    astral = [index for index, char in enumerate(text) if ord(char) > 0xFFFF]
    if not astral:
        return lambda offset: offset
    return lambda offset: offset + bisect_left(astral, offset)


def detail(db: Session, doc: Document, *, max_tlp: str | None = None) -> dict[str, Any]:
    """Full document view: body, provenance, revisions, observations (with KEV context) and notes.

    ``max_tlp`` hides other revisions above the reader's limit; the caller has already checked ``doc``.
    """
    result = summary(db, doc)
    result.update(
        body=doc.body,
        content_hash=doc.content_hash,
        extractor_version=doc.extractor_version,
        source_key=doc.source_key,
        external_id=doc.external_id,
        supersedes_id=doc.supersedes_id,
        revisions=revisions(db, doc, max_tlp=max_tlp),
    )
    rows = db.execute(
        select(Observation, Entity, KEVRecord)
        .join(Entity, Observation.entity_id == Entity.id)
        .outerjoin(KEVRecord, (Entity.kind == 'cve') & (KEVRecord.cve == Entity.value))
        .where(Observation.document_id == doc.id)
        .order_by(Observation.start_offset, Entity.kind)
    )
    utf16 = _utf16_offsets(doc.body)
    result['observations'] = [
        {
            'id': obs.id,
            'entity_id': entity.id,
            'kind': entity.kind,
            'value': entity.value,
            'evidence': obs.evidence,
            'start_offset': obs.start_offset,
            'end_offset': obs.end_offset,
            'start_offset_utf16': utf16(obs.start_offset),
            'end_offset_utf16': utf16(obs.end_offset),
            'review_status': obs.review_status,
            'kev': _kev_view(kev),
        }
        for obs, entity, kev in rows
    ]
    result['notes'] = [
        {'id': n.id, 'body': n.body, 'created_at': n.created_at}
        for n in db.scalars(select(Note).where(Note.document_id == doc.id).order_by(Note.created_at))
    ]
    return result


def stats(db: Session, *, max_tlp: str | None = None) -> dict[str, int]:
    """Workspace counters. Document counts include current revisions only; ``max_tlp`` counts what the reader
    may see (entities: those mentioned in at least one visible report)."""
    current = [Document.is_current.is_(True), *_visible(max_tlp)]
    if max_tlp is None:
        entities = select(func.count()).select_from(Entity)
    else:
        entities = (
            select(func.count(func.distinct(Observation.entity_id)))
            .select_from(Observation)
            .join(Document, Observation.document_id == Document.id)
            .where(*_visible(max_tlp))
        )
    return {
        'documents': db.scalar(select(func.count()).select_from(Document).where(*current)) or 0,
        'entities': db.scalar(entities) or 0,
        'unreviewed': db.scalar(
            select(func.count()).select_from(Document).where(*current, Document.status != 'reviewed')
        )
        or 0,
        'observations_unreviewed': db.scalar(
            select(func.count())
            .select_from(Observation)
            .join(Document, Observation.document_id == Document.id)
            .where(*current, Observation.review_status == 'unreviewed')
        )
        or 0,
    }
