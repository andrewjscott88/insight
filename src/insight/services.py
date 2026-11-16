"""Domain services: the single query/command layer shared by the JSON API and the NiceGUI workspace.

Neither ``main.py`` nor ``insight.ui`` builds SQL; they call these functions. That keeps behaviour (search
semantics, revision handling, audit events) identical across both front ends.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from bisect import bisect_left
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import ColumnElement, and_, func, or_, select
from sqlalchemy.orm import Session

from .extraction import ZERO_WIDTH, Mention, extract
from .ioc_export import IocMention, build_export
from .models import (
    AuditEvent,
    Document,
    Enrichment,
    Entity,
    KEVRecord,
    Note,
    Observation,
    SourceRun,
    WatchTerm,
    now,
    uid,
)
from .schemas import (
    DOCUMENT_STATUSES,
    REVIEW_STATUSES,
    TLP_LEVELS,
    DocumentInput,
    IocExportQuery,
    most_restrictive,
    tlp_markings,
)

SUMMARY_LENGTH: Final = 220
PIVOT_PAGE_SIZE: Final = 25
MAX_PAGE_SIZE: Final = 200
MAX_QUERY_LENGTH: Final = 200
MAX_WATCH_TERM_LENGTH: Final = 120
#: Upper bound on indicator mentions in one IOC export, so a single request cannot exhaust memory.
MAX_EXPORT_MENTIONS: Final = 100_000


@dataclass(frozen=True, slots=True)
class SourceRef:
    """Stable identity of an item at a curated source, e.g. ``SourceRef('cisa-kev', 'CVE-2024-3400')``."""

    source_key: str
    external_id: str


@dataclass(frozen=True, slots=True)
class DocumentQuery:
    """Inbox search. ``q`` is a literal, case-insensitive substring of title, body or source name."""

    q: str = ''
    status: str | None = None
    tlp: str | None = None
    include_superseded: bool = False
    offset: int = 0
    limit: int = 100


# --------------------------------------------------------------------------- audit


def audit(db: Session, action: str, object_id: str, detail: str = '') -> None:
    """Record an application audit event in the current transaction."""
    db.add(AuditEvent(action=action, object_id=object_id, detail=detail))


def audit_events(db: Session, limit: int = 200) -> list[AuditEvent]:
    return list(db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)))


# --------------------------------------------------------------------------- text folding


def fold(text: str) -> str:
    """Case-, accent- and width-insensitive form for search and watch terms.

    NFKD, drop combining marks and zero-width characters, casefold, NFC. So ``ÜBERWACHUNG``, ``überwachung``
    and ``uberwachung`` match; ``İSTANBUL`` matches ``istanbul``; NFC and NFD spellings of ``café`` match.
    The same function runs in Python for stored text and queries, so SQLite and PostgreSQL behave identically.
    """
    decomposed = unicodedata.normalize('NFKD', text)
    kept = ''.join(c for c in decomposed if not unicodedata.combining(c) and c not in ZERO_WIDTH)
    return unicodedata.normalize('NFC', kept.casefold())


# --------------------------------------------------------------------------- ingestion


def fingerprint(item: DocumentInput) -> str:
    """Stable identity of a submission: exact title, body, source, URL and TLP."""
    return hashlib.sha256(json.dumps(item.model_dump(), sort_keys=True).encode()).hexdigest()


def _current_revision(db: Session, ref: SourceRef) -> Document | None:
    return db.scalar(
        select(Document).where(
            Document.source_key == ref.source_key,
            Document.external_id == ref.external_id,
            Document.is_current.is_(True),
        )
    )


def _resolve_entities(db: Session, keys: set[tuple[str, str]]) -> dict[tuple[str, str], Entity]:
    """Load existing entities with one query and create the missing ones in one batched insert.

    Per-mention lookups cost two round trips each, which dominated ingest time on PostgreSQL (found by the
    milestone performance gate: 7.5 vs 105 documents/s on SQLite).
    """
    if not keys:
        db.flush()
        return {}
    by_kind: dict[str, set[str]] = defaultdict(set)
    for kind, value in keys:
        by_kind[kind].add(value)
    condition = or_(
        *(and_(Entity.kind == kind, Entity.value.in_(values)) for kind, values in by_kind.items())
    )
    entities = {(e.kind, e.value): e for e in db.scalars(select(Entity).where(condition))}
    created = [Entity(id=uid(), kind=kind, value=value) for kind, value in sorted(keys - entities.keys())]
    db.add_all(created)
    db.flush()  # the document and new entities are written before observations reference them
    entities.update({(e.kind, e.value): e for e in created})
    return entities


def apply_tlp_policy(item: DocumentInput) -> DocumentInput:
    """Raise the label to the most restrictive ``TLP:`` marking in the title or body. Never lowers it."""
    effective = most_restrictive(item.tlp, *tlp_markings(f'{item.title}\n{item.body}'))
    return item if effective == item.tlp else item.model_copy(update={'tlp': effective})


def _create_document(
    db: Session,
    item: DocumentInput,
    fp: str,
    ref: SourceRef | None,
    mentions: list[Mention],
    *,
    truncated: bool = False,
) -> Document:
    doc = Document(
        **item.model_dump(),
        fingerprint=fp,
        content_hash=hashlib.sha256(item.body.encode()).hexdigest(),
        source_key=ref.source_key if ref else None,
        external_id=ref.external_id if ref else None,
        search_text=fold(f'{item.title}\n{item.source_name}\n{item.body}'),
        truncated=truncated,
    )
    db.add(doc)
    entities = _resolve_entities(db, {(m.kind, m.value) for m in mentions})
    db.add_all(
        Observation(
            document_id=doc.id,
            entity_id=entities[(m.kind, m.value)].id,
            evidence=m.evidence,
            start_offset=m.start,
            end_offset=m.end,
        )
        for m in mentions
    )
    audit(db, 'document.ingest', doc.id, doc.content_hash)
    return doc


def ingest(
    db: Session, item: DocumentInput, *, ref: SourceRef | None = None, truncated: bool = False
) -> tuple[Document, bool]:
    """Store ``item`` with its extracted observations. Returns ``(document, created)``.

    The TLP label is first raised to any more restrictive ``TLP:`` marking in the text (``apply_tlp_policy``);
    compare ``document.tlp`` with ``item.tlp`` to tell the submitter. ``truncated`` records that a connector
    shortened the publisher's text.

    Without ``ref`` (manual submissions): exact re-submissions return the existing document; distinct
    sources or TLP labels are retained separately even when their bodies are identical.

    With ``ref`` (curated sources): at most one revision per source item is current. Changed content creates
    a new revision that supersedes the previous one; reverting to an earlier revision's exact content makes
    that revision current again. Stored bodies are never edited, so observation offsets stay valid.
    """
    submitted_tlp = item.tlp
    item = apply_tlp_policy(item)
    fp = fingerprint(item)
    existing = db.scalar(select(Document).where(Document.fingerprint == fp))
    if ref is None:
        if existing is not None:
            return existing, False
        doc = _create_document(db, item, fp, None, extract(item.body), truncated=truncated)
        _audit_tlp_raise(db, doc, submitted_tlp)
        db.flush()
        return doc, True

    current = _current_revision(db, ref)
    if existing is not None:
        if (
            existing.is_current
            or existing.source_key != ref.source_key
            or existing.external_id != ref.external_id
        ):
            return existing, False
        # The publisher reverted to an earlier revision: make that exact revision current again.
        if current is not None:
            current.is_current = False
            db.flush()
        existing.is_current = True
        audit(db, 'document.revision.reactivate', existing.id, current.id if current else '')
        db.flush()
        return existing, False

    mentions = extract(item.body)  # May raise ValueError: do it before changing any existing revision.
    if current is not None:
        # Flush the demotion first so the partial unique index never sees two current revisions.
        current.is_current = False
        db.flush()
    doc = _create_document(db, item, fp, ref, mentions, truncated=truncated)
    _audit_tlp_raise(db, doc, submitted_tlp)
    if current is not None:
        doc.supersedes_id = current.id
        audit(db, 'document.revision.supersede', doc.id, current.id)
    db.flush()
    return doc, True


def _audit_tlp_raise(db: Session, doc: Document, submitted: str) -> None:
    if doc.tlp != submitted:
        audit(db, 'document.tlp_raised', doc.id, f'{submitted} -> {doc.tlp} (marking found in the text)')


# --------------------------------------------------------------------------- read models


def like_pattern(term: str) -> str:
    """Escape ``term`` for a literal ``LIKE/ILIKE ... ESCAPE '\\'`` substring match."""
    escaped = term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    return f'%{escaped}%'


def _document_conditions(
    *, q: str, status: str | None, tlp: str | None, include_superseded: bool
) -> list[ColumnElement[bool]]:
    """Report selection shared by the inbox search and the IOC export, so both pick the same reports."""
    conditions: list[ColumnElement[bool]] = []
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
        q=query.q, status=query.status, tlp=query.tlp, include_superseded=query.include_superseded
    )
    if conditions:
        stmt = stmt.where(*conditions)
    limit = min(max(1, query.limit), MAX_PAGE_SIZE)
    stmt = stmt.order_by(Document.created_at.desc(), Document.id).offset(max(0, query.offset)).limit(limit)
    return list(db.scalars(stmt))


def get_document(db: Session, doc_id: str) -> Document | None:
    return db.get(Document, doc_id)


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
    }


def revisions(db: Session, doc: Document) -> list[dict[str, Any]]:
    """All revisions of the same source item, oldest first (empty for manual documents)."""
    if doc.source_key is None or doc.external_id is None:
        return []
    rows = db.scalars(
        select(Document)
        .where(Document.source_key == doc.source_key, Document.external_id == doc.external_id)
        .order_by(Document.created_at, Document.id)
    )
    return [
        {
            'id': r.id,
            'title': r.title,
            'created_at': r.created_at,
            'is_current': r.is_current,
            'status': r.status,
        }
        for r in rows
    ]


def _utf16_offsets(text: str) -> Callable[[int], int]:
    """Map code-point offsets (Python) to UTF-16 code-unit offsets (JavaScript ``String.slice``)."""
    astral = [index for index, char in enumerate(text) if ord(char) > 0xFFFF]
    if not astral:
        return lambda offset: offset
    return lambda offset: offset + bisect_left(astral, offset)


def detail(db: Session, doc: Document) -> dict[str, Any]:
    """Full document view: body, provenance, revisions, observations (with KEV context) and notes."""
    result = summary(db, doc)
    result.update(
        body=doc.body,
        content_hash=doc.content_hash,
        extractor_version=doc.extractor_version,
        source_key=doc.source_key,
        external_id=doc.external_id,
        supersedes_id=doc.supersedes_id,
        revisions=revisions(db, doc),
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


def stats(db: Session) -> dict[str, int]:
    """Workspace counters. Document counts include current revisions only."""
    current = Document.is_current.is_(True)
    return {
        'documents': db.scalar(select(func.count()).select_from(Document).where(current)) or 0,
        'entities': db.scalar(select(func.count()).select_from(Entity)) or 0,
        'unreviewed': db.scalar(
            select(func.count()).select_from(Document).where(current, Document.status != 'reviewed')
        )
        or 0,
        'observations_unreviewed': db.scalar(
            select(func.count())
            .select_from(Observation)
            .join(Document, Observation.document_id == Document.id)
            .where(current, Observation.review_status == 'unreviewed')
        )
        or 0,
    }


def list_entities(db: Session, q: str = '', limit: int = 200) -> list[tuple[Entity, int]]:
    """Entities with the number of distinct documents mentioning them (literal, case-insensitive search)."""
    stmt = (
        select(Entity, func.count(func.distinct(Observation.document_id)))
        .join(Observation, Observation.entity_id == Entity.id)
        .group_by(Entity.id)
        .order_by(Entity.kind, Entity.value)
        .limit(limit)
    )
    if term := q.strip()[:MAX_QUERY_LENGTH]:
        stmt = stmt.where(Entity.value.ilike(like_pattern(term), escape='\\'))
    return [(entity, count) for entity, count in db.execute(stmt)]


def get_entity(db: Session, entity_id: str) -> Entity | None:
    return db.get(Entity, entity_id)


def entity_documents(
    db: Session, entity_id: str, *, offset: int = 0, limit: int = PIVOT_PAGE_SIZE
) -> list[Document]:
    """One page of documents (all revisions) mentioning the entity, newest first.

    Always paginated: widely shared indicators can appear in thousands of reports (the workspace used to
    render every one of them for every entity, which grew the page without bound).
    """
    ids = select(Observation.document_id).where(Observation.entity_id == entity_id).distinct()
    stmt = (
        select(Document)
        .where(Document.id.in_(ids))
        .order_by(Document.created_at.desc(), Document.id)
        .offset(max(0, offset))
        .limit(min(max(1, limit), MAX_PAGE_SIZE))
    )
    return list(db.scalars(stmt))


def count_entity_documents(db: Session, entity_id: str) -> int:
    stmt = select(func.count(func.distinct(Observation.document_id))).where(
        Observation.entity_id == entity_id
    )
    return db.scalar(stmt) or 0


# --------------------------------------------------------------------------- IOC export


def _ioc_conditions(query: IocExportQuery) -> list[ColumnElement[bool]]:
    """Which mentions an IOC export (or its preview) includes: report filters plus kind and review state.

    Reports chosen explicitly with ``document_ids`` are included even when they are superseded revisions.
    """
    conditions = _document_conditions(
        q=query.q,
        status=query.status,
        tlp=query.tlp,
        include_superseded=query.include_superseded or bool(query.document_ids),
    )
    if query.document_ids:
        conditions.append(Document.id.in_(query.document_ids))
    if query.max_tlp is not None:
        conditions.append(Document.tlp.in_(TLP_LEVELS[: TLP_LEVELS.index(query.max_tlp) + 1]))
    conditions.append(Entity.kind.in_(query.kinds))
    conditions.append(Observation.review_status.in_(query.review_statuses))
    return conditions


def ioc_export_counts(db: Session, query: IocExportQuery) -> dict[str, int]:
    """``{'iocs', 'documents', 'mentions'}`` an export with ``query`` would contain. One query, not audited.

    Used to preview an export before downloading it; compare ``mentions`` with ``MAX_EXPORT_MENTIONS``.
    """
    row = db.execute(
        select(
            func.count(func.distinct(Entity.id)),
            func.count(func.distinct(Document.id)),
            func.count(Observation.id),
        )
        .select_from(Observation)
        .join(Entity, Observation.entity_id == Entity.id)
        .join(Document, Observation.document_id == Document.id)
        .where(*_ioc_conditions(query))
    ).one()
    return {'iocs': row[0], 'documents': row[1], 'mentions': row[2]}


def ioc_mentions(db: Session, query: IocExportQuery) -> list[IocMention]:
    """Every indicator mention matching ``query``, ordered by indicator, report age and position.

    Only the columns the export needs are selected: loading whole documents would repeat each report body
    once per mention. Raises ``ValueError`` above ``MAX_EXPORT_MENTIONS`` mentions (narrow the filters).
    """
    stmt = (
        select(
            Observation.review_status,
            Observation.evidence,
            Entity.id,
            Entity.kind,
            Entity.value,
            Document.id,
            Document.title,
            Document.source_name,
            Document.source_url,
            Document.tlp,
            Document.status,
            Document.created_at,
            Document.is_current,
            Document.extractor_version,
            KEVRecord,
        )
        .select_from(Observation)
        .join(Entity, Observation.entity_id == Entity.id)
        .join(Document, Observation.document_id == Document.id)
        .outerjoin(KEVRecord, (Entity.kind == 'cve') & (KEVRecord.cve == Entity.value))
        .where(*_ioc_conditions(query))
        .order_by(
            Entity.kind,
            Entity.value,
            Document.created_at,
            Document.id,
            Observation.start_offset,
            Observation.id,
        )
        .limit(MAX_EXPORT_MENTIONS + 1)
    )
    mentions = [
        IocMention(
            entity_id=entity_id,
            kind=kind,
            value=value,
            review_status=review_status,
            evidence=evidence,
            document_id=document_id,
            title=title,
            source_name=source_name,
            source_url=source_url,
            tlp=tlp,
            status=status,
            created_at=created_at,
            is_current=is_current,
            kev=_kev_view(kev),
            extractor_version=extractor_version,
        )
        for (
            review_status,
            evidence,
            entity_id,
            kind,
            value,
            document_id,
            title,
            source_name,
            source_url,
            tlp,
            status,
            created_at,
            is_current,
            extractor_version,
            kev,
        ) in db.execute(stmt)
    ]
    if len(mentions) > MAX_EXPORT_MENTIONS:
        raise ValueError(
            f'More than {MAX_EXPORT_MENTIONS:,} indicator mentions match; narrow the filters '
            '(indicator types, search, TLP) and export in parts.'
        )
    return mentions


def export_iocs(db: Session, query: IocExportQuery) -> dict[str, Any]:
    """Build an ``insight-ioc-v1`` export for ``query`` and audit it (``ioc.export``).

    Shared by the API, the workspace and ``insight export-iocs``. The audit event's object ID is the
    ``export_id`` written into the file, so a file found later can be traced back to its audit record.
    """
    mentions = ioc_mentions(db, query)
    export_id = uid()
    filters = query.model_dump(mode='json', exclude={'defang'})
    result = build_export(
        mentions,
        filters=filters,
        defanged=query.defang,
        export_id=export_id,
        generated_at=now(),
        include_evidence=query.include_evidence,
    )
    audit_detail = {
        'iocs': result['counts']['iocs'],
        'documents': result['counts']['documents'],
        'tlp': result['tlp'],
        'defanged': query.defang,
        'filters': filters,
    }
    audit(db, 'ioc.export', export_id, json.dumps(audit_detail, sort_keys=True))
    return result


# --------------------------------------------------------------------------- analyst actions


def set_document_status(db: Session, doc_id: str, status: str) -> Document | None:
    if status not in DOCUMENT_STATUSES:
        raise ValueError(f'Unknown document status: {status}')
    doc = db.get(Document, doc_id)
    if doc is not None:
        doc.status = status
        audit(db, 'document.review', doc.id, status)
    return doc


def set_observation_status(db: Session, obs_id: str, status: str) -> Observation | None:
    if status not in REVIEW_STATUSES:
        raise ValueError(f'Unknown review status: {status}')
    obs = db.get(Observation, obs_id)
    if obs is not None:
        obs.review_status = status
        audit(db, 'observation.review', obs.id, status)
    return obs


def add_note(db: Session, doc_id: str, body: str) -> Note | None:
    if db.get(Document, doc_id) is None:
        return None
    note = Note(document_id=doc_id, body=body)
    db.add(note)
    db.flush()
    audit(db, 'note.add', note.id, doc_id)
    return note


def list_watch_terms(db: Session) -> list[WatchTerm]:
    return list(db.scalars(select(WatchTerm).order_by(WatchTerm.term)))


def add_watch_term(db: Session, term: str) -> WatchTerm | None:
    """Add a watch term. Returns ``None`` if it already exists (case-insensitively)."""
    term = term.strip()
    if not term or len(term) > MAX_WATCH_TERM_LENGTH:
        raise ValueError(f'Enter a term between 1 and {MAX_WATCH_TERM_LENGTH} characters.')
    if any(fold(t) == fold(term) for t in db.scalars(select(WatchTerm.term))):
        return None
    obj = WatchTerm(term=term)
    db.add(obj)
    db.flush()
    audit(db, 'watch_term.create', obj.id, term)
    return obj


def remove_watch_term(db: Session, term_id: str) -> bool:
    obj = db.get(WatchTerm, term_id)
    if obj is None:
        return False
    audit(db, 'watch_term.remove', term_id, obj.term)
    db.delete(obj)
    db.flush()
    return True


def watch_matches(terms: Sequence[str], text: str) -> list[str]:
    """Watch terms that occur in ``text`` (literal substring, folded exactly like search)."""
    haystack = fold(text)
    return [t for t in terms if fold(t) in haystack]


def recent_source_runs(db: Session, source_key: str | None = None, limit: int = 12) -> list[SourceRun]:
    stmt = select(SourceRun).order_by(SourceRun.created_at.desc()).limit(limit)
    if source_key is not None:
        stmt = stmt.where(SourceRun.source_key == source_key)
    return list(db.scalars(stmt))


def cached_enrichments(db: Session, cve: str) -> list[Enrichment]:
    return list(db.scalars(select(Enrichment).where(Enrichment.cve == cve).order_by(Enrichment.provider)))
