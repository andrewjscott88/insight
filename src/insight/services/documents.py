"""Ingest, fingerprints, revisions and the TLP policy on the way in."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from ..extraction import EXTRACTOR_VERSION, Mention, extract
from ..models import (
    Document,
    Entity,
    Observation,
    uid,
)
from ..schemas import (
    TLP_LEVELS,
    DocumentInput,
)
from .alerts import queue_report_alerts
from .audit import audit
from .common import fold
from .techniques import carry_decisions, record_report_techniques
from .tlp import _refuse_above, _visible, apply_tlp_policy, tlp_permitted, visible_levels


@dataclass(frozen=True, slots=True)
class SourceRef:
    """Stable identity of an item at a curated source, e.g. ``SourceRef('cisa-kev', 'CVE-2024-3400')``."""

    source_key: str
    external_id: str


@dataclass(frozen=True, slots=True)
class StructuredObservations:
    """Validated values and evidence spans supplied by a structured-format parser."""

    version: str
    mentions: list[Mention]


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


def count_documents_above(db: Session, max_tlp: str) -> int:
    """Stored reports labelled more restrictively than ``max_tlp`` (e.g. from before the limit was set)."""
    above = [label for label in TLP_LEVELS if not tlp_permitted(label, max_tlp)]
    if not above:
        return 0
    return db.scalar(select(func.count()).select_from(Document).where(Document.tlp.in_(above))) or 0


def _create_document(
    db: Session,
    item: DocumentInput,
    fp: str,
    ref: SourceRef | None,
    observations: StructuredObservations,
    *,
    truncated: bool = False,
    document_id: str | None = None,
) -> Document:
    doc = Document(
        **item.model_dump(),
        id=document_id or uid(),
        extractor_version=observations.version,
        fingerprint=fp,
        content_hash=hashlib.sha256(item.body.encode()).hexdigest(),
        source_key=ref.source_key if ref else None,
        external_id=ref.external_id if ref else None,
        search_text=fold(f'{item.title}\n{item.source_name}\n{item.body}'),
        truncated=truncated,
    )
    db.add(doc)
    mentions = observations.mentions
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
    db: Session,
    item: DocumentInput,
    *,
    ref: SourceRef | None = None,
    truncated: bool = False,
    max_tlp: str | None = None,
    structured: StructuredObservations | None = None,
    initial_document_id: str | None = None,
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

    ``max_tlp`` (manual submissions: ``INSIGHT_MAX_TLP``) refuses the report with :class:`TlpNotPermitted`
    when its label *after* raising is more restrictive, so a marking in the text cannot slip past the limit.
    Nothing is stored and no exact duplicate is returned.

    A structured importer can supply its validated, typed observations and the initial source document ID.
    Later revisions get new IDs as usual. Evidence offsets must refer to the supplied document body.
    """
    submitted_tlp = item.tlp
    item = apply_tlp_policy(item)
    if max_tlp is not None:
        _refuse_above(submitted_tlp, item.tlp, max_tlp)
    fp = fingerprint(item)
    existing = db.scalar(select(Document).where(Document.fingerprint == fp))
    if ref is None:
        if existing is not None:
            return existing, False
        observations = structured or StructuredObservations(EXTRACTOR_VERSION, extract(item.body))
        doc = _create_document(
            db, item, fp, None, observations, truncated=truncated, document_id=initial_document_id
        )
        _audit_tlp_raise(db, doc, submitted_tlp)
        db.flush()
        record_report_techniques(db, doc)
        queue_report_alerts(db, doc)
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
        if current is not None:
            carry_decisions(db, from_doc=current, to_doc=existing)
        audit(db, 'document.revision.reactivate', existing.id, current.id if current else '')
        db.flush()
        return existing, False

    observations = structured or StructuredObservations(EXTRACTOR_VERSION, extract(item.body))
    if current is not None:
        # Flush the demotion first so the partial unique index never sees two current revisions.
        current.is_current = False
        db.flush()
    doc = _create_document(
        db,
        item,
        fp,
        ref,
        observations,
        truncated=truncated,
        document_id=initial_document_id if current is None else None,
    )
    _audit_tlp_raise(db, doc, submitted_tlp)
    if current is not None:
        doc.supersedes_id = current.id
        audit(db, 'document.revision.supersede', doc.id, current.id)
    db.flush()
    record_report_techniques(db, doc, previous=current)
    queue_report_alerts(db, doc)
    db.flush()
    return doc, True


def _audit_tlp_raise(db: Session, doc: Document, submitted: str) -> None:
    if doc.tlp != submitted:
        audit(db, 'document.tlp_raised', doc.id, f'{submitted} -> {doc.tlp} (marking found in the text)')


def get_document(db: Session, doc_id: str, *, max_tlp: str | None = None) -> Document | None:
    """The report, or ``None`` if it does not exist or is above the reader's TLP limit (indistinguishable)."""
    doc = db.get(Document, doc_id)
    if doc is None or doc.tlp not in visible_levels(max_tlp):
        return None
    return doc


def revisions(db: Session, doc: Document, *, max_tlp: str | None = None) -> list[dict[str, Any]]:
    """All revisions of the same source item visible to the reader, oldest first (empty for manual ones)."""
    if doc.source_key is None or doc.external_id is None:
        return []
    rows = db.scalars(
        select(Document)
        .where(
            Document.source_key == doc.source_key,
            Document.external_id == doc.external_id,
            *_visible(max_tlp),
        )
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
