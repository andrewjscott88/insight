"""Deleting a report for legal or retention reasons (review finding C4; ``insight delete-report``).

Reports carry victims' names, addresses and hosts, so data-protection law can require deleting one. This
replaces the runbook's manual SQL procedure with one audited transaction:

- the report's observations and notes are deleted with it;
- indicators that no other report mentions are deleted too, with any verdict on them (the verdict rested on
  reports that no longer exist);
- the revision chain is repaired: later revisions point past the deleted one, and when it was the current
  revision of a synced item, the newest remaining revision becomes current (so the item never ends up with
  none);
- one ``document.delete`` audit event keeps the reason and the content hash, never the title or the text.

There is deliberately no API route or workspace button: like API keys and MFA, deletion needs shell access.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from ..models import Document, Entity, EntityAssessment, Note, Observation
from .audit import audit

MAX_REASON_LENGTH = 500


@dataclass(frozen=True, slots=True)
class DeletionPreview:
    """What ``delete_document`` would remove, for a confirmation prompt."""

    id: str
    title: str
    tlp: str
    created_at: str
    source_name: str
    source_key: str | None
    is_current: bool
    observations: int
    notes: int
    revisions: int  # other stored revisions of the same source item


@dataclass(frozen=True, slots=True)
class DeletionResult:
    document_id: str
    content_hash: str
    observations: int
    notes: int
    entities: int  # indicators no other report mentions, deleted with the report
    verdicts: int  # verdicts on those indicators
    now_current: str | None  # the revision made current in the deleted one's place, if any


def _same_item(db: Session, doc: Document) -> list[Document]:
    """The other stored revisions of a synced item (none for a manual report)."""
    if doc.source_key is None or doc.external_id is None:
        return []
    stmt = select(Document).where(
        Document.source_key == doc.source_key, Document.external_id == doc.external_id, Document.id != doc.id
    )
    return list(db.scalars(stmt))


def _count(db: Session, model: type[Observation] | type[Note], document_id: str) -> int:
    return db.scalar(select(func.count()).select_from(model).where(model.document_id == document_id)) or 0


def deletion_preview(db: Session, document_id: str) -> DeletionPreview | None:
    doc = db.get(Document, document_id)
    if doc is None:
        return None
    return DeletionPreview(
        id=doc.id,
        title=doc.title,
        tlp=doc.tlp,
        created_at=doc.created_at,
        source_name=doc.source_name,
        source_key=doc.source_key,
        is_current=doc.is_current,
        observations=_count(db, Observation, doc.id),
        notes=_count(db, Note, doc.id),
        revisions=len(_same_item(db, doc)),
    )


def delete_document(db: Session, document_id: str, reason: str) -> DeletionResult:
    """Delete one report and everything that exists only because of it (see the module docstring).

    Raises ``LookupError`` for an unknown ID and ``ValueError`` for a blank or over-long reason. Audited as
    ``document.delete`` with the session's actor.
    """
    reason = reason.strip()
    if not reason:
        raise ValueError('a reason is required: a ticket or the retention rule, for example')
    if len(reason) > MAX_REASON_LENGTH:
        raise ValueError(f'keep the reason to {MAX_REASON_LENGTH} characters')
    doc = db.get(Document, document_id)
    if doc is None:
        raise LookupError(f'no report with ID {document_id}')
    others = _same_item(db, doc)
    was_current = doc.is_current
    entity_ids = set(db.scalars(select(Observation.entity_id).where(Observation.document_id == doc.id)))
    observations, notes = _count(db, Observation, doc.id), _count(db, Note, doc.id)

    db.execute(
        update(Document).where(Document.supersedes_id == doc.id).values(supersedes_id=doc.supersedes_id)
    )
    db.execute(delete(Observation).where(Observation.document_id == doc.id))
    db.execute(delete(Note).where(Note.document_id == doc.id))
    content_hash = doc.content_hash
    db.delete(doc)
    db.flush()  # Gone before a predecessor is made current: one current revision per item (a unique index).

    now_current = None
    if was_current and others:
        newest = max(others, key=lambda d: (d.created_at, d.id))
        db.refresh(newest)
        newest.is_current = True
        now_current = newest.id

    still_used = set(
        db.scalars(select(Observation.entity_id).where(Observation.entity_id.in_(entity_ids)).distinct())
    )
    orphans = sorted(entity_ids - still_used)
    verdicts = 0
    if orphans:
        verdicts = (
            db.scalar(
                select(func.count())
                .select_from(EntityAssessment)
                .where(EntityAssessment.entity_id.in_(orphans))
            )
            or 0
        )
        db.execute(delete(EntityAssessment).where(EntityAssessment.entity_id.in_(orphans)))
        db.execute(delete(Entity).where(Entity.id.in_(orphans)))
    result = DeletionResult(
        document_id=document_id,
        content_hash=content_hash,
        observations=observations,
        notes=notes,
        entities=len(orphans),
        verdicts=verdicts,
        now_current=now_current,
    )
    detail = {'reason': reason, **asdict(result)}
    del detail['document_id']
    audit(db, 'document.delete', document_id, json.dumps(detail, sort_keys=True))
    db.flush()
    return result
