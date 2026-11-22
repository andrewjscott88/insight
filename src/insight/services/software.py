"""Catalog software and explicit report links. Name matches are candidates, never attribution."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import SoftwareDocument, now
from ..schemas import SoftwareLinkInput, most_restrictive, tlp_markings
from ..threat_library import Software, library
from .actors import _check_label, _insert_link, _visible_report, _who
from .audit import audit
from .software_views import _software_entry
from .tlp import visible_levels


def _catalog_software(ref: str) -> Software:
    item = library().software.get(ref.strip().upper())
    if item is None:
        raise LookupError('No such software in the current catalog')
    return item


def search_software(
    *, q: str = '', limit: int = 50, offset: int = 0, max_tlp: str | None = None
) -> list[dict[str, Any]]:
    """Public catalog names; the limit is accepted so callers keep the same policy boundary."""
    text = q.strip()[:120].casefold()
    found = [
        item
        for item in library().software.values()
        if text in item.id.casefold()
        or any(text in name.casefold() for name in (item.name, *getattr(item, 'aliases', ())))
    ]
    found.sort(key=lambda item: (item.name.casefold(), item.id))
    return [
        _software_entry(item) for item in found[max(0, offset) : max(0, offset) + min(200, max(1, limit))]
    ]


def link_software_report(
    db: Session, ref: str, payload: SoftwareLinkInput, *, max_tlp: str | None = None
) -> SoftwareDocument:
    """Save a labelled analyst decision; repeated updates can raise, never lower, its label."""
    item = _catalog_software(ref)
    doc = _visible_report(db, payload.document_id, max_tlp)
    label = most_restrictive(doc.tlp, payload.tlp, *tlp_markings(payload.note))
    _check_label(label, max_tlp, 'software links')
    created = _insert_link(
        db,
        SoftwareDocument,
        {
            'software_id': item.id,
            'software_name': item.name,
            'software_type': item.type,
            'document_id': doc.id,
            'tlp': label,
            'note': payload.note.strip(),
            'actor': _who(db),
        },
    )
    row = db.scalars(
        select(SoftwareDocument)
        .where(SoftwareDocument.software_id == item.id, SoftwareDocument.document_id == doc.id)
        .with_for_update()
    ).one()
    if row.tlp not in visible_levels(max_tlp):
        raise LookupError('Report link unavailable')
    label = most_restrictive(label, row.tlp)
    if not created and row.note == payload.note.strip() and row.tlp == label:
        return row
    row.note, row.tlp = payload.note.strip(), label
    row.updated_at = now()
    db.flush()
    audit(db, 'software.link', item.id, doc.id)
    return row


def unlink_software_report(db: Session, ref: str, document_id: str, *, max_tlp: str | None = None) -> None:
    """Remove a visible link, including one whose software has left the catalog."""
    _visible_report(db, document_id, max_tlp)
    row = db.scalar(
        select(SoftwareDocument).where(
            SoftwareDocument.software_id == ref.strip().upper(),
            SoftwareDocument.document_id == document_id,
            SoftwareDocument.tlp.in_(visible_levels(max_tlp)),
        )
    )
    if row is None:
        raise LookupError('No such software report link')
    db.delete(row)
    audit(db, 'software.unlink', row.software_id, document_id)


def software_link_view(row: SoftwareDocument) -> dict[str, Any]:
    """A write result; the caller has already checked both endpoints and the link label."""
    return {
        'id': row.id,
        'software_id': row.software_id,
        'document_id': row.document_id,
        'note': row.note,
        'tlp': row.tlp,
        'created_at': row.created_at,
        'created_by': row.actor,
    }
