"""Bounded, TLP-filtered software views; retained links survive catalog removal."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Campaign, Document, SoftwareDocument, ThreatActor, ThreatLink
from ..schemas import most_restrictive
from ..threat_library import Software, library
from .actors import _visible_report
from .threat_profiles import MAX_SCANNED, _scan_mentions
from .tlp import _visible, visible_levels


def _software_entry(item: Software) -> dict[str, Any]:
    fields = asdict(item)
    for key in ('aliases', 'platforms', 'techniques', 'groups'):
        fields.setdefault(key, ())
    fields.setdefault('description', '')
    return {**fields, 'url': item.url, 'tlp': 'CLEAR', 'retired': False}


def software_reports(
    db: Session, ref: str, *, max_tlp: str | None = None, offset: int = 0, limit: int = 50
) -> list[dict[str, Any]]:
    """Visible report and link metadata only; notes carry the stricter effective label."""
    rows = db.execute(
        select(SoftwareDocument, Document.id, Document.title, Document.tlp, Document.created_at)
        .join(Document, Document.id == SoftwareDocument.document_id)
        .where(
            SoftwareDocument.software_id == ref.strip().upper(),
            SoftwareDocument.tlp.in_(visible_levels(max_tlp)),
            *_visible(max_tlp),
        )
        .order_by(SoftwareDocument.created_at.desc(), SoftwareDocument.id)
        .offset(max(0, offset))
        .limit(min(200, max(1, limit)))
    )
    return [
        {
            'document_id': doc_id,
            'title': title,
            'created_at': added,
            'linked_at': link.created_at,
            'note': link.note,
            'tlp': most_restrictive(link.tlp, label),
            'software_id': link.software_id,
            'software_name': link.software_name,
            'software_type': link.software_type,
        }
        for link, doc_id, title, label, added in rows
    ]


def software_uses(
    db: Session, ref: str, *, max_tlp: str | None = None, limit: int = 50
) -> list[dict[str, Any]]:
    """Explicit analyst actor/campaign uses decisions, never report co-occurrence."""
    found: list[dict[str, Any]] = []
    levels = visible_levels(max_tlp)
    for kind, subject, owner in (
        ('actor', ThreatActor, ThreatLink.actor_id),
        ('campaign', Campaign, ThreatLink.campaign_id),
    ):
        rows = db.execute(
            select(ThreatLink, subject.id, subject.name, subject.tlp)
            .join(subject, owner == subject.id)
            .where(
                ThreatLink.software_id == ref.strip().upper(),
                ThreatLink.tlp.in_(levels),
                subject.tlp.in_(levels),
            )
            .order_by(ThreatLink.created_at.desc(), ThreatLink.id)
            .limit(min(200, max(1, limit)))
        )
        found.extend(
            {
                'kind': kind,
                'ref': identifier,
                'name': name,
                'tlp': most_restrictive(link.tlp, label),
                'linked_at': link.created_at,
                'software_name': link.software_name,
                'software_type': link.software_type,
            }
            for link, identifier, name, label in rows
        )
    return sorted(found, key=lambda row: (row['linked_at'], row['ref']), reverse=True)[
        : min(200, max(1, limit))
    ]


def software_detail(db: Session, ref: str, *, max_tlp: str | None = None) -> dict[str, Any]:
    ref = ref.strip().upper()
    item = library().software.get(ref)
    reports = software_reports(db, ref, max_tlp=max_tlp)
    uses = software_uses(db, ref, max_tlp=max_tlp)
    candidates: list[dict[str, Any]] = []
    scanned = 0
    scan_labels: set[str] = set()
    if item is not None:
        entry = _software_entry(item)
        matches, scanned, scan_labels = _scan_mentions(
            db, {ref: (item.name, *getattr(item, 'aliases', ()))}, max_tlp=max_tlp
        )
        # Only visible decisions affect this list. A hidden link must not change visible candidates.
        matched_ids = [row.document_id for row in matches[ref]]
        linked: set[str] = set()
        for start in range(0, len(matched_ids), 500):
            linked.update(
                db.scalars(
                    select(SoftwareDocument.document_id).where(
                        SoftwareDocument.software_id == ref,
                        SoftwareDocument.tlp.in_(visible_levels(max_tlp)),
                        SoftwareDocument.document_id.in_(matched_ids[start : start + 500]),
                    )
                )
            )
        candidates = [asdict(row) for row in matches[ref] if row.document_id not in linked][:50]
    elif reports or uses:
        snapshot = (reports or uses)[0]
        entry = {
            'id': ref,
            'name': snapshot['software_name'],
            'type': snapshot['software_type'],
            'aliases': (),
            'description': '',
            'platforms': (),
            'techniques': (),
            'groups': (),
            'url': '',
            'tlp': snapshot['tlp'],
            'retired': True,
        }
    else:
        raise LookupError('No such software')
    return {
        **entry,
        'reports': reports,
        'uses': uses,
        'candidates': candidates,
        'reports_scanned': scanned,
        'scan_capped': scanned >= MAX_SCANNED,
        'tlp': most_restrictive(
            entry['tlp'], *scan_labels, *(r['tlp'] for r in [*reports, *uses, *candidates])
        ),
    }


def report_software(db: Session, document_id: str, *, max_tlp: str | None = None) -> list[dict[str, Any]]:
    doc = _visible_report(db, document_id, max_tlp)
    rows = db.scalars(
        select(SoftwareDocument)
        .where(
            SoftwareDocument.document_id == document_id,
            SoftwareDocument.tlp.in_(visible_levels(max_tlp)),
        )
        .order_by(SoftwareDocument.software_name, SoftwareDocument.software_id)
        .limit(200)
    )
    return [
        {
            'id': row.software_id,
            'name': row.software_name,
            'type': row.software_type,
            'tlp': most_restrictive(doc.tlp, row.tlp),
            'note': row.note,
            'retired': row.software_id not in library().software,
        }
        for row in rows
    ]
