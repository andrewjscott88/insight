"""Store validated, typed STIX reports and their import receipts in the caller's transaction."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Document
from ..stix_import import ImportedReport, parse_stix
from .audit import audit
from .documents import SourceRef, StructuredObservations, fingerprint, ingest
from .tlp import _refuse_above, apply_tlp_policy, tlp_permitted

SOURCE = 'stix-import'
RESTRICTED_SOURCE = 'stix-import-metadata'


def _preflight(db: Session, report: ImportedReport, max_tlp: str) -> SourceRef:
    key = RESTRICTED_SOURCE if report.metadata_only else SOURCE
    ref = SourceRef(key, report.source_id)
    item = apply_tlp_policy(report.item)
    _refuse_above(report.item.tlp, item.tlp, max_tlp)
    current = db.scalar(select(Document).where(
        Document.source_key.in_([SOURCE, RESTRICTED_SOURCE]), Document.external_id == report.source_id,
        Document.is_current.is_(True)))
    # A new bundle cannot relax an existing publisher restriction, lower a stored label,
    # or claim the identity of a document this importer did not create.
    if current and (current.source_key != key or not tlp_permitted(current.tlp, item.tlp)):
        raise ValueError('Import conflicts with an existing document or handling restriction')
    for existing in (db.get(Document, report.initial_id),
                     db.scalar(select(Document).where(Document.fingerprint == fingerprint(item)))):
        if existing and (existing.source_key != key or existing.external_id != report.source_id):
            raise ValueError('Import conflicts with an existing document or handling restriction')
    return ref


def import_stix(db: Session, data: bytes, *, max_tlp: str) -> dict[str, Any]:
    """Import every report together, recording the source bundle and byte digest per document."""
    bundle = parse_stix(data, max_tlp)
    refs = [_preflight(db, report, max_tlp) for report in bundle.reports]
    ids: list[str] = []
    count = 0
    for report, ref in zip(bundle.reports, refs, strict=True):
        doc, created = ingest(
            db, report.item, ref=ref, max_tlp=max_tlp, initial_document_id=report.initial_id,
            structured=StructuredObservations('stix-2.1', report.mentions, report.technique_ids),
        )
        audit(db, 'stix.import', doc.id, f'{bundle.bundle_id} sha256={bundle.sha256}')
        ids.append(doc.id)
        count += created
    db.flush()
    return {'bundle_id': bundle.bundle_id, 'bundle_sha256': bundle.sha256, 'reports': len(ids),
            'created': count, 'document_ids': ids}
