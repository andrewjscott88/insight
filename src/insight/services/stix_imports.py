"""Store validated, typed STIX reports and their import receipts in the caller's transaction."""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..models import Document, now
from ..schemas import TLP, most_restrictive
from ..source_registry import is_operator_source
from ..stix_import import ImportedBundle, ImportedReport, parse_stix
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
    current = db.scalar(
        select(Document).where(
            Document.source_key.in_([SOURCE, RESTRICTED_SOURCE]),
            Document.external_id == report.source_id,
            Document.is_current.is_(True),
        )
    )
    # A new bundle cannot relax an existing publisher restriction, lower a stored label,
    # or claim the identity of a document this importer did not create.
    if current and (current.source_key != key or not tlp_permitted(current.tlp, item.tlp)):
        raise ValueError('Import conflicts with an existing document or handling restriction')
    for existing in (
        db.get(Document, report.initial_id),
        db.scalar(select(Document).where(Document.fingerprint == fingerprint(item))),
    ):
        if existing and (existing.source_key != key or existing.external_id != report.source_id):
            raise ValueError('Import conflicts with an existing document or handling restriction')
    return ref


def import_stix(db: Session, data: bytes, *, max_tlp: str) -> dict[str, Any]:
    """Import every report together, recording the source bundle and byte digest per document."""
    bundle = parse_stix(data, max_tlp)
    refs = [_preflight(db, report, max_tlp) for report in bundle.reports]
    return _store(db, bundle, refs, max_tlp)


def import_operator_stix(
    db: Session, data: bytes, *, source_key: str, source_tlp: TLP, max_tlp: str
) -> dict[str, Any]:
    """Import one fully assembled collection pull inside the caller's source/cursor transaction.

    IDs and revision history belong to this operator source. References must resolve in the pull,
    apart from the standard TLP definitions whose IDs are validated offline by the parser.
    """
    if not is_operator_source(source_key):
        raise ValueError('Expected an operator source')
    _refuse_above(source_tlp, source_tlp, max_tlp)
    bundle = parse_stix(data, max_tlp, individual_observables=True)
    initial_ids = {
        report.source_id: str(uuid5(NAMESPACE_URL, f'insight:operator-stix:{source_key}:{report.source_id}'))
        for report in bundle.reports
    }
    native_by_id = {initial_id: native_id for native_id, initial_id in initial_ids.items()}
    owners = db.execute(
        select(Document.id, Document.source_key, Document.external_id).where(Document.id.in_(native_by_id))
    )
    if any(key != source_key or external_id != native_by_id[doc_id] for doc_id, key, external_id in owners):
        raise ValueError('Import conflicts with an existing document or handling restriction')
    current = {
        external_id: (tlp, metadata_only)
        for external_id, tlp, metadata_only in db.execute(
            select(Document.external_id, Document.tlp, Document.operator_publisher_metadata_only).where(
                Document.source_key == source_key,
                Document.external_id.in_(native_by_id.values()),
                Document.is_current.is_(True),
            )
        )
    }
    reports: list[ImportedReport] = []
    tightened: list[str] = []
    for report in bundle.reports:
        previous = current.get(report.source_id)
        if previous:
            previous_restriction = previous[1]
            if previous_restriction and not report.metadata_only:
                report = report.with_publisher_restriction()
            elif report.metadata_only and not previous_restriction:
                tightened.append(report.source_id)
        incoming = most_restrictive(report.item.tlp, source_tlp)
        item = apply_tlp_policy(report.item.model_copy(update={'tlp': incoming}))
        retained = most_restrictive(item.tlp, previous[0]) if previous else item.tlp
        _refuse_above(retained, retained, max_tlp)
        # Ingest applies the retained label to the stored revision and audits the raise.
        reports.append(replace(report, initial_id=initial_ids[report.source_id], item=item))
    if tightened:
        # A publisher can withdraw permission. Explicit exports of earlier revisions must
        # also withhold their text, even when the operator marks the collection public.
        db.execute(
            update(Document)
            .where(
                Document.source_key == source_key,
                Document.external_id.in_(tightened),
                Document.operator_publisher_metadata_only.is_(False),
            )
            .values(operator_publisher_metadata_only=True, reuse_changed_at=now())
        )
    refs = [SourceRef(source_key, report.source_id) for report in reports]
    return _store(db, replace(bundle, reports=reports), refs, max_tlp)


def _store(db: Session, bundle: ImportedBundle, refs: list[SourceRef], max_tlp: str) -> dict[str, Any]:
    ids: list[str] = []
    count = 0
    for report, ref in zip(bundle.reports, refs, strict=True):
        doc, created = ingest(
            db,
            report.item,
            ref=ref,
            max_tlp=max_tlp,
            initial_document_id=report.initial_id,
            operator_publisher_metadata_only=is_operator_source(ref.source_key) and report.metadata_only,
            preserve_source_tlp=True,
            structured=StructuredObservations('stix-2.1', report.mentions, report.technique_ids),
        )
        audit(db, 'stix.import', doc.id, f'{bundle.bundle_id} sha256={bundle.sha256}')
        ids.append(doc.id)
        count += created
    if not ids:
        audit(db, 'stix.import.empty', bundle.bundle_id.removeprefix('bundle--'), bundle.sha256)
    db.flush()
    return {
        'bundle_id': bundle.bundle_id,
        'bundle_sha256': bundle.sha256,
        'reports': len(ids),
        'created': count,
        'document_ids': ids,
    }
