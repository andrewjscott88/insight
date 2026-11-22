"""The objects behind the read-only TAXII 2.1 collections (TIP 3.1, ADR 0026).

A collection is a fresh, policy-filtered snapshot of the STIX export, with stable IDs and real change times
so that a client polling with ``added_after`` sees every new or changed object exactly when it changes.
"""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from ..schemas import IocExportQuery
from ..stix_export import StableVersions, build_stix_bundle, stix_timestamp
from ..stix_validation import validate_stix_bundle
from ..taxii import COLLECTIONS, TaxiiError, TaxiiObject
from .audit import audit
from .exports import _selection


def taxii_collection_objects(db: Session, collection_id: str, *, max_tlp: str | None) -> list[TaxiiObject]:
    """Every object the caller may read in one collection, sorted by ``(date_added, id)``. Audited.

    The indicators collection uses the STIX export's own selection with ``review_statuses=('accepted',)``:
    the caller's TLP limit, superseded revisions, verdict meanings and publisher reuse rules (ADR 0021) all
    apply unchanged. An indicator or report changes when a visible mention of it arrives or is reviewed.
    Marking definitions enter the collection with the newest object they mark.
    """
    if collection_id not in COLLECTIONS:
        raise TaxiiError(404, 'Collection not found')
    query = IocExportQuery(review_statuses=('accepted',), max_tlp=max_tlp)
    try:
        export, metadata_only_ids, mentions = _selection(db, query)
    except ValueError as exc:  # more mentions than one export may hold
        raise TaxiiError(413, 'Collection too large to serve', str(exc)) from None
    indicators: dict[tuple[str, str], str] = {}
    reports: dict[str, str] = {}
    for mention in mentions:
        arrived = stix_timestamp(mention.created_at)
        changed = max(arrived, stix_timestamp(mention.reviewed_at)) if mention.reviewed_at else arrived
        key = (mention.kind, mention.value)
        if changed > indicators.get(key, ''):
            indicators[key] = changed
        if changed > reports.get(mention.document_id, ''):
            reports[mention.document_id] = changed
    bundle = build_stix_bundle(export, metadata_only_ids, versions=StableVersions(indicators, reports))
    validate_stix_bundle(bundle)
    objects = bundle.get('objects', [])
    added: dict[str, str] = {}
    for obj in objects:
        if obj['type'] != 'marking-definition':
            added[obj['id']] = obj['modified']
    for obj in objects:
        if obj['type'] == 'marking-definition':
            continue
        for marking in obj.get('object_marking_refs', []):
            if added[obj['id']] > added.get(marking, ''):
                added[marking] = added[obj['id']]
    items = sorted(
        (TaxiiObject(added.get(obj['id'], stix_timestamp(obj['created'])), obj) for obj in objects),
        key=lambda item: (item.date_added, item.id),
    )
    detail = {'collection': collection_id, 'objects': len(items), 'max_tlp': max_tlp}
    audit(db, 'taxii.read', collection_id, json.dumps(detail, sort_keys=True))
    return items
