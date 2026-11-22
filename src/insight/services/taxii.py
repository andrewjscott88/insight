"""The objects behind the read-only TAXII 2.1 collections (TIP 3.1, ADR 0026).

A collection is a fresh, policy-filtered snapshot, with stable IDs and real change times so that a client
polling with ``added_after`` sees every new or changed object exactly when it changes.

- **Reviewed indicators**: the STIX export of accepted indicators and CVEs, their reports, the ATT&CK
  techniques tagged on those reports, and the analyst's actors and campaigns linked to any of them.
- **CISA KEV**: every synced entry of CISA's Known Exploited Vulnerabilities catalog (public, TLP:CLEAR).
"""

from __future__ import annotations

import json
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import KEVRecord
from ..schemas import IocExportQuery
from ..stix_export import (
    TLP_MARKINGS,
    StableVersions,
    build_stix_bundle,
    stable_id,
    stix_timestamp,
    tlp_marking,
)
from ..stix_validation import validate_stix_bundle
from ..taxii import COLLECTIONS, KEV_COLLECTION, TaxiiError, TaxiiObject
from .audit import audit
from .exports import _selection
from .stix_techniques import _add_stix_techniques
from .stix_threats import _add_stix_threats

KEV_CATALOG_URL: Final = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'


def taxii_collection_objects(db: Session, collection_id: str, *, max_tlp: str | None) -> list[TaxiiObject]:
    """Every object the caller may read in one collection, sorted by ``(date_added, id)``. Audited.

    The indicators collection uses the STIX export's own selection with ``review_statuses=('accepted',)``:
    the caller's TLP limit, superseded revisions, verdict meanings and publisher reuse rules (ADR 0021) all
    apply unchanged. An indicator or report changes when a visible mention of it arrives or is reviewed.
    Marking definitions enter the collection with the newest object they mark; an actor or campaign enters
    with the first relationship that makes it visible.
    """
    if collection_id not in COLLECTIONS:
        raise TaxiiError(404, 'Collection not found')
    bundle = _kev_bundle(db) if collection_id == KEV_COLLECTION else _indicator_bundle(db, max_tlp)
    validate_stix_bundle(bundle)
    items = _dated(bundle.get('objects', []))
    detail = {'collection': collection_id, 'objects': len(items), 'max_tlp': max_tlp}
    audit(db, 'taxii.read', collection_id, json.dumps(detail, sort_keys=True))
    return items


def _indicator_bundle(db: Session, max_tlp: str | None) -> dict[str, Any]:
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
    entities: dict[str, dict[str, Any]] = {}
    bundle = build_stix_bundle(
        export, metadata_only_ids, entities=entities, versions=StableVersions(indicators, reports)
    )
    if not bundle.get('objects'):
        return bundle
    try:
        techniques = _add_stix_techniques(db, bundle, max_tlp=max_tlp, stable=True)
        _add_stix_threats(
            db,
            bundle,
            entities,
            techniques,
            max_tlp=max_tlp,
            initial_tlp=export['tlp'],
            modified='',
            stable=True,
        )
    except ValueError as exc:  # more technique tags or threat links than one export may hold
        raise TaxiiError(413, 'Collection too large to serve', str(exc)) from None
    return bundle


def _kev_vulnerability(record: KEVRecord) -> dict[str, Any]:
    """One KEV entry as a STIX vulnerability. Its ID differs from the indicators collection's CVE object
    (whose content differs); clients relate the two by the ``cve`` external reference."""
    created = stix_timestamp(f'{record.date_added[:10]}T00:00:00+00:00')
    changed = stix_timestamp(record.changed_at or record.imported_at)
    details: dict[str, Any] = {
        'vendor': record.vendor,
        'product': record.product,
        'date_added': record.date_added,
        'due_date': record.due_date,
        'required_action': record.required_action,
        'known_ransomware_campaign_use': record.ransomware_use or 'Unknown',
    }
    if cwes := [c for c in record.cwes.split(',') if c]:
        details['cwes'] = cwes
    obj: dict[str, Any] = {
        'type': 'vulnerability',
        'spec_version': '2.1',
        'id': stable_id('vulnerability', 'cisa-kev', record.cve),
        'created': created,
        'modified': max(created, changed),
        'name': record.cve,
        'external_references': [
            {'source_name': 'cve', 'external_id': record.cve},
            {'source_name': 'cisa-kev', 'external_id': record.cve, 'url': KEV_CATALOG_URL},
        ],
        'object_marking_refs': [TLP_MARKINGS['CLEAR']],
        'x_insight_kev': details,
    }
    if record.vulnerability_name:
        obj['description'] = record.vulnerability_name
    return obj


def _kev_bundle(db: Session) -> dict[str, Any]:
    records = db.scalars(select(KEVRecord).order_by(KEVRecord.cve)).all()
    bundle: dict[str, Any] = {'type': 'bundle', 'id': stable_id('bundle', 'cisa-kev', 'catalog')}
    if records:
        bundle['objects'] = [tlp_marking('CLEAR'), *(_kev_vulnerability(r) for r in records)]
    return bundle


def _dated(objects: list[dict[str, Any]]) -> list[TaxiiObject]:
    """When each object version entered the collection: its ``modified`` time, except that a marking enters
    with the newest object it marks, and an actor or campaign no earlier than the first relationship that
    makes it visible (it may have been created long before anyone could see it here)."""
    added: dict[str, str] = {}
    for obj in objects:
        if obj['type'] != 'marking-definition':
            added[obj['id']] = obj['modified']
    first_link: dict[str, str] = {}
    for obj in objects:
        if obj['type'] == 'relationship':
            source = obj['source_ref']
            first_link[source] = min(first_link.get(source, added[obj['id']]), added[obj['id']])
    for source, linked in first_link.items():
        if source in added and linked > added[source]:
            added[source] = linked
    for obj in objects:
        if obj['type'] == 'marking-definition':
            continue
        for marking in obj.get('object_marking_refs', []):
            if added[obj['id']] > added.get(marking, ''):
                added[marking] = added[obj['id']]
    return sorted(
        (TaxiiObject(added.get(obj['id'], stix_timestamp(obj['created'])), obj) for obj in objects),
        key=lambda item: (item.date_added, item.id),
    )
