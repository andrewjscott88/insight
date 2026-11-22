"""Explicit software associations on selected STIX reports and analyst subjects, never inferred uses."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Campaign, Document, SoftwareDocument, ThreatActor, ThreatLink
from ..schemas import most_restrictive
from ..stix_export import TLP_MARKINGS, stable_id, stix_timestamp, tlp_marking
from .stix_threats import _subject_object
from .tlp import _visible, visible_levels

_MAX_LINKS = 100_000
_MARKING_LEVEL = {ref: level for level, ref in TLP_MARKINGS.items()}


def _software_object(
    ref: str, name: str, kind: str, label: str, created: str, changed: str
) -> dict[str, Any]:
    """Snapshot fields make the projection independent of catalog changes and preserve retired software."""
    obj: dict[str, Any] = {
        'type': kind,
        'spec_version': '2.1',
        'id': stable_id(kind, 'insight-software', f'{ref}|{name}|{label}'),
        'name': name,
        'created': created,
        'modified': changed,
        'object_marking_refs': [TLP_MARKINGS[label]],
        'external_references': [
            {
                'source_name': 'mitre-attack',
                'external_id': ref,
                'url': f'https://attack.mitre.org/software/{ref}/',
            }
        ],
    }
    if kind == 'malware':
        obj['is_family'] = True
    return obj


def _add_stix_software(db: Session, bundle: dict[str, Any], *, max_tlp: str | None) -> str:
    if not bundle.get('objects'):
        return 'CLEAR'
    reports = {
        obj['id'].removeprefix('report--'): obj
        for obj in bundle.get('objects', [])
        if obj['type'] == 'report'
    }
    existing = {obj['id']: obj for obj in bundle.get('objects', [])}
    selected_subjects: dict[str, set[str]] = {'threat-actor': set(), 'campaign': set()}
    subject_objects: dict[tuple[str, str, str], dict[str, Any]] = {}
    for obj in existing.values():
        if obj['type'] in selected_subjects:
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'Insight':
                    selected_subjects[obj['type']].add(ref['external_id'])
                    subject_objects[(obj['type'], ref['external_id'], obj['object_marking_refs'][0])] = obj
    objects: dict[str, dict[str, Any]] = {}
    selected_software: set[str] = set()
    labels: set[str] = set()
    count = 0

    def add_software(
        ref: str, name: str, kind: str, label: str, created: str, changed: str
    ) -> dict[str, Any]:
        obj = _software_object(ref, name, kind, label, created, changed)
        old = objects.setdefault(obj['id'], obj)
        old['created'] = min(old['created'], created)
        old['modified'] = max(old['modified'], changed)
        selected_software.add(ref)
        return old

    def relate(
        link_id: str, source: str, target: str, label: str, created: str, changed: str, kind: str
    ) -> None:
        nonlocal count
        count += 1
        if count > _MAX_LINKS:
            raise ValueError(f'More than {_MAX_LINKS:,} software links match; narrow the filters.')
        identifier = stable_id(
            'relationship', 'insight-software-link', f'{link_id}|{source}|{target}|{label}'
        )
        objects[identifier] = {
            'type': 'relationship',
            'spec_version': '2.1',
            'id': identifier,
            'created': created,
            'modified': changed,
            'relationship_type': kind,
            'source_ref': source,
            'target_ref': target,
            'object_marking_refs': [TLP_MARKINGS[label]],
        }
        labels.add(label)

    ids = sorted(reports)
    for start in range(0, len(ids), 500):
        rows = db.scalars(
            select(SoftwareDocument)
            .join(Document, Document.id == SoftwareDocument.document_id)
            .where(
                SoftwareDocument.document_id.in_(ids[start : start + 500]),
                SoftwareDocument.tlp.in_(visible_levels(max_tlp)),
                *_visible(max_tlp),
            )
            .order_by(SoftwareDocument.id)
            .limit(_MAX_LINKS - count + 1)
        )
        for link in rows:
            report = reports[link.document_id]
            label = most_restrictive(link.tlp, _MARKING_LEVEL[report['object_marking_refs'][0]])
            created = stix_timestamp(link.created_at)
            changed = max(created, stix_timestamp(link.updated_at), report['modified'])
            obj = add_software(
                link.software_id, link.software_name, link.software_type, label, created, changed
            )
            # Do not append to report.object_refs: a link can be more restricted than its report.
            relate(link.id, report['id'], obj['id'], label, created, changed, 'related-to')

    eligible_software = frozenset(selected_software)
    levels = visible_levels(max_tlp)
    # Select endpoints in bounded chunks; querying each subject type once avoids duplicate relationships.
    for subject, owner, kind in (
        (ThreatActor, ThreatLink.actor_id, 'threat-actor'),
        (Campaign, ThreatLink.campaign_id, 'campaign'),
    ):
        if not eligible_software and not selected_subjects[kind]:
            continue
        updated = (
            ThreatActor.updated_at
            if subject is ThreatActor
            else getattr(Campaign, 'updated_at', Campaign.created_at)
        )
        stmt = (
            select(
                subject.id.label('subject_id'),
                subject.name,
                subject.aliases,
                subject.tlp.label('subject_tlp'),
                subject.created_at.label('subject_created'),
                updated.label('subject_updated'),
                ThreatLink.id.label('link_id'),
                ThreatLink.tlp.label('link_tlp'),
                ThreatLink.created_at.label('link_created'),
                ThreatLink.updated_at.label('link_updated'),
                ThreatLink.software_id,
                ThreatLink.software_name,
                ThreatLink.software_type,
            )
            .select_from(ThreatLink)
            .join(subject, owner == subject.id)
            .where(subject.tlp.in_(levels), ThreatLink.tlp.in_(levels), ThreatLink.software_id.is_not(None))
            .order_by(ThreatLink.id)
            .execution_options(yield_per=500)
        )
        # Stream the visible links with a hard cap, without an unbounded IN parameter list.
        scanned = 0
        for row in db.execute(stmt.limit(_MAX_LINKS + 1)).mappings():
            scanned += 1
            if scanned > _MAX_LINKS:
                raise ValueError(f'More than {_MAX_LINKS:,} software links; narrow the collection.')
            if (
                row['software_id'] not in eligible_software
                and row['subject_id'] not in selected_subjects[kind]
            ):
                continue
            label = most_restrictive(row['subject_tlp'], row['link_tlp'])
            created = stix_timestamp(row['link_created'])
            changed = max(
                created, stix_timestamp(row['link_updated']), stix_timestamp(row['subject_updated'])
            )
            software = add_software(
                row['software_id'], row['software_name'], row['software_type'], label, created, changed
            )
            key = (kind, row['subject_id'], TLP_MARKINGS[label])
            actor = subject_objects.get(key)
            if actor is None:
                actor = _subject_object(kind, label, row, stable=True)
                subject_objects[key] = actor
                objects[actor['id']] = actor
            # A new link can first expose an old subject, or change an existing projection. Keep one
            # version per identity/label and use the latest contributing change, independent of row order.
            actor['modified'] = max(actor['modified'], changed)
            relate(row['link_id'], actor['id'], software['id'], label, created, changed, 'uses')
    for label in labels:
        if TLP_MARKINGS[label] not in existing:
            objects[TLP_MARKINGS[label]] = tlp_marking(label)
    bundle['objects'].extend(objects.values())
    return most_restrictive('CLEAR', *labels)
