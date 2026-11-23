"""Project manually linked local actors and campaigns onto the already selected STIX objects."""

from __future__ import annotations

from typing import Any, Final
from uuid import uuid4

from sqlalchemy import RowMapping, select
from sqlalchemy.orm import Session

from ..models import ActorDocument, Campaign, ThreatActor, ThreatLink
from ..schemas import most_restrictive
from ..stix_export import TLP_MARKINGS, stable_id, stix_timestamp, tlp_marking
from .tlp import visible_levels

MAX_EXPORT_THREAT_RELATIONSHIPS: Final = 100_000
_MARKING_LEVEL = {ref: level for level, ref in TLP_MARKINGS.items()}


def _subject_object(kind: str, label: str, row: RowMapping, *, stable: bool = False) -> dict[str, Any]:
    # A more restrictive association gets its own subject projection, just like a marked technique copy.
    if label == row['subject_tlp']:
        object_id = f'{kind}--{row["subject_id"]}'
    elif stable:  # TAXII: the same projection always has the same ID (ADR 0026)
        object_id = stable_id(kind, 'insight-projection', f'{row["subject_id"]}|{label}')
    else:
        object_id = f'{kind}--{uuid4()}'
    obj: dict[str, Any] = {
        'type': kind,
        'spec_version': '2.1',
        'id': object_id,
        'name': row['name'],
        'created': stix_timestamp(row['subject_created']),
        'modified': stix_timestamp(row['subject_updated']),
        'object_marking_refs': [TLP_MARKINGS[label]],
        'external_references': [{'source_name': 'Insight', 'external_id': row['subject_id']}],
    }
    if row['aliases']:
        obj['aliases'] = row['aliases'].splitlines()
    return obj


def _add_stix_threats(
    db: Session,
    bundle: dict[str, Any],
    entities: dict[str, dict[str, Any]],
    techniques: dict[str, list[dict[str, Any]]],
    *,
    max_tlp: str | None,
    initial_tlp: str,
    modified: str,
    stable: bool = False,
) -> str:
    """Emit only visible links with selected endpoints. Return the highest marking for the export audit.

    With ``stable`` (TAXII, ADR 0026), every ID is deterministic and a relationship's ``modified`` is the
    latest contributing link, subject or target change time, so it appears to a polling client when
    the client can first see it; ``modified`` (the export time) is not used.
    """
    reports = {
        obj['id'].removeprefix('report--'): [obj]
        for obj in bundle.get('objects', [])
        if obj['type'] == 'report'
    }
    indicators = {entity_id: [obj] for entity_id, obj in entities.items()}
    # One database link to a technique can have a separate STIX endpoint for each report marking.
    # ActorDocument may also name catalog groups. An inner join with the local actor excludes them.
    selections = (
        (ThreatActor, ActorDocument, ActorDocument.group_ref, ActorDocument.document_id, reports),
        (Campaign, ThreatLink, ThreatLink.campaign_id, ThreatLink.document_id, reports),
        (ThreatActor, ThreatLink, ThreatLink.actor_id, ThreatLink.entity_id, indicators),
        (Campaign, ThreatLink, ThreatLink.campaign_id, ThreatLink.entity_id, indicators),
        (ThreatActor, ThreatLink, ThreatLink.actor_id, ThreatLink.technique_id, techniques),
        (Campaign, ThreatLink, ThreatLink.campaign_id, ThreatLink.technique_id, techniques),
    )
    levels = visible_levels(max_tlp)
    subjects: dict[tuple[str, str, str], dict[str, Any]] = {}
    needed_labels: set[str] = set()
    count = 0
    for subject, link, owner, endpoint, targets in selections:
        ids = list(targets)
        kind = 'threat-actor' if subject is ThreatActor else 'campaign'
        updated = subject.updated_at
        stmt = (
            select(
                subject.id.label('subject_id'),
                subject.name,
                subject.aliases,
                subject.tlp.label('subject_tlp'),
                subject.created_at.label('subject_created'),
                updated.label('subject_updated'),
                link.id.label('link_id'),
                link.tlp.label('link_tlp'),
                link.created_at.label('link_created'),
                getattr(link, 'updated_at', link.created_at).label('link_updated'),
                endpoint.label('target_id'),
            )
            .select_from(link)
            .join(subject, owner == subject.id)
            .where(subject.tlp.in_(levels), link.tlp.in_(levels))
            .execution_options(yield_per=500)
        )
        for start in range(0, len(ids), 500):
            rows = db.execute(
                stmt.where(endpoint.in_(ids[start : start + 500])).limit(
                    MAX_EXPORT_THREAT_RELATIONSHIPS - count + 1
                )
            )
            for row in rows.mappings():
                for target in targets[row['target_id']]:
                    count += 1
                    if count > MAX_EXPORT_THREAT_RELATIONSHIPS:
                        raise ValueError(
                            f'More than {MAX_EXPORT_THREAT_RELATIONSHIPS:,} threat relationships match; '
                            'narrow the filters.'
                        )
                    target_tlp = _MARKING_LEVEL[target['object_marking_refs'][0]]
                    label = most_restrictive(row['subject_tlp'], row['link_tlp'], target_tlp)
                    key = (kind, row['subject_id'], label)
                    if key not in subjects:
                        obj = _subject_object(kind, label, row, stable=stable)
                        bundle['objects'].append(obj)
                        subjects[key] = obj
                    needed_labels.add(label)
                    created = stix_timestamp(row['link_created'])
                    if target['type'] == 'report' and label == row['subject_tlp']:
                        relationship_id = f'relationship--{row["link_id"]}'
                    elif stable:
                        relationship_id = stable_id(
                            'relationship', 'insight-link', f'{row["link_id"]}|{target["id"]}|{label}'
                        )
                    else:
                        relationship_id = f'relationship--{uuid4()}'
                    changed = (
                        max(
                            created,
                            target['modified'],
                            stix_timestamp(row['link_updated']),
                            stix_timestamp(row['subject_updated']),
                        )
                        if stable
                        else max(modified, created)
                    )
                    if stable:
                        subjects[key]['modified'] = max(subjects[key]['modified'], changed)
                    bundle['objects'].append(
                        {
                            'type': 'relationship',
                            'spec_version': '2.1',
                            'id': relationship_id,
                            'created': created,
                            'modified': changed,
                            'relationship_type': 'related-to',
                            'source_ref': subjects[key]['id'],
                            'target_ref': target['id'],
                            'object_marking_refs': [TLP_MARKINGS[label]],
                        }
                    )
    present = {obj['id'] for obj in bundle.get('objects', []) if obj['type'] == 'marking-definition'}
    for label, ref in TLP_MARKINGS.items():
        if label in needed_labels and ref not in present:
            bundle['objects'].append(tlp_marking(label))
    return most_restrictive(initial_tlp, *needed_labels)
