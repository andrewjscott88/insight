"""Attach current MITRE ATT&CK catalog entries for the technique tags on exported STIX Reports."""

from __future__ import annotations

from typing import Any, Final
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..attack import Technique, catalog
from ..models import Document, DocumentTechnique
from ..stix_export import stable_id
from .techniques import TAGGED
from .tlp import _visible

MAX_EXPORT_TECHNIQUE_TAGS: Final = 100_000


def _attack_pattern(
    technique: Technique, markings: tuple[str, ...], created: str, *, stable: bool = False
) -> dict[str, Any]:
    """An Insight projection of the catalog entry, cited by its public Enterprise technique ID.

    ``stable`` (TAXII, ADR 0026): the ID is derived from everything the object says (catalog version,
    technique, markings), so the same content always has the same ID and a new catalog gets new IDs.
    """
    source = catalog()
    if stable:
        object_id = stable_id(
            'attack-pattern', 'mitre-attack', f'{source.version}|{technique.id}|{",".join(markings)}'
        )
    else:
        object_id = f'attack-pattern--{uuid4()}'
    obj: dict[str, Any] = {
        'type': 'attack-pattern',
        'spec_version': '2.1',
        'id': object_id,
        'created': created,
        'modified': created,
        'name': technique.full_name,
        'object_marking_refs': list(markings),
        'external_references': [
            {'source_name': 'mitre-attack', 'external_id': technique.id, 'url': technique.url},
            {
                'source_name': f'MITRE ATT&CK Enterprise {source.version}',
                'description': source.notice,
                'url': source.terms,
            },
        ],
    }
    if technique.tactics:
        obj['kill_chain_phases'] = [
            {'kill_chain_name': 'mitre-attack', 'phase_name': tactic} for tactic in technique.tactics
        ]
    return obj


def _add_stix_techniques(
    db: Session, bundle: dict[str, Any], *, max_tlp: str | None, stable: bool = False
) -> dict[str, list[dict[str, Any]]]:
    """Link active catalog tags on already-selected reports, under each report's own markings.

    Read only the two keys needed for the links. In particular a tag's contextual evidence may contain
    publisher text and must never be copied into a catalog object. With ``stable`` (TAXII), IDs are
    deterministic and each pattern dates from the earliest change time of the reports that cite it, so it
    does not depend on the order reports are read in.
    """
    reports = {
        obj['id'].removeprefix('report--'): obj
        for obj in bundle.get('objects', [])
        if obj['type'] == 'report'
    }
    ids = sorted(reports)
    patterns: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    by_technique: dict[str, list[dict[str, Any]]] = {}
    count = 0
    for start in range(0, len(ids), 500):  # stay under database parameter limits
        stmt = (
            select(DocumentTechnique.document_id, DocumentTechnique.technique_id)
            .join(Document, Document.id == DocumentTechnique.document_id)
            .where(
                DocumentTechnique.document_id.in_(ids[start : start + 500]),
                DocumentTechnique.status == TAGGED,
                *_visible(max_tlp),
            )
            .order_by(DocumentTechnique.document_id, DocumentTechnique.technique_id)
            .limit(MAX_EXPORT_TECHNIQUE_TAGS - count + 1)
        )
        for document_id, technique_id in db.execute(stmt):
            count += 1
            if count > MAX_EXPORT_TECHNIQUE_TAGS:
                raise ValueError(
                    f'More than {MAX_EXPORT_TECHNIQUE_TAGS:,} technique tags match; narrow the filters.'
                )
            technique = catalog().techniques.get(technique_id)
            if technique is None:  # tag from a retired catalog entry
                continue
            report = reports[document_id]
            markings = tuple(report['object_marking_refs'])
            key = (technique_id, markings)
            if key not in patterns:
                pattern = _attack_pattern(technique, markings, report['modified'], stable=stable)
                bundle['objects'].append(pattern)
                by_technique.setdefault(technique_id, []).append(pattern)
                patterns[key] = pattern
            elif stable and report['modified'] < patterns[key]['created']:
                patterns[key]['created'] = patterns[key]['modified'] = report['modified']
            report['object_refs'].append(patterns[key]['id'])
    return by_technique
