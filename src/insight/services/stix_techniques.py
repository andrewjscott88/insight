"""Attach current MITRE ATT&CK catalog entries for the technique tags on exported STIX Reports."""

from __future__ import annotations

from typing import Any, Final
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..attack import Technique, catalog
from ..models import Document, DocumentTechnique
from .techniques import TAGGED
from .tlp import _visible

MAX_EXPORT_TECHNIQUE_TAGS: Final = 100_000


def _attack_pattern(technique: Technique, markings: tuple[str, ...], created: str) -> dict[str, Any]:
    """An Insight projection of the catalog entry, cited by its public Enterprise technique ID."""
    source = catalog()
    obj: dict[str, Any] = {
        'type': 'attack-pattern',
        'spec_version': '2.1',
        'id': f'attack-pattern--{uuid4()}',
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


def add_stix_techniques(db: Session, bundle: dict[str, Any], *, max_tlp: str | None) -> None:
    """Link active catalog tags on already-selected reports, under each report's own markings.

    Read only the two keys needed for the links. In particular a tag's contextual evidence may contain
    publisher text and must never be copied into a catalog object.
    """
    reports = {
        obj['id'].removeprefix('report--'): obj
        for obj in bundle.get('objects', [])
        if obj['type'] == 'report'
    }
    ids = sorted(reports)
    patterns: dict[tuple[str, tuple[str, ...]], str] = {}
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
                pattern = _attack_pattern(technique, markings, report['modified'])
                bundle['objects'].append(pattern)
                patterns[key] = pattern['id']
            report['object_refs'].append(patterns[key])
