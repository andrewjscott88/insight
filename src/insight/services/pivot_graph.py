"""Read eligible cached infrastructure as graph neighbours, never as new intelligence records."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Document, Entity, Observation
from .pivots import cached_pivots
from .tlp import _visible

_KINDS = frozenset({'domain', 'address', 'as', 'certificate_name', 'name_server'})
_Neighbour = tuple[str, str, str, str]


def _rows(db: Session, entity_id: str, max_tlp: str | None) -> list[tuple[str, dict[str, Any], str]]:
    entity = db.get(Entity, entity_id)
    if entity is None:
        return []
    try:
        records = cached_pivots(db, entity.value, max_tlp=max_tlp)
    except LookupError:
        return []
    return [
        (f'{entity_id}:{r["provider"]}:{index}', node, f'{r["provider"]} · {r["fetched_at"][:10]}')
        for r in records
        for index, node in enumerate(r.get('nodes', []))
        if node.get('type') in _KINDS
    ]


def _known(db: Session, value: str, max_tlp: str | None) -> str | None:
    return db.scalar(
        select(Entity.id)
        .join(Observation, Observation.entity_id == Entity.id)
        .join(Document, Document.id == Observation.document_id)
        .where(
            Entity.value == value,
            Entity.kind.in_(('ip', 'domain')),
            Observation.review_status != 'rejected',
            *_visible(max_tlp),
        )
        .limit(1)
    )


def _pivot_neighbours(db: Session, entity_id: str, max_tlp: str | None) -> list[_Neighbour]:
    neighbours: list[_Neighbour] = []
    for key, node, label in _rows(db, entity_id, max_tlp):
        value = str(node['value'])
        known = _known(db, value, max_tlp)
        identifier = f'indicator:{known}' if known else f'{node["type"]}:{key}'
        neighbours.append((identifier, value, 'Provider context', label))
    return neighbours


def _pivot_description(db: Session, kind: str, key: str, max_tlp: str | None) -> _Neighbour | None:
    entity_id = key.partition(':')[0]
    for candidate, node, label in _rows(db, entity_id, max_tlp):
        if candidate == key and node['type'] == kind:
            return f'{kind}:{key}', str(node['value']), 'Provider context', label
    return None


def _pivot_parent(db: Session, kind: str, key: str, max_tlp: str | None) -> list[_Neighbour]:
    found = _pivot_description(db, kind, key, max_tlp)
    entity = db.get(Entity, key.partition(':')[0]) if found else None
    return [(f'indicator:{entity.id}', entity.value, entity.kind, found[3])] if entity and found else []
