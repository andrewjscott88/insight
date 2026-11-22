"""Sightings (TIP 4.2, ADR 0035): a hunt tool saw a known indicator in its own data.

A sighting says when (first and last seen), how often and where an indicator was seen, and optionally which
hunt package the hunt came from. It is intelligence coming back from a hunt tool, not a response record:
nothing here says what was done about it. Sightings are the strongest confidence signal (ADR 0033): each
place an indicator was seen counts as one completely reliable source, ageing like a report.

TLP: a sighting has its own label (default AMBER, raised by markings in its text and by its hunt package). A
reader sees it only within its limit, and only for an indicator it can see.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final

from sqlalchemy import ColumnElement, exists, select
from sqlalchemy.orm import Session

from ..extraction import canonical
from ..models import Document, Entity, Observation, Sighting
from ..schemas import SightingInput, most_restrictive, tlp_markings
from .actors import _check_label, _who
from .audit import audit
from .campaigns import _target
from .hunt_package_views import _package
from .tlp import _visible, visible_levels

MAX_SIGHTINGS: Final = 500


@dataclass(frozen=True, slots=True)
class SightingView:
    id: str
    entity_id: str
    kind: str
    value: str
    hunt_package_id: str | None
    first_seen: str
    last_seen: str
    count: int
    where: str
    observer: str
    note: str
    external_ref: str
    tlp: str
    created_at: str
    created_by: str


def _indicator(db: Session, value: str, kind: str | None, max_tlp: str | None) -> str:
    """The ID of the known indicator ``value`` names, if the caller can see it (``LookupError`` otherwise)."""
    if kind is not None:
        try:
            wanted = canonical(kind, value.strip())
        except (ValueError, UnicodeError) as exc:
            raise ValueError(f'Not a valid {kind}: {exc}') from exc
        stmt = select(Entity.id).where(Entity.kind == kind, Entity.value == wanted)
    else:
        text = value.strip()
        stmt = select(Entity.id).where(Entity.value.in_({text, text.lower(), text.upper()}))
    found = list(db.scalars(stmt.limit(3)))
    if len(found) > 1:
        raise ValueError('That value names more than one kind of indicator; say which with "kind".')
    if not found:
        raise LookupError('No such indicator')
    entity_id, _, _ = _target(db, 'indicator', found[0], max_tlp)
    return entity_id


def record_sighting(db: Session, payload: SightingInput, *, max_tlp: str | None = None) -> Sighting:
    """Store a sighting of a known indicator. Audited as ``sighting.add`` on the indicator."""
    entity_id = _indicator(db, payload.value, payload.kind, max_tlp)
    where, observer, note = payload.where.strip(), payload.observer.strip(), payload.note.strip()
    label = most_restrictive(payload.tlp, *tlp_markings(f'{where}\n{observer}\n{note}'))
    if payload.hunt_package_id is not None:
        label = most_restrictive(label, _package(db, payload.hunt_package_id, max_tlp).tlp)
    _check_label(label, max_tlp, 'sightings')
    first = payload.first_seen.isoformat()
    row = Sighting(
        entity_id=entity_id,
        hunt_package_id=payload.hunt_package_id,
        first_seen=first,
        last_seen=payload.last_seen.isoformat() if payload.last_seen else first,
        count=payload.count,
        location=where,
        observer=observer,
        note=note,
        external_ref=payload.external_ref.strip(),
        tlp=label,
        actor=_who(db),
    )
    db.add(row)
    db.flush()
    detail = {'sighting': row.id, 'count': row.count, 'tlp': label, 'hunt_package': payload.hunt_package_id}
    audit(db, 'sighting.add', entity_id, json.dumps(detail, sort_keys=True))
    return row


def _visible_sightings(max_tlp: str | None) -> list[ColumnElement[bool]]:
    """Sightings within the limit, of indicators a visible report mentions."""
    if max_tlp is None:
        return []
    seen = exists(
        select(Observation.id)
        .join(Document, Document.id == Observation.document_id)
        .where(Observation.entity_id == Sighting.entity_id, *_visible(max_tlp))
    )
    return [Sighting.tlp.in_(visible_levels(max_tlp)), seen]


def list_sightings(
    db: Session,
    *,
    max_tlp: str | None = None,
    entity_id: str | None = None,
    hunt_package_id: str | None = None,
    limit: int = 200,
) -> list[SightingView]:
    """Sightings the caller may see, most recently seen first."""
    stmt = (
        select(Sighting, Entity.kind, Entity.value)
        .join(Entity, Entity.id == Sighting.entity_id)
        .where(*_visible_sightings(max_tlp))
        .order_by(Sighting.last_seen.desc(), Sighting.id)
        .limit(min(max(1, limit), MAX_SIGHTINGS))
    )
    if entity_id is not None:
        stmt = stmt.where(Sighting.entity_id == entity_id)
    if hunt_package_id is not None:
        stmt = stmt.where(Sighting.hunt_package_id == hunt_package_id)
    return [
        SightingView(
            s.id, s.entity_id, kind, value, s.hunt_package_id, s.first_seen, s.last_seen, s.count, s.location,
            s.observer, s.note, s.external_ref, s.tlp, s.created_at, s.actor,
        )
        for s, kind, value in db.execute(stmt)
    ]  # fmt: skip


def delete_sighting(db: Session, sighting_id: str, *, max_tlp: str | None = None) -> None:
    """Delete a sighting reported by mistake. Audited as ``sighting.delete`` on the indicator."""
    row = db.scalar(select(Sighting).where(Sighting.id == sighting_id, *_visible_sightings(max_tlp)))
    if row is None:
        raise LookupError('No such sighting')
    detail = json.dumps({'sighting': row.id, 'tlp': row.tlp}, sort_keys=True)
    audit(db, 'sighting.delete', row.entity_id, detail)
    db.delete(row)


def _sighting_places(
    db: Session, entity_id: str, max_tlp: str | None, limit: int
) -> list[tuple[str, int, str]]:
    """``(where, sightings, last seen)`` for one indicator, per place, within the reader's limit."""
    rows = db.execute(
        select(Sighting.location, Sighting.observer, Sighting.last_seen)
        .where(Sighting.entity_id == entity_id, *_visible_sightings(max_tlp))
        .order_by(Sighting.last_seen.desc())
        .limit(limit)
    )
    places: dict[str, tuple[int, str]] = {}
    for location, observer, last_seen in rows:
        place = location or observer or 'your environment'
        count, newest = places.get(place, (0, ''))
        places[place] = (count + 1, max(newest, str(last_seen)))
    return [(place, count, newest) for place, (count, newest) in places.items()]
