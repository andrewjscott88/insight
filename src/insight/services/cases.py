"""Lightweight case management (TIP 3.8, ADR 0029): one investigation's reports, indicators, actors,
campaigns and notes, opened and closed by the operator. Not a SOAR: nothing runs by itself.

TLP: a case carries the most restrictive label of everything ever added to it, and of its own text. Removing
an item never lowers the label (the title, summary and notes may have been written with it in view); only an
explicit change can, and never below the items still in the case. A reader limited to a TLP level sees a
case only within that limit, and then every item in it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final

from sqlalchemy import case as when
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AuditEvent, Campaign, Case, CaseItem, Document, Entity, ThreatActor, now
from ..schemas import (
    CaseCloseInput,
    CaseInput,
    CaseItemInput,
    CaseItemKind,
    CaseNoteInput,
    CaseStatusFilter,
    CaseUpdate,
    most_restrictive,
    tlp_markings,
)
from .actors import _check_label, _insert_link, _who
from .audit import audit
from .campaigns import _target
from .tlp import visible_levels

MAX_CASE_ITEMS: Final = 1_000
_TARGET_COLUMN: Final = {
    'document': CaseItem.document_id,
    'indicator': CaseItem.entity_id,
    'actor': CaseItem.actor_id,
    'campaign': CaseItem.campaign_id,
}


class CaseClosed(ValueError):
    """A closed case cannot change; reopen it first."""


@dataclass(frozen=True, slots=True)
class CaseSummary:
    id: str
    title: str
    status: str
    tlp: str
    items: int
    created_at: str
    updated_at: str
    closed_at: str | None


@dataclass(frozen=True, slots=True)
class CaseItemView:
    id: str
    kind: str
    target_id: str
    name: str
    note: str
    tlp: str
    added_at: str
    added_by: str


@dataclass(frozen=True, slots=True)
class CaseView:
    id: str
    title: str
    summary: str
    status: str
    tlp: str
    created_at: str
    updated_at: str
    closed_at: str | None
    close_note: str
    created_by: str
    items: tuple[CaseItemView, ...]


@dataclass(frozen=True, slots=True)
class CaseEvent:
    at: str
    action: str
    actor: str
    detail: str


def _case(db: Session, case_id: str, max_tlp: str | None, *, lock: bool = False) -> Case:
    stmt = select(Case).where(Case.id == case_id, Case.tlp.in_(visible_levels(max_tlp)))
    found = db.scalar(stmt.with_for_update() if lock else stmt)
    if found is None:
        raise LookupError('No such case')
    return found


def _open(db: Session, case_id: str, max_tlp: str | None) -> Case:
    found = _case(db, case_id, max_tlp, lock=True)
    if found.status != 'open':
        raise CaseClosed('This case is closed. Reopen it to change it.')
    return found


def _raise(row: Case, *labels: str) -> None:
    row.tlp = most_restrictive(row.tlp, *labels)
    row.updated_at = now()


def _item_labels(db: Session, case_id: str) -> list[str]:
    return list(db.scalars(select(CaseItem.tlp).where(CaseItem.case_id == case_id).distinct()))


def create_case(db: Session, payload: CaseInput, *, max_tlp: str | None = None) -> Case:
    label = most_restrictive(payload.tlp, *tlp_markings(f'{payload.title}\n{payload.summary}'))
    _check_label(label, max_tlp, 'cases')
    row = Case(title=payload.title.strip(), summary=payload.summary.strip(), tlp=label, actor=_who(db))
    db.add(row)
    db.flush()
    audit(db, 'case.open', row.id, row.tlp)
    return row


def list_cases(
    db: Session,
    *,
    max_tlp: str | None = None,
    status: CaseStatusFilter = 'open',
    offset: int = 0,
    limit: int = 100,
    holding: tuple[CaseItemKind, str] | None = None,
) -> list[CaseSummary]:
    """Cases within the caller's limit, most recently changed first; with ``holding``, only those that hold
    that report, indicator, actor or campaign."""
    items = (
        select(CaseItem.case_id, func.count().label('items'))
        .where(CaseItem.kind != 'note')
        .group_by(CaseItem.case_id)
        .subquery()
    )
    stmt = (
        select(Case, func.coalesce(items.c['items'], 0))
        .outerjoin(items, items.c.case_id == Case.id)
        .where(Case.tlp.in_(visible_levels(max_tlp)))
        .order_by(Case.updated_at.desc(), Case.id)
        .offset(max(0, offset))
        .limit(min(max(1, limit), 200))
    )
    if status != 'all':
        stmt = stmt.where(Case.status == status)
    if holding is not None:
        kind, target_id = holding
        stmt = stmt.where(Case.id.in_(select(CaseItem.case_id).where(_TARGET_COLUMN[kind] == target_id)))
    return [
        CaseSummary(c.id, c.title, c.status, c.tlp, int(n), c.created_at, c.updated_at, c.closed_at)
        for c, n in db.execute(stmt)
    ]


def _names(db: Session, rows: list[CaseItem]) -> dict[str, str]:
    wanted: dict[str, set[str]] = {}
    for row in rows:
        if row.kind != 'note':
            wanted.setdefault(row.kind, set()).add(_target_of(row))
    names: dict[str, str] = {}
    for kind, model, label in (
        ('document', Document, Document.title),
        ('indicator', Entity, Entity.value),
        ('actor', ThreatActor, ThreatActor.name),
        ('campaign', Campaign, Campaign.name),
    ):
        if ids := sorted(wanted.get(kind, ())):
            found = db.execute(select(model.id, label).where(model.id.in_(ids)))
            names.update({str(target): str(name) for target, name in found})
    return names


def _target_of(row: CaseItem) -> str:
    return row.document_id or row.entity_id or row.actor_id or row.campaign_id or ''


def get_case(db: Session, case_id: str, *, max_tlp: str | None = None) -> CaseView:
    row = _case(db, case_id, max_tlp)
    items = list(
        db.scalars(
            select(CaseItem)
            .where(CaseItem.case_id == row.id)
            .order_by(when((CaseItem.kind == 'note', 1), else_=0), CaseItem.added_at, CaseItem.id)
            .limit(MAX_CASE_ITEMS)
        )
    )
    names = _names(db, items)
    return CaseView(
        id=row.id,
        title=row.title,
        summary=row.summary,
        status=row.status,
        tlp=row.tlp,
        created_at=row.created_at,
        updated_at=row.updated_at,
        closed_at=row.closed_at,
        close_note=row.close_note,
        created_by=row.actor,
        items=tuple(
            CaseItemView(
                i.id, i.kind, _target_of(i), names.get(_target_of(i), ''), i.note, i.tlp, i.added_at, i.actor
            )
            for i in items
        ),
    )


def update_case(db: Session, case_id: str, payload: CaseUpdate, *, max_tlp: str | None = None) -> Case:
    row = _open(db, case_id, max_tlp)
    title = payload.title.strip() if payload.title is not None else row.title
    summary = payload.summary.strip() if payload.summary is not None else row.summary
    # An explicit label may lower the case, but never below its items or the markings in its text.
    text = f'{title}\n{summary}\n{row.close_note}'
    floor = most_restrictive('CLEAR', *_item_labels(db, row.id), *tlp_markings(text))
    label = most_restrictive(payload.tlp if payload.tlp is not None else row.tlp, floor)
    _check_label(label, max_tlp, 'cases')
    changed = {k for k, old, new in (('title', row.title, title), ('summary', row.summary, summary),
                                     ('tlp', row.tlp, label)) if old != new}  # fmt: skip
    row.title, row.summary, row.tlp, row.updated_at = title, summary, label, now()
    if changed:
        audit(
            db, 'case.update', row.id, json.dumps({'changed': sorted(changed), 'tlp': label}, sort_keys=True)
        )
    return row


def _resolve(db: Session, kind: CaseItemKind, ref: str, max_tlp: str | None) -> tuple[str, str]:
    """``(target ID, the target's own label)``; ``LookupError`` if missing or above ``max_tlp``."""
    if kind in ('document', 'indicator'):
        target_id, _, floor = _target(db, kind, ref, max_tlp)
        return target_id, floor
    levels = visible_levels(max_tlp)
    if kind == 'actor':
        row = db.execute(
            select(ThreatActor.id, ThreatActor.tlp).where(ThreatActor.id == ref, ThreatActor.tlp.in_(levels))
        )
    else:
        row = db.execute(
            select(Campaign.id, Campaign.tlp).where(Campaign.id == ref, Campaign.tlp.in_(levels))
        )
    found = row.first()
    if found is None:
        raise LookupError(f'No such {kind}')
    return str(found[0]), str(found[1])


def add_case_item(
    db: Session, case_id: str, payload: CaseItemInput, *, max_tlp: str | None = None
) -> CaseItemView:
    """Add a report, indicator, actor or campaign (adding it twice changes nothing). Raises the case label."""
    row = _open(db, case_id, max_tlp)
    target_id, floor = _resolve(db, payload.kind, payload.target_id, max_tlp)
    label = most_restrictive(floor, payload.tlp)
    _check_label(label, max_tlp, 'case items')
    count = db.scalar(select(func.count()).select_from(CaseItem).where(CaseItem.case_id == row.id)) or 0
    if count >= MAX_CASE_ITEMS:
        raise ValueError(f'A case holds at most {MAX_CASE_ITEMS:,} items')
    column = _TARGET_COLUMN[payload.kind]
    values = {'case_id': row.id, 'kind': payload.kind, column.key: target_id, 'tlp': label, 'actor': _who(db)}
    if _insert_link(db, CaseItem, values):
        _raise(row, label)
        detail = {'kind': payload.kind, 'target_id': target_id, 'tlp': label}
        audit(db, 'case.item.add', row.id, json.dumps(detail, sort_keys=True))
    item = db.scalars(select(CaseItem).where(CaseItem.case_id == row.id, column == target_id)).one()
    name = _names(db, [item]).get(target_id, '')
    return CaseItemView(item.id, item.kind, target_id, name, '', item.tlp, item.added_at, item.actor)


def remove_case_item(db: Session, case_id: str, item_id: str, *, max_tlp: str | None = None) -> None:
    """Remove one item. The case keeps its label (see the module docstring)."""
    row = _open(db, case_id, max_tlp)
    item = db.scalar(select(CaseItem).where(CaseItem.id == item_id, CaseItem.case_id == row.id))
    if item is None:
        raise LookupError('No such item in this case')
    detail = {'kind': item.kind, 'target_id': _target_of(item), 'tlp': item.tlp}
    db.delete(item)
    row.updated_at = now()
    audit(db, 'case.item.remove', row.id, json.dumps(detail, sort_keys=True))


def add_case_note(
    db: Session, case_id: str, payload: CaseNoteInput, *, max_tlp: str | None = None
) -> CaseItemView:
    row = _open(db, case_id, max_tlp)
    label = most_restrictive(payload.tlp or row.tlp, *tlp_markings(payload.text))
    _check_label(label, max_tlp, 'case notes')
    item = CaseItem(case_id=row.id, kind='note', note=payload.text.strip(), tlp=label, actor=_who(db))
    db.add(item)
    _raise(row, label)
    db.flush()
    audit(db, 'case.note', row.id, label)
    return CaseItemView(item.id, 'note', '', '', item.note, label, item.added_at, item.actor)


def close_case(db: Session, case_id: str, payload: CaseCloseInput, *, max_tlp: str | None = None) -> Case:
    row = _open(db, case_id, max_tlp)
    label = most_restrictive(row.tlp, *tlp_markings(payload.note))
    _check_label(label, max_tlp, 'cases')
    row.status, row.close_note, row.closed_at, row.tlp = 'closed', payload.note.strip(), now(), label
    row.updated_at = row.closed_at
    audit(db, 'case.close', row.id, label)
    return row


def reopen_case(db: Session, case_id: str, *, max_tlp: str | None = None) -> Case:
    row = _case(db, case_id, max_tlp, lock=True)
    if row.status == 'open':
        return row
    row.status, row.closed_at, row.updated_at = 'open', None, now()
    audit(db, 'case.reopen', row.id, row.tlp)
    return row


def delete_case(db: Session, case_id: str, *, max_tlp: str | None = None) -> None:
    """Delete a case and its items and notes (the reports, indicators, actors and campaigns stay)."""
    row = _case(db, case_id, max_tlp, lock=True)
    db.delete(row)
    db.flush()
    audit(db, 'case.delete', case_id, row.title[:200])


def case_timeline(db: Session, case_id: str, *, max_tlp: str | None = None) -> list[CaseEvent]:
    """What happened to the case, oldest first: its audit events (at most 1,000)."""
    row = _case(db, case_id, max_tlp)
    events = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.object_id == row.id, AuditEvent.action.like('case.%'))
        .order_by(AuditEvent.created_at, AuditEvent.id)
        .limit(1_000)
    )
    return [CaseEvent(e.created_at, e.action, e.actor, e.detail) for e in events]
