"""Hunt records started from a threat guide (TIP 2.10, ADR 0024).

A hunt belongs to one group and has one check per hypothesis (ATT&CK technique): what data was searched, over
which time range, and the result. It makes a hunt repeatable and lets the next analyst see what was covered.
Every change is audited. A hunt carries its own TLP label (its notes may describe your network).
"""

from __future__ import annotations

from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..attack import technique
from ..models import Hunt, HuntCheck, now
from ..schemas import HuntCheckInput, HuntInput, HuntUpdate
from .actors import _check_label, _who, resolve_group
from .audit import audit
from .tlp import tlp_permitted, visible_levels

MAX_HUNTS: Final = 200


def start_hunt(db: Session, ref: str, payload: HuntInput, *, max_tlp: str | None = None) -> Hunt:
    """Open a hunt for a group or actor. Audited as ``hunt.start``."""
    _check_label(payload.tlp, max_tlp, 'hunts')
    subject = resolve_group(db, ref, max_tlp=max_tlp)
    hunt = Hunt(group_ref=subject.ref, title=payload.title.strip(), tlp=payload.tlp, actor=_who(db))
    db.add(hunt)
    db.flush()
    audit(db, 'hunt.start', hunt.id, f'{subject.ref} (TLP:{hunt.tlp})')
    return hunt


def hunts_for(db: Session, ref: str | None = None, *, max_tlp: str | None = None) -> list[Hunt]:
    """Hunts the reader may see (for one group, or all), newest first."""
    stmt = select(Hunt).order_by(Hunt.created_at.desc(), Hunt.id).limit(MAX_HUNTS)
    if ref is not None:
        stmt = stmt.where(Hunt.group_ref == ref)
    if max_tlp is not None:
        stmt = stmt.where(Hunt.tlp.in_(visible_levels(max_tlp)))
    return list(db.scalars(stmt))


def get_hunt(db: Session, hunt_id: str, *, max_tlp: str | None = None) -> Hunt | None:
    hunt = db.get(Hunt, hunt_id)
    if hunt is None or (max_tlp is not None and not tlp_permitted(hunt.tlp, max_tlp)):
        return None
    return hunt


def hunt_checks(db: Session, hunt_id: str) -> dict[str, tuple[str, str, str, str, str]]:
    """``{technique: (result, data checked, period start, period end, notes)}`` for one hunt."""
    stmt = select(HuntCheck).where(HuntCheck.hunt_id == hunt_id).order_by(HuntCheck.technique_id)
    return {
        c.technique_id: (c.result, c.data_checked, c.period_start, c.period_end, c.notes)
        for c in db.scalars(stmt)
    }


def _editable(db: Session, hunt_id: str, max_tlp: str | None) -> Hunt:
    hunt = get_hunt(db, hunt_id, max_tlp=max_tlp)
    if hunt is None:
        raise LookupError('Hunt not found')
    return hunt


def update_hunt(db: Session, hunt_id: str, payload: HuntUpdate, *, max_tlp: str | None = None) -> Hunt:
    """Change a hunt's status or summary. Audited as ``hunt.update``."""
    hunt = _editable(db, hunt_id, max_tlp)
    changed = []
    if payload.status != hunt.status:
        hunt.status = payload.status
        changed.append(f'status {payload.status}')
    if payload.summary.strip() != hunt.summary:
        hunt.summary = payload.summary.strip()
        changed.append('summary')
    if changed:
        hunt.updated_at = now()
        audit(db, 'hunt.update', hunt.id, ', '.join(changed))
    return hunt


def record_check(
    db: Session, hunt_id: str, technique_id: str, payload: HuntCheckInput, *, max_tlp: str | None = None
) -> HuntCheck:
    """Record (or replace) the check of one hypothesis. Audited as ``hunt.check``.

    ``ValueError`` for an unknown technique or a time range that ends before it starts.
    """
    hunt = _editable(db, hunt_id, max_tlp)
    found = technique(technique_id)
    if found is None:
        raise ValueError('Not a current ATT&CK technique ID (for example T1059 or T1059.001)')
    if problem := payload.problem():
        raise ValueError(problem)
    if hunt.status == 'closed':
        raise ValueError('This hunt is closed. Reopen it to record more checks.')
    row = db.scalar(select(HuntCheck).where(HuntCheck.hunt_id == hunt.id, HuntCheck.technique_id == found.id))
    if row is None:
        row = HuntCheck(hunt_id=hunt.id, technique_id=found.id)
        db.add(row)
    row.result = payload.result
    row.data_checked = payload.data_checked.strip()
    row.period_start = payload.period_start.isoformat() if payload.period_start else ''
    row.period_end = payload.period_end.isoformat() if payload.period_end else ''
    row.notes = payload.notes.strip()
    row.updated_at = hunt.updated_at = now()
    row.actor = _who(db)
    db.flush()
    audit(db, 'hunt.check', hunt.id, f'{found.id} {payload.result}')
    return row
