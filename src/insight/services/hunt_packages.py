"""Hunt packages (TIP 4.3, ADR 0034): what a hunt tool needs to test one hypothesis.

A package holds a hypothesis, an optional threat group, and ATT&CK techniques, indicators, detection rules
(YARA, Sigma, Suricata, Snort) and reports for context. Insight prepares and publishes packages; running the
hunt and recording what it found belong to the hunt tool, which reports sightings back.

Status: ``draft`` (not served), ``published`` (served over TAXII; every change goes out as a new version) and
``retired`` (served as revoked STIX objects; it refuses changes until published again, under new STIX IDs).

TLP: as for cases (ADR 0029), the label is the most restrictive of the text, the group and every item ever
added. Removing an item never lowers it; an explicit change can, but never below what remains.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Final

from sqlalchemy import func, select, update
from sqlalchemy.orm import InstrumentedAttribute, Session

from ..attack import technique
from ..models import DetectionRule, HuntPackage, HuntPackageItem, now
from ..schemas import (
    HuntPackageInput,
    HuntPackageItemInput,
    HuntPackageItemKind,
    HuntPackageUpdate,
    most_restrictive,
    tlp_markings,
)
from .actors import _check_label, _insert_link, _who
from .audit import audit
from .campaigns import _target
from .hunt_package_views import HuntPackageItemView, _group, _names, _package, _target_of, _view
from .tlp import visible_levels

MAX_HUNT_PACKAGE_ITEMS: Final = 500
_TARGET_COLUMN: Final = {
    'technique': HuntPackageItem.technique_id,
    'indicator': HuntPackageItem.entity_id,
    'rule': HuntPackageItem.rule_id,
    'document': HuntPackageItem.document_id,
}
#: What a hunt tool can act on. Reports are context only, so a package needs at least one of these.
_HUNTABLE: Final = ('technique', 'indicator', 'rule')


class HuntPackageConflict(ValueError):
    """The package's status does not allow this (answered with ``409``)."""


def _changeable(db: Session, package_id: str, max_tlp: str | None) -> HuntPackage:
    row = _package(db, package_id, max_tlp, lock=True)
    if row.status == 'retired':
        raise HuntPackageConflict('This hunt package is retired. Publish it again to change it.')
    return row


def _item_labels(db: Session, package_id: str) -> list[str]:
    return list(
        db.scalars(select(HuntPackageItem.tlp).where(HuntPackageItem.package_id == package_id).distinct())
    )


def _resolve(db: Session, kind: HuntPackageItemKind, ref: str, max_tlp: str | None) -> tuple[str, str]:
    """``(target ID, the target's own label)``; ``LookupError`` if it is missing or above ``max_tlp``."""
    if kind == 'technique':
        found = technique(ref)
        if found is None:
            raise LookupError('No such ATT&CK technique (for example T1059 or T1059.001)')
        return found.id, 'CLEAR'
    if kind == 'rule':
        rule = db.execute(
            select(DetectionRule.id, DetectionRule.tlp).where(
                DetectionRule.id == ref, DetectionRule.tlp.in_(visible_levels(max_tlp))
            )
        ).first()
        if rule is None:
            raise LookupError('No such rule')
        return str(rule[0]), str(rule[1])
    target_id, _, floor = _target(db, kind, ref, max_tlp)
    return target_id, floor


def _insert(db: Session, row: HuntPackage, kind: str, target_id: str, label: str) -> bool:
    count = db.scalar(
        select(func.count()).select_from(HuntPackageItem).where(HuntPackageItem.package_id == row.id)
    )
    if (count or 0) >= MAX_HUNT_PACKAGE_ITEMS:
        raise ValueError(f'A hunt package holds at most {MAX_HUNT_PACKAGE_ITEMS:,} items')
    column = _TARGET_COLUMN[kind]
    values = {'package_id': row.id, 'kind': kind, column.key: target_id, 'tlp': label, 'actor': _who(db)}
    return _insert_link(db, HuntPackageItem, values)


def create_hunt_package(db: Session, payload: HuntPackageInput, *, max_tlp: str | None = None) -> HuntPackage:
    """A draft package, with any items given. Audited as ``hunt_package.create``."""
    title, hypothesis = payload.title.strip(), payload.hypothesis.strip()
    label = most_restrictive(payload.tlp, *tlp_markings(f'{title}\n{hypothesis}'))
    group_ref = None
    if payload.group is not None:
        group_ref, _, group_label = _group(db, payload.group, max_tlp)
        label = most_restrictive(label, group_label)
    items = [(i.kind, *_resolve(db, i.kind, i.target_id, max_tlp)) for i in payload.items]
    label = most_restrictive(label, *(item_label for _, _, item_label in items))
    _check_label(label, max_tlp, 'hunt packages')
    row = HuntPackage(title=title, hypothesis=hypothesis, group_ref=group_ref, tlp=label, actor=_who(db))
    db.add(row)
    db.flush()
    for kind, target_id, item_label in items:
        _insert(db, row, kind, target_id, item_label)
    audit(db, 'hunt_package.create', row.id, json.dumps({'items': len(items), 'tlp': label}, sort_keys=True))
    return row


def update_hunt_package(
    db: Session, package_id: str, payload: HuntPackageUpdate, *, max_tlp: str | None = None
) -> HuntPackage:
    """Change the title, hypothesis, group or label. Audited as ``hunt_package.update``."""
    row = _changeable(db, package_id, max_tlp)
    title = payload.title.strip() if payload.title is not None else row.title
    hypothesis = payload.hypothesis.strip() if payload.hypothesis is not None else row.hypothesis
    group_ref, group_label = row.group_ref, 'CLEAR'
    if 'group' in payload.model_fields_set:
        group_ref = None
        if payload.group is not None:
            group_ref, _, group_label = _group(db, payload.group, max_tlp)
    elif row.group_ref is not None:
        try:
            group_label = _group(db, row.group_ref, None)[2]
        except LookupError:  # an analyst actor deleted since
            group_label = 'CLEAR'
    # An explicit label may lower the package, but never below its items, its group or its text's markings.
    floor = most_restrictive(
        'CLEAR', group_label, *_item_labels(db, row.id), *tlp_markings(f'{title}\n{hypothesis}')
    )
    label = most_restrictive(payload.tlp if payload.tlp is not None else row.tlp, floor)
    _check_label(label, max_tlp, 'hunt packages')
    changed = sorted(
        name
        for name, old, new in (
            ('title', row.title, title),
            ('hypothesis', row.hypothesis, hypothesis),
            ('group', row.group_ref, group_ref),
            ('tlp', row.tlp, label),
        )
        if old != new
    )
    if changed:
        row.title, row.hypothesis, row.group_ref, row.tlp = title, hypothesis, group_ref, label
        row.updated_at = now()
        audit(
            db, 'hunt_package.update', row.id, json.dumps({'changed': changed, 'tlp': label}, sort_keys=True)
        )
    return row


def add_hunt_package_item(
    db: Session, package_id: str, payload: HuntPackageItemInput, *, max_tlp: str | None = None
) -> HuntPackageItemView:
    """Add a technique, indicator, rule or report (adding it twice changes nothing). Raises the label."""
    row = _changeable(db, package_id, max_tlp)
    target_id, label = _resolve(db, payload.kind, payload.target_id, max_tlp)
    if _insert(db, row, payload.kind, target_id, label):
        row.tlp, row.updated_at = most_restrictive(row.tlp, label), now()
        detail = {'kind': payload.kind, 'target_id': target_id, 'tlp': label}
        audit(db, 'hunt_package.item.add', row.id, json.dumps(detail, sort_keys=True))
    column = _TARGET_COLUMN[payload.kind]
    item = db.scalars(
        select(HuntPackageItem).where(HuntPackageItem.package_id == row.id, column == target_id)
    ).one()
    return _view(item, _names(db, [item]))


def _huntable(db: Session, package_id: str) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(HuntPackageItem)
            .where(HuntPackageItem.package_id == package_id, HuntPackageItem.kind.in_(_HUNTABLE))
        )
        or 0
    )


def remove_hunt_package_item(
    db: Session, package_id: str, item_id: str, *, max_tlp: str | None = None
) -> None:
    """Remove one item. The package keeps its label; a published package keeps at least one huntable item."""
    row = _changeable(db, package_id, max_tlp)
    item = db.scalar(
        select(HuntPackageItem).where(HuntPackageItem.id == item_id, HuntPackageItem.package_id == row.id)
    )
    if item is None:
        raise LookupError('No such item in this hunt package')
    if row.status == 'published' and item.kind in _HUNTABLE and _huntable(db, row.id) <= 1:
        raise HuntPackageConflict(
            'A published hunt package needs at least one technique, indicator or rule. Retire it instead.'
        )
    detail = {'kind': item.kind, 'target_id': _target_of(item), 'tlp': item.tlp}
    db.delete(item)
    row.updated_at = now()
    audit(db, 'hunt_package.item.remove', row.id, json.dumps(detail, sort_keys=True))


def publish_hunt_package(db: Session, package_id: str, *, max_tlp: str | None = None) -> HuntPackage:
    """Serve the package over TAXII. Publishing a retired package again gives it new STIX IDs."""
    row = _package(db, package_id, max_tlp, lock=True)
    if row.status == 'published':
        return row
    if not _huntable(db, row.id):
        raise HuntPackageConflict('Add at least one ATT&CK technique, indicator or rule before publishing.')
    if row.status == 'retired':
        row.publication += 1
    row.status, row.published_at = 'published', now()
    row.updated_at = row.published_at
    audit(
        db,
        'hunt_package.publish',
        row.id,
        json.dumps({'publication': row.publication, 'tlp': row.tlp}, sort_keys=True),
    )
    return row


def retire_hunt_package(db: Session, package_id: str, *, max_tlp: str | None = None) -> HuntPackage:
    """Withdraw the package: TAXII serves it as revoked, so hunt tools learn it no longer applies."""
    row = _package(db, package_id, max_tlp, lock=True)
    if row.status == 'retired':
        return row
    row.status, row.updated_at = 'retired', now()
    audit(db, 'hunt_package.retire', row.id, row.tlp)
    return row


def delete_hunt_package(db: Session, package_id: str, *, max_tlp: str | None = None) -> None:
    """Delete a draft or retired package and its items (the techniques, indicators, rules and reports
    stay). Audited as ``hunt_package.delete``."""
    row = _package(db, package_id, max_tlp, lock=True)
    if row.status == 'published':
        raise HuntPackageConflict('Retire this hunt package first, so hunt tools learn it was withdrawn.')
    audit(
        db, 'hunt_package.delete', row.id, json.dumps({'status': row.status, 'tlp': row.tlp}, sort_keys=True)
    )
    db.delete(row)
    db.flush()


def _touch_packages(db: Session, column: InstrumentedAttribute[str | None], ids: Iterable[str]) -> None:
    """Before a target is deleted (which removes its items), mark the packages holding it as changed, so TAXII
    clients get a new version. Retired packages are left alone: a revoked STIX object gets no new versions."""
    wanted = sorted(set(ids))
    for start in range(0, len(wanted), 500):
        holding = select(HuntPackageItem.package_id).where(column.in_(wanted[start : start + 500]))
        db.execute(
            update(HuntPackage)
            .where(HuntPackage.id.in_(holding), HuntPackage.status != 'retired')
            .values(updated_at=now())
        )
