"""Reading hunt packages (TIP 4.3, ADR 0034): lists with item counts, and one package with its items. The
helpers here are shared with the write side in ``hunt_packages``."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from sqlalchemy import case as when
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..attack import technique
from ..models import DetectionRule, Document, Entity, HuntPackage, HuntPackageItem
from ..schemas import HuntPackageStatusFilter
from .actors import resolve_group
from .tlp import visible_levels

MAX_HUNT_PACKAGES: Final = 200


@dataclass(frozen=True, slots=True)
class HuntPackageSummary:
    id: str
    title: str
    status: str
    tlp: str
    group_ref: str | None
    techniques: int
    indicators: int
    rules: int
    documents: int
    created_at: str
    updated_at: str
    published_at: str | None


@dataclass(frozen=True, slots=True)
class HuntPackageItemView:
    id: str
    kind: str
    target_id: str
    name: str
    tlp: str
    added_at: str
    added_by: str


@dataclass(frozen=True, slots=True)
class HuntPackageView:
    id: str
    title: str
    hypothesis: str
    group_ref: str | None
    group_name: str
    status: str
    publication: int
    tlp: str
    created_at: str
    updated_at: str
    published_at: str | None
    created_by: str
    items: tuple[HuntPackageItemView, ...]


def _package(db: Session, package_id: str, max_tlp: str | None, *, lock: bool = False) -> HuntPackage:
    stmt = select(HuntPackage).where(
        HuntPackage.id == package_id, HuntPackage.tlp.in_(visible_levels(max_tlp))
    )
    found = db.scalar(stmt.with_for_update() if lock else stmt)
    if found is None:
        raise LookupError('No such hunt package')
    return found


def _target_of(item: HuntPackageItem) -> str:
    return item.technique_id or item.entity_id or item.rule_id or item.document_id or ''


def _group(db: Session, ref: str, max_tlp: str | None) -> tuple[str, str, str]:
    """``(ref, name, label)`` of a catalog group or analyst actor the caller may see."""
    subject = resolve_group(db, ref, max_tlp=max_tlp)
    return subject.ref, subject.name, subject.tlp


def _names(db: Session, items: Iterable[HuntPackageItem]) -> dict[str, str]:
    wanted: dict[str, set[str]] = {}
    for item in items:
        wanted.setdefault(item.kind, set()).add(_target_of(item))
    names = {t: found.full_name for t in wanted.get('technique', ()) if (found := technique(t))}
    for kind, model, label in (
        ('indicator', Entity, Entity.value),
        ('rule', DetectionRule, DetectionRule.name),
        ('document', Document, Document.title),
    ):
        if ids := sorted(wanted.get(kind, ())):
            found_rows = db.execute(select(model.id, label).where(model.id.in_(ids)))
            names.update({str(target): str(name) for target, name in found_rows})
    return names


def _view(item: HuntPackageItem, names: dict[str, str]) -> HuntPackageItemView:
    target = _target_of(item)
    return HuntPackageItemView(
        item.id, item.kind, target, names.get(target, ''), item.tlp, item.added_at, item.actor
    )


def list_hunt_packages(
    db: Session, *, max_tlp: str | None = None, status: HuntPackageStatusFilter = 'all'
) -> list[HuntPackageSummary]:
    """Packages within the caller's limit, most recently changed first, with their item counts."""
    counts = (
        select(
            HuntPackageItem.package_id,
            *(
                func.sum(when((HuntPackageItem.kind == kind, 1), else_=0)).label(kind)
                for kind in ('technique', 'indicator', 'rule', 'document')
            ),
        )
        .group_by(HuntPackageItem.package_id)
        .subquery()
    )
    stmt = (
        select(HuntPackage, counts.c.technique, counts.c.indicator, counts.c.rule, counts.c.document)
        .outerjoin(counts, counts.c.package_id == HuntPackage.id)
        .where(HuntPackage.tlp.in_(visible_levels(max_tlp)))
        .order_by(HuntPackage.updated_at.desc(), HuntPackage.id)
        .limit(MAX_HUNT_PACKAGES)
    )
    if status != 'all':
        stmt = stmt.where(HuntPackage.status == status)
    return [
        HuntPackageSummary(
            p.id, p.title, p.status, p.tlp, p.group_ref, int(t or 0), int(i or 0), int(r or 0), int(d or 0),
            p.created_at, p.updated_at, p.published_at,
        )
        for p, t, i, r, d in db.execute(stmt)
    ]  # fmt: skip


def get_hunt_package(db: Session, package_id: str, *, max_tlp: str | None = None) -> HuntPackageView:
    row = _package(db, package_id, max_tlp)
    items = list(
        db.scalars(
            select(HuntPackageItem)
            .where(HuntPackageItem.package_id == row.id)
            .order_by(HuntPackageItem.kind, HuntPackageItem.added_at, HuntPackageItem.id)
        )
    )
    group_name = ''
    if row.group_ref:
        try:
            group_name = _group(db, row.group_ref, row.tlp)[1]
        except LookupError:  # an analyst actor deleted, or relabelled above the package, since
            group_name = ''
    names = _names(db, items)
    return HuntPackageView(
        id=row.id,
        title=row.title,
        hypothesis=row.hypothesis,
        group_ref=row.group_ref,
        group_name=group_name,
        status=row.status,
        publication=row.publication,
        tlp=row.tlp,
        created_at=row.created_at,
        updated_at=row.updated_at,
        published_at=row.published_at,
        created_by=row.actor,
        items=tuple(_view(item, names) for item in items),
    )
