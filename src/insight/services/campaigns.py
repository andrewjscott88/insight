"""Manually curated campaigns and links to reports, indicators and ATT&CK techniques."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from sqlalchemy import case, func, literal, select, union_all
from sqlalchemy.orm import InstrumentedAttribute, Session

from ..attack import technique
from ..models import ActorDocument, Campaign, Document, Entity, Observation, ThreatActor, ThreatLink, now
from ..schemas import (
    TLP_LEVELS,
    ActorLinkInput,
    CampaignInput,
    ThreatLinkInput,
    ThreatSubjectKind,
    ThreatTargetKind,
    most_restrictive,
    tlp_markings,
)
from .actors import _check_label, _insert_link, _who, link_report, unlink_report
from .audit import audit
from .common import like_pattern
from .software import _catalog_software
from .tlp import _visible, visible_levels


@dataclass(frozen=True, slots=True)
class ThreatLinkView:
    target_kind: ThreatTargetKind
    target_id: str
    name: str
    tlp: str


def create_campaign(db: Session, payload: CampaignInput, *, max_tlp: str | None = None) -> Campaign:
    label = most_restrictive(
        payload.tlp, *tlp_markings(' '.join((payload.name, *payload.aliases, payload.description)))
    )
    _check_label(label, max_tlp, 'campaigns')
    aliases = [a for a in dict.fromkeys(payload.aliases) if a.casefold() != payload.name.casefold()]
    row = Campaign(
        name=payload.name,
        aliases='\n'.join(aliases),
        description=payload.description.strip(),
        tlp=label,
        actor=_who(db),
    )
    db.add(row)
    db.flush()
    audit(db, 'campaign.create', row.id, row.tlp)
    return row


def list_campaigns(
    db: Session, *, max_tlp: str | None = None, offset: int = 0, limit: int = 100, q: str = ''
) -> list[Campaign]:
    stmt = (
        select(Campaign).where(Campaign.tlp.in_(visible_levels(max_tlp))).order_by(Campaign.name, Campaign.id)
    )
    if q.strip():
        stmt = stmt.where(Campaign.name.ilike(like_pattern(q.strip()[:120]), escape='\\'))
    return list(db.scalars(stmt.offset(max(0, offset)).limit(min(max(1, limit), 200))))


def _subject(
    db: Session, kind: ThreatSubjectKind, ref: str, max_tlp: str | None, *, lock: bool = False
) -> Campaign | ThreatActor:
    model: type[Campaign] | type[ThreatActor] = Campaign if kind == 'campaign' else ThreatActor
    stmt = select(model).where(model.id == ref, model.tlp.in_(visible_levels(max_tlp)))
    subject = db.scalar(stmt.with_for_update() if lock else stmt)
    if subject is None:
        raise LookupError(f'No such {kind}')
    return cast('Campaign | ThreatActor', subject)


def get_campaign(db: Session, ref: str, *, max_tlp: str | None = None) -> Campaign:
    row = db.scalar(select(Campaign).where(Campaign.id == ref, Campaign.tlp.in_(visible_levels(max_tlp))))
    if row is None:
        raise LookupError('No such campaign')
    return row


def _target(db: Session, kind: ThreatTargetKind, ref: str, max_tlp: str | None) -> tuple[str, str, str]:
    if kind == 'document':
        doc = db.scalar(select(Document).where(Document.id == ref, *_visible(max_tlp)))
        if doc:
            return doc.id, doc.title, doc.tlp
    elif kind == 'technique':
        found = technique(ref)
        if found:
            return found.id, found.full_name, 'CLEAR'
    elif kind == 'software':
        item = _catalog_software(ref)
        return item.id, item.name, 'CLEAR'
    else:
        rows = db.execute(
            select(Entity.value, Document.tlp)
            .select_from(Entity)
            .join(Observation, Observation.entity_id == Entity.id)
            .join(Document, Document.id == Observation.document_id)
            .where(Entity.id == ref, *_visible(max_tlp))
            .distinct()
        ).all()
        if rows:
            return ref, rows[0][0], min((r[1] for r in rows), key=TLP_LEVELS.index)
    raise LookupError(f'No such {kind}')


_TARGETS = {
    'document': ThreatLink.document_id,
    'indicator': ThreatLink.entity_id,
    'technique': ThreatLink.technique_id,
    'software': ThreatLink.software_id,
}


def _owner(kind: ThreatSubjectKind) -> InstrumentedAttribute[str | None]:
    return ThreatLink.actor_id if kind == 'actor' else ThreatLink.campaign_id


def link_threat(
    db: Session, kind: ThreatSubjectKind, ref: str, payload: ThreatLinkInput, *, max_tlp: str | None = None
) -> ThreatLinkView:
    subject = _subject(db, kind, ref, max_tlp, lock=True)
    target_id, name, floor = _target(db, payload.target_kind, payload.target_id, max_tlp)
    label = most_restrictive(subject.tlp, payload.tlp, floor)
    _check_label(label, max_tlp, 'links')
    if kind == 'actor' and payload.target_kind == 'document':
        item = ActorLinkInput.model_validate({'document_id': target_id, 'tlp': label})
        row = link_report(db, ref, item, max_tlp=max_tlp, preserve_note=True)
        return ThreatLinkView('document', target_id, name, row.tlp)
    target = _TARGETS[payload.target_kind]
    owner = _owner(kind)
    values = {owner.key: ref, target.key: target_id, 'tlp': label, 'actor': _who(db)}
    if payload.target_kind == 'software':
        values.update(software_name=name, software_type=_catalog_software(target_id).type)
    created = _insert_link(db, ThreatLink, values)
    if not created:
        existing = db.scalars(
            select(ThreatLink).where(owner == ref, target == target_id).with_for_update()
        ).one()
        if existing.tlp not in visible_levels(max_tlp):
            raise LookupError('Link unavailable')
        label = most_restrictive(label, existing.tlp)
        if label == existing.tlp:
            return ThreatLinkView(payload.target_kind, target_id, name, label)
        existing.tlp = label
        existing.updated_at = now()
    db.flush()
    audit(db, f'{kind}.link', ref, f'{payload.target_kind} {target_id}')
    return ThreatLinkView(payload.target_kind, target_id, name, label)


def unlink_threat(
    db: Session,
    kind: ThreatSubjectKind,
    ref: str,
    target_kind: ThreatTargetKind,
    target_id: str,
    *,
    max_tlp: str | None = None,
) -> None:
    _subject(db, kind, ref, max_tlp, lock=True)
    if kind == 'actor' and target_kind == 'document':
        unlink_report(db, ref, target_id, max_tlp=max_tlp)
        return
    if target_kind in ('technique', 'software'):
        target_id = target_id.strip().upper()  # retired tags can still be removed
    else:
        _target(db, target_kind, target_id, max_tlp)
    row = db.scalar(
        select(ThreatLink).where(
            _owner(kind) == ref,
            _TARGETS[target_kind] == target_id,
            ThreatLink.tlp.in_(visible_levels(max_tlp)),
        )
    )
    if row is None:
        raise LookupError('No such link')
    db.delete(row)
    audit(db, f'{kind}.unlink', ref, f'{target_kind} {target_id}')


def list_threat_links(
    db: Session,
    kind: ThreatSubjectKind,
    ref: str,
    *,
    max_tlp: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> list[ThreatLinkView]:
    subject = _subject(db, kind, ref, max_tlp)
    levels = visible_levels(max_tlp)
    owned = (_owner(kind) == ref, ThreatLink.tlp.in_(levels))
    rank = case({label: i for i, label in enumerate(TLP_LEVELS)}, value=Document.tlp)
    flags = (
        select(Observation.entity_id.label('entity'), func.min(rank).label('floor'))
        .join(Document, Document.id == Observation.document_id)
        .where(
            Document.tlp.in_(levels), Observation.entity_id.in_(select(ThreatLink.entity_id).where(*owned))
        )
        .group_by(Observation.entity_id)
        .subquery()
    )
    entities = (
        select(
            literal('indicator').label('kind'),
            Entity.id.label('id'),
            Entity.value.label('name'),
            ThreatLink.tlp.label('tlp'),
            flags.c.floor.label('floor'),
        )
        .select_from(ThreatLink)
        .join(Entity, Entity.id == ThreatLink.entity_id)
        .join(flags, flags.c.entity == Entity.id)
        .where(*owned)
    )
    techniques = select(
        literal('technique'), ThreatLink.technique_id, ThreatLink.technique_id, ThreatLink.tlp, literal(0)
    ).where(*owned, ThreatLink.technique_id.is_not(None))
    if kind == 'actor':
        docs = (
            select(literal('document'), Document.id, Document.title, ActorDocument.tlp, rank)
            .select_from(ActorDocument)
            .join(Document)
            .where(ActorDocument.group_ref == ref, ActorDocument.tlp.in_(levels), Document.tlp.in_(levels))
        )
    else:
        docs = (
            select(literal('document'), Document.id, Document.title, ThreatLink.tlp, rank)
            .select_from(ThreatLink)
            .join(Document)
            .where(*owned, Document.tlp.in_(levels))
        )
    software = select(
        literal('software'), ThreatLink.software_id, ThreatLink.software_name, ThreatLink.tlp, literal(0)
    ).where(*owned, ThreatLink.software_id.is_not(None))
    links = union_all(entities, techniques, docs, software).subquery()
    rows = db.execute(
        select(links).order_by(links.c.kind, links.c.id).offset(max(0, offset)).limit(min(max(1, limit), 200))
    )
    result = []
    for target_kind, target_id, name, tlp, floor in rows:
        found = technique(target_id) if target_kind == 'technique' else None
        result.append(
            ThreatLinkView(
                target_kind,
                target_id,
                found.full_name if found else name,
                most_restrictive(subject.tlp, tlp, TLP_LEVELS[floor]),
            )
        )
    return result
