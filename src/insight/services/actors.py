"""Threat actors and groups as the analyst records them (TIP 2.5 minimum, TIP 2.10; ADR 0025).

A *group reference* is either an ATT&CK group ID from the threat library (``G0016``, catalog data, TLP:CLEAR)
or the ID of a :class:`ThreatActor` the analyst created. Everything the analyst adds is an explicit decision:
links from a group to a report, industries added with a citation, catalog claims removed with a reason.
Insight never creates an actor, a link or a claim by itself, and never from indicators shared between reports.

Every read takes ``max_tlp``; every write refuses labels above it (``TlpNotPermitted``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..industries import BY_KEY
from ..models import ActorDocument, Document, IndustryClaim, ThreatActor, now
from ..schemas import ActorInput, ActorLinkInput, IndustryClaimInput, most_restrictive, tlp_markings
from ..threat_library import Group, library
from .audit import DEFAULT_ACTOR, audit
from .tlp import TlpNotPermitted, _visible, tlp_permitted, visible_levels

CATALOG_REF: Final = re.compile(r'^G\d{4}$')
MAX_LINKED_REPORTS: Final = 200


@dataclass(frozen=True, slots=True)
class GroupSubject:
    """What a guide or profile is about: a catalog group, or an analyst's actor (maybe linked to one)."""

    ref: str
    kind: str  # 'catalog' or 'analyst'
    name: str
    aliases: tuple[str, ...]
    description: str
    tlp: str  # CLEAR for catalog data; the actor's own label otherwise
    catalog: Group | None
    created_by: str = ''

    @property
    def names(self) -> tuple[str, ...]:
        names = [self.name, *self.aliases]
        if self.catalog is not None:
            names += [*self.catalog.names]
        return tuple(dict.fromkeys(n for n in names if n.strip()))


def _who(db: Session) -> str:
    return str(db.info.get('actor', DEFAULT_ACTOR))


def _check_label(label: str, max_tlp: str | None, what: str) -> None:
    if max_tlp is not None and not tlp_permitted(label, max_tlp):
        raise TlpNotPermitted(f'TLP:{label} {what} cannot be stored by this caller (limit TLP:{max_tlp}).')


def is_catalog_ref(ref: str) -> bool:
    return bool(CATALOG_REF.match(ref.strip().upper()))


def actor_aliases(actor: ThreatActor) -> tuple[str, ...]:
    return tuple(a for a in actor.aliases.split('\n') if a.strip())


def _visible_actor(db: Session, actor_id: str, max_tlp: str | None) -> ThreatActor | None:
    stmt = select(ThreatActor).where(ThreatActor.id == actor_id)
    if max_tlp is not None:
        stmt = stmt.where(ThreatActor.tlp.in_(visible_levels(max_tlp)))
    return db.scalar(stmt)


def resolve_group(db: Session, ref: str, *, max_tlp: str | None = None) -> GroupSubject:
    """The catalog group or analyst actor ``ref`` names (``LookupError`` if unknown or above ``max_tlp``)."""
    ref = ref.strip()
    if is_catalog_ref(ref):
        group = library().group(ref)
        if group is None:
            raise LookupError('No such group in the threat library')
        return GroupSubject(group.id, 'catalog', group.name, group.aliases, group.description, 'CLEAR', group)
    actor = _visible_actor(db, ref, max_tlp)
    if actor is None:
        raise LookupError('No such actor')
    linked = library().group(actor.attack_group_id) if actor.attack_group_id else None
    return GroupSubject(
        actor.id,
        'analyst',
        actor.name,
        actor_aliases(actor),
        actor.description,
        actor.tlp,
        linked,
        actor.actor,
    )


def create_actor(db: Session, payload: ActorInput, *, max_tlp: str | None = None) -> ThreatActor:
    """Record an actor the analyst tracks. Audited as ``actor.create``.

    ``ValueError`` for an ``attack_group_id`` that is not in the threat library.
    """
    label = most_restrictive(
        payload.tlp, *tlp_markings(' '.join((payload.name, *payload.aliases, payload.description)))
    )
    _check_label(label, max_tlp, 'actors')
    group_id = payload.attack_group_id.upper() if payload.attack_group_id else None
    if group_id is not None and library().group(group_id) is None:
        raise ValueError(f'{group_id} is not a group in the threat library')
    aliases = [a for a in dict.fromkeys(payload.aliases) if a.casefold() != payload.name.casefold()]
    actor = ThreatActor(
        name=payload.name,
        aliases='\n'.join(aliases),
        description=payload.description.strip(),
        attack_group_id=group_id,
        tlp=label,
        actor=_who(db),
    )
    db.add(actor)
    db.flush()
    audit(
        db,
        'actor.create',
        actor.id,
        f'{actor.name} (TLP:{actor.tlp})' + (f' = {group_id}' if group_id else ''),
    )
    return actor


def list_actors(db: Session, *, max_tlp: str | None = None) -> list[ThreatActor]:
    stmt = select(ThreatActor).order_by(ThreatActor.name, ThreatActor.id)
    if max_tlp is not None:
        stmt = stmt.where(ThreatActor.tlp.in_(visible_levels(max_tlp)))
    return list(db.scalars(stmt))


def _visible_report(db: Session, document_id: str, max_tlp: str | None) -> Document:
    doc = db.scalar(select(Document).where(Document.id == document_id, *_visible(max_tlp)))
    if doc is None:
        raise LookupError('Report not found')
    return doc


def link_report(
    db: Session, ref: str, payload: ActorLinkInput, *, max_tlp: str | None = None
) -> ActorDocument:
    """Link a report to a group or actor (idempotent). Audited as ``actor.link``."""
    subject = resolve_group(db, ref, max_tlp=max_tlp)
    doc = _visible_report(db, payload.document_id, max_tlp)
    row = db.scalar(
        select(ActorDocument).where(
            ActorDocument.group_ref == subject.ref, ActorDocument.document_id == doc.id
        )
    )
    label = most_restrictive(subject.tlp, doc.tlp, payload.tlp, *tlp_markings(payload.note))
    _check_label(label, max_tlp, 'links')
    if row is None:
        row = ActorDocument(group_ref=subject.ref, document_id=doc.id, actor=_who(db), tlp=label)
        db.add(row)
    else:
        if row.tlp not in visible_levels(max_tlp):
            raise LookupError('Report link unavailable')
        label = most_restrictive(label, row.tlp)
        if row.note == payload.note.strip() and row.tlp == label:
            return row
    row.note = payload.note.strip()
    row.tlp = label
    db.flush()
    audit(db, 'actor.link', subject.ref, doc.id)
    return row


def unlink_report(db: Session, ref: str, document_id: str, *, max_tlp: str | None = None) -> None:
    """Remove a link made by :func:`link_report`. Audited as ``actor.unlink``."""
    subject = resolve_group(db, ref, max_tlp=max_tlp)
    _visible_report(db, document_id, max_tlp)
    row = db.scalar(
        select(ActorDocument).where(
            ActorDocument.group_ref == subject.ref, ActorDocument.document_id == document_id
        )
    )
    if row is None or row.tlp not in visible_levels(max_tlp):
        raise LookupError('That report is not linked to this group')
    db.delete(row)
    audit(db, 'actor.unlink', subject.ref, document_id)


def linked_reports(
    db: Session, ref: str, *, max_tlp: str | None = None
) -> list[tuple[Document, ActorDocument]]:
    """Reports the analyst linked to ``ref`` that the reader may see, newest first."""
    resolve_group(db, ref, max_tlp=max_tlp)
    stmt = (
        select(Document, ActorDocument)
        .join(ActorDocument, ActorDocument.document_id == Document.id)
        .where(
            ActorDocument.group_ref == ref, ActorDocument.tlp.in_(visible_levels(max_tlp)), *_visible(max_tlp)
        )
        .order_by(Document.created_at.desc(), Document.id)
        .limit(MAX_LINKED_REPORTS)
    )
    return [(doc, link) for doc, link in db.execute(stmt)]


def record_industry_claim(
    db: Session, ref: str, payload: IndustryClaimInput, *, max_tlp: str | None = None
) -> IndustryClaim:
    """Add an industry to a group with a citation, or remove a catalog claim with a reason.

    One decision per group and industry: a new one replaces the last. ``ValueError`` for an unknown industry
    or a claim without its citation or reason. Audited as ``actor.industry``.
    """
    if payload.industry not in BY_KEY:
        raise ValueError(f'Unknown industry: {payload.industry}')
    if problem := payload.problem():
        raise ValueError(problem)
    _check_label(payload.tlp, max_tlp, 'industry mappings')
    subject = resolve_group(db, ref, max_tlp=max_tlp)
    doc = _visible_report(db, payload.document_id, max_tlp) if payload.document_id else None
    row = db.scalar(
        select(IndustryClaim).where(
            IndustryClaim.group_ref == subject.ref, IndustryClaim.industry == payload.industry
        )
    )
    if row is not None and max_tlp is not None and not tlp_permitted(row.effective_tlp, max_tlp):
        # Like a hidden hunt or rule: a decision above the caller's limit looks missing, so a limited key
        # cannot learn from the answer that one exists.
        raise LookupError('Industry mapping not found')
    if row is None:
        row = IndustryClaim(group_ref=subject.ref, industry=payload.industry)
        db.add(row)
    row.decision = payload.decision
    row.citation_url = payload.citation_url
    row.document_id = payload.document_id
    row.reason = payload.reason.strip()
    row.tlp = most_restrictive(payload.tlp, subject.tlp, doc.tlp if doc else 'CLEAR')
    row.created_at = now()
    row.actor = _who(db)
    db.flush()
    audit(db, 'actor.industry', subject.ref, f'{payload.decision} {payload.industry} (TLP:{row.tlp})')
    return row


def analyst_claims(
    db: Session, *, max_tlp: str | None = None, group_ref: str | None = None, industry: str | None = None
) -> list[IndustryClaim]:
    """The analyst's industry decisions the reader may see, optionally for one group or industry."""
    stmt = select(IndustryClaim).order_by(IndustryClaim.group_ref, IndustryClaim.industry)
    if max_tlp is not None:
        levels = visible_levels(max_tlp)
        stmt = stmt.where(
            IndustryClaim.tlp.in_(levels),
            or_(IndustryClaim.subject_tlp.is_(None), IndustryClaim.subject_tlp.in_(levels)),
            or_(IndustryClaim.source_tlp.is_(None), IndustryClaim.source_tlp.in_(levels)),
        )
    if group_ref is not None:
        stmt = stmt.where(IndustryClaim.group_ref == group_ref)
    if industry is not None:
        stmt = stmt.where(IndustryClaim.industry == industry)
    return list(db.scalars(stmt))


def report_groups(db: Session, document_id: str, *, max_tlp: str | None = None) -> list[GroupSubject]:
    """Groups and actors the analyst linked this report to, that the reader may see, by name."""
    _visible_report(db, document_id, max_tlp)
    refs = db.scalars(
        select(ActorDocument.group_ref).where(
            ActorDocument.document_id == document_id, ActorDocument.tlp.in_(visible_levels(max_tlp))
        )
    )
    found = []
    for ref in refs:
        try:
            found.append(resolve_group(db, ref, max_tlp=max_tlp))
        except LookupError:
            continue
    return sorted(found, key=lambda s: s.name.casefold())
