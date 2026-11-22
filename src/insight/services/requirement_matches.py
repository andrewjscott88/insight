"""Which reports address an intelligence requirement (TIP 4.1, ADR 0032), computed on read.

A requirement's criteria say what makes a report relevant: a term in its text, a CVE it mentions (unless the
mention was rejected in review), an ATT&CK technique tagged on it, or an explicit link to a threat group or
campaign. A report matches when any criterion does. Only current reports the reader may see count, and links
count only when the reader may see the link itself, so a match never reveals what the reader cannot see.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import ColumnElement, func, or_, select
from sqlalchemy.orm import Session

from ..models import (
    ActorDocument,
    Document,
    DocumentTechnique,
    Entity,
    Observation,
    RequirementCriterion,
    ThreatActor,
    ThreatLink,
)
from .actors import is_catalog_ref
from .common import fold, like_pattern
from .techniques import TAGGED
from .tlp import _visible, visible_levels

#: A requirement is "quiet" when nothing matched in this many days.
QUIET_DAYS: Final = 30
MAX_MATCHES: Final = 50


@dataclass(frozen=True, slots=True)
class _Criterion:
    kind: str
    value: str


@dataclass(frozen=True, slots=True)
class MatchView:
    document_id: str
    title: str
    source_name: str
    tlp: str
    created_at: str
    #: Which criteria the report meets, such as ``term: ransomware`` or ``cve: CVE-2024-3400``.
    because: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Coverage:
    recent: int
    last_match_at: str | None
    quiet: bool


def _since(days: int = QUIET_DAYS) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


def _group_refs(db: Session, ref: str, max_tlp: str | None) -> set[str]:
    """A catalog group and the analyst actors linked to it count as one group, both ways."""
    levels = visible_levels(max_tlp)
    refs = {ref}
    if is_catalog_ref(ref):
        refs |= set(
            db.scalars(
                select(ThreatActor.id).where(ThreatActor.attack_group_id == ref, ThreatActor.tlp.in_(levels))
            )
        )
    else:
        linked = db.scalar(
            select(ThreatActor.attack_group_id).where(ThreatActor.id == ref, ThreatActor.tlp.in_(levels))
        )
        if linked:
            refs.add(linked)
    return refs


def _condition(db: Session, criterion: _Criterion, max_tlp: str | None) -> ColumnElement[bool]:
    """SQL condition on ``Document`` for one criterion."""
    levels = visible_levels(max_tlp)
    if criterion.kind == 'term':
        return Document.search_text.like(like_pattern(fold(criterion.value)), escape='\\')
    if criterion.kind == 'cve':
        mentions = (
            select(Observation.document_id)
            .join(Entity, Entity.id == Observation.entity_id)
            .where(
                Entity.kind == 'cve', Entity.value == criterion.value, Observation.review_status != 'rejected'
            )
        )
        return Document.id.in_(mentions)
    if criterion.kind == 'technique':
        tagged = select(DocumentTechnique.document_id).where(
            DocumentTechnique.technique_id == criterion.value, DocumentTechnique.status == TAGGED
        )
        return Document.id.in_(tagged)
    if criterion.kind == 'group':
        linked = select(ActorDocument.document_id).where(
            ActorDocument.group_ref.in_(_group_refs(db, criterion.value, max_tlp)),
            ActorDocument.tlp.in_(levels),
        )
        return Document.id.in_(linked)
    campaign = select(ThreatLink.document_id).where(
        ThreatLink.campaign_id == criterion.value,
        ThreatLink.document_id.is_not(None),
        ThreatLink.tlp.in_(levels),
    )
    return Document.id.in_(campaign)


def _base(max_tlp: str | None) -> list[ColumnElement[bool]]:
    return [Document.is_current.is_(True), *_visible(max_tlp)]


def _coverage(db: Session, criteria: list[_Criterion], max_tlp: str | None) -> _Coverage:
    """How many visible reports matched in the last :data:`QUIET_DAYS` days, and the newest match ever."""
    if not criteria:
        return _Coverage(0, None, False)
    any_of = or_(*(_condition(db, c, max_tlp) for c in criteria))
    recent = db.scalar(
        select(func.count(Document.id)).where(*_base(max_tlp), any_of, Document.created_at >= _since())
    )
    last = db.scalar(select(func.max(Document.created_at)).where(*_base(max_tlp), any_of))
    return _Coverage(int(recent or 0), str(last) if last else None, not recent)


def _matches(db: Session, criteria: list[_Criterion], max_tlp: str | None) -> list[MatchView]:
    """The newest :data:`MAX_MATCHES` visible reports meeting any criterion, with the criteria each meets."""
    because: dict[str, list[str]] = {}
    rows: dict[str, Document] = {}
    for criterion in criteria:
        found = db.scalars(
            select(Document)
            .where(*_base(max_tlp), _condition(db, criterion, max_tlp))
            .order_by(Document.created_at.desc(), Document.id)
            .limit(MAX_MATCHES)
        )
        for doc in found:
            rows[doc.id] = doc
            because.setdefault(doc.id, []).append(f'{criterion.kind}: {criterion.value}')
    newest = sorted(rows.values(), key=lambda d: (d.created_at, d.id), reverse=True)[:MAX_MATCHES]
    return [
        MatchView(d.id, d.title, d.source_name, d.tlp, d.created_at, tuple(because[d.id])) for d in newest
    ]


def _matches_document(
    db: Session, document_id: str, criteria: list[_Criterion], max_tlp: str | None
) -> list[str]:
    """Which of ``criteria`` one visible report meets (an empty list if none, or if the report is hidden)."""
    met = []
    for criterion in criteria:
        found = db.scalar(
            select(Document.id).where(
                Document.id == document_id, *_visible(max_tlp), _condition(db, criterion, max_tlp)
            )
        )
        if found:
            met.append(f'{criterion.kind}: {criterion.value}')
    return met


def _criteria_of(db: Session, requirement_ids: list[str]) -> dict[str, list[_Criterion]]:
    """Criteria per requirement, in the order they were added."""
    found: dict[str, list[_Criterion]] = {rid: [] for rid in requirement_ids}
    if requirement_ids:
        rows = db.execute(
            select(RequirementCriterion.requirement_id, RequirementCriterion.kind, RequirementCriterion.value)
            .where(RequirementCriterion.requirement_id.in_(requirement_ids))
            .order_by(RequirementCriterion.added_at, RequirementCriterion.id)
        )
        for rid, kind, value in rows:
            found[rid].append(_Criterion(kind, value))
    return found
