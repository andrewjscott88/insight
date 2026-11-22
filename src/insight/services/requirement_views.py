"""Reading intelligence requirements (TIP 4.1, ADR 0032): lists with coverage, one requirement with its
criteria, citations and matching reports, and the requirements one report addresses. TLP rules are in
``requirements``; every query here keeps to the caller's limit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Campaign, Document, Requirement, RequirementCriterion, RequirementEvidence
from ..schemas import CriterionInput, RequirementKind, RequirementStatusFilter, most_restrictive, tlp_markings
from .actors import resolve_group
from .requirement_matches import MatchView, _coverage, _criteria_of, _Criterion, _matches, _matches_document
from .tlp import visible_levels

MAX_EVIDENCE: Final = 500
MAX_LISTED: Final = 200
PRIORITY_ORDER: Final = {'high': 0, 'medium': 1, 'low': 2}


@dataclass(frozen=True, slots=True)
class RequirementSummary:
    id: str
    kind: str
    parent_id: str | None
    question: str
    stakeholder: str
    priority: str
    status: str
    tlp: str
    due_at: str | None
    answered_at: str | None
    created_at: str
    updated_at: str
    criteria_count: int
    evidence_count: int
    #: Visible reports matching in the last 30 days, the newest match ever, and whether it has gone quiet.
    recent_matches: int
    last_match_at: str | None
    quiet: bool


@dataclass(frozen=True, slots=True)
class CriterionView:
    id: str
    kind: str
    value: str
    name: str
    tlp: str
    added_at: str
    added_by: str


@dataclass(frozen=True, slots=True)
class EvidenceView:
    id: str
    document_id: str
    title: str
    note: str
    tlp: str
    added_at: str
    added_by: str


@dataclass(frozen=True, slots=True)
class RequirementView:
    summary: RequirementSummary
    context: str
    answer: str
    external_ref: str
    created_by: str
    criteria: tuple[CriterionView, ...]
    evidence: tuple[EvidenceView, ...]
    children: tuple[RequirementSummary, ...]
    matches: tuple[MatchView, ...]


@dataclass(frozen=True, slots=True)
class DocumentRequirement:
    """An open requirement a report addresses, and why."""

    id: str
    kind: str
    question: str
    priority: str
    because: tuple[str, ...]


def _requirement(db: Session, requirement_id: str, max_tlp: str | None, *, lock: bool = False) -> Requirement:
    stmt = select(Requirement).where(
        Requirement.id == requirement_id, Requirement.tlp.in_(visible_levels(max_tlp))
    )
    found = db.scalar(stmt.with_for_update() if lock else stmt)
    if found is None:
        raise LookupError('No such requirement')
    return found


def _criterion(db: Session, payload: CriterionInput, max_tlp: str | None) -> tuple[str, str, str]:
    """``(value, display name, label)``; ``LookupError`` for an unknown group or campaign."""
    value = payload.normalised()
    if payload.kind == 'group':
        group = resolve_group(db, value, max_tlp=max_tlp)
        return group.ref, group.name, group.tlp
    if payload.kind == 'campaign':
        found = db.execute(
            select(Campaign.id, Campaign.name, Campaign.tlp).where(
                Campaign.id == value, Campaign.tlp.in_(visible_levels(max_tlp))
            )
        ).first()
        if found is None:
            raise LookupError('No such campaign')
        return str(found[0]), str(found[1]), str(found[2])
    return value, value, most_restrictive('CLEAR', *tlp_markings(value))


def _counts(
    db: Session, model: type[RequirementCriterion] | type[RequirementEvidence], ids: list[str]
) -> dict[str, int]:
    if not ids:
        return {}
    rows = db.execute(
        select(model.requirement_id, func.count())
        .where(model.requirement_id.in_(ids))
        .group_by(model.requirement_id)
    )
    return {str(rid): int(n) for rid, n in rows}


def _summaries(db: Session, rows: list[Requirement], max_tlp: str | None) -> list[RequirementSummary]:
    ids = [r.id for r in rows]
    criteria, evidence, found = (
        _counts(db, RequirementCriterion, ids),
        _counts(db, RequirementEvidence, ids),
        _criteria_of(db, ids),
    )
    summaries = []
    for r in rows:
        cover = _coverage(db, found[r.id], max_tlp)
        summaries.append(
            RequirementSummary(
                r.id, r.kind, r.parent_id, r.question, r.stakeholder, r.priority, r.status, r.tlp, r.due_at,
                r.answered_at, r.created_at, r.updated_at, criteria.get(r.id, 0), evidence.get(r.id, 0),
                cover.recent, cover.last_match_at, cover.quiet and r.status == 'open',
            )
        )  # fmt: skip
    return summaries


def list_requirements(
    db: Session,
    *,
    max_tlp: str | None = None,
    status: RequirementStatusFilter = 'open',
    kind: RequirementKind | None = None,
) -> list[RequirementSummary]:
    """Requirements within the caller's limit: high priority first, then the most recently changed."""
    stmt = select(Requirement).where(Requirement.tlp.in_(visible_levels(max_tlp)))
    if status != 'all':
        stmt = stmt.where(Requirement.status == status)
    if kind is not None:
        stmt = stmt.where(Requirement.kind == kind)
    rows = list(db.scalars(stmt.order_by(Requirement.updated_at.desc(), Requirement.id).limit(MAX_LISTED)))
    rows.sort(key=lambda r: PRIORITY_ORDER.get(r.priority, 1))
    return _summaries(db, rows, max_tlp)


def get_requirement(db: Session, requirement_id: str, *, max_tlp: str | None = None) -> RequirementView:
    row = _requirement(db, requirement_id, max_tlp)
    levels = visible_levels(max_tlp)
    criteria_rows = list(
        db.scalars(
            select(RequirementCriterion)
            .where(RequirementCriterion.requirement_id == row.id)
            .order_by(RequirementCriterion.added_at, RequirementCriterion.id)
        )
    )
    criteria = []
    for c in criteria_rows:
        try:
            _, name, _ = _criterion(db, CriterionInput(kind=c.kind, value=c.value), max_tlp)
        except (LookupError, ValueError):
            name = c.value  # A deleted actor or campaign: the criterion stays, and matches nothing new.
        criteria.append(CriterionView(c.id, c.kind, c.value, name, c.tlp, c.added_at, c.actor))
    evidence = db.execute(
        select(RequirementEvidence, Document.title)
        .join(Document, Document.id == RequirementEvidence.document_id)
        .where(RequirementEvidence.requirement_id == row.id, Document.tlp.in_(levels))
        .order_by(RequirementEvidence.added_at, RequirementEvidence.id)
        .limit(MAX_EVIDENCE)
    )
    children = list(
        db.scalars(
            select(Requirement)
            .where(Requirement.parent_id == row.id, Requirement.tlp.in_(levels))
            .order_by(Requirement.created_at, Requirement.id)
        )
    )
    found = [_Criterion(c.kind, c.value) for c in criteria_rows]
    return RequirementView(
        summary=_summaries(db, [row], max_tlp)[0],
        context=row.context,
        answer=row.answer,
        external_ref=row.external_ref,
        created_by=row.actor,
        criteria=tuple(criteria),
        evidence=tuple(
            EvidenceView(e.id, e.document_id, str(title), e.note, e.tlp, e.added_at, e.actor)
            for e, title in evidence
        ),
        children=tuple(_summaries(db, children, max_tlp)),
        matches=tuple(_matches(db, found, max_tlp)),
    )


def document_requirements(
    db: Session, document_id: str, *, max_tlp: str | None = None
) -> list[DocumentRequirement]:
    """Open requirements (within the caller's limit) that one visible report addresses."""
    rows = list(
        db.scalars(
            select(Requirement)
            .where(Requirement.status == 'open', Requirement.tlp.in_(visible_levels(max_tlp)))
            .order_by(Requirement.created_at, Requirement.id)
            .limit(MAX_LISTED)
        )
    )
    found = _criteria_of(db, [r.id for r in rows])
    met = ((r, _matches_document(db, document_id, found[r.id], max_tlp)) for r in rows)
    hits = [DocumentRequirement(r.id, r.kind, r.question, r.priority, tuple(b)) for r, b in met if b]
    hits.sort(key=lambda h: PRIORITY_ORDER.get(h.priority, 1))
    return hits


def requirement_counts(db: Session, *, max_tlp: str | None = None) -> dict[str, int]:
    """``open_rfis``: requests waiting for an answer; ``quiet``: open requirements with no recent match."""
    open_rfis = db.scalar(
        select(func.count())
        .select_from(Requirement)
        .where(
            Requirement.kind == 'rfi',
            Requirement.status == 'open',
            Requirement.tlp.in_(visible_levels(max_tlp)),
        )
    )
    quiet = sum(1 for s in list_requirements(db, max_tlp=max_tlp) if s.quiet)
    return {'open_rfis': int(open_rfis or 0), 'quiet': quiet}
