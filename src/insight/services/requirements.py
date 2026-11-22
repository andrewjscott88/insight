"""Intelligence requirements and requests for information (TIP 4.1, ADR 0032).

A requirement is a question someone needs answered: a priority intelligence requirement (PIR), a narrower
intelligence requirement (IR) under one, or a request for information (RFI). Its criteria say which reports
address it (``requirement_matches``); analysts cite reports as evidence and record the current answer.

TLP: like a case, a requirement carries the most restrictive label of its text, its criteria (an analyst's
actor or campaign keeps its own label) and its cited reports. Removing a criterion or a citation never lowers
it; only an explicit change can, and never below what remains. A reader limited to a TLP level sees a
requirement only within that limit, and counts only the reports it may see.
"""

from __future__ import annotations

import json
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Document, Requirement, RequirementCriterion, RequirementEvidence, now
from ..schemas import (
    AnswerInput,
    CriterionInput,
    EvidenceInput,
    RequirementInput,
    RequirementUpdate,
    RfiInput,
    end_of_day,
    most_restrictive,
    tlp_markings,
)
from .actors import _check_label, _insert_link, _who
from .audit import audit
from .requirement_views import MAX_EVIDENCE, CriterionView, EvidenceView, _criterion, _requirement
from .tlp import _visible

MAX_CRITERIA: Final = 50


class RequirementRetired(ValueError):
    """A retired requirement cannot change; reopen it first."""


class RequirementInUse(ValueError):
    """A PIR with intelligence requirements under it cannot be deleted."""


def _changeable(db: Session, requirement_id: str, max_tlp: str | None) -> Requirement:
    found = _requirement(db, requirement_id, max_tlp, lock=True)
    if found.status == 'retired':
        raise RequirementRetired('This requirement is retired. Reopen it to change it.')
    return found


def _text_label(*texts: str) -> tuple[str, ...]:
    return tuple(tlp_markings('\n'.join(texts)))


def _touch(row: Requirement, *labels: str) -> None:
    row.tlp = most_restrictive(row.tlp, *labels)
    row.updated_at = now()


def _insert_criterion(db: Session, row: Requirement, payload: CriterionInput, max_tlp: str | None) -> str:
    value, _, label = _criterion(db, payload, max_tlp)
    _check_label(label, max_tlp, 'requirement criteria')
    count = db.scalar(
        select(func.count())
        .select_from(RequirementCriterion)
        .where(RequirementCriterion.requirement_id == row.id)
    )
    if (count or 0) >= MAX_CRITERIA:
        raise ValueError(f'A requirement has at most {MAX_CRITERIA} criteria')
    values = {'requirement_id': row.id, 'kind': payload.kind, 'value': value, 'tlp': label, 'actor': _who(db)}
    if _insert_link(db, RequirementCriterion, values):
        _touch(row, label)
        detail = json.dumps({'kind': payload.kind, 'value': value, 'tlp': label}, sort_keys=True)
        audit(db, 'requirement.criterion.add', row.id, detail)
    return value


def create_requirement(db: Session, payload: RequirementInput, *, max_tlp: str | None = None) -> Requirement:
    if (payload.kind == 'ir') != (payload.parent_id is not None):
        raise ValueError('An intelligence requirement (IR) needs a parent PIR; a PIR or RFI has none')
    if payload.parent_id is not None:
        parent = _requirement(db, payload.parent_id, max_tlp)
        if parent.kind != 'pir':
            raise ValueError('The parent of an intelligence requirement must be a PIR')
    label = most_restrictive(payload.tlp, *_text_label(payload.question, payload.context))
    _check_label(label, max_tlp, 'requirements')
    row = Requirement(
        kind=payload.kind,
        parent_id=payload.parent_id,
        question=payload.question.strip(),
        context=payload.context.strip(),
        stakeholder=payload.stakeholder.strip(),
        priority=payload.priority,
        tlp=label,
        due_at=end_of_day(payload.due),
        actor=_who(db),
    )
    db.add(row)
    db.flush()
    audit(db, 'requirement.create', row.id, json.dumps({'kind': row.kind, 'tlp': label}, sort_keys=True))
    for criterion in payload.criteria:
        _insert_criterion(db, row, criterion, max_tlp)
    return row


def file_rfi(db: Session, payload: RfiInput, *, max_tlp: str | None = None) -> Requirement:
    """A request for information from another tool or person (``POST /api/rfis``)."""
    label = most_restrictive(payload.tlp, *_text_label(payload.question, payload.context))
    _check_label(label, max_tlp, 'requests for information')
    row = Requirement(
        kind='rfi',
        question=payload.question.strip(),
        context=payload.context.strip(),
        stakeholder=payload.requester.strip(),
        priority=payload.priority,
        tlp=label,
        due_at=end_of_day(payload.due),
        external_ref=payload.external_ref.strip(),
        actor=_who(db),
    )
    db.add(row)
    db.flush()
    audit(db, 'requirement.rfi', row.id, json.dumps({'tlp': label, 'ref': row.external_ref}, sort_keys=True))
    return row


def update_requirement(
    db: Session, requirement_id: str, payload: RequirementUpdate, *, max_tlp: str | None = None
) -> Requirement:
    row = _changeable(db, requirement_id, max_tlp)
    question = payload.question.strip() if payload.question is not None else row.question
    context = payload.context.strip() if payload.context is not None else row.context
    labels = [
        *db.scalars(select(RequirementCriterion.tlp).where(RequirementCriterion.requirement_id == row.id)),
        *db.scalars(select(RequirementEvidence.tlp).where(RequirementEvidence.requirement_id == row.id)),
    ]
    floor = most_restrictive('CLEAR', *labels, *_text_label(question, context, row.answer))
    label = most_restrictive(payload.tlp if payload.tlp is not None else row.tlp, floor)
    _check_label(label, max_tlp, 'requirements')
    new = {
        'question': question,
        'context': context,
        'stakeholder': payload.stakeholder.strip() if payload.stakeholder is not None else row.stakeholder,
        'priority': payload.priority or row.priority,
        'tlp': label,
        'due_at': end_of_day(payload.due) if 'due' in payload.model_fields_set else row.due_at,
    }
    changed = sorted(k for k, v in new.items() if getattr(row, k) != v)
    for key, value in new.items():
        setattr(row, key, value)
    row.updated_at = now()
    if changed:
        audit(
            db, 'requirement.update', row.id, json.dumps({'changed': changed, 'tlp': label}, sort_keys=True)
        )
    return row


def add_criterion(
    db: Session, requirement_id: str, payload: CriterionInput, *, max_tlp: str | None = None
) -> CriterionView:
    row = _changeable(db, requirement_id, max_tlp)
    value = _insert_criterion(db, row, payload, max_tlp)
    stored = db.scalars(
        select(RequirementCriterion).where(
            RequirementCriterion.requirement_id == row.id,
            RequirementCriterion.kind == payload.kind,
            RequirementCriterion.value == value,
        )
    ).one()
    _, name, _ = _criterion(db, payload, max_tlp)
    return CriterionView(
        stored.id, stored.kind, stored.value, name, stored.tlp, stored.added_at, stored.actor
    )


def remove_criterion(
    db: Session, requirement_id: str, criterion_id: str, *, max_tlp: str | None = None
) -> None:
    """Remove one criterion. The requirement keeps its label (see the module docstring)."""
    row = _changeable(db, requirement_id, max_tlp)
    found = db.scalar(
        select(RequirementCriterion).where(
            RequirementCriterion.id == criterion_id, RequirementCriterion.requirement_id == row.id
        )
    )
    if found is None:
        raise LookupError('No such criterion on this requirement')
    detail = json.dumps({'kind': found.kind, 'value': found.value}, sort_keys=True)
    db.delete(found)
    row.updated_at = now()
    audit(db, 'requirement.criterion.remove', row.id, detail)


def add_evidence(
    db: Session, requirement_id: str, payload: EvidenceInput, *, max_tlp: str | None = None
) -> EvidenceView:
    """Cite a report (citing it twice changes nothing). Raises the requirement's label to the report's."""
    row = _changeable(db, requirement_id, max_tlp)
    doc = db.scalar(select(Document).where(Document.id == payload.document_id, *_visible(max_tlp)))
    if doc is None:
        raise LookupError('No such report')
    label = most_restrictive(doc.tlp, *tlp_markings(payload.note))
    _check_label(label, max_tlp, 'requirement evidence')
    count = db.scalar(
        select(func.count())
        .select_from(RequirementEvidence)
        .where(RequirementEvidence.requirement_id == row.id)
    )
    if (count or 0) >= MAX_EVIDENCE:
        raise ValueError(f'A requirement cites at most {MAX_EVIDENCE} reports')
    values = {
        'requirement_id': row.id, 'document_id': doc.id, 'note': payload.note.strip(), 'tlp': label,
        'actor': _who(db),
    }  # fmt: skip
    if _insert_link(db, RequirementEvidence, values):
        _touch(row, label)
        detail = json.dumps({'document_id': doc.id, 'tlp': label}, sort_keys=True)
        audit(db, 'requirement.evidence.add', row.id, detail)
    item = db.scalars(
        select(RequirementEvidence).where(
            RequirementEvidence.requirement_id == row.id, RequirementEvidence.document_id == doc.id
        )
    ).one()
    return EvidenceView(item.id, doc.id, doc.title, item.note, item.tlp, item.added_at, item.actor)


def remove_evidence(
    db: Session, requirement_id: str, evidence_id: str, *, max_tlp: str | None = None
) -> None:
    row = _changeable(db, requirement_id, max_tlp)
    found = db.scalar(
        select(RequirementEvidence).where(
            RequirementEvidence.id == evidence_id, RequirementEvidence.requirement_id == row.id
        )
    )
    if found is None:
        raise LookupError('No such citation on this requirement')
    detail = json.dumps({'document_id': found.document_id}, sort_keys=True)
    db.delete(found)
    row.updated_at = now()
    audit(db, 'requirement.evidence.remove', row.id, detail)


def answer_requirement(
    db: Session, requirement_id: str, payload: AnswerInput, *, max_tlp: str | None = None
) -> Requirement:
    """Record the current answer. An RFI becomes ``answered``; a PIR or IR stays open."""
    row = _changeable(db, requirement_id, max_tlp)
    label = most_restrictive(row.tlp, *tlp_markings(payload.answer))
    _check_label(label, max_tlp, 'answers')
    row.answer, row.answered_at, row.tlp = payload.answer.strip(), now(), label
    row.updated_at = row.answered_at
    if row.kind == 'rfi':
        row.status = 'answered'
    audit(db, 'requirement.answer', row.id, label)
    return row


def retire_requirement(db: Session, requirement_id: str, *, max_tlp: str | None = None) -> Requirement:
    row = _requirement(db, requirement_id, max_tlp, lock=True)
    if row.status != 'retired':
        row.status, row.updated_at = 'retired', now()
        audit(db, 'requirement.retire', row.id, row.tlp)
    return row


def reopen_requirement(db: Session, requirement_id: str, *, max_tlp: str | None = None) -> Requirement:
    row = _requirement(db, requirement_id, max_tlp, lock=True)
    if row.status != 'open':
        row.status, row.updated_at = 'open', now()
        audit(db, 'requirement.reopen', row.id, row.tlp)
    return row


def delete_requirement(db: Session, requirement_id: str, *, max_tlp: str | None = None) -> None:
    """Delete a requirement with its criteria and citations (the reports stay). A PIR with IRs under it
    cannot be deleted: retire it, or delete the IRs first."""
    row = _requirement(db, requirement_id, max_tlp, lock=True)
    if db.scalar(select(Requirement.id).where(Requirement.parent_id == row.id).limit(1)):
        raise RequirementInUse(
            'This PIR has intelligence requirements under it. Retire it, or delete those first.'
        )
    db.delete(row)
    db.flush()
    audit(db, 'requirement.delete', requirement_id, row.question[:200])
