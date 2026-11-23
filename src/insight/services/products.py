"""Writing intelligence products (TIP 4.4, ADR 0036): key judgements, intelligence gaps and publishing.

A key judgement is a statement with how likely it is (ICD 203's seven expressions) and the analyst's
confidence (low, moderate, high), supported by evidence the product holds. A gap is a question the product
cannot answer yet; asking it as an RFI files a request for information (TIP 4.1). Publishing stores the
product exactly as it is, as the next numbered version; the product stays open for the next one.

TLP, as for the rest of a case: each judgement and gap is labelled at least like the product unless the caller
says otherwise, TLP markings in its text raise that, and the product's label rises with it and never drops
when one is removed.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Final

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..models import CaseGap, CaseItem, CaseJudgement, CaseJudgementItem, CaseVersion, Requirement, now
from ..schemas import GapInput, JudgementInput, JudgementUpdate, RfiInput, most_restrictive, tlp_markings
from .actors import _check_label, _who
from .audit import audit
from .cases import _open, _raise
from .product_views import GapView, JudgementView, VersionSummary, _draft, _judgements
from .requirements import file_rfi

MAX_JUDGEMENTS: Final = 50
MAX_GAPS: Final = 50


class ProductIncomplete(ValueError):
    """The product cannot be published yet (answered with ``409``)."""


def _judgement(db: Session, case_id: str, judgement_id: str) -> CaseJudgement:
    found = db.scalar(
        select(CaseJudgement).where(CaseJudgement.id == judgement_id, CaseJudgement.case_id == case_id)
    )
    if found is None:
        raise LookupError('No such key judgement in this product')
    return found


def _evidence(db: Session, case_id: str, item_ids: Iterable[str]) -> list[str]:
    """The given case items, each checked to be evidence (not a note) in this product."""
    wanted = list(dict.fromkeys(i.strip() for i in item_ids))
    if not wanted:
        return []
    found = set(
        db.scalars(
            select(CaseItem.id).where(
                CaseItem.id.in_(wanted), CaseItem.case_id == case_id, CaseItem.kind != 'note'
            )
        )
    )
    if missing := [i for i in wanted if i not in found]:
        raise LookupError(f'Not evidence in this product: {missing[0]}')
    return wanted


def _link(db: Session, judgement_id: str, item_ids: list[str]) -> None:
    db.execute(delete(CaseJudgementItem).where(CaseJudgementItem.judgement_id == judgement_id))
    db.add_all(CaseJudgementItem(judgement_id=judgement_id, item_id=item) for item in item_ids)
    db.flush()


def _view(db: Session, case_id: str, judgement_id: str) -> JudgementView:
    return next(j for j in _judgements(db, case_id) if j.id == judgement_id)


def add_judgement(
    db: Session, case_id: str, payload: JudgementInput, *, max_tlp: str | None = None
) -> JudgementView:
    """Add a key judgement at the end. Audited as ``case.judgement.add``."""
    row = _open(db, case_id, max_tlp)
    label = most_restrictive(payload.tlp or row.tlp, *tlp_markings(payload.statement))
    _check_label(label, max_tlp, 'key judgements')
    evidence = _evidence(db, row.id, payload.evidence)
    count, last = db.execute(
        select(func.count(), func.coalesce(func.max(CaseJudgement.position), 0)).where(
            CaseJudgement.case_id == row.id
        )
    ).one()
    if count >= MAX_JUDGEMENTS:
        raise ValueError(f'A product holds at most {MAX_JUDGEMENTS} key judgements')
    judgement = CaseJudgement(
        case_id=row.id,
        position=int(last) + 1,
        statement=payload.statement.strip(),
        likelihood=payload.likelihood,
        confidence=payload.confidence,
        tlp=label,
        actor=_who(db),
    )
    db.add(judgement)
    db.flush()
    _link(db, judgement.id, evidence)
    _raise(row, label)
    detail = {'judgement': judgement.id, 'likelihood': payload.likelihood, 'confidence': payload.confidence,
              'tlp': label}  # fmt: skip
    audit(db, 'case.judgement.add', row.id, json.dumps(detail, sort_keys=True))
    return _view(db, row.id, judgement.id)


def update_judgement(
    db: Session, case_id: str, judgement_id: str, payload: JudgementUpdate, *, max_tlp: str | None = None
) -> JudgementView:
    """Change a key judgement; ``evidence`` replaces its list; ``position`` moves it. Audited."""
    row = _open(db, case_id, max_tlp)
    judgement = _judgement(db, row.id, judgement_id)
    changed: list[str] = []
    if payload.statement is not None and payload.statement.strip() != judgement.statement:
        judgement.statement = payload.statement.strip()
        judgement.tlp = most_restrictive(judgement.tlp, *tlp_markings(judgement.statement))
        _check_label(judgement.tlp, max_tlp, 'key judgements')
        changed.append('statement')
    for name, value in (('likelihood', payload.likelihood), ('confidence', payload.confidence)):
        if value is not None and value != getattr(judgement, name):
            setattr(judgement, name, value)
            changed.append(name)
    if payload.evidence is not None:
        _link(db, judgement.id, _evidence(db, row.id, payload.evidence))
        changed.append('evidence')
    if payload.position is not None:
        ordered = [j for j in _judgements(db, row.id) if j.id != judgement.id]
        at = min(payload.position, len(ordered) + 1) - 1
        ids = [j.id for j in ordered[:at]] + [judgement.id] + [j.id for j in ordered[at:]]
        for position, other in enumerate(ids, start=1):
            db.get_one(CaseJudgement, other).position = position
        changed.append('position')
    if changed:
        judgement.updated_at = now()
        _raise(row, judgement.tlp)
        detail = {'judgement': judgement.id, 'changed': changed, 'tlp': judgement.tlp}
        audit(db, 'case.judgement.update', row.id, json.dumps(detail, sort_keys=True))
    db.flush()
    return _view(db, row.id, judgement.id)


def remove_judgement(db: Session, case_id: str, judgement_id: str, *, max_tlp: str | None = None) -> None:
    """Remove a key judgement. The product keeps its label. Audited as ``case.judgement.remove``."""
    row = _open(db, case_id, max_tlp)
    judgement = _judgement(db, row.id, judgement_id)
    detail = json.dumps({'judgement': judgement.id, 'tlp': judgement.tlp}, sort_keys=True)
    db.delete(judgement)
    row.updated_at = now()
    audit(db, 'case.judgement.remove', row.id, detail)


def add_gap(db: Session, case_id: str, payload: GapInput, *, max_tlp: str | None = None) -> GapView:
    """Record a question the product cannot answer yet. Audited as ``case.gap.add``."""
    row = _open(db, case_id, max_tlp)
    label = most_restrictive(payload.tlp or row.tlp, *tlp_markings(payload.question))
    _check_label(label, max_tlp, 'intelligence gaps')
    count = db.scalar(select(func.count()).select_from(CaseGap).where(CaseGap.case_id == row.id)) or 0
    if count >= MAX_GAPS:
        raise ValueError(f'A product holds at most {MAX_GAPS} intelligence gaps')
    gap = CaseGap(case_id=row.id, question=payload.question.strip(), tlp=label, actor=_who(db))
    db.add(gap)
    db.flush()
    _raise(row, label)
    audit(db, 'case.gap.add', row.id, json.dumps({'gap': gap.id, 'tlp': label}, sort_keys=True))
    return GapView(gap.id, gap.question, None, gap.tlp, gap.created_at, gap.actor)


def _gap(db: Session, case_id: str, gap_id: str) -> CaseGap:
    found = db.scalar(select(CaseGap).where(CaseGap.id == gap_id, CaseGap.case_id == case_id))
    if found is None:
        raise LookupError('No such intelligence gap in this product')
    return found


def remove_gap(db: Session, case_id: str, gap_id: str, *, max_tlp: str | None = None) -> None:
    """Remove a gap (its RFI, if any, stays). The product keeps its label. Audited as ``case.gap.remove``."""
    row = _open(db, case_id, max_tlp)
    gap = _gap(db, row.id, gap_id)
    detail = json.dumps({'gap': gap.id, 'tlp': gap.tlp}, sort_keys=True)
    db.delete(gap)
    row.updated_at = now()
    audit(db, 'case.gap.remove', row.id, detail)


def ask_gap(db: Session, case_id: str, gap_id: str, *, max_tlp: str | None = None) -> Requirement:
    """File the gap as a request for information, labelled like the gap (once: asking again returns it)."""
    row = _open(db, case_id, max_tlp)
    gap = _gap(db, row.id, gap_id)
    if gap.requirement_id is not None and (asked := db.get(Requirement, gap.requirement_id)) is not None:
        return asked
    payload = RfiInput(
        question=gap.question,
        context=f'An intelligence gap in the product "{row.title}".',
        tlp=gap.tlp,
        external_ref=f'insight-product:{row.id}',
    )
    rfi = file_rfi(db, payload, max_tlp=max_tlp)
    gap.requirement_id = rfi.id
    row.updated_at = now()
    audit(db, 'case.gap.rfi', row.id, json.dumps({'gap': gap.id, 'rfi': rfi.id}, sort_keys=True))
    return rfi


def publish_product(db: Session, case_id: str, *, max_tlp: str | None = None) -> VersionSummary:
    """Store the product exactly as it is now as its next version. ``ProductIncomplete`` without a bottom line
    up front, a key judgement, or evidence for every judgement. Audited as ``case.publish``."""
    row = _open(db, case_id, max_tlp)
    judgements = _judgements(db, row.id)
    missing = []
    if not row.bluf.strip():
        missing.append('a bottom line up front')
    if not judgements:
        missing.append('at least one key judgement')
    if unsupported := [str(j.position) for j in judgements if not j.evidence]:
        missing.append(f'evidence for key judgement {", ".join(unsupported)}')
    if missing:
        raise ProductIncomplete(f'To publish, add {" and ".join(missing)}.')
    stamp = now()
    row.version += 1
    row.published_at = row.updated_at = stamp
    snapshot = _draft(db, row) | {'version': row.version, 'published_at': stamp, 'generated_at': stamp}
    who = _who(db)
    db.add(
        CaseVersion(
            case_id=row.id,
            version=row.version,
            tlp=row.tlp,
            published_at=stamp,
            actor=who,
            snapshot=json.dumps(snapshot, sort_keys=True),
        )
    )
    audit(db, 'case.publish', row.id, json.dumps({'version': row.version, 'tlp': row.tlp}, sort_keys=True))
    return VersionSummary(row.version, row.tlp, stamp, who)
