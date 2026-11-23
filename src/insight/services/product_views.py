"""Reading intelligence products (TIP 4.4, ADR 0036).

A case holds a product: a bottom line up front, key judgements in ICD 203's estimative language with the
analyst's confidence and the evidence behind each, the analysis, intelligence gaps, and the sources cited.
This module builds it in the ``insight-product-1`` shape that publishing stores and every export renders: as
it is now (a draft), or exactly as a version was published. Working notes are never part of a product.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Campaign,
    Case,
    CaseGap,
    CaseItem,
    CaseJudgement,
    CaseJudgementItem,
    CaseVersion,
    Document,
    Entity,
    ThreatActor,
    now,
)
from .cases import _case
from .confidence import _ratings, indicator_confidence
from .tlp import visible_levels

PRODUCT_FORMAT: Final = 'insight-product-1'
#: Sources are numbered in this order: what was read first, then what it is about.
_SOURCE_ORDER: Final = {'document': 0, 'indicator': 1, 'actor': 2, 'campaign': 3}


@dataclass(frozen=True, slots=True)
class JudgementView:
    id: str
    position: int
    statement: str
    likelihood: str
    confidence: str
    evidence: tuple[str, ...]  # case item IDs
    tlp: str
    created_at: str
    updated_at: str
    created_by: str


@dataclass(frozen=True, slots=True)
class GapView:
    id: str
    question: str
    requirement_id: str | None
    tlp: str
    created_at: str
    created_by: str


@dataclass(frozen=True, slots=True)
class VersionSummary:
    version: int
    tlp: str
    published_at: str
    published_by: str


@dataclass(frozen=True, slots=True)
class ProductParts:
    judgements: tuple[JudgementView, ...]
    gaps: tuple[GapView, ...]
    versions: tuple[VersionSummary, ...]


def _judgements(db: Session, case_id: str) -> list[JudgementView]:
    rows = list(
        db.scalars(
            select(CaseJudgement)
            .where(CaseJudgement.case_id == case_id)
            .order_by(CaseJudgement.position, CaseJudgement.created_at, CaseJudgement.id)
        )
    )
    evidence: dict[str, list[str]] = {r.id: [] for r in rows}
    if rows:
        links = db.execute(
            select(CaseJudgementItem.judgement_id, CaseJudgementItem.item_id)
            .join(CaseItem, CaseItem.id == CaseJudgementItem.item_id)
            .where(CaseJudgementItem.judgement_id.in_(list(evidence)))
            .order_by(CaseItem.added_at, CaseItem.id)
        )
        for judgement_id, item_id in links:
            evidence[judgement_id].append(item_id)
    return [
        JudgementView(
            r.id, r.position, r.statement, r.likelihood, r.confidence, tuple(evidence[r.id]), r.tlp,
            r.created_at, r.updated_at, r.actor,
        )
        for r in rows
    ]  # fmt: skip


def _gaps(db: Session, case_id: str) -> list[GapView]:
    rows = db.scalars(
        select(CaseGap).where(CaseGap.case_id == case_id).order_by(CaseGap.created_at, CaseGap.id)
    )
    return [GapView(g.id, g.question, g.requirement_id, g.tlp, g.created_at, g.actor) for g in rows]


def product_parts(db: Session, case_id: str, *, max_tlp: str | None = None) -> ProductParts:
    """The key judgements, gaps and published versions of a product the caller may see."""
    row = _case(db, case_id, max_tlp)
    versions = db.scalars(
        select(CaseVersion)
        .where(CaseVersion.case_id == row.id, CaseVersion.tlp.in_(visible_levels(max_tlp)))
        .order_by(CaseVersion.version.desc())
    )
    return ProductParts(
        tuple(_judgements(db, row.id)),
        tuple(_gaps(db, row.id)),
        tuple(VersionSummary(v.version, v.tlp, v.published_at, v.actor) for v in versions),
    )


def _sources(db: Session, row: Case) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """The product's evidence as numbered sources, and each case item's number."""
    items = sorted(
        db.scalars(select(CaseItem).where(CaseItem.case_id == row.id, CaseItem.kind != 'note')),
        key=lambda i: (_SOURCE_ORDER.get(i.kind, 9), i.added_at, i.id),
    )
    ids = {kind: [i.document_id or i.entity_id or i.actor_id or i.campaign_id or '' for i in items
                  if i.kind == kind] for kind in _SOURCE_ORDER}  # fmt: skip
    docs = {d.id: d for d in db.scalars(select(Document).where(Document.id.in_(ids['document'])))}
    ratings = _ratings(db, {d.source_name for d in docs.values()})
    entities = {e.id: e for e in db.scalars(select(Entity).where(Entity.id.in_(ids['indicator'])))}
    # ``.all()``: a Result has ``keys()``, so ``dict()`` would read it as a mapping.
    actors = dict(
        db.execute(select(ThreatActor.id, ThreatActor.name).where(ThreatActor.id.in_(ids['actor']))).all()
    )
    campaigns = dict(
        db.execute(select(Campaign.id, Campaign.name).where(Campaign.id.in_(ids['campaign']))).all()
    )
    sources: list[dict[str, Any]] = []
    numbers: dict[str, int] = {}
    for item in items:
        target = item.document_id or item.entity_id or item.actor_id or item.campaign_id or ''
        entry: dict[str, Any] = {'n': len(sources) + 1, 'kind': item.kind, 'id': target, 'tlp': item.tlp}
        if item.kind == 'document' and target in docs:
            doc = docs[target]
            rating = ratings.get(doc.source_name)
            entry.update(name=doc.title, source_name=doc.source_name, url=doc.source_url,
                         added_at=doc.created_at, reliability=rating.reliability if rating else 'F',
                         credibility=doc.credibility)  # fmt: skip
        elif item.kind == 'indicator' and target in entities:
            entity = entities[target]
            found = indicator_confidence(db, target, max_tlp=row.tlp)
            entry.update(
                name=entity.value, indicator_kind=entity.kind, confidence=found.score, band=found.band
            )
        elif item.kind in ('actor', 'campaign'):
            entry['name'] = (actors if item.kind == 'actor' else campaigns).get(target, '')
        else:  # the target was deleted while the item stayed (it cascades; kept for safety)
            continue
        numbers[item.id] = entry['n']
        sources.append(entry)
    return sources, numbers


def _draft(db: Session, row: Case) -> dict[str, Any]:
    sources, numbers = _sources(db, row)
    return {
        'format': PRODUCT_FORMAT,
        'id': row.id,
        'title': row.title,
        'product_type': row.product_type,
        'audience': row.audience,
        'tlp': row.tlp,
        'version': None,
        'published_at': None,
        'author': row.actor,
        'generated_at': now(),
        'bluf': row.bluf,
        'judgements': [
            {
                'statement': j.statement,
                'likelihood': j.likelihood,
                'confidence': j.confidence,
                'sources': sorted(numbers[i] for i in j.evidence if i in numbers),
            }
            for j in _judgements(db, row.id)
        ],
        'analysis': row.summary,
        'gaps': [{'question': g.question, 'rfi': g.requirement_id} for g in _gaps(db, row.id)],
        'sources': sources,
    }


def product_view(
    db: Session, case_id: str, *, max_tlp: str | None = None, version: int | None = None
) -> dict[str, Any]:
    """The product as it is now, or (with ``version``) exactly as that version was published."""
    row = _case(db, case_id, max_tlp)
    if version is None:
        return _draft(db, row)
    found = db.scalar(
        select(CaseVersion).where(
            CaseVersion.case_id == row.id,
            CaseVersion.version == version,
            CaseVersion.tlp.in_(visible_levels(max_tlp)),
        )
    )
    if found is None:
        raise LookupError('No such version')
    view: dict[str, Any] = json.loads(found.snapshot)
    return view
