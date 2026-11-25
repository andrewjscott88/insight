"""Private subject-query helpers for deterministic focused briefs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime

from sqlalchemy import Select, literal, select
from sqlalchemy.orm import InstrumentedAttribute, Session
from sqlalchemy.sql.elements import ColumnElement

from ..cve_scores import VULNCHECK_NOTICE
from ..models import Document, Entity, KEVRecord, Observation
from ..schemas import most_restrictive
from .assessments import _expires_at, entity_assessment
from .exploits import exploit_context
from .hunt_guide_subjects import _entities
from .tlp import _visible

_ReportQuery = Select[str, str, str, str, str, str]


@dataclass(frozen=True)
class _Focus:
    ref: str
    title: str
    tlp: str
    background: str
    query: _ReportQuery


def _text(value: str, cap: int = 300) -> str:
    text = ' '.join(value.split())
    return text if len(text) <= cap else text[: cap - 1].rstrip() + '…'


def _catalog(description: str, fallback: str) -> str:
    text = re.sub(r'\(Citation:[^)]*\)', '', description)
    text = re.sub(r'\[([^]]+)\]\([^)]*\)', r'\1', text)
    return 'Background from MITRE ATT&CK: ' + _text(text.split('. ')[0] or fallback, 260).rstrip('.') + '.'


def _query(label: ColumnElement[str] | InstrumentedAttribute[str] | None = None) -> _ReportQuery:
    return select(
        Document.id,
        Document.title,
        Document.tlp,
        Document.created_at,
        Document.source_name,
        literal('CLEAR') if label is None else label,
    )


def _dated(value: str, moment: datetime) -> bool:
    try:
        return date.fromisoformat(value) <= moment.date()
    except ValueError:
        return False


def _entity_focus(
    db: Session,
    kind: str,
    ref: str,
    max_tlp: str | None,
    moment: datetime,
) -> _Focus:
    stmt = _entities(max_tlp)
    stmt = (
        stmt.where(Entity.id == ref)
        if kind == 'indicator'
        else stmt.where(
            Entity.kind == 'cve',
            Entity.value == ref.upper(),
        )
    )
    entity = db.scalar(stmt)
    if entity is None:
        raise LookupError('Brief topic not found')
    mentions = select(Observation.document_id).where(
        Observation.entity_id == entity.id,
        Observation.review_status != 'rejected',
    )
    query = _query().where(Document.id.in_(mentions))
    # Even the existence of an indicator or flaw can come only from a restricted report.
    labels = db.scalars(
        select(Document.tlp)
        .where(
            Document.id.in_(mentions),
            Document.is_current.is_(True),
            *_visible(max_tlp),
        )
        .distinct()
    )
    label = most_restrictive('CLEAR', *labels)
    if kind == 'indicator':
        background = f'Saved indicator: {_text(entity.value, 180)} ({entity.kind}).'
        assessment = entity_assessment(db, entity.id, max_tlp=max_tlp)
        if assessment is None:
            background += ' No analyst verdict is available in this view.'
        else:
            label = most_restrictive(label, assessment.tlp)
            expiry = _expires_at(entity.kind, assessment)
            try:
                expires = datetime.fromisoformat(expiry) if expiry is not None else None
                if expires is not None and expires.tzinfo is None:
                    expires = expires.replace(tzinfo=UTC)
                expired = expires is not None and expires <= moment
            except ValueError:
                expired = True
            background += (
                ' Its saved analyst verdict has expired.'
                if expired
                else f' The saved analyst verdict is {assessment.verdict}.'
            )
        return _Focus(entity.id, entity.value, label, background, query)
    context = exploit_context(db, [entity.value], max_tlp=max_tlp).get(entity.value)
    kev = db.get(KEVRecord, entity.value)
    if kev is not None and not _dated(kev.date_added, moment):
        kev = None
    reported = bool(
        context
        and context.reported_exploited
        and context.vulncheck
        and _dated(context.vulncheck.date_added, moment)
    )
    if kind == 'exploit' and not (kev or reported or (context and context.public_exploit)):
        raise LookupError('Brief topic not found')
    if kev:
        background = (
            f'Saved CISA catalog: {entity.value} is a flaw in {_text(kev.vendor + " " + kev.product, 100)} '
            'that has been used in real attacks.'
        )
    elif reported:
        background = (
            f'Saved VulnCheck KEV catalog: {entity.value} has been used in real attacks. {VULNCHECK_NOTICE}'
        )
    elif context and context.public_exploit:
        background = (
            f'Saved evidence for {entity.value} says exploit code is public. '
            'Public code does not prove that an attack occurred.'
        )
        if context.vulncheck and context.vulncheck.exploit_count > 0:
            background += ' ' + VULNCHECK_NOTICE
    else:
        background = (
            f'{entity.value} identifies a software flaw. The saved catalogs do not confirm use in attacks; '
            'that does not prove it is unused.'
        )
    return _Focus(entity.value, entity.value, label, background, query)
