"""Entities and pivots: the reports an indicator appears in."""

from __future__ import annotations

from typing import Final

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import (
    Document,
    Entity,
    Observation,
)
from .common import like_pattern
from .search import MAX_PAGE_SIZE, MAX_QUERY_LENGTH
from .tlp import _visible

PIVOT_PAGE_SIZE: Final = 25


def list_entities(
    db: Session, q: str = '', limit: int = 200, *, max_tlp: str | None = None
) -> list[tuple[Entity, int]]:
    """Entities with the number of distinct documents mentioning them (literal, case-insensitive search).

    With ``max_tlp``, only reports the reader may see count; entities mentioned only in others are left out.
    """
    stmt = (
        select(Entity, func.count(func.distinct(Observation.document_id)))
        .join(Observation, Observation.entity_id == Entity.id)
        .join(Document, Observation.document_id == Document.id)
        .where(*_visible(max_tlp))
        .group_by(Entity.id)
        .order_by(Entity.kind, Entity.value)
        .limit(limit)
    )
    if term := q.strip()[:MAX_QUERY_LENGTH]:
        stmt = stmt.where(Entity.value.ilike(like_pattern(term), escape='\\'))
    return [(entity, count) for entity, count in db.execute(stmt)]


def get_entity(db: Session, entity_id: str) -> Entity | None:
    return db.get(Entity, entity_id)


def entity_documents(
    db: Session,
    entity_id: str,
    *,
    offset: int = 0,
    limit: int = PIVOT_PAGE_SIZE,
    max_tlp: str | None = None,
) -> list[Document]:
    """One page of documents (all revisions) mentioning the entity, newest first.

    Always paginated: widely shared indicators can appear in thousands of reports (the workspace used to
    render every one of them for every entity, which grew the page without bound).
    """
    ids = select(Observation.document_id).where(Observation.entity_id == entity_id).distinct()
    stmt = (
        select(Document)
        .where(Document.id.in_(ids), *_visible(max_tlp))
        .order_by(Document.created_at.desc(), Document.id)
        .offset(max(0, offset))
        .limit(min(max(1, limit), MAX_PAGE_SIZE))
    )
    return list(db.scalars(stmt))


def count_entity_documents(db: Session, entity_id: str, *, max_tlp: str | None = None) -> int:
    """Distinct reports mentioning the entity that the reader may see (0: treat the entity as not found)."""
    stmt = (
        select(func.count(func.distinct(Observation.document_id)))
        .join(Document, Observation.document_id == Document.id)
        .where(Observation.entity_id == entity_id, *_visible(max_tlp))
    )
    return db.scalar(stmt) or 0
