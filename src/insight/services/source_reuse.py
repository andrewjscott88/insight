"""Current publisher permissions for report and MCP projections."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Document, OperatorSource
from ..source_registry import is_operator_source, metadata_only


def _restricted_reports(db: Session, documents: Sequence[Document]) -> set[str]:
    """Resolve sharing rules for a page of reports, including references to deleted sources."""
    keys = {doc.source_key for doc in documents if is_operator_source(doc.source_key)}
    stmt = select(OperatorSource.key, OperatorSource.reuse).where(OperatorSource.key.in_(keys))
    rules = dict(db.execute(stmt).all()) if keys else {}
    return {doc.id for doc in documents if metadata_only(doc.source_key, rules.get(doc.source_key or ''))}
