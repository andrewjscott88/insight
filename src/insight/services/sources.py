"""Source runs, the enrichment cache and conditional-fetch state."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Enrichment,
    FetchState,
    SourceRun,
    now,
)


def recent_source_runs(db: Session, source_key: str | None = None, limit: int = 12) -> list[SourceRun]:
    stmt = select(SourceRun).order_by(SourceRun.created_at.desc()).limit(limit)
    if source_key is not None:
        stmt = stmt.where(SourceRun.source_key == source_key)
    return list(db.scalars(stmt))


def cached_enrichments(db: Session, cve: str) -> list[Enrichment]:
    return list(db.scalars(select(Enrichment).where(Enrichment.cve == cve).order_by(Enrichment.provider)))


def get_fetch_state(db: Session, url: str) -> FetchState | None:
    return db.get(FetchState, url)


def save_fetch_state(
    db: Session, url: str, *, etag: str, last_modified: str, payload_sha256: str, version: str
) -> None:
    """Remember what ``url`` returned; call in the transaction that stores what was read from it."""
    state = db.get(FetchState, url) or FetchState(url=url)
    state.etag, state.last_modified = etag[:200], last_modified[:100]
    state.payload_sha256, state.insight_version, state.updated_at = payload_sha256, version, now()
    db.add(state)
