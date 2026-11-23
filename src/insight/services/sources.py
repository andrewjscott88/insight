"""Source runs, source switches, the enrichment cache and conditional-fetch state."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Enrichment,
    FetchState,
    Schedule,
    SourceRun,
    SourceSwitch,
    now,
)
from ..source_registry import SOURCES
from .audit import DEFAULT_ACTOR, audit
from .common import stamp
from .jobs import set_schedule


def recent_source_runs(
    db: Session, source_key: str | None = None, limit: int = 12, *, max_tlp: str | None = None
) -> list[SourceRun]:
    from .operator_sources import _visible_operator_history

    visible = SourceRun.source_key.in_(tuple(SOURCES)) | _visible_operator_history(
        SourceRun.source_key, SourceRun.created_at, max_tlp
    )
    stmt = select(SourceRun).where(visible).order_by(SourceRun.created_at.desc(), SourceRun.id).limit(limit)
    if source_key is not None:
        stmt = stmt.where(SourceRun.source_key == source_key)
    return list(db.scalars(stmt))


def source_switches(db: Session) -> dict[str, bool]:
    """The sources the operator switched on (``True``) or off; a source without a row keeps its default.

    Keys with a colon are other switches stored in the same table (``lookup:nvd``, ADR 0023), not sources.
    """
    return {s.source_key: s.enabled for s in db.scalars(select(SourceSwitch)) if ':' not in s.source_key}


def set_source_switch(db: Session, source_key: str, enabled: bool, *, at: datetime) -> SourceSwitch:
    """Switch a source on or off; off also turns its schedule off. Callers check that the source exists.

    Audited as ``source.on`` or ``source.off``.
    """
    switch = db.get(SourceSwitch, source_key) or SourceSwitch(source_key=source_key)
    switch.enabled = enabled
    switch.updated_at = stamp(at)
    switch.actor = str(db.info.get('actor', DEFAULT_ACTOR))
    db.add(switch)
    schedule = db.get(Schedule, source_key)
    if not enabled and schedule is not None and schedule.enabled:
        set_schedule(db, source_key, 0, at=at)
    audit(db, 'source.on' if enabled else 'source.off', source_key, '')
    return switch


def cached_enrichments(db: Session, cve: str) -> list[Enrichment]:
    return list(db.scalars(select(Enrichment).where(Enrichment.cve == cve).order_by(Enrichment.provider)))


def get_fetch_state(db: Session, url: str) -> FetchState | None:
    return db.get(FetchState, url)


def fetch_cursor(db: Session, url: str) -> str:
    """Where a paged feed resumes (issue #11), ``''`` before its first sync."""
    state = db.get(FetchState, url)
    return state.cursor if state is not None else ''


def save_fetch_cursor(db: Session, url: str, cursor: str) -> None:
    """Remember where a paged feed resumes; call in the transaction that stores the page it follows."""
    state = db.get(FetchState, url) or FetchState(url=url)
    state.cursor, state.updated_at = cursor, now()
    db.add(state)


def save_fetch_state(
    db: Session, url: str, *, etag: str, last_modified: str, payload_sha256: str, version: str
) -> None:
    """Remember what ``url`` returned; call in the transaction that stores what was read from it."""
    state = db.get(FetchState, url) or FetchState(url=url)
    state.etag, state.last_modified = etag[:200], last_modified[:100]
    state.payload_sha256, state.insight_version, state.updated_at = payload_sha256, version, now()
    db.add(state)
