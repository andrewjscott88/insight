"""Operator-owned feed configurations, switches, and visibility of their operational history."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast
from uuid import uuid4

from sqlalchemy import ColumnElement, Select, delete, or_, select, update
from sqlalchemy.orm import InstrumentedAttribute, Session

from ..models import Document, FetchState, Job, OperatorSource, Schedule, SourceSwitch, now
from ..schemas import TLP, OperatorSourceInput
from ..source_registry import OPERATOR_PREFIX, Reuse
from .audit import DEFAULT_ACTOR, audit
from .jobs import SOURCE_SYNC
from .sources import set_source_switch
from .tlp import TlpNotPermitted, tlp_permitted, visible_levels


@dataclass(frozen=True, slots=True)
class OperatorSourceView:
    key: str
    name: str
    kind: Literal['rss', 'taxii']
    url: str
    tlp: TLP
    reuse: Reuse
    enabled: bool
    revision: int
    created_at: str
    updated_at: str
    actor: str
    collection_id: str | None = None
    credential_env: str | None = None
    configured: bool = True


def _view(source: OperatorSource, enabled: bool | None) -> OperatorSourceView:
    configured = True
    if source.kind == 'taxii':
        from ..taxii_client import credentials_configured

        configured = credentials_configured(source.credential_env)
    return OperatorSourceView(
        source.key,
        source.name,
        cast("Literal['rss', 'taxii']", source.kind),
        source.url,
        cast('TLP', source.tlp),
        cast('Reuse', source.reuse),
        bool(enabled),
        source.revision,
        source.created_at,
        source.updated_at,
        source.actor,
        source.collection_id,
        source.credential_env,
        configured,
    )


def _visible_operator_keys(max_tlp: str | None) -> Select[str]:
    return select(OperatorSource.key).where(OperatorSource.tlp.in_(visible_levels(max_tlp)))


def _visible_operator_history(
    key: InstrumentedAttribute[str], created_at: InstrumentedAttribute[str], max_tlp: str | None
) -> ColumnElement[bool]:
    """Older job/run details may refer to a source before its label was lowered."""
    stmt = _visible_operator_keys(max_tlp).where(OperatorSource.key == key)
    if max_tlp is not None:
        stmt = stmt.where(
            or_(
                OperatorSource.history_visible_since.is_(None),
                created_at > OperatorSource.history_visible_since,
            )
        )
    return stmt.exists()


def _source(db: Session, key: str, max_tlp: str | None, *, lock: bool) -> tuple[OperatorSource, bool | None]:
    where = (OperatorSource.key == key, OperatorSource.tlp.in_(visible_levels(max_tlp)))
    if lock:
        # An UPDATE acquires a write lock on both SQLite and PostgreSQL. SELECT FOR UPDATE is ignored
        # on SQLite. Take the lock before reading so a sync cannot save after a concurrent edit or switch.
        db.execute(
            update(OperatorSource)
            .where(*where)
            .values(revision=OperatorSource.revision)
            .execution_options(synchronize_session=False)
        )
    row = db.execute(
        select(OperatorSource, SourceSwitch.enabled)
        .outerjoin(SourceSwitch, SourceSwitch.source_key == OperatorSource.key)
        .where(*where)
        .execution_options(populate_existing=True)
    ).one_or_none()
    if row is None:
        raise LookupError('Source not found.')
    source, enabled = row
    return source, enabled


def get_operator_source(
    db: Session, key: str, *, max_tlp: str | None = None, lock: bool = False
) -> OperatorSourceView:
    """Return a snapshot. Writers lock and recheck its revision in the transaction that saves their work."""
    return _view(*_source(db, key, max_tlp, lock=lock))


def list_operator_sources(db: Session, *, max_tlp: str | None = None) -> list[OperatorSourceView]:
    rows = db.execute(
        select(OperatorSource, SourceSwitch.enabled)
        .outerjoin(SourceSwitch, SourceSwitch.source_key == OperatorSource.key)
        .where(OperatorSource.tlp.in_(visible_levels(max_tlp)))
        .order_by(OperatorSource.name, OperatorSource.key)
    )
    return [_view(source, enabled) for source, enabled in rows]


def _check_label(label: str, limit: str | None) -> None:
    if limit is not None and not tlp_permitted(label, limit):
        raise TlpNotPermitted('The source label exceeds the permitted TLP limit.')


def _changed(db: Session, source: OperatorSource) -> None:
    source.revision += 1
    source.updated_at = now()
    source.actor = str(db.info.get('actor', DEFAULT_ACTOR))


def _mark_reuse_change(db: Session, key: str, stamp: str) -> None:
    db.execute(
        update(Document)
        .where(Document.source_key == key, Document.operator_publisher_metadata_only.is_(False))
        .values(reuse_changed_at=stamp)
    )


def _stop_jobs(db: Session, key: str) -> None:
    scope = (Job.kind == SOURCE_SYNC, Job.key == key)
    db.execute(delete(Job).where(*scope, Job.status == 'queued'))
    # The worker can still finish this row; neither its retry path nor recovery after a restart should
    # enqueue a request which the operator approved for the previous endpoint.
    db.execute(
        update(Job)
        .where(*scope, Job.status == 'running')
        .values(
            status='failed',
            max_attempts=Job.attempts,
            finished_at=now(),
            message='Source changed or switched off.',
        )
    )


def create_operator_source(
    db: Session, payload: OperatorSourceInput, *, max_tlp: str | None = None
) -> OperatorSourceView:
    _check_label(payload.tlp, max_tlp)
    stamp = now()
    actor = str(db.info.get('actor', DEFAULT_ACTOR))
    source = OperatorSource(
        key=OPERATOR_PREFIX + uuid4().hex,
        name=payload.name,
        kind=payload.kind,
        collection_id=payload.collection_id,
        credential_env=payload.credential_env,
        url=payload.url,
        tlp=payload.tlp,
        reuse=payload.reuse,
        revision=1,
        created_at=stamp,
        updated_at=stamp,
        actor=actor,
    )
    db.add(source)
    db.add(SourceSwitch(source_key=source.key, enabled=False, actor=actor, updated_at=stamp))
    audit(db, 'source.create', source.key)
    db.flush()
    return _view(source, False)


def update_operator_source(
    db: Session, key: str, payload: OperatorSourceInput, *, max_tlp: str | None = None
) -> OperatorSourceView:
    source, enabled = _source(db, key, max_tlp, lock=True)
    _check_label(payload.tlp, max_tlp)
    endpoint = (source.kind, source.url, source.collection_id, source.credential_env)
    new_endpoint = (payload.kind, payload.url, payload.collection_id, payload.credential_env)
    if endpoint == new_endpoint and (source.name, source.tlp, source.reuse) == (
        payload.name,
        payload.tlp,
        payload.reuse,
    ):
        return _view(source, enabled)
    _changed(db, source)
    if not tlp_permitted(source.tlp, payload.tlp):
        source.history_visible_since = source.updated_at
    if endpoint != new_endpoint:
        if enabled:
            set_source_switch(db, key, False, at=datetime.now(UTC))
        enabled = False
        _stop_jobs(db, key)
        db.execute(delete(Schedule).where(Schedule.source_key == key))
    if source.reuse != payload.reuse:
        _mark_reuse_change(db, key, source.updated_at)
    source.name = payload.name
    source.kind, source.url, source.collection_id, source.credential_env = new_endpoint
    source.tlp, source.reuse = payload.tlp, payload.reuse
    db.execute(delete(FetchState).where(FetchState.url == key))
    audit(db, 'source.update', key)
    return _view(source, enabled)


def set_operator_source_enabled(
    db: Session, key: str, enabled: bool, *, max_tlp: str | None = None
) -> OperatorSourceView:
    source, previous = _source(db, key, max_tlp, lock=True)
    if bool(previous) != enabled:
        _changed(db, source)
        set_source_switch(db, key, enabled, at=datetime.now(UTC))
        if not enabled:
            _stop_jobs(db, key)
    return _view(source, enabled)


def delete_operator_source(db: Session, key: str, *, max_tlp: str | None = None) -> None:
    source, _ = _source(db, key, max_tlp, lock=True)
    if source.reuse == 'public':
        _mark_reuse_change(db, key, now())
    _stop_jobs(db, key)
    db.execute(delete(FetchState).where(FetchState.url == key))
    db.execute(delete(Schedule).where(Schedule.source_key == key))
    db.execute(delete(SourceSwitch).where(SourceSwitch.source_key == key))
    db.delete(source)
    audit(db, 'source.delete', key)
