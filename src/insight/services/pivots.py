"""Manual pivot switches, disclosure eligibility and metadata cache (ADR 0037)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .. import pivot_data
from ..models import Document, Enrichment, Entity, Observation, SourceSwitch, now
from .audit import DEFAULT_ACTOR, audit
from .tlp import visible_levels


def pivot_switches(db: Session) -> dict[str, bool]:
    rows = {row.source_key: row.enabled for row in db.scalars(select(SourceSwitch))}
    return {key: rows.get('pivot:' + key, False) for key in pivot_data.PROVIDERS}


def set_pivot_switch(db: Session, provider: str, enabled: bool) -> None:
    if provider not in pivot_data.PROVIDERS:
        raise ValueError('Unknown pivot provider')
    key = 'pivot:' + provider
    row = db.get(SourceSwitch, key) or SourceSwitch(source_key=key)
    row.enabled, row.updated_at = enabled, now()
    row.actor = str(db.info.get('actor', DEFAULT_ACTOR))
    db.add(row)
    audit(db, 'pivot.on' if enabled else 'pivot.off', provider, '')


def eligible_pivot(db: Session, value: str, *, max_tlp: str | None = None) -> str | None:
    try:
        kind, value = pivot_data.subject(value)
    except ValueError:
        return None
    if max_tlp is not None and 'CLEAR' not in visible_levels(max_tlp):
        return None
    return db.scalar(
        select(Entity.id)
        .join(Observation, Observation.entity_id == Entity.id)
        .join(Document, Document.id == Observation.document_id)
        .where(
            Entity.kind == kind,
            Entity.value == value,
            Observation.review_status == 'accepted',
            Document.is_current.is_(True),
            Document.tlp == 'CLEAR',
        )
        .limit(1)
    )


def cached_pivots(db: Session, value: str, *, max_tlp: str | None = None) -> list[dict[str, Any]]:
    """Only fresh results whose source is still eligible. A cache never grants access by itself."""
    entity_id = eligible_pivot(db, value, max_tlp=max_tlp)
    if entity_id is None:
        raise LookupError('No eligible reviewed indicator')
    cutoff = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    rows = db.scalars(
        select(Enrichment)
        .where(
            Enrichment.subject == entity_id,
            Enrichment.provider.in_(tuple(pivot_data.PROVIDERS)),
            Enrichment.fetched_at > cutoff,
        )
        .order_by(Enrichment.provider)
    )
    return [
        dict(provider=row.provider, value=value, fetched_at=row.fetched_at, **json.loads(row.payload))
        for row in rows
    ]


def store_pivot(
    db: Session, provider: str, value: str, payload: dict[str, Any], *, max_tlp: str | None = None
) -> dict[str, Any]:
    """Synchronize with retention, then recheck disclosure policy after the network request."""
    kind, _ = pivot_data.subject(value)
    db.execute(
        update(Entity)
        .where(Entity.kind == kind, Entity.value == value)
        .values(value=Entity.value)
        .execution_options(synchronize_session=False)
    )
    entity_id = eligible_pivot(db, value, max_tlp=max_tlp)
    if entity_id is None:
        raise LookupError('No eligible reviewed indicator')
    if not pivot_switches(db).get(provider, False):
        raise ValueError('This pivot provider is off')
    row = db.scalar(
        select(Enrichment).where(
            Enrichment.subject == entity_id,
            Enrichment.provider == provider,
        )
    ) or Enrichment(subject=entity_id, provider=provider)
    row.payload, row.fetched_at = json.dumps(payload), now()
    db.add(row)
    audit(db, 'pivot.lookup', entity_id, provider)
    return dict(provider=provider, value=value, fetched_at=row.fetched_at, **payload)
