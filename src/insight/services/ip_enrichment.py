"""The local disclosure policy and cache for GreyNoise Community IPv4 lookups."""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .. import egress
from ..models import Document, Enrichment, Entity, Observation, now
from .audit import audit


def _public_ipv4(value: str) -> bool:
    try:
        return egress.is_public(ipaddress.IPv4Address(value))
    except ValueError:
        return False


def eligible_greynoise_ip(db: Session, value: str) -> str | None:
    """Only an analyst-accepted observation in a current CLEAR report may justify this disclosure."""
    if not _public_ipv4(value):
        return None
    return db.scalar(
        select(Entity.id)
        .join(Observation, Observation.entity_id == Entity.id)
        .join(Document, Document.id == Observation.document_id)
        .where(
            Entity.kind == 'ip',
            Entity.value == value,
            Observation.review_status == 'accepted',
            Document.is_current.is_(True),
            Document.tlp == 'CLEAR',
        )
        .limit(1)
    )


def _cached_row(db: Session, entity_id: str) -> Enrichment | None:
    return db.scalar(
        select(Enrichment).where(Enrichment.provider == 'greynoise', Enrichment.subject == entity_id)
    )


def _view(record: Enrichment, value: str) -> dict[str, Any]:
    return {
        'provider': 'greynoise',
        'ip': value,
        'fetched_at': record.fetched_at,
        **json.loads(record.payload),
    }


def cached_greynoise_context(db: Session, value: str) -> dict[str, Any] | None:
    """Check eligibility even on a cache hit and after a report revision or review decision changes."""
    entity_id = eligible_greynoise_ip(db, value)
    if entity_id is None:
        raise LookupError('No eligible reviewed public IPv4 in a current TLP:CLEAR report')
    record = _cached_row(db, entity_id)
    return _view(record, value) if record else None


def store_greynoise_context(db: Session, value: str, payload: dict[str, Any]) -> dict[str, Any]:
    # The cache has no entity FK. Acquire the entity's write lock on SQLite and PostgreSQL before
    # rechecking eligibility or writing. Retention removes its cache after deleting the locked entity.
    db.execute(
        update(Entity)
        .where(Entity.kind == 'ip', Entity.value == value)
        .values(value=Entity.value)
        .execution_options(synchronize_session=False)
    )
    entity_id = eligible_greynoise_ip(db, value)
    if not entity_id:
        raise LookupError('No eligible reviewed public IPv4 in a current TLP:CLEAR report')
    record = _cached_row(db, entity_id) or Enrichment(subject=entity_id, provider='greynoise')
    record.payload, record.fetched_at = json.dumps(payload), now()
    db.add(record)
    audit(db, 'ip.lookup', entity_id, 'GreyNoise Community')
    return _view(record, value)
