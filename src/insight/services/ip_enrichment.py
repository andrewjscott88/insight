"""The local disclosure policy and cache for manual IPv4 lookups: GreyNoise Community and Shodan (TIP 3.7)."""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Final

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


#: Manual IP lookup providers and the name the audit log records.
IP_PROVIDERS: Final = {'greynoise': 'GreyNoise Community', 'shodan': 'Shodan'}


def _cached_row(db: Session, entity_id: str, provider: str = 'greynoise') -> Enrichment | None:
    return db.scalar(
        select(Enrichment).where(Enrichment.provider == provider, Enrichment.subject == entity_id)
    )


def _view(record: Enrichment, value: str, provider: str = 'greynoise') -> dict[str, Any]:
    return {
        'provider': provider,
        'ip': value,
        'fetched_at': record.fetched_at,
        **json.loads(record.payload),
    }


def cached_ip_context(db: Session, provider: str, value: str) -> dict[str, Any] | None:
    """Check eligibility even on a cache hit and after a report revision or review decision changes."""
    entity_id = eligible_greynoise_ip(db, value)
    if entity_id is None:
        raise LookupError('No eligible reviewed public IPv4 in a current TLP:CLEAR report')
    record = _cached_row(db, entity_id, provider)
    return _view(record, value, provider) if record else None


def cached_greynoise_context(db: Session, value: str) -> dict[str, Any] | None:
    return cached_ip_context(db, 'greynoise', value)


def store_greynoise_context(db: Session, value: str, payload: dict[str, Any]) -> dict[str, Any]:
    return store_ip_context(db, 'greynoise', value, payload)


def store_ip_context(db: Session, provider: str, value: str, payload: dict[str, Any]) -> dict[str, Any]:
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
    record = _cached_row(db, entity_id, provider) or Enrichment(subject=entity_id, provider=provider)
    record.payload, record.fetched_at = json.dumps(payload), now()
    db.add(record)
    audit(db, 'ip.lookup', entity_id, IP_PROVIDERS[provider])
    return _view(record, value, provider)
