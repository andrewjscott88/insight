"""Eligible public IPs and private Censys metadata; never included in intelligence exports."""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .. import egress
from ..models import Document, Enrichment, Entity, Observation, now
from .audit import audit
from .tlp import visible_levels


def eligible_censys_ip(db: Session, value: str, *, max_tlp: str | None = None) -> str | None:
    """A separately accepted observation in a current CLEAR report authorizes disclosure of an IP."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not egress.is_public(address) or 'CLEAR' not in visible_levels(max_tlp):
        return None
    return db.scalar(
        select(Entity.id)
        .join(Observation, Observation.entity_id == Entity.id)
        .join(Document, Document.id == Observation.document_id)
        .where(
            Entity.kind == 'ip',
            Entity.value == str(address),
            Observation.review_status == 'accepted',
            Document.is_current.is_(True),
            Document.tlp == 'CLEAR',
        )
        .limit(1)
    )


def cached_censys_context(db: Session, value: str, *, max_tlp: str | None = None) -> dict[str, Any] | None:
    """A cache row does not grant access after the supporting report or review decision changes."""
    entity_id = eligible_censys_ip(db, value, max_tlp=max_tlp)
    if entity_id is None:
        raise LookupError('No eligible reviewed public IP in a current TLP:CLEAR report')
    row = db.scalar(
        select(Enrichment).where(Enrichment.subject == entity_id, Enrichment.provider == 'censys')
    )
    if row is None:
        return None
    return {
        'provider': 'censys',
        'ip': str(ipaddress.ip_address(value)),
        'fetched_at': row.fetched_at,
        **json.loads(row.payload),
    }


def store_censys_context(
    db: Session,
    value: str,
    payload: dict[str, Any],
    *,
    max_tlp: str | None = None,
) -> dict[str, Any]:
    """Lock the subject before eligibility recheck so retention cannot leave an orphaned cache row."""
    canonical = str(ipaddress.ip_address(value))
    db.execute(
        update(Entity)
        .where(Entity.kind == 'ip', Entity.value == canonical)
        .values(value=Entity.value)
        .execution_options(synchronize_session=False)
    )
    entity_id = eligible_censys_ip(db, canonical, max_tlp=max_tlp)
    if entity_id is None:
        raise LookupError('No eligible reviewed public IP in a current TLP:CLEAR report')
    row = db.scalar(
        select(Enrichment).where(Enrichment.subject == entity_id, Enrichment.provider == 'censys')
    )
    row = row or Enrichment(subject=entity_id, provider='censys')
    row.payload, row.fetched_at = json.dumps(payload), now()
    db.add(row)
    audit(db, 'ip.lookup', entity_id, 'Censys Platform')
    return {'provider': 'censys', 'ip': canonical, 'fetched_at': row.fetched_at, **payload}
