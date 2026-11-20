"""The audit trail: who did what, recorded in the same transaction as the change."""

from __future__ import annotations

from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AuditEvent,
)

#: Actor recorded when the caller did not name one (e.g. the synthetic demo loaded by a test).
DEFAULT_ACTOR: Final = 'system'


def set_actor(db: Session, actor: str) -> Session:
    """Name who acts in this session: ``operator``, ``api-key:<key id>``, ``cli``, ``connector:<source>``.

    Every audit event written through ``db`` records it, so service functions need no extra parameter.
    """
    db.info['actor'] = actor
    return db


def audit(db: Session, action: str, object_id: str, detail: str = '') -> None:
    """Record an application audit event (with the session's actor) in the current transaction."""
    actor = str(db.info.get('actor', DEFAULT_ACTOR))
    db.add(AuditEvent(action=action, object_id=object_id, detail=detail, actor=actor))


def audit_events(db: Session, limit: int = 200) -> list[AuditEvent]:
    return list(db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)))
