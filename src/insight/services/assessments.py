"""Verdicts on indicators and the blocklist built from them (review Design 1).

Review says a mention was copied correctly; a verdict says what the indicator means. Only a ``malicious``
verdict that has not expired, on an indicator with an accepted mention and no warning flag, reaches the
blocklist, and only for readers allowed to see both the verdict and a report mentioning the indicator.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..flags import flags
from ..models import Document, Entity, EntityAssessment, Observation, now
from ..schemas import AssessmentInput
from .audit import DEFAULT_ACTOR, audit
from .entities import count_entity_documents
from .tlp import TlpNotPermitted, _visible, tlp_permitted, visible_levels

#: Kinds a blocklist can hold. CVE identifiers name weaknesses, not things to block.
BLOCKLIST_KINDS: Final = ('ip', 'domain', 'url', 'md5', 'sha1', 'sha256', 'sha512')
#: How long a ``malicious`` verdict without its own expiry stays on the blocklist (review finding J2):
#: addresses and domains are reassigned, a file hash names the same file forever. Change to suit your feeds.
DEFAULT_LIFETIME: Final[dict[str, timedelta | None]] = {
    'ip': timedelta(days=30),
    'domain': timedelta(days=90),
    'url': timedelta(days=90),
    'md5': None,
    'sha1': None,
    'sha256': None,
    'sha512': None,
}


@dataclass(frozen=True)
class BlocklistEntry:
    value: str
    kind: str
    decided_at: str
    expires_at: str | None  # the verdict's own expiry, or the default lifetime's end; None: never
    tlp: str


def _readable(assessment: EntityAssessment | None, max_tlp: str | None) -> EntityAssessment | None:
    if assessment is None or max_tlp is None or tlp_permitted(assessment.tlp, max_tlp):
        return assessment
    return None


def entity_assessment(db: Session, entity_id: str, *, max_tlp: str | None = None) -> EntityAssessment | None:
    """The verdict on one entity, or None when there is none or the reader may not see its label."""
    return _readable(db.get(EntityAssessment, entity_id), max_tlp)


def visible_assessments(
    db: Session, entity_ids: Iterable[str], *, max_tlp: str | None = None
) -> dict[str, EntityAssessment]:
    """Verdicts on these entities that a reader limited to ``max_tlp`` may see, by entity ID."""
    ids = sorted(set(entity_ids))
    found: dict[str, EntityAssessment] = {}
    for start in range(0, len(ids), 500):  # stay under SQL parameter limits for large exports
        stmt = select(EntityAssessment).where(EntityAssessment.entity_id.in_(ids[start : start + 500]))
        if max_tlp is not None:
            stmt = stmt.where(EntityAssessment.tlp.in_(visible_levels(max_tlp)))
        found.update((row.entity_id, row) for row in db.scalars(stmt))
    return found


def assess_entity(
    db: Session, entity_id: str, payload: AssessmentInput, *, max_tlp: str | None = None
) -> EntityAssessment | None:
    """Record (or, for ``unknown``, clear) the verdict on an entity. Audited as ``entity.assess``.

    Raises ``LookupError`` if the reader cannot see the entity; ``TlpNotPermitted`` if the verdict's label,
    or a verdict already recorded, is above the reader's limit: a limited key never overwrites what it cannot
    read.
    """
    if db.get(Entity, entity_id) is None or count_entity_documents(db, entity_id, max_tlp=max_tlp) == 0:
        raise LookupError('Entity not found')
    existing = db.get(EntityAssessment, entity_id)
    for label in (payload.tlp, existing.tlp if existing else None):
        if label is not None and max_tlp is not None and not tlp_permitted(label, max_tlp):
            raise TlpNotPermitted(
                f'This API key is limited to TLP:{max_tlp}; it cannot set or replace this verdict.'
            )
    if payload.verdict == 'unknown':
        if existing is not None:
            db.delete(existing)
        audit(db, 'entity.assess', entity_id, 'unknown')
        return None
    actor = str(db.info.get('actor', DEFAULT_ACTOR))
    assessment = existing or EntityAssessment(entity_id=entity_id, actor=actor, verdict=payload.verdict)
    assessment.verdict = payload.verdict
    assessment.reason = payload.reason.strip()
    assessment.tlp = payload.tlp
    assessment.valid_until = payload.valid_until_timestamp()
    assessment.decided_at = now()
    assessment.actor = actor
    db.add(assessment)
    expiry = f', until {payload.valid_until}' if payload.valid_until else ''
    audit(db, 'entity.assess', entity_id, f'{payload.verdict} (TLP:{payload.tlp}{expiry})')
    db.flush()
    return assessment


def entity_seen(db: Session, entity_id: str, *, max_tlp: str | None = None) -> tuple[str | None, str | None]:
    """When the oldest and newest report the reader may see that mentions the entity was added.

    Computed on read from visible reports: a stored "last seen" would tell a TLP-limited reader that a
    report above its limit mentioned the indicator recently.
    """
    row = db.execute(
        select(func.min(Document.created_at), func.max(Document.created_at))
        .join(Observation, Observation.document_id == Document.id)
        .where(Observation.entity_id == entity_id, *_visible(max_tlp))
    ).one()
    return row[0], row[1]


def _expires_at(kind: str, assessment: EntityAssessment) -> str | None:
    if assessment.valid_until is not None:
        return assessment.valid_until
    lifetime = DEFAULT_LIFETIME.get(kind)
    if lifetime is None:
        return None
    return (datetime.fromisoformat(assessment.decided_at) + lifetime).isoformat()


def blocklist(
    db: Session, kind: str, *, max_tlp: str | None = None, at: datetime | None = None
) -> list[BlocklistEntry]:
    """Values of ``kind`` that are safe to block, sorted. Each one has:

    * a ``malicious`` verdict the reader may see, not past its expiry (its own, or ``DEFAULT_LIFETIME``);
    * at least one *accepted* mention in a report the reader may see;
    * no warning flag (``insight.flags``): no private, documentation or reserved values, no vendor domains.
    """
    if kind not in BLOCKLIST_KINDS:
        raise ValueError(f'kind must be one of: {", ".join(BLOCKLIST_KINDS)}')
    accepted = (
        select(Observation.entity_id)
        .join(Document, Observation.document_id == Document.id)
        .where(Observation.review_status == 'accepted', *_visible(max_tlp))
    )
    stmt = (
        select(Entity, EntityAssessment)
        .join(EntityAssessment, EntityAssessment.entity_id == Entity.id)
        .where(Entity.kind == kind, EntityAssessment.verdict == 'malicious', Entity.id.in_(accepted))
        .order_by(Entity.value)
    )
    if max_tlp is not None:
        stmt = stmt.where(EntityAssessment.tlp.in_(visible_levels(max_tlp)))
    moment = (at or datetime.now(UTC)).isoformat()
    entries = []
    for entity, assessment in db.execute(stmt):
        expires = _expires_at(kind, assessment)
        if (expires is not None and expires <= moment) or flags(entity.kind, entity.value):
            continue
        entries.append(
            BlocklistEntry(entity.value, entity.kind, assessment.decided_at, expires, assessment.tlp)
        )
    return entries
