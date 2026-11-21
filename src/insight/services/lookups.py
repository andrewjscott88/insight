"""CVE lookups at NIST NVD and FIRST EPSS: switches, which CVEs are due, and the cached scores (ADR 0023).

Automatic lookups are off until the operator switches a provider on. Then each job-runner tick queues a
lookup job when a CVE is due: one that a current report labelled **TLP:CLEAR or GREEN** mentions (an
indicator the analyst has not rejected), with no answer cached from that provider, or an old one (EPSS after
7 days, NVD after 30). Newest reporting first. CVEs seen only in AMBER or RED reports are never looked up by
themselves: a lookup tells the provider that someone is interested in the CVE. Only the CVE number is sent.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..cve_scores import CveScores, scores
from ..models import Document, Enrichment, Entity, Job, LookupFailure, Observation, SourceSwitch
from .audit import DEFAULT_ACTOR, audit
from .common import stamp
from .jobs import enqueue_job
from .tlp import _visible

#: The job kind that looks CVEs up; its key is the provider.
CVE_LOOKUP: Final = 'lookup'
LOOKUP_PROVIDERS: Final = ('epss', 'nvd')
#: Labels whose reports may cause an automatic lookup.
PUBLIC_TLPS: Final = ('CLEAR', 'GREEN')
#: An answer older than this is looked up again.
STALE_AFTER: Final[dict[str, timedelta]] = {'epss': timedelta(days=7), 'nvd': timedelta(days=30)}
#: After a lookup job fails for good, wait this long before queueing that provider again.
PAUSE_AFTER_FAILURE: Final = timedelta(hours=1)
#: A CVE the provider could not answer for waits this long, doubling after each failure up to
#: :data:`MAX_CVE_BACKOFF`, so one bad CVE never holds up the others (review M2).
CVE_BACKOFF: Final = timedelta(hours=1)
MAX_CVE_BACKOFF: Final = timedelta(days=7)
_SWITCH: Final = 'lookup:{}'
_CHUNK: Final = 500


def lookup_switches(db: Session) -> dict[str, bool]:
    """Whether each provider looks CVEs up by itself (off unless switched on)."""
    rows = {s.source_key: s.enabled for s in db.scalars(select(SourceSwitch))}
    return {p: rows.get(_SWITCH.format(p), False) for p in LOOKUP_PROVIDERS}


def set_lookup_switch(db: Session, provider: str, enabled: bool, *, at: datetime) -> None:
    """Turn automatic lookups at ``provider`` on or off. Raises ``ValueError``. Audited."""
    if provider not in LOOKUP_PROVIDERS:
        raise ValueError('Unknown provider')
    key = _SWITCH.format(provider)
    switch = db.get(SourceSwitch, key) or SourceSwitch(source_key=key)
    switch.enabled, switch.updated_at = enabled, stamp(at)
    switch.actor = str(db.info.get('actor', DEFAULT_ACTOR))
    db.add(switch)
    audit(db, 'lookup.on' if enabled else 'lookup.off', provider, '')


def cves_to_look_up(db: Session, provider: str, *, at: datetime, limit: int) -> list[str]:
    """CVEs due for an automatic lookup at ``provider``, newest reporting first."""
    last_seen = func.max(Document.created_at)
    rows = db.execute(
        select(Entity.value, last_seen)
        .join(Observation, Observation.entity_id == Entity.id)
        .join(Document, Observation.document_id == Document.id)
        .where(
            Entity.kind == 'cve',
            Document.is_current.is_(True),
            Document.tlp.in_(PUBLIC_TLPS),
            Observation.review_status != 'rejected',
        )
        .group_by(Entity.value)
        .order_by(last_seen.desc(), Entity.value)
    ).all()
    fresh = set(
        db.scalars(
            select(Enrichment.cve).where(
                Enrichment.provider == provider, Enrichment.fetched_at >= stamp(at - STALE_AFTER[provider])
            )
        )
    )
    waiting = set(
        db.scalars(
            select(LookupFailure.cve).where(
                LookupFailure.provider == provider, LookupFailure.retry_at > stamp(at)
            )
        )
    )
    return [cve for cve, _ in rows if cve not in fresh and cve not in waiting][:limit]


def record_lookup_failure(db: Session, provider: str, cve: str, message: str, *, at: datetime) -> datetime:
    """Note that ``provider`` could not answer for ``cve``; returns when it is tried again (review M2)."""
    failure = db.get(LookupFailure, (provider, cve))
    if failure is None:
        failure = LookupFailure(provider=provider, cve=cve, failures=0)
        db.add(failure)
    failure.failures += 1
    wait = min(CVE_BACKOFF * (1 << min(failure.failures - 1, 16)), MAX_CVE_BACKOFF)
    failure.message, failure.failed_at, failure.retry_at = message[:200], stamp(at), stamp(at + wait)
    return at + wait


def clear_lookup_failure(db: Session, provider: str, cve: str) -> None:
    """Forget earlier failures once ``provider`` has answered for ``cve``."""
    if (failure := db.get(LookupFailure, (provider, cve))) is not None:
        db.delete(failure)


def lookup_failures(db: Session, *, at: datetime) -> dict[str, int]:
    """How many CVEs each provider is waiting to try again (for the Sources tab)."""
    rows = db.execute(
        select(LookupFailure.provider, func.count())
        .where(LookupFailure.retry_at > stamp(at))
        .group_by(LookupFailure.provider)
    ).all()
    found = {provider: int(count) for provider, count in rows}
    return {p: found.get(p, 0) for p in LOOKUP_PROVIDERS}


def _paused(db: Session, provider: str, at: datetime) -> bool:
    failed = db.scalar(
        select(func.max(Job.finished_at)).where(
            Job.kind == CVE_LOOKUP, Job.key == provider, Job.status == 'failed'
        )
    )
    return failed is not None and failed >= stamp(at - PAUSE_AFTER_FAILURE)


def enqueue_due_lookups(db: Session, *, at: datetime) -> list[str]:
    """Queue a lookup job for each switched-on provider with CVEs due (each tick); returns the providers."""
    queued = []
    for provider, on in lookup_switches(db).items():
        if on and not _paused(db, provider, at) and cves_to_look_up(db, provider, at=at, limit=1):
            enqueue_job(db, CVE_LOOKUP, provider, at=at, actor='lookup')
            queued.append(provider)
    return queued


def lookup_backlog(db: Session, *, at: datetime) -> dict[str, int]:
    """How many CVEs each provider would look up now (for the Sources tab)."""
    return {p: len(cves_to_look_up(db, p, at=at, limit=100_000)) for p in LOOKUP_PROVIDERS}


def cve_scores(db: Session, cves: Iterable[str]) -> dict[str, CveScores]:
    """The cached scores of each CVE in ``cves`` that has any (callers decide who may see them)."""
    wanted = sorted(set(cves))
    if not wanted:
        return {}
    cached: dict[str, list[tuple[str, str, str]]] = {}
    for start in range(0, len(wanted), _CHUNK):  # Stay well under database parameter limits.
        chunk = wanted[start : start + _CHUNK]
        for row in db.scalars(select(Enrichment).where(Enrichment.cve.in_(chunk))):
            cached.setdefault(row.cve, []).append((row.provider, row.payload, row.fetched_at))
    return {cve: scores(cve, rows) for cve, rows in cached.items()}


def cve_score_view(db: Session, cve: str, *, max_tlp: str | None = None) -> CveScores:
    """The cached scores of ``cve``, if a current report the reader may see mentions it.

    Raises ``LookupError`` otherwise, so a TLP-limited key cannot learn which CVEs were looked up for reports
    above its limit.
    """
    seen = db.scalar(
        select(Entity.id)
        .join(Observation, Observation.entity_id == Entity.id)
        .join(Document, Observation.document_id == Document.id)
        .where(Entity.kind == 'cve', Entity.value == cve, Document.is_current.is_(True), *_visible(max_tlp))
        .limit(1)
    )
    if seen is None:
        raise LookupError(cve)
    return cve_scores(db, [cve]).get(cve) or CveScores(cve)
