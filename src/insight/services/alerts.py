"""Alerts: where they go, when they fire, and the queue the job runner sends from (ADR 0022).

An alert fires when a **new** current report mentions a watch term (the same literal, case- and
accent-insensitive match as the workspace's highlights, on the title and text), or when CISA adds an entry
to its KEV list after Insight has imported the list once. Each alert is queued per enabled target with a
``dedupe_key``, so a new revision of the same item, or the same entry seen again, adds nothing. Nothing is
sent here: ``insight.alerts`` sends what :func:`due_alerts` returns, from the job runner, never on a
request.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final
from urllib.parse import urlsplit

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import Alert, AlertTarget, Document, KEVRecord, WatchTerm
from ..schemas import TLP_LEVELS
from .audit import DEFAULT_ACTOR, audit
from .common import fold, stamp
from .jobs import enqueue_job

#: The job kind that sends due alerts.
ALERT_DELIVERY: Final = 'alerts'
#: Target styles and the kind of address each takes.
STYLES: Final[dict[str, str]] = {'json': 'webhook', 'chat': 'webhook', 'email': 'email'}
#: Labels a target may receive titles up to. RED is never sent anywhere.
TARGET_TLPS: Final = tuple(level for level in TLP_LEVELS if level != 'RED')
MAX_ATTEMPTS: Final = 3
RETRY_AFTER: Final = timedelta(minutes=5)
#: More new KEV entries than this in one import become one alert listing them.
MAX_KEV_ALERTS: Final = 10
#: Set ``db.info[QUIET] = True`` to store reports without alerts (the synthetic demo).
QUIET: Final = 'quiet_alerts'
_EMAIL: Final = re.compile(r'[^@\s<>,;"]+@[^@\s<>,;"]+\.[^@\s<>,;"]+')


@dataclass(frozen=True, slots=True)
class AlertReport:
    """What a sent alert may say about its report (``insight.alerts`` decides how much of it, by TLP)."""

    id: str
    title: str
    tlp: str
    source_name: str
    created_at: str


@dataclass(frozen=True, slots=True)
class DueAlert:
    id: str
    trigger: str
    subject: str
    created_at: str
    attempts: int
    target: AlertTarget
    report: AlertReport | None


# --------------------------------------------------------------------------- targets


def list_targets(db: Session) -> list[AlertTarget]:
    return list(db.scalars(select(AlertTarget).order_by(AlertTarget.created_at, AlertTarget.id)))


def validate_address(style: str, address: str) -> str:
    """The cleaned address for ``style``; raises ``ValueError`` with a plain reason."""
    address = address.strip()
    if style not in STYLES:
        raise ValueError('Choose a webhook or an e-mail address.')
    if STYLES[style] == 'email':
        if len(address) > 254 or not _EMAIL.fullmatch(address):
            raise ValueError('Enter one e-mail address, such as soc@example.org.')
        return address
    parts = urlsplit(address)
    if len(address) > 2048 or parts.scheme != 'https' or not parts.hostname:
        raise ValueError('Enter a webhook address that starts with https://.')
    if parts.username or parts.password:
        raise ValueError('Put no user name or password in the webhook address.')
    return address


def add_target(db: Session, *, name: str, style: str, address: str, max_tlp: str = 'AMBER') -> AlertTarget:
    """Add an enabled target. Raises ``ValueError``. Audited (``alert.target.add``) without the address,
    which can itself be a credential (chat webhooks)."""
    name = ' '.join(name.split())
    if not 1 <= len(name) <= 80:
        raise ValueError('Give the destination a name of up to 80 characters.')
    if max_tlp not in TARGET_TLPS:
        raise ValueError('Choose a TLP label up to TLP:AMBER+STRICT.')
    target = AlertTarget(
        name=name,
        kind=STYLES.get(style, ''),
        style=style,
        address=validate_address(style, address),
        secret=secrets.token_hex(32) if style == 'json' else '',
        max_tlp=max_tlp,
        enabled=True,
        actor=str(db.info.get('actor', DEFAULT_ACTOR)),
    )
    db.add(target)
    db.flush()
    audit(db, 'alert.target.add', target.id, f'{style}: {name}')
    return target


def set_target_enabled(db: Session, target_id: str, enabled: bool) -> AlertTarget:
    """Raises ``LookupError``. Turning a target off leaves its queued alerts unsent until it is on again."""
    target = db.get(AlertTarget, target_id)
    if target is None:
        raise LookupError(target_id)
    target.enabled = enabled
    audit(db, 'alert.target.on' if enabled else 'alert.target.off', target.id, target.name)
    return target


def delete_target(db: Session, target_id: str) -> None:
    """Delete a target and its alerts. Raises ``LookupError``. Audited."""
    target = db.get(AlertTarget, target_id)
    if target is None:
        raise LookupError(target_id)
    db.execute(delete(Alert).where(Alert.target_id == target_id))
    db.delete(target)
    audit(db, 'alert.target.delete', target_id, target.name)


# --------------------------------------------------------------------------- firing


def _queue(
    db: Session, targets: Sequence[AlertTarget], trigger: str, key: str, subject: str, doc_id: str | None
) -> int:
    key = key[:300]
    sent_to = set(db.scalars(select(Alert.target_id).where(Alert.dedupe_key == key)))
    queued = 0
    for target in targets:
        if target.id in sent_to:
            continue
        db.add(
            Alert(
                target_id=target.id,
                trigger=trigger,
                dedupe_key=key,
                subject=subject[:200],
                document_id=doc_id,
                status='pending',
            )
        )
        queued += 1
    return queued


def _enabled_targets(db: Session) -> list[AlertTarget]:
    return list(db.scalars(select(AlertTarget).where(AlertTarget.enabled.is_(True))))


def queue_report_alerts(db: Session, doc: Document) -> int:
    """Queue an alert per enabled target for each watch term a new current report mentions; returns how many.

    The key is the term and the source item (or, for a pasted report, the report), so later revisions of an
    item add nothing for a term that already fired.
    """
    if db.info.get(QUIET) or not (targets := _enabled_targets(db)):
        return 0
    text = fold(f'{doc.title}\n{doc.body}')
    item = f'{doc.source_key}:{doc.external_id}' if doc.source_key else doc.id
    queued = 0
    for term in db.scalars(select(WatchTerm.term).order_by(WatchTerm.term)):
        if fold(term) in text:
            queued += _queue(db, targets, 'watch', f'watch:{fold(term)}:{item}', term, doc.id)
    return queued


def known_kev(db: Session) -> set[str]:
    """CVE IDs already in Insight's copy of the KEV list (before an import adds to it)."""
    return set(db.scalars(select(KEVRecord.cve)))


def queue_kev_alerts(db: Session, entries: Sequence[tuple[str, str, str]]) -> int:
    """Queue alerts for KEV entries new since the last import: ``(cve, vendor, product)`` each.

    Up to :data:`MAX_KEV_ALERTS` entries get one alert each; more become a single alert that lists them.
    """
    if not entries or db.info.get(QUIET) or not (targets := _enabled_targets(db)):
        return 0
    if len(entries) <= MAX_KEV_ALERTS:
        return sum(
            _queue(db, targets, 'kev', f'kev:{cve}', f'{cve} · {vendor} {product}', None)
            for cve, vendor, product in entries
        )
    cves = sorted(cve for cve, _, _ in entries)
    shown = ', '.join(cves[:5])
    subject = f'{len(cves)} new entries: {shown} and {len(cves) - 5} more'
    return _queue(db, targets, 'kev', f'kev-batch:{cves[0]}:{cves[-1]}:{len(cves)}', subject, None)


def queue_test_alert(db: Session, target_id: str) -> Alert:
    """Queue a test alert for one target (enabled or not). Raises ``LookupError``."""
    target = db.get(AlertTarget, target_id)
    if target is None:
        raise LookupError(target_id)
    alert = Alert(
        target_id=target.id,
        trigger='test',
        dedupe_key=f'test:{secrets.token_hex(8)}',
        subject='Test alert',
        status='pending',
    )
    db.add(alert)
    db.flush()
    audit(db, 'alert.test', target.id, target.name)
    return alert


# --------------------------------------------------------------------------- the queue


def due_alerts(db: Session, *, at: datetime, limit: int = 100, ids: Sequence[str] = ()) -> list[DueAlert]:
    """Pending alerts due by ``at`` for enabled targets (or exactly ``ids``), oldest first."""
    query = select(Alert, AlertTarget).join(AlertTarget, Alert.target_id == AlertTarget.id)
    if ids:
        query = query.where(Alert.id.in_(ids), Alert.status == 'pending')
    else:
        query = query.where(
            Alert.status == 'pending', Alert.next_attempt_at <= stamp(at), AlertTarget.enabled.is_(True)
        )
    rows = db.execute(query.order_by(Alert.created_at, Alert.id).limit(limit)).all()
    docs = {
        d.id: d
        for d in db.scalars(
            select(Document).where(Document.id.in_({a.document_id for a, _ in rows if a.document_id}))
        )
    }
    due = []
    for alert, target in rows:
        doc = docs.get(alert.document_id or '')
        report = AlertReport(doc.id, doc.title, doc.tlp, doc.source_name, doc.created_at) if doc else None
        due.append(
            DueAlert(alert.id, alert.trigger, alert.subject, alert.created_at, alert.attempts, target, report)
        )
    return due


def mark_alert(db: Session, alert_id: str, *, error: str = '', at: datetime) -> Alert:
    """Record a send: ``error`` empty for success; otherwise try again later, up to :data:`MAX_ATTEMPTS`."""
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise LookupError(alert_id)
    target = db.get(AlertTarget, alert.target_id)
    alert.attempts += 1
    if not error:
        alert.status, alert.sent_at, alert.error = 'sent', stamp(at), ''
    else:
        alert.error = error[:300]
        if alert.attempts >= MAX_ATTEMPTS or alert.trigger == 'test':
            alert.status = 'failed'
        else:
            alert.next_attempt_at = stamp(at + RETRY_AFTER * alert.attempts)
    if target is not None:
        target.last_status = 'sent' if not error else 'failed'
        target.last_sent_at = stamp(at)
        target.last_error = error[:300]
    return alert


def enqueue_due_alerts(db: Session, *, at: datetime) -> bool:
    """Queue the delivery job if an alert is due (each job-runner tick calls this); returns whether it did."""
    if not due_alerts(db, at=at, limit=1):
        return False
    enqueue_job(db, ALERT_DELIVERY, 'deliver', at=at)
    return True


def recent_alerts(db: Session, limit: int = 20) -> list[tuple[Alert, str]]:
    """The newest alerts with their target's name."""
    rows = db.execute(
        select(Alert, AlertTarget.name)
        .join(AlertTarget, Alert.target_id == AlertTarget.id)
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .limit(limit)
    ).all()
    return [(alert, name) for alert, name in rows]
