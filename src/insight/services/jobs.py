"""The job queue and schedules (ADR 0018); the runner itself lives in insight.jobs."""

from __future__ import annotations

import re
from collections.abc import Collection
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import (
    Job,
    Schedule,
)
from ..source_registry import SOURCES, is_operator_source
from .audit import DEFAULT_ACTOR, audit
from .common import stamp

#: Choices for how often a source syncs by itself, in minutes (0: never, the default).
SCHEDULE_INTERVALS: Final = (0, 60, 360, 1440)

JOB_BACKOFF: Final = timedelta(minutes=5)

JOB_ACTIVE: Final = ('queued', 'running')

SOURCE_SYNC: Final = 'source.sync'


def list_schedules(db: Session) -> dict[str, Schedule]:
    return {s.source_key: s for s in db.scalars(select(Schedule))}


def time_of_day(hhmm: str, at: datetime) -> datetime:
    """``HH:MM`` (UTC) on the day of ``at``; raises ``ValueError`` for anything else."""
    if not re.fullmatch(r'([01]\d|2[0-3]):[0-5]\d', hhmm):
        raise ValueError('Start time must be HH:MM in UTC, from 00:00 to 23:59')
    hours, minutes = map(int, hhmm.split(':'))
    return at.astimezone(UTC).replace(hour=hours, minute=minutes, second=0, microsecond=0)


def _next_slot(start: datetime, interval: timedelta, at: datetime) -> datetime:
    """The first moment ``start + n * interval`` (n >= 0) that is not before ``at``."""
    if start >= at:
        return start
    return start + interval * -((start - at) // interval)


def set_schedule(
    db: Session,
    source_key: str,
    interval_minutes: int,
    *,
    at: datetime,
    starts_at: datetime | None = None,
    max_tlp: str | None = None,
) -> Schedule:
    """Turn a source's schedule on (``interval_minutes`` from :data:`SCHEDULE_INTERVALS`) or off (``0``).

    A schedule that is turned on runs at the next tick, or at ``starts_at`` (rolled forward by whole intervals
    if it has passed), then every interval from there: a daily sync at 00:00 stays at 00:00. Callers check
    that the source exists. Audited as ``schedule.update``.
    """
    if interval_minutes not in SCHEDULE_INTERVALS:
        raise ValueError(f'Interval must be one of {", ".join(map(str, SCHEDULE_INTERVALS))} minutes')
    if is_operator_source(source_key):
        from ..taxii_client import TaxiiNotConfigured
        from .operator_sources import get_operator_source

        source = get_operator_source(db, source_key, lock=True, max_tlp=max_tlp)
        if interval_minutes and not source.configured:
            raise TaxiiNotConfigured('Source credentials are not configured.')
        if interval_minutes and not source.enabled:
            raise ValueError('Source is switched off.')
    schedule = db.get(Schedule, source_key) or Schedule(source_key=source_key)
    was = schedule.interval_minutes if schedule.enabled else 0
    schedule.interval_minutes = interval_minutes
    schedule.enabled = interval_minutes > 0
    if not schedule.enabled:
        schedule.next_run_at = None
    elif starts_at is not None:
        schedule.next_run_at = stamp(_next_slot(starts_at, timedelta(minutes=interval_minutes), at))
    elif interval_minutes != was:  # Choosing the same interval again does not postpone the next run.
        schedule.next_run_at = stamp(at)
    schedule.updated_at = stamp(at)
    schedule.actor = str(db.info.get('actor', DEFAULT_ACTOR))
    db.add(schedule)
    audit(
        db, 'schedule.update', source_key, f'every {interval_minutes} minutes' if interval_minutes else 'off'
    )
    return schedule


def enqueue_job(db: Session, kind: str, key: str, *, at: datetime, actor: str = '') -> Job:
    """Queue ``kind`` for ``key`` to run now, or return the job already queued or running for it."""
    if (active := _active_job(db, kind, key)) is not None:
        return active
    job = Job(kind=kind, key=key, status='queued', run_after=stamp(at), actor=actor)
    try:
        with db.begin_nested():
            db.add(job)
    except IntegrityError:  # Another process queued it between the check and the insert.
        if (active := _active_job(db, kind, key)) is None:
            raise
        return active
    return job


def _active_job(db: Session, kind: str, key: str) -> Job | None:
    return db.scalar(select(Job).where(Job.kind == kind, Job.key == key, Job.status.in_(JOB_ACTIVE)))


def enqueue_due_schedules(db: Session, *, at: datetime) -> list[Job]:
    """Queue a sync for every enabled schedule that is due, and move each one's next run on by its interval.

    The next run keeps the schedule's slot (a daily 00:00 sync stays at 00:00) and is the first slot after
    ``at``, so a server that was off for days runs each schedule once, not once for every missed slot.
    """
    due = db.scalars(
        select(Schedule)
        .where(Schedule.enabled.is_(True), Schedule.next_run_at <= stamp(at))
        .order_by(Schedule.source_key)
    ).all()
    jobs = []
    for schedule in due:
        if is_operator_source(schedule.source_key):
            from .operator_sources import get_operator_source

            try:
                # Check availability here. The sync itself enforces the running instance's ceiling.
                source = get_operator_source(db, schedule.source_key, max_tlp=None, lock=True)
            except LookupError:
                continue
            if not source.enabled or not source.configured:
                # Keep the due slot during an outage. The next tick after recovery can use it.
                continue
            # A schedule edit or endpoint change can finish between the due scan and the source lock.
            fresh = db.get(Schedule, schedule.source_key, populate_existing=True)
            if fresh is None or not fresh.enabled or not fresh.next_run_at or fresh.next_run_at > stamp(at):
                continue
            schedule = fresh
        jobs.append(enqueue_job(db, SOURCE_SYNC, schedule.source_key, at=at, actor='schedule'))
        interval = timedelta(minutes=schedule.interval_minutes)
        slot = datetime.fromisoformat(schedule.next_run_at or stamp(at))
        # The first slot strictly after `at`: due now and run, so the next one is at least one interval away.
        schedule.next_run_at = stamp(_next_slot(slot + interval, interval, at + timedelta(microseconds=1)))
    return jobs


def claim_job(
    db: Session, *, at: datetime, kinds: Collection[str] | None = None, exclude: Collection[str] = ()
) -> Job | None:
    """Mark the oldest due queued job (of ``kinds``, if given, and not of ``exclude``) as running and return
    it, or ``None``.

    The update only succeeds while the job is still queued, so of two runners that pick the same job exactly
    one gets it (the other sees no row changed). Commit straight after, before running the job.
    """
    which = [Job.kind.in_(kinds)] if kinds is not None else []
    if exclude:
        which.append(Job.kind.not_in(exclude))
    while (
        candidate := db.scalar(
            select(Job.id)
            .where(Job.status == 'queued', Job.run_after <= stamp(at), *which)
            .order_by(Job.run_after, Job.created_at, Job.id)
            .limit(1)
        )
    ) is not None:
        claimed = db.execute(
            update(Job)
            .where(Job.id == candidate, Job.status == 'queued')
            .values(status='running', started_at=stamp(at), attempts=Job.attempts + 1)
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount == 1:  # type: ignore[attr-defined]
            return db.get(Job, candidate, populate_existing=True)
    return None


def finish_job(db: Session, job_id: str, *, ok: bool, message: str, at: datetime) -> Job:
    """Record how a running job ended. A failure with attempts left is queued again after a growing wait
    (5, 10, 20 minutes ...); the last failure marks the job ``failed``."""
    job = db.get(Job, job_id, populate_existing=True)
    if job is None:
        raise ValueError('Unknown job')
    job.message = message[:2000]
    if ok or job.attempts >= job.max_attempts:
        job.status, job.finished_at = ('succeeded' if ok else 'failed'), stamp(at)
    else:
        job.status = 'queued'
        job.run_after = stamp(at + JOB_BACKOFF * 2 ** (job.attempts - 1))
    return job


def requeue_running_jobs(db: Session) -> int:
    """At start-up: jobs left ``running`` by a stopped process run again (their attempt still counts)."""
    result = db.execute(update(Job).where(Job.status == 'running').values(status='queued'))
    return int(result.rowcount)  # type: ignore[attr-defined]


def prune_jobs(db: Session, *, before: datetime) -> int:
    """Delete finished jobs that ended before ``before``; returns how many."""
    result = db.execute(
        delete(Job).where(Job.status.in_(('succeeded', 'failed')), Job.finished_at < stamp(before))
    )
    return int(result.rowcount)  # type: ignore[attr-defined]


def recent_jobs(db: Session, limit: int = 20, *, max_tlp: str | None = None) -> list[Job]:
    from .operator_sources import _visible_operator_history

    visible = (
        (Job.kind != SOURCE_SYNC)
        | Job.key.in_(tuple(SOURCES))
        | _visible_operator_history(Job.key, Job.created_at, max_tlp)
    )
    return list(db.scalars(select(Job).where(visible).order_by(Job.created_at.desc(), Job.id).limit(limit)))
