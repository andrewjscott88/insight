"""Background jobs: opt-in scheduled source syncs and alert delivery, inside the Insight process (ADR 0018).

Nothing is scheduled until someone turns a schedule on: in the Sources tab, with ``PUT /api/schedules/{key}``
from a browser session, or with ``insight schedule``. The runner wakes every :data:`TICK_SECONDS`, queues the
syncs whose schedule is due, then runs the queued jobs. A failed sync is tried again after 5, then 10 minutes,
then recorded as failed; every attempt is also a ``SourceRun`` in *Recent sync activity*.

Each tick also queues one alert-delivery job when an alert is due (ADR 0022), and a CVE lookup job for each
provider switched on with CVEs due (ADR 0023): both run here, never while someone waits for a page.

**Lanes (code review L5).** Jobs run in lanes, side by side, each lane one job at a time under its own lock:
source syncs under the same lock as *Sync now* and *Sync all sources* (so a schedule and a person never sync
at the same moment), CVE lookups, alert deliveries, and any other kind. Before, one lock covered everything,
so a 65-second NVD batch made *Sync all* answer 409 and alerts waited behind long CSAF syncs. The lanes write
different data (reports and KEV; lookup caches; alert rows), so they need no mutual exclusion. **Lock order:**
a job takes exactly one lane lock and nothing takes two, so the lanes cannot deadlock.

Run it in exactly one process (``INSIGHT_RUN_JOBS=on``, the default for ``insight serve``): at start-up it
takes back jobs that a stopped process left running. This module builds no SQL; ``services`` owns the queries.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable, Collection, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final

from . import alerts, lookups, services
from .connectors import SourceSyncError, sync_source
from .models import SessionFactory, shares_one_connection
from .source_registry import SOURCES

log = logging.getLogger('insight.jobs')
TICK_SECONDS: Final = 15.0
#: Finished jobs are kept this long as a record, then pruned.
KEEP_FINISHED: Final = timedelta(days=30)

Clock = Callable[[], datetime]
Handler = Callable[[SessionFactory, str], Awaitable[str]]


@dataclass(frozen=True, slots=True)
class JobLocks:
    """One lock per lane (review L5). ``sync`` is the app's ``sync_lock``, shared with *Sync now*."""

    sync: asyncio.Lock = field(default_factory=asyncio.Lock)
    lookup: asyncio.Lock = field(default_factory=asyncio.Lock)
    alerts: asyncio.Lock = field(default_factory=asyncio.Lock)
    other: asyncio.Lock = field(default_factory=asyncio.Lock)


def utcnow() -> datetime:
    return datetime.now(UTC)


async def _sync(sessions: SessionFactory, key: str) -> str:
    return await sync_source(sessions, key)


async def _deliver_alerts(sessions: SessionFactory, key: str) -> str:
    return await alerts.deliver_due(sessions)


async def _look_up(sessions: SessionFactory, provider: str) -> str:
    return await lookups.look_up_due(sessions, provider)


HANDLERS: Final[Mapping[str, Handler]] = {
    services.SOURCE_SYNC: _sync,
    services.ALERT_DELIVERY: _deliver_alerts,
    services.CVE_LOOKUP: _look_up,
}


def _queue_due(sessions: SessionFactory, at: datetime) -> None:
    with sessions.begin() as db:
        services.set_actor(db, 'schedule')
        services.enqueue_due_schedules(db, at=at)
        services.enqueue_due_alerts(db, at=at)
        services.enqueue_due_lookups(db, at=at)
        services.prune_jobs(db, before=at - KEEP_FINISHED)


def _claim(
    sessions: SessionFactory, at: datetime, kinds: Collection[str] | None, exclude: Collection[str]
) -> tuple[str, str, str] | None:
    with sessions.begin() as db:
        job = services.claim_job(db, at=at, kinds=kinds, exclude=exclude)
        return (job.id, job.kind, job.key) if job is not None else None


def _finish(sessions: SessionFactory, job_id: str, ok: bool, message: str, at: datetime) -> None:
    with sessions.begin() as db:
        services.finish_job(db, job_id, ok=ok, message=message, at=at)


def _lanes(locks: JobLocks) -> list[tuple[asyncio.Lock, Collection[str] | None, Collection[str]]]:
    """``(lock, kinds, excluded kinds)`` for each lane; the last takes every kind the others do not."""
    named = [  # Alerts first: when lanes take turns, the most time-sensitive work goes first.
        (locks.alerts, (services.ALERT_DELIVERY,)),
        (locks.sync, (services.SOURCE_SYNC,)),
        (locks.lookup, (services.CVE_LOOKUP,)),
    ]
    known = [kind for _, kinds in named for kind in kinds]
    return [(lock, kinds, ()) for lock, kinds in named] + [(locks.other, None, known)]


async def run_due(sessions: SessionFactory, locks: JobLocks | asyncio.Lock, *, clock: Clock = utcnow) -> int:
    """Queue the syncs whose schedule is due, then run every job that is due, the lanes side by side;
    returns how many ran. A bare lock is the sync lane's (the other lanes then get their own)."""
    if isinstance(locks, asyncio.Lock):
        locks = JobLocks(sync=locks)
    await asyncio.to_thread(_queue_due, sessions, clock())
    lanes = _lanes(locks)
    if shares_one_connection(sessions):  # In-memory SQLite: one connection, so the lanes take turns.
        return sum([await _run_lane(sessions, *lane, clock) for lane in lanes])
    results = await asyncio.gather(
        *(_run_lane(sessions, lock, kinds, exclude, clock) for lock, kinds, exclude in lanes),
        return_exceptions=True,
    )
    for result in results:
        if isinstance(result, BaseException):
            raise result
    return sum(r for r in results if isinstance(r, int))


async def _run_lane(
    sessions: SessionFactory,
    lock: asyncio.Lock,
    kinds: Collection[str] | None,
    exclude: Collection[str],
    clock: Clock,
) -> int:
    ran = 0
    while (claimed := await asyncio.to_thread(_claim, sessions, clock(), kinds, exclude)) is not None:
        job_id, kind, key = claimed
        async with lock:
            try:
                handler = HANDLERS.get(kind)
                if handler is None:
                    raise ValueError(f'No handler for job kind {kind!r}')
                ok, message = True, await handler(sessions, key)
            except SourceSyncError as exc:
                ok, message = False, str(exc)  # Already "Type: detail", and recorded as a SourceRun.
            except Exception as exc:
                ok, message = False, f'{type(exc).__name__}: {str(exc)[:350]}'
        await asyncio.to_thread(_finish, sessions, job_id, ok, message, clock())
        ran += 1
    return ran


def describe_schedules(sessions: SessionFactory) -> str:
    """One log line: which sources sync by themselves, and how often."""
    with sessions() as db:
        schedules = services.list_schedules(db)
    on = [f'{key} every {s.interval_minutes} min' for key, s in sorted(schedules.items()) if s.enabled]
    if not on:
        return 'No scheduled syncs: sources sync only when someone presses Sync now or Sync all sources.'
    unknown = sorted(set(schedules) - set(SOURCES))
    note = f' (ignoring unknown sources: {", ".join(unknown)})' if unknown else ''
    return 'Scheduled syncs: ' + ', '.join(on) + note


def _recover(sessions: SessionFactory) -> int:
    with sessions.begin() as db:
        return services.requeue_running_jobs(db)


async def run_forever(
    sessions: SessionFactory,
    lock: JobLocks | asyncio.Lock,
    stop: asyncio.Event,
    *,
    tick: float = TICK_SECONDS,
    clock: Clock = utcnow,
) -> None:
    """Recover, log what is scheduled, then call :func:`run_due` every ``tick`` until ``stop`` is set."""
    if recovered := await asyncio.to_thread(_recover, sessions):
        log.warning('Re-queued %d job(s) left running by a stopped process', recovered)
    log.info(await asyncio.to_thread(describe_schedules, sessions))
    while not stop.is_set():
        try:
            await run_due(sessions, lock, clock=clock)
        except Exception:  # A database hiccup must not stop scheduled syncs for good.
            log.exception('Background jobs failed; trying again at the next tick')
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=tick)
