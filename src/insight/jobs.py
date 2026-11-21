"""Background jobs: opt-in scheduled source syncs, run inside the Insight process (ADR 0018).

Nothing is scheduled until someone turns a schedule on: in the Sources tab, with ``PUT /api/schedules/{key}``
from a browser session, or with ``insight schedule``. The runner wakes every :data:`TICK_SECONDS`, queues the
syncs whose schedule is due, then runs queued jobs one at a time under the same lock as *Sync now* and *Sync
all sources*, so a schedule and a person never sync at the same moment. A failed sync is tried again after 5,
then 10 minutes, then recorded as failed; every attempt is also a ``SourceRun`` in *Recent sync activity*.

Run it in exactly one process (``INSIGHT_RUN_JOBS=on``, the default for ``insight serve``): at start-up it
takes back jobs that a stopped process left running. This module builds no SQL; ``services`` owns the queries.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Final

from . import services
from .connectors import SourceSyncError, sync_source
from .models import SessionFactory
from .source_registry import SOURCES

log = logging.getLogger('insight.jobs')
TICK_SECONDS: Final = 15.0
#: Finished jobs are kept this long as a record, then pruned.
KEEP_FINISHED: Final = timedelta(days=30)

Clock = Callable[[], datetime]
Handler = Callable[[SessionFactory, str], Awaitable[str]]


def utcnow() -> datetime:
    return datetime.now(UTC)


async def _sync(sessions: SessionFactory, key: str) -> str:
    return await sync_source(sessions, key)


HANDLERS: Final[Mapping[str, Handler]] = {services.SOURCE_SYNC: _sync}


def _queue_due(sessions: SessionFactory, at: datetime) -> None:
    with sessions.begin() as db:
        services.set_actor(db, 'schedule')
        services.enqueue_due_schedules(db, at=at)
        services.prune_jobs(db, before=at - KEEP_FINISHED)


def _claim(sessions: SessionFactory, at: datetime) -> tuple[str, str, str] | None:
    with sessions.begin() as db:
        job = services.claim_job(db, at=at)
        return (job.id, job.kind, job.key) if job is not None else None


def _finish(sessions: SessionFactory, job_id: str, ok: bool, message: str, at: datetime) -> None:
    with sessions.begin() as db:
        services.finish_job(db, job_id, ok=ok, message=message, at=at)


async def run_due(sessions: SessionFactory, lock: asyncio.Lock, *, clock: Clock = utcnow) -> int:
    """Queue the syncs whose schedule is due, then run every job that is due; returns how many ran."""
    await asyncio.to_thread(_queue_due, sessions, clock())
    ran = 0
    while (claimed := await asyncio.to_thread(_claim, sessions, clock())) is not None:
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
    lock: asyncio.Lock,
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
