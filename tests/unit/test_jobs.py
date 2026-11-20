"""Opt-in scheduled syncs (ADR 0018): schedules, the job queue, retries and the in-process runner.

A fake clock drives the runner; downloads are fakes, so nothing touches the network.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from insight import connectors, jobs, services
from insight.models import AuditEvent, Job, SourceRun
from insight.services import SOURCE_SYNC

T0 = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
RSS = b'<rss><channel><item><title>Advisory CVE-2024-9999</title></item></channel></rss>'


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: float) -> None:
        self.now += timedelta(**delta)


def schedule(factory: sessionmaker[Session], key: str, minutes: int, at: datetime = T0) -> None:
    with factory.begin() as db:
        services.set_actor(db, 'operator')
        services.set_schedule(db, key, minutes, at=at)


def all_jobs(factory: sessionmaker[Session]) -> list[tuple[str, str, int]]:
    with factory() as db:
        return [(j.key, j.status, j.attempts) for j in db.scalars(select(Job).order_by(Job.created_at))]


def runs(factory: sessionmaker[Session]) -> list[tuple[str, str]]:
    with factory() as db:
        return [(r.status, r.message) for r in db.scalars(select(SourceRun).order_by(SourceRun.created_at))]


# --------------------------------------------------------------------------- schedules


def test_a_schedule_runs_at_the_next_tick_then_every_interval(session_factory: sessionmaker[Session]) -> None:
    schedule(session_factory, 'cisa-kev', 360)
    with session_factory.begin() as db:
        kev = services.list_schedules(db)['cisa-kev']
        assert (kev.enabled, kev.interval_minutes, kev.next_run_at) == (True, 360, services.stamp(T0))
        assert [j.key for j in services.enqueue_due_schedules(db, at=T0)] == ['cisa-kev']
        assert kev.next_run_at == services.stamp(T0 + timedelta(hours=6))
        assert services.enqueue_due_schedules(db, at=T0 + timedelta(hours=5)) == []


def test_choosing_the_same_interval_again_keeps_the_next_run(session_factory: sessionmaker[Session]) -> None:
    schedule(session_factory, 'ncsc', 1440)
    schedule(session_factory, 'ncsc', 1440, at=T0 + timedelta(hours=3))
    with session_factory() as db:
        assert services.list_schedules(db)['ncsc'].next_run_at == services.stamp(T0)


def test_turning_a_schedule_off_stops_it_and_is_audited(session_factory: sessionmaker[Session]) -> None:
    schedule(session_factory, 'ncsc', 60)
    schedule(session_factory, 'ncsc', 0)
    with session_factory.begin() as db:
        ncsc = services.list_schedules(db)['ncsc']
        assert (ncsc.enabled, ncsc.next_run_at, ncsc.actor) == (False, None, 'operator')
        assert services.enqueue_due_schedules(db, at=T0 + timedelta(days=3)) == []
        events = db.scalars(select(AuditEvent).where(AuditEvent.action == 'schedule.update')).all()
    assert [(e.object_id, e.detail, e.actor) for e in events] == [
        ('ncsc', 'every 60 minutes', 'operator'),
        ('ncsc', 'off', 'operator'),
    ]


@pytest.mark.parametrize('minutes', [-1, 1, 30, 720, 10_080])
def test_only_the_offered_intervals_are_accepted(
    session_factory: sessionmaker[Session], minutes: int
) -> None:
    with (
        session_factory.begin() as db,
        pytest.raises(ValueError, match='Interval must be one of 0, 60, 360, 1440'),
    ):
        services.set_schedule(db, 'ncsc', minutes, at=T0)


def test_a_server_that_was_off_does_not_catch_up_with_a_burst(session_factory: sessionmaker[Session]) -> None:
    schedule(session_factory, 'sans-isc', 60)
    later = T0 + timedelta(days=2)
    with session_factory.begin() as db:
        assert len(services.enqueue_due_schedules(db, at=later)) == 1
        assert services.list_schedules(db)['sans-isc'].next_run_at == services.stamp(
            later + timedelta(hours=1)
        )


# --------------------------------------------------------------------------- the queue


def test_one_active_job_per_source(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as db:
        first = services.enqueue_job(db, SOURCE_SYNC, 'ncsc', at=T0, actor='schedule')
        assert services.enqueue_job(db, SOURCE_SYNC, 'ncsc', at=T0, actor='operator') is first
        other = services.enqueue_job(db, SOURCE_SYNC, 'sans-isc', at=T0)
        assert other is not first


def test_the_database_itself_refuses_a_second_active_job(session_factory: sessionmaker[Session]) -> None:
    """The partial unique index backs up enqueue_job against another process racing it."""
    with session_factory.begin() as db:
        db.add(Job(kind=SOURCE_SYNC, key='ncsc', status='queued', run_after=services.stamp(T0)))
    with pytest.raises(IntegrityError), session_factory.begin() as db:
        db.add(Job(kind=SOURCE_SYNC, key='ncsc', status='running', run_after=services.stamp(T0)))
    with session_factory.begin() as db:  # A finished job does not count.
        db.add(Job(kind=SOURCE_SYNC, key='ncsc', status='failed', run_after=services.stamp(T0)))


def test_claim_takes_the_oldest_due_job_once(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as db:
        services.enqueue_job(db, SOURCE_SYNC, 'ncsc', at=T0 + timedelta(minutes=5))
        services.enqueue_job(db, SOURCE_SYNC, 'sans-isc', at=T0)
    with session_factory.begin() as db:
        first = services.claim_job(db, at=T0)
        assert first is not None
        assert (first.key, first.status, first.attempts) == ('sans-isc', 'running', 1)
    with session_factory.begin() as db:
        assert services.claim_job(db, at=T0) is None  # ncsc is not due yet; sans-isc is taken
        second = services.claim_job(db, at=T0 + timedelta(minutes=5))
        assert second is not None
        assert second.key == 'ncsc'


def test_a_failed_job_is_retried_after_5_then_10_minutes_then_fails(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as db:
        job = services.enqueue_job(db, SOURCE_SYNC, 'ncsc', at=T0)
    at = T0
    for wait in (5, 10):
        with session_factory.begin() as db:
            claimed = services.claim_job(db, at=at)
            assert claimed is not None
            done = services.finish_job(db, claimed.id, ok=False, message='OSError: down', at=at)
            assert (done.status, done.run_after) == ('queued', services.stamp(at + timedelta(minutes=wait)))
        at += timedelta(minutes=wait)
    with session_factory.begin() as db:
        claimed = services.claim_job(db, at=at)
        assert claimed is not None
        done = services.finish_job(db, claimed.id, ok=False, message='OSError: still down', at=at)
        assert (done.status, done.attempts, done.message, done.finished_at) == (
            'failed', 3, 'OSError: still down', services.stamp(at)
        )  # fmt: skip
        assert done.id == job.id


def test_jobs_left_running_by_a_stopped_process_run_again(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as db:
        services.enqueue_job(db, SOURCE_SYNC, 'ncsc', at=T0)
        assert services.claim_job(db, at=T0) is not None
    with session_factory.begin() as db:
        assert services.requeue_running_jobs(db) == 1
    assert all_jobs(session_factory) == [('ncsc', 'queued', 1)]


def test_old_finished_jobs_are_pruned(session_factory: sessionmaker[Session]) -> None:
    with session_factory.begin() as db:
        for key, finished in (('ncsc', T0 - timedelta(days=40)), ('sans-isc', T0 - timedelta(days=1))):
            db.add(
                Job(
                    kind=SOURCE_SYNC,
                    key=key,
                    status='succeeded',
                    run_after='',
                    finished_at=services.stamp(finished),
                )
            )
        services.enqueue_job(db, SOURCE_SYNC, 'cisa-kev', at=T0 - timedelta(days=60))
    with session_factory.begin() as db:
        assert services.prune_jobs(db, before=T0 - jobs.KEEP_FINISHED) == 1
    assert sorted(k for k, _, _ in all_jobs(session_factory)) == ['cisa-kev', 'sans-isc']


# --------------------------------------------------------------------------- the runner


@pytest.fixture
def rss(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    async def download(url: str, params: Any = None, **_: Any) -> bytes:
        calls.append(url)
        return RSS

    monkeypatch.setattr(connectors, 'download', download)
    return calls


async def test_the_runner_syncs_scheduled_sources_and_skips_unchanged_feeds(
    session_factory: sessionmaker[Session], rss: list[str]
) -> None:
    clock, lock = Clock(), asyncio.Lock()
    schedule(session_factory, 'sans-isc', 60)
    assert await jobs.run_due(session_factory, lock, clock=clock) == 1
    clock.advance(minutes=30)
    assert await jobs.run_due(session_factory, lock, clock=clock) == 0
    clock.advance(minutes=31)
    assert await jobs.run_due(session_factory, lock, clock=clock) == 1
    assert runs(session_factory) == [
        ('success', 'Read 1 feed items; 1 new reports.'),
        ('success', connectors.UNCHANGED),
    ]
    assert all_jobs(session_factory) == [('sans-isc', 'succeeded', 1), ('sans-isc', 'succeeded', 1)]
    assert rss == [connectors.SOURCES['sans-isc'].url] * 2


async def test_the_runner_retries_a_failing_source_then_gives_up(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def offline(url: str, params: Any = None, **_: Any) -> bytes:
        raise OSError('offline')

    monkeypatch.setattr(connectors, 'download', offline)
    clock, lock = Clock(), asyncio.Lock()
    schedule(session_factory, 'ncsc', 1440)
    for minutes in (0, 5, 10):
        clock.advance(minutes=minutes)
        assert await jobs.run_due(session_factory, lock, clock=clock) == 1
        assert await jobs.run_due(session_factory, lock, clock=clock) == 0  # the retry waits its turn
    assert all_jobs(session_factory) == [('ncsc', 'failed', 3)]
    assert runs(session_factory) == [('error', 'OSError: offline')] * 3


async def test_the_runner_waits_for_a_sync_someone_started(
    session_factory: sessionmaker[Session], rss: list[str]
) -> None:
    lock = asyncio.Lock()
    schedule(session_factory, 'ncsc', 60)
    await lock.acquire()  # Someone pressed Sync now.
    task = asyncio.create_task(jobs.run_due(session_factory, lock, clock=Clock()))
    await asyncio.sleep(0.2)
    assert not task.done()
    assert rss == []
    lock.release()
    assert await task == 1


async def test_an_unknown_job_kind_fails_without_stopping_the_runner(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as db:
        db.add(Job(kind='mystery', key='x', status='queued', run_after=services.stamp(T0), max_attempts=1))
    assert await jobs.run_due(session_factory, asyncio.Lock(), clock=Clock()) == 1
    with session_factory() as db:
        job = db.scalar(select(Job))
        assert job is not None
        assert (job.status, job.message) == ('failed', "ValueError: No handler for job kind 'mystery'")


async def test_run_forever_recovers_logs_and_stops(
    session_factory: sessionmaker[Session], rss: list[str], caplog: pytest.LogCaptureFixture
) -> None:
    schedule(session_factory, 'ncsc', 360)
    with session_factory.begin() as db:
        services.enqueue_job(db, SOURCE_SYNC, 'sans-isc', at=T0)
        assert services.claim_job(db, at=T0) is not None  # left running by a stopped process
    stop = asyncio.Event()
    caplog.set_level(logging.INFO, logger='insight.jobs')
    task = asyncio.create_task(
        jobs.run_forever(session_factory, asyncio.Lock(), stop, tick=0.05, clock=Clock())
    )
    for _ in range(100):
        await asyncio.sleep(0.02)
        if len(rss) >= 2:
            break
    stop.set()
    await asyncio.wait_for(task, timeout=5)
    assert sorted(rss) == sorted([connectors.SOURCES['ncsc'].url, connectors.SOURCES['sans-isc'].url])
    assert 'Re-queued 1 job(s) left running by a stopped process' in caplog.text
    assert 'Scheduled syncs: ncsc every 360 min' in caplog.text


def test_describe_schedules_says_when_nothing_is_scheduled(session_factory: sessionmaker[Session]) -> None:
    assert jobs.describe_schedules(session_factory).startswith('No scheduled syncs')


# --------------------------------------------------------------------------- a time of day


MIDNIGHT = datetime(2026, 11, 21, 0, 0, tzinfo=UTC)


def test_a_daily_schedule_keeps_its_hour(session_factory: sessionmaker[Session]) -> None:
    """Daily at 00:00 UTC, chosen at 09:00: the first sync is tomorrow 00:00, and every one after at 00:00."""
    now = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
    with session_factory.begin() as db:
        services.set_schedule(db, 'cisa-kev', 1440, at=now, starts_at=services.time_of_day('00:00', now))
        assert services.list_schedules(db)['cisa-kev'].next_run_at == services.stamp(MIDNIGHT)
        assert services.enqueue_due_schedules(db, at=MIDNIGHT - timedelta(seconds=1)) == []
        ran_at = MIDNIGHT + timedelta(seconds=12)  # the runner's tick lands a little after the hour
        assert len(services.enqueue_due_schedules(db, at=ran_at)) == 1
        assert services.list_schedules(db)['cisa-kev'].next_run_at == services.stamp(
            MIDNIGHT + timedelta(days=1)
        )


def test_after_downtime_the_next_sync_is_still_on_the_hour(session_factory: sessionmaker[Session]) -> None:
    now = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
    with session_factory.begin() as db:
        services.set_schedule(db, 'ncsc', 360, at=now, starts_at=services.time_of_day('00:00', now))
        assert services.list_schedules(db)['ncsc'].next_run_at == services.stamp(now.replace(hour=12))
        back = datetime(2026, 11, 23, 14, 7, tzinfo=UTC)  # off for three days
        assert len(services.enqueue_due_schedules(db, at=back)) == 1  # once, not once per missed slot
        assert services.list_schedules(db)['ncsc'].next_run_at == services.stamp(
            back.replace(hour=18, minute=0)
        )


def test_a_start_time_in_the_future_is_kept(session_factory: sessionmaker[Session]) -> None:
    now = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)
    with session_factory.begin() as db:
        services.set_schedule(db, 'ncsc', 60, at=now, starts_at=services.time_of_day('23:30', now))
        assert services.list_schedules(db)['ncsc'].next_run_at == services.stamp(
            now.replace(hour=23, minute=30)
        )


@pytest.mark.parametrize('value', ['24:00', '7:00', '00:60', 'midnight', '00:00:00', ''])
def test_start_times_are_hh_mm_utc(value: str) -> None:
    with pytest.raises(ValueError, match='HH:MM in UTC'):
        services.time_of_day(value, T0)
