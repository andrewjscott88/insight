"""Review L5: background jobs run in lanes with their own locks, so a long sync or CVE lookup batch neither
blocks a person's sync nor holds up alerts. These tests use a file database (separate connections), where the
lanes run side by side; an in-memory database is one shared connection and its lanes take turns."""

from __future__ import annotations

import asyncio
import dataclasses
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import connectors, jobs, main, services
from insight.config import Settings
from insight.models import Job, database, shares_one_connection
from insight.services import ALERT_DELIVERY, CVE_LOOKUP, SOURCE_SYNC

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
CSRF = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')


@pytest.fixture
def file_sessions(database_url: str) -> Iterator[sessionmaker[Session]]:
    engine, factory = database(database_url)
    yield factory
    engine.dispose()


def status(factory: sessionmaker[Session], kind: str) -> str:
    with factory() as db:
        return db.scalars(select(Job.status).where(Job.kind == kind)).one()


class Slow:
    """A handler that runs until released."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def __call__(self, sessions: Any, key: str) -> str:
        self.started.set()
        await self.release.wait()
        return 'done'


async def wait_for(check: Any, seconds: float = 5.0) -> None:
    for _ in range(int(seconds / 0.02)):
        if check():
            return
        await asyncio.sleep(0.02)
    raise AssertionError('timed out')


def test_only_an_in_memory_database_makes_the_lanes_take_turns(
    session_factory: sessionmaker[Session], file_sessions: sessionmaker[Session]
) -> None:
    assert shares_one_connection(file_sessions) is False
    in_memory = session_factory.kw['bind'].url.render_as_string() == 'sqlite://'
    assert shares_one_connection(session_factory) is in_memory


@pytest.mark.parametrize('slow_kind', [SOURCE_SYNC, CVE_LOOKUP])
async def test_regression_l5_alerts_are_not_held_up_by_a_long_job(
    file_sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, slow_kind: str
) -> None:
    slow = Slow()

    async def deliver(sessions: Any, key: str) -> str:
        return 'sent'

    monkeypatch.setitem(jobs.HANDLERS, slow_kind, slow)
    monkeypatch.setitem(jobs.HANDLERS, ALERT_DELIVERY, deliver)
    with file_sessions.begin() as db:
        services.enqueue_job(db, slow_kind, 'k', at=NOW)
        services.enqueue_job(db, ALERT_DELIVERY, 'alerts', at=NOW)
    locks = jobs.JobLocks()
    runner = asyncio.create_task(jobs.run_due(file_sessions, locks, clock=lambda: NOW))
    await asyncio.wait_for(slow.started.wait(), 5)
    await wait_for(lambda: status(file_sessions, ALERT_DELIVERY) == 'succeeded')
    assert status(file_sessions, slow_kind) == 'running'
    assert locks.sync.locked() is (slow_kind == SOURCE_SYNC)  # a lookup leaves the sync lock free
    slow.release.set()
    assert await asyncio.wait_for(runner, 5) == 2


async def test_regression_l5_a_manual_sync_is_accepted_while_lookups_run(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before, a 65-second NVD batch held the one shared lock, so *Sync all* and *Sync now* answered 409."""
    slow = Slow()
    monkeypatch.setitem(jobs.HANDLERS, CVE_LOOKUP, slow)

    async def feed(url: str, params: Any = None, **_: Any) -> bytes:
        return b'<rss><channel><item><title>Advisory CVE-2024-9999</title></item></channel></rss>'

    monkeypatch.setattr(connectors, 'download', feed)
    app = main.create_app(dataclasses.replace(settings, run_jobs=False), with_ui=False)
    sessions = app.state.session_factory
    with sessions.begin() as db:
        services.enqueue_job(db, CVE_LOOKUP, 'nvd', at=NOW)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='http://testserver') as client,
    ):
        match = CSRF.search((await client.get('/login')).text)
        assert match is not None
        await client.post('/login', data={'csrf_token': match.group(1), 'password': settings.password})
        csrf = (await client.get('/api/session')).json()['csrf_token']
        runner = asyncio.create_task(
            jobs.run_due(sessions, jobs.JobLocks(sync=app.state.sync_lock), clock=lambda: NOW)
        )
        await asyncio.wait_for(slow.started.wait(), 5)
        response = await client.post('/api/sources/sans-isc/sync', headers={'X-CSRF-Token': csrf})
        assert response.status_code == 200, response.text
        slow.release.set()
        assert await asyncio.wait_for(runner, 5) == 1
