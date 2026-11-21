"""Passive GreyNoise Community lookups with a fake provider and synthetic reports."""

from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event
from typing import Any

import pytest
from sqlalchemy import event, select
from tests.greynoise_fixtures import ANSWER, IP, OTHER, provider_error, reviewed

from insight import greynoise, services
from insight.connectors import ProviderError
from insight.lookups import THROTTLES
from insight.models import Enrichment, EntityAssessment, Observation, SessionFactory, database
from insight.schemas import TLP


async def test_only_the_selected_address_leaves_and_cached_metadata_never_sets_a_verdict(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory.begin() as db:
        report_id = reviewed(db)
    calls = []

    async def provider(url: str, **opts: Any) -> bytes:
        calls.append((url, opts))
        return json.dumps(ANSWER).encode()

    monkeypatch.setattr(greynoise, 'download', provider)
    monkeypatch.setenv('INSIGHT_GREYNOISE_KEY', 'synthetic-key')
    answer = await greynoise.lookup(session_factory, IP, actor='operator')
    assert answer['found'] is True
    assert answer['classification'] == 'benign'
    assert answer['last_seen'] == '2026-11-20'
    assert datetime.fromisoformat(answer['fetched_at']).utcoffset() == timedelta(0)
    assert set(answer) == {
        'provider',
        'ip',
        'fetched_at',
        'found',
        'noise',
        'riot',
        'name',
        'classification',
        'last_seen',
    }
    assert await greynoise.lookup(session_factory, IP, actor='operator') == answer
    assert calls == [
        (
            'https://api.greynoise.io/v3/community/8.8.8.8',
            {'headers': {'key': 'synthetic-key'}, 'allowed_hosts': frozenset({'api.greynoise.io'})},
        )
    ]
    with session_factory.begin() as db:
        assert db.scalars(select(EntityAssessment)).all() == []
        assert [e.actor for e in services.audit_events(db) if e.action == 'ip.lookup'] == ['operator']
        services.delete_document(db, report_id, 'Synthetic retention test')
        assert db.scalars(select(Enrichment)).all() == []


@pytest.mark.parametrize(
    ('ip', 'tlp', 'review'),
    [
        ('192.0.2.1', 'CLEAR', 'accepted'),
        ('10.1.2.3', 'CLEAR', 'accepted'),
        ('224.0.0.1', 'CLEAR', 'accepted'),
        ('2001:4860:4860::8888', 'CLEAR', 'accepted'),
        ('8.8.8.0/24', 'CLEAR', 'accepted'),
        (IP, 'CLEAR', 'unreviewed'),
        (IP, 'CLEAR', 'rejected'),
        (IP, 'GREEN', 'accepted'),
        (IP, 'RED', 'accepted'),
    ],
)
async def test_ineligible_input_never_contacts_greynoise_or_consumes_quota(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch, ip: str, tlp: TLP, review: str
) -> None:
    with session_factory.begin() as db:
        reviewed(db, ip, tlp=tlp, status=review)
    monkeypatch.setenv('INSIGHT_GREYNOISE_KEY', 'fixture')
    with pytest.raises(LookupError, match='eligible'):
        await greynoise.lookup(session_factory, ip, actor='operator')
    assert THROTTLES['greynoise'].wait_time() == 0


async def test_missing_or_malformed_key_and_superseded_public_source_fail_closed(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory.begin() as db:
        src = services.SourceRef('fixture', 'stable-id')
        reviewed(db, source=src)
        reviewed(db, OTHER, source=src)
        reviewed(db, IP, tlp='AMBER')
    for key in ('', 'malformed\nkey'):
        monkeypatch.setenv('INSIGHT_GREYNOISE_KEY', key)
        with pytest.raises(greynoise.NotConfigured):
            await greynoise.lookup(session_factory, IP, actor='operator')
    monkeypatch.setenv('INSIGHT_GREYNOISE_KEY', 'fixture')
    with pytest.raises(LookupError):
        await greynoise.lookup(session_factory, IP, actor='operator')


async def test_not_found_is_cached_expires_and_provider_rate_limit_is_shared(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory.begin() as db:
        reviewed(db)
        reviewed(db, OTHER)
    monkeypatch.setenv('INSIGHT_GREYNOISE_KEY', 'fixture')
    codes = [404, 429]

    async def provider(*args: Any, **kwargs: Any) -> bytes:
        raise provider_error(codes.pop(0), '127')

    monkeypatch.setattr(greynoise, 'download', provider)
    result = await greynoise.lookup(session_factory, IP, actor='operator')
    assert result['found'] is False
    assert await greynoise.lookup(session_factory, IP, actor='operator') == result
    with session_factory.begin() as db:
        row = db.scalars(select(Enrichment)).one()
        row.fetched_at = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    THROTTLES['greynoise'].reset()
    for address in (IP, OTHER):
        with pytest.raises(greynoise.RateLimited) as limit:
            await greynoise.lookup(session_factory, address, actor='operator')
        assert 126 <= limit.value.seconds <= 127
    assert not codes
    with session_factory() as db:
        assert db.scalars(select(Enrichment)).one().fetched_at != result['fetched_at']


@pytest.mark.parametrize(
    'bad',
    [
        b'bad JSON',
        json.dumps({**ANSWER, 'ip': OTHER}).encode(),
        json.dumps({**ANSWER, 'noise': 'false'}).encode(),
        json.dumps({**ANSWER, 'last_seen': 'PRIVATE-RAW'}).encode(),
    ],
)
async def test_invalid_answers_are_redacted_and_not_cached(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch, bad: bytes
) -> None:
    with session_factory.begin() as db:
        reviewed(db)
    monkeypatch.setenv('INSIGHT_GREYNOISE_KEY', 'fixture')

    async def provider(*args: Any, **kwargs: Any) -> bytes:
        return bad

    monkeypatch.setattr(greynoise, 'download', provider)
    with pytest.raises(ProviderError, match='invalid Community') as raised:
        await greynoise.lookup(session_factory, IP, actor='operator')
    assert 'PRIVATE-RAW' not in str(raised.value)
    with session_factory() as db:
        assert services.cached_greynoise_context(db, IP) is None


async def test_simultaneous_fetches_and_retracted_disclosure_permission(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_factory.begin() as db:
        reviewed(db)
    monkeypatch.setenv('INSIGHT_GREYNOISE_KEY', 'fixture')
    started, resume = asyncio.Event(), asyncio.Event()

    async def provider(*args: Any, **kwargs: Any) -> bytes:
        started.set()
        await resume.wait()
        return json.dumps(ANSWER).encode()

    monkeypatch.setattr(greynoise, 'download', provider)
    first = asyncio.create_task(greynoise.lookup(session_factory, IP, actor='operator'))
    await asyncio.wait_for(started.wait(), 5)
    try:
        with pytest.raises(greynoise.RateLimited):
            await greynoise.lookup(session_factory, IP, actor='operator')
        with session_factory.begin() as db:
            db.scalars(select(Observation)).one().review_status = 'rejected'
    finally:
        resume.set()
    with pytest.raises(LookupError):
        await first
    with session_factory() as db:
        assert db.scalars(select(Enrichment)).all() == []


def test_retention_committing_before_first_cache_write_cannot_leave_an_orphan(database_url: str) -> None:
    # The fixture supplies a real file-backed SQLite DB or the configured PostgreSQL test database.
    engine, sessions = database(database_url, migrate=False)
    writing, resume = Event(), Event()

    def store() -> None:
        with sessions.begin() as db:

            def pause_first_write(
                _conn: Any, _cursor: Any, statement: str, _params: Any, _context: Any, _many: bool
            ) -> None:
                if not writing.is_set() and statement.startswith(('INSERT', 'UPDATE')):
                    writing.set()
                    assert resume.wait(timeout=10), 'retention did not finish'

            event.listen(db.connection(), 'before_cursor_execute', pause_first_write)
            services.store_greynoise_context(db, IP, {'found': False})

    try:
        with sessions.begin() as db:
            report_id = reviewed(db)
        with ThreadPoolExecutor(max_workers=1) as executor:
            worker = executor.submit(store)
            try:
                assert writing.wait(timeout=10), 'lookup did not reach its first write'
                with sessions.begin() as db:
                    services.delete_document(db, report_id, 'Synthetic retention request')
            finally:
                resume.set()
            with pytest.raises(LookupError, match='No eligible'):
                worker.result(timeout=10)
        with sessions() as db:
            assert db.scalars(select(Enrichment)).all() == []
            assert all(e.action != 'ip.lookup' for e in services.audit_events(db))
    finally:
        engine.dispose()
