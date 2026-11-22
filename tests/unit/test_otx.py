"""OTX subscription parsing and sync with synthetic pulses and an offline transport."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from insight import connectors, otx, services
from insight.models import Document, SourceRun
from insight.schemas import INDICATOR_KINDS
from insight.source_registry import SOURCES

SOURCE = 'alienvault-otx'
ENDPOINT = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
PUBLIC_ID = '1234567890abcdef12345678'
FIXTURE = Path(__file__).parents[1] / 'fixtures' / 'otx-pulses.json'
KEY = 'a' * 64  # synthetic OTX key


def pulse_data() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURE.read_bytes())
    return data


def test_public_clear_pulse_maps_supported_indicator_types() -> None:
    batch = otx.parse_pulses(FIXTURE.read_bytes(), SOURCES[SOURCE])
    assert batch.skipped == 1
    (item,) = batch.items
    assert item.external_id == PUBLIC_ID
    assert item.document.tlp == 'CLEAR'
    assert item.document.source_url == f'https://otx.alienvault.com/pulse/{PUBLIC_ID}'
    body = item.document.body
    for value in (
        '198.51.100.17',
        '2001:db8::17',
        'lab.example',
        'sensor.lab.example',
        'https://portal.example/study',
        'CVE-2024-12345',
        'a' * 32,
        'b' * 40,
        'c' * 64,
        'd' * 128,
    ):
        assert value in body
    for kind, value in (('cidr', '203.0.113.0/24'), ('email', 'analyst@example.org')):
        assert (value in body) == (kind in INDICATOR_KINDS)
    for skipped in ('192.0.2.84', '198.51.100.999', 'skip-fixture-value', 'confidential-marker'):
        assert skipped not in body


@pytest.mark.parametrize(
    'fields',
    [
        {'public': False, 'tlp': 'white'},
        {'public': 0, 'tlp': 'white'},
        {'tlp': 'white'},
        {'public': 'true', 'tlp': 'white'},
        {'public': 1},
        {'public': 1, 'tlp': 'green'},
        {'public': True, 'TLP': 'RED'},
        {'public': 1, 'tlp': None},
        {'public': 1, 'tlp': 'tbc'},
        {'public': True, 'tlp': 'clear', 'TLP': 'amber'},
        {'public': True, 'tlp': 'white', 'id': '../unexpected'},
        {'public': True, 'tlp': 'clear', 'description': 'Updated distribution: TLP:AMBER'},
        {'public': True, 'tlp': 'clear', 'name': 'Restricted title (TLP:RED)'},
        {'public': True, 'tlp': 'clear', 'indicators': 'broken'},
    ],
)
def test_uncertain_or_restricted_pulses_are_skipped(fields: dict[str, Any]) -> None:
    data = pulse_data()['results'][0]
    del data['public'], data['tlp']
    batch = otx.parse_pulses(json.dumps({'results': [data | fields]}).encode(), SOURCES[SOURCE])
    assert not batch.items
    assert batch.skipped == 1


@pytest.mark.parametrize(
    'fields', [{'public': True, 'TLP': 'TLP:CLEAR'}, {'public': 1, 'TLP': 'CLEAR', 'tlp': 'WHITE'}]
)
def test_explicit_white_or_clear_pulses_are_accepted(fields: dict[str, Any]) -> None:
    data = pulse_data()['results'][0]
    del data['tlp']
    batch = otx.parse_pulses(json.dumps({'results': [data | fields]}).encode(), SOURCES[SOURCE])
    assert [item.external_id for item in batch.items] == [PUBLIC_ID]
    assert batch.skipped == 0


def test_limits_pulses_per_page_and_indicators_per_pulse() -> None:
    template = pulse_data()['results'][0]
    indicators = [{'type': 'IPv4', 'indicator': f'192.0.2.{i}'} for i in range(1, 102)]
    rows = [template | {'id': f'{i:024x}', 'indicators': indicators} for i in range(1, 27)]
    batch = otx.parse_pulses(json.dumps({'results': rows}).encode(), SOURCES[SOURCE])
    assert [item.external_id for item in batch.items] == [row['id'] for row in rows[:25]]
    for item in batch.items:
        assert item.truncated
        assert '192.0.2.100' in item.document.body
        assert '192.0.2.101' not in item.document.body


@pytest.mark.parametrize(
    'payload', [b'example-secret-input', b'[]', b'{}', b'{"results":"example-secret-input"}']
)
def test_invalid_envelope_has_a_safe_error(payload: bytes) -> None:
    with pytest.raises(ValueError, match='OTX') as error:
        otx.parse_pulses(payload, SOURCES[SOURCE])
    assert 'example-secret-input' not in str(error.value)


def enable(factory: sessionmaker[Session]) -> None:
    with factory.begin() as db:
        services.set_source_switch(db, SOURCE, True, at=datetime.now(UTC))


async def test_otx_is_skipped_until_switched_on(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def no_download(*args: Any, **kwargs: Any) -> bytes:
        pytest.fail('OTX was contacted while switched off')

    monkeypatch.setattr(connectors, 'download', no_download)
    with session_factory.begin() as db:
        for key, source in SOURCES.items():
            if not source.optional:
                services.set_source_switch(db, key, False, at=datetime.now(UTC))
    with pytest.raises(connectors.SourceSwitchedOff):
        await connectors.sync_source(session_factory, SOURCE)
    assert await connectors.sync_all(session_factory) == []


@pytest.mark.parametrize('key', [None, 'synthetic invalid key'])
async def test_missing_or_invalid_key_fails_before_download(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, key: str | None
) -> None:
    async def no_download(*args: Any, **kwargs: Any) -> bytes:
        pytest.fail('OTX was contacted without a key')

    enable(session_factory)
    if key is None:
        monkeypatch.delenv('INSIGHT_OTX_API_KEY', raising=False)
    else:
        monkeypatch.setenv('INSIGHT_OTX_API_KEY', key)
    monkeypatch.setattr(connectors, 'download', no_download)
    with pytest.raises(connectors.SourceSyncError, match='INSIGHT_OTX_API_KEY') as error:
        await connectors.sync_source(session_factory, SOURCE)
    if key is not None:
        assert key not in str(error.value)


async def test_authentication_failure_keeps_credentials_out_of_sync_history(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def reject(url: str, params: Any = None, **kwargs: Any) -> bytes:
        request = httpx.Request('GET', url)
        raise httpx.HTTPStatusError(
            f'Denied synthetic key {KEY}', request=request, response=httpx.Response(401)
        )

    enable(session_factory)
    monkeypatch.setenv('INSIGHT_OTX_API_KEY', KEY)
    monkeypatch.setattr(connectors, 'download', reject)
    with pytest.raises(connectors.SourceSyncError, match='401') as error:
        await connectors.sync_source(session_factory, SOURCE)
    assert KEY not in str(error.value)
    with session_factory() as db:
        (run,) = db.scalars(select(SourceRun)).all()
        assert run.status == 'error'
        assert KEY not in run.message
        assert db.scalar(select(Document)) is None


async def test_bounded_request_is_repeatable_and_pulse_edits_become_revisions(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    data = {**pulse_data(), 'next': None}  # one page: paging is tested below
    calls: list[str] = []
    sent: list[dict[str, str]] = []

    async def fetch(url: str, params: Any = None, **kwargs: Any) -> bytes:
        assert url == ENDPOINT
        sent.append({k: str(v) for k, v in params.items()})
        assert httpx.Headers(kwargs['headers'])['X-OTX-API-KEY'] == KEY
        assert kwargs.get('validators') is None
        calls.append(url)
        return json.dumps(data).encode()

    enable(session_factory)
    monkeypatch.setenv('INSIGHT_OTX_API_KEY', KEY)
    monkeypatch.setattr(connectors, 'download', fetch)
    for _ in range(2):
        await connectors.sync_source(session_factory, SOURCE)
    with session_factory() as db:
        (first,) = db.scalars(select(Document)).all()
        assert (first.external_id, first.source_key, first.tlp) == (PUBLIC_ID, SOURCE, 'CLEAR')
        first_id = first.id
    data['results'][0]['indicators'].append({'type': 'IPv4', 'indicator': '192.0.2.193'})
    await connectors.sync_source(session_factory, SOURCE)
    assert calls == [ENDPOINT] * 3
    # The first sync asks for everything; later ones only for pulses changed since the newest one seen.
    since = {'page': '1', 'limit': '25', 'modified_since': '2026-11-20T12:00:00.000000'}
    assert sent == [{'page': '1', 'limit': '25'}, since, since]
    with session_factory() as db:
        current = db.scalars(select(Document).where(Document.is_current)).one()
        assert (current.supersedes_id, current.external_id) == (first_id, PUBLIC_ID)
        assert '192.0.2.193' in current.body
        assert len(db.scalars(select(Document)).all()) == 2
        assert all(r.status == 'success' and KEY not in r.message for r in db.scalars(select(SourceRun)))


# --------------------------------------------------------------------------- paging and resume (issue #11)


def page_of(n: int, *, more: bool, modified: str) -> dict[str, Any]:
    """A synthetic page holding one public pulse whose ID encodes ``n``."""
    pulse = {**pulse_data()['results'][0], 'id': f'{n:024x}', 'name': f'Pulse {n}', 'modified': modified}
    return {'count': 99, 'next': 'https://example.invalid/untrusted' if more else None, 'results': [pulse]}


class FakeOtx:
    """Serves numbered pages; ``fail_on`` pages raise a connection error."""

    def __init__(self, pages: dict[int, dict[str, Any]], fail_on: set[int] | None = None) -> None:
        self.pages, self.fail_on = pages, fail_on or set()
        self.sent: list[dict[str, str]] = []

    async def __call__(self, url: str, params: Any = None, **kwargs: Any) -> bytes:
        assert url == ENDPOINT  # never the provider's next link
        query = {k: str(v) for k, v in params.items()}
        self.sent.append(query)
        page = int(query['page'])
        if page in self.fail_on:
            raise httpx.ConnectError('offline')
        return json.dumps(self.pages[page]).encode()


def pulses(session_factory: sessionmaker[Session]) -> set[str]:
    with session_factory() as db:
        return {d.title for d in db.scalars(select(Document).where(Document.source_key == SOURCE))}


def cursor(session_factory: sessionmaker[Session]) -> otx.Cursor:
    with session_factory() as db:
        return otx.Cursor.parse(services.fetch_cursor(db, ENDPOINT))


async def test_a_long_backlog_is_read_a_few_pages_per_sync_and_resumes(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    pages = {n: page_of(n, more=n < 6, modified=f'2026-11-{10 + n:02d}T08:00:00') for n in range(1, 7)}
    fake = FakeOtx(pages)
    enable(session_factory)
    monkeypatch.setenv('INSIGHT_OTX_API_KEY', KEY)
    monkeypatch.setattr(connectors, 'download', fake)
    first = await connectors.sync_source(session_factory, SOURCE)
    assert first.endswith('More remain; the next sync continues from page 5.')
    assert [q['page'] for q in fake.sent] == ['1', '2', '3', '4']
    assert all('modified_since' not in q for q in fake.sent)
    assert pulses(session_factory) == {f'Pulse {n}' for n in range(1, 5)}
    assert cursor(session_factory) == otx.Cursor('', 5, '2026-11-14T08:00:00.000000')
    fake.sent.clear()
    second = await connectors.sync_source(session_factory, SOURCE)
    assert 'on 2 pages' in second
    assert 'More remain' not in second
    assert [q['page'] for q in fake.sent] == ['5', '6']
    assert pulses(session_factory) == {f'Pulse {n}' for n in range(1, 7)}
    # The pass is complete: the next sync asks only for what changed since its newest pulse.
    assert cursor(session_factory) == otx.Cursor('2026-11-16T08:00:00.000000', 1, '')
    fake.pages = {1: page_of(7, more=False, modified='2026-11-20T08:00:00')}
    fake.sent.clear()
    await connectors.sync_source(session_factory, SOURCE)
    assert fake.sent == [{'page': '1', 'limit': '25', 'modified_since': '2026-11-16T08:00:00.000000'}]
    assert cursor(session_factory).since == '2026-11-20T08:00:00.000000'


async def test_a_failed_page_keeps_earlier_pages_and_the_next_sync_continues_there(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    pages = {n: page_of(n, more=n < 3, modified=f'2026-11-0{n}T08:00:00') for n in range(1, 4)}
    fake = FakeOtx(pages, fail_on={2})
    enable(session_factory)
    monkeypatch.setenv('INSIGHT_OTX_API_KEY', KEY)
    monkeypatch.setattr(connectors, 'download', fake)
    with pytest.raises(connectors.SourceSyncError, match='OTX subscription request failed'):
        await connectors.sync_source(session_factory, SOURCE)
    assert pulses(session_factory) == {'Pulse 1'}  # page 1 was stored before page 2 failed
    assert cursor(session_factory) == otx.Cursor('', 2, '2026-11-01T08:00:00.000000')
    fake.fail_on.clear()
    fake.sent.clear()
    await connectors.sync_source(session_factory, SOURCE)
    assert [q['page'] for q in fake.sent] == ['2', '3']
    assert pulses(session_factory) == {'Pulse 1', 'Pulse 2', 'Pulse 3'}
    assert cursor(session_factory) == otx.Cursor('2026-11-03T08:00:00.000000', 1, '')
    with session_factory() as db:
        assert [r.status for r in db.scalars(select(SourceRun).order_by(SourceRun.created_at))] == [
            'error',
            'success',
        ]


@pytest.mark.parametrize(
    ('stored', 'expected'),
    [
        ('', otx.Cursor()),
        ('not json', otx.Cursor()),
        ('[1, 2]', otx.Cursor()),
        ('{"since": "yesterday", "page": 0, "newest": 5}', otx.Cursor()),
        ('{"since": "2026-11-20T08:00:00Z", "page": 3}', otx.Cursor('2026-11-20T08:00:00.000000', 3, '')),
        (
            '{"since": "2026-11-20T10:00:00+02:00", "page": true}',
            otx.Cursor('2026-11-20T08:00:00.000000', 1, ''),
        ),
    ],
)
def test_a_damaged_cursor_starts_over_instead_of_failing(stored: str, expected: otx.Cursor) -> None:
    assert otx.Cursor.parse(stored) == expected
