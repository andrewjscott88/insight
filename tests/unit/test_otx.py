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
    data = pulse_data()
    calls: list[str] = []

    async def fetch(url: str, params: Any = None, **kwargs: Any) -> bytes:
        assert url == ENDPOINT
        assert {k: str(v) for k, v in params.items()} == {'page': '1', 'limit': '25'}
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
    with session_factory() as db:
        current = db.scalars(select(Document).where(Document.is_current)).one()
        assert (current.supersedes_id, current.external_id) == (first_id, PUBLIC_ID)
        assert '192.0.2.193' in current.body
        assert len(db.scalars(select(Document)).all()) == 2
        assert all(r.status == 'success' and KEY not in r.message for r in db.scalars(select(SourceRun)))
