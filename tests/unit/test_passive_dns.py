"""Offline CIRCL interface, credential boundaries, passive-only requests and response validation."""

from __future__ import annotations

import base64
import json
import socket
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from tests.greynoise_fixtures import reviewed

from insight import connectors, pivot_data, pivots, services
from insight import passive_dns as pdns
from insight.connectors import ProviderError
from insight.lookups import THROTTLES
from insight.models import Enrichment

FIXTURE = Path(__file__).parents[1] / 'fixtures' / 'circl-pdns.ndjson'


@pytest.fixture(autouse=True)
def credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('INSIGHT_CIRCL_PDNS_USER', 'synthetic-user')
    monkeypatch.setenv('INSIGHT_CIRCL_PDNS_PASSWORD', 'synthetic-password')


def _row(**changes: Any) -> dict[str, Any]:
    row: dict[str, Any] = json.loads(FIXTURE.read_text().splitlines()[0])
    return row | changes


def _raw(*rows: dict[str, Any]) -> bytes:
    return '\n'.join(json.dumps(row) for row in rows).encode()


def test_metadata_binding_both_orientations_dedup_and_no_extra_fields() -> None:
    result = pdns.parse(FIXTURE.read_bytes(), 'example.com')
    assert result['found']
    assert not result['truncated']
    assert len(result['records']) == 4
    assert {n['value'] for n in result['nodes']} == {
        '198.51.100.5',
        '198.51.100.6',
        'ns1.example.net',
        'ns2.example.net',
    }
    assert 'DO-NOT-STORE' not in json.dumps(result)
    assert pdns.parse(b'', 'example.com') == {'found': False, 'records': [], 'truncated': False, 'nodes': []}
    repeated = pdns.parse(_raw(_row(), _row(time_first=1609459200, count=7)), 'example.com')
    assert len(repeated['records']) == 1
    assert repeated['records'][0]['count'] == 12
    assert repeated['records'][0]['first_seen'] == '2021-01-01T00:00:00+00:00'
    assert repeated['records'][0]['last_seen'] == '2025-01-01T00:00:00+00:00'
    assert pdns.parse(_raw(_row(rrname='8.8.8.8', rdata='example.com')), '8.8.8.8')['found']
    assert pdns.parse(_raw(_row(rdata='8.8.8.8')), '8.8.8.8')['found']


@pytest.mark.parametrize(
    'changes',
    [
        {'rrname': 'notexample.com'},
        {'rrname': 'example.com.attacker.net'},
        {'rrname': ''},
        {'rdata': ''},
        {'rdata': []},
        {'rdata': ['8.8.8.8', None]},
        {'rrname': 'x' * 2049},
        {'rdata': 'line\nbreak'},
        {'rrtype': True},
        {'rrtype': {}},
        {'rrtype': 'A\n'},
        {'time_first': True},
        {'time_first': -1},
        {'time_first': '9' * 20},
        {'time_first': 'yesterday'},
        {'time_last': 1},
        {'time_last': 2**63 - 1},
        {'count': -1},
        {'count': 'NaN'},
        {'count': False},
    ],
)
def test_invalid_or_unrelated_rows_fail_closed(changes: dict[str, Any]) -> None:
    with pytest.raises((ValueError, OverflowError, OSError)):
        pdns.parse(_raw(_row(**changes)), 'example.com')


@pytest.mark.parametrize('raw', [b'null', b'[]', b'<html>unavailable</html>', b'\xff', b'\n'])
def test_malformed_protocol_fails_closed(raw: bytes) -> None:
    with pytest.raises(ValueError, match=r'Invalid|Expecting|codec'):
        pdns.parse(raw, 'example.com')


def test_bounds_and_every_row_binding_including_after_output_cap() -> None:
    with pytest.raises(ValueError, match='large'):
        pdns.parse(b' ' * (pivot_data.MAX_BYTES + 1), 'example.com')
    with pytest.raises(ValueError, match='many'):
        pdns.parse(b'{}\n' * (pdns.MAX_RECORDS + 1), 'example.com')
    with pytest.raises(ValueError, match='answers'):
        pdns.parse(_raw(_row(rdata=['8.8.8.8'] * 501)), 'example.com')
    rows = [_row(rdata=f'n{i}.example.net') for i in range(501)]
    result = pdns.parse(_raw(*rows), 'example.com')
    assert len(result['records']) == len(result['nodes']) == 500
    assert result['truncated']
    with pytest.raises(ValueError, match='requested'):
        pdns.parse(_raw(*rows, _row(rrname='unrelated.example.net')), 'example.com')
    record = pdns.parse(_raw(_row(rrtype=16, rdata='plain text, not a graph node')), 'example.com')
    assert record['nodes'] == []
    assert record['records'][0]['type'] == '16'


def test_reverse_name_server_queries_do_not_invent_endpoint_roles() -> None:
    """Regression: a reverse NS lookup must not label a DNS zone as a name server."""
    record = pdns.parse(_raw(_row(rrtype='NS', rdata='ns1.example.net')), 'ns1.example.net')
    assert record['nodes'] == [{'type': 'domain', 'value': 'example.com'}]


@pytest.mark.parametrize(
    ('name', 'value'),
    [
        ('INSIGHT_CIRCL_PDNS_USER', ''),
        ('INSIGHT_CIRCL_PDNS_PASSWORD', ''),
        ('INSIGHT_CIRCL_PDNS_USER', 'bad:user'),
        ('INSIGHT_CIRCL_PDNS_PASSWORD', 'line\nbreak'),
        ('INSIGHT_CIRCL_PDNS_USER', 'é'),
        ('INSIGHT_CIRCL_PDNS_PASSWORD', 'x' * 1025),
    ],
)
async def test_missing_or_invalid_credentials_disable_before_any_request(
    monkeypatch: pytest.MonkeyPatch, db: Session, name: str, value: str
) -> None:
    services.set_pivot_switch(db, 'circl', True)
    monkeypatch.setenv(name, value)
    assert not pdns.configured()
    assert services.pivot_switches(db) == {'circl': False}
    with pytest.raises(ValueError, match='credentials'):
        services.set_pivot_switch(db, 'circl', True)
    with pytest.raises(ValueError, match='credentials'):
        pdns.request_headers()
    with pytest.raises(pivots.NotConfigured, match='credentials'):
        await pivots._fetch('circl', 'example.com')
    services.set_pivot_switch(db, 'circl', False)


async def test_fixed_https_endpoint_basic_auth_and_active_resolution_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[str, dict[str, str] | None, dict[str, Any]]] = []

    async def fake(url: str, params: dict[str, str] | None = None, **kwargs: Any) -> bytes:
        seen.append((url, params, kwargs))
        return FIXTURE.read_bytes()

    monkeypatch.setattr(pivots, 'download', fake)
    assert (await pivots._fetch('circl', 'example.com'))['found']
    assert len(seen) == 1
    url, params, options = seen[0]
    assert url == 'https://www.circl.lu/pdns/query/example.com'
    assert params is None
    assert options['allowed_hosts'] == frozenset({'www.circl.lu'})
    assert options['max_bytes'] == pivot_data.MAX_BYTES
    headers = options['headers']
    assert headers['dribble-disable-active-query'] == '1'
    assert headers['dribble-paginate-count'] == '501'
    assert (
        base64.b64decode(headers['Authorization'].removeprefix('Basic '))
        == b'synthetic-user:synthetic-password'
    )
    assert THROTTLES['circl'].interval == 5
    with pytest.raises(ValueError, match='public IP'):
        await pivots._fetch('circl', 'example.com/../../evil')
    assert len(seen) == 1


@pytest.mark.parametrize('status', [301, 401, 403, 429, 500])
async def test_http_errors_are_sanitized(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    async def fail(*args: Any, **kwargs: Any) -> bytes:
        request = httpx.Request('GET', 'https://www.circl.lu/pdns/query/DO-NOT-ECHO')
        response = httpx.Response(status, request=request, headers={'Retry-After': '120'})
        raise httpx.HTTPStatusError('synthetic-password DO-NOT-ECHO', request=request, response=response)

    monkeypatch.setattr(pivots, 'download', fail)
    THROTTLES['circl'].reset()
    with pytest.raises((ProviderError, pivots.RateLimited)) as raised:
        await pivots._fetch('circl', 'example.com')
    assert 'DO-NOT-ECHO' not in str(raised.value)
    assert 'synthetic-password' not in str(raised.value)
    if status == 429:
        assert THROTTLES['circl'].wait_time() > 119
    THROTTLES['circl'].reset()


async def test_bad_epoch_os_errors_are_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: platform timestamp failures must not bypass provider error normalization."""

    async def fake(*args: Any, **kwargs: Any) -> bytes:
        return FIXTURE.read_bytes()

    def invalid(raw: bytes, value: str) -> dict[str, Any]:
        raise OSError('DO-NOT-ECHO platform timestamp')

    monkeypatch.setattr(pivots, 'download', fake)
    monkeypatch.setattr(pdns, 'parse', invalid)
    with pytest.raises(ProviderError, match='invalid or unrelated') as caught:
        await pivots._fetch('circl', 'example.com')
    assert 'DO-NOT-ECHO' not in str(caught.value)


async def test_guarded_redirect_cannot_forward_credentials(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Regression: Basic credentials must never follow a provider redirect to another endpoint."""
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *_a, **_k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))],
    )
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={'Location': 'https://elsewhere.example/DO-NOT-ECHO'})

    async def guarded(url: str, params: dict[str, str] | None = None, **kwargs: Any) -> bytes:
        return await connectors.download(url, params, transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(pivots, 'download', guarded)
    with pytest.raises(ProviderError, match='connection, redirect or response limits') as caught:
        await pivots._fetch('circl', 'example.com')
    assert len(seen) == 1
    assert seen[0].url.host == '8.8.8.8'
    assert seen[0].headers['host'] == 'www.circl.lu'
    assert seen[0].extensions['sni_hostname'] == 'www.circl.lu'
    assert seen[0].headers['authorization'].startswith('Basic ')
    assert seen[0].headers['dribble-disable-active-query'] == '1'
    assert 'synthetic-password' not in caplog.text + str(caught.value)
    assert pdns.request_headers()['Authorization'] not in caplog.text + str(caught.value)
    assert 'DO-NOT-ECHO' not in str(caught.value)


@pytest.mark.parametrize('payload', [b'{}', b' ' * (pivot_data.MAX_BYTES + 1)])
async def test_failed_response_is_audited_but_never_cached(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, payload: bytes
) -> None:
    with session_factory.begin() as db:
        reviewed(db, 'example.com')
        services.set_pivot_switch(db, 'circl', True)

    async def fake(*args: Any, **kwargs: Any) -> bytes:
        return payload

    monkeypatch.setattr(pivots, 'download', fake)
    THROTTLES['circl'].reset()
    with pytest.raises(ProviderError, match='invalid or unrelated'):
        await pivots.lookup(session_factory, 'circl', 'example.com', approved=True, actor='operator')
    with session_factory() as db:
        assert db.scalar(select(Enrichment)) is None
        assert any(e.action == 'pivot.request' for e in services.audit_events(db))
    THROTTLES['circl'].reset()
