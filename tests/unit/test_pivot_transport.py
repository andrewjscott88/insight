"""Offline transport contracts for manual, bounded infrastructure disclosures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from tests.greynoise_fixtures import IP, provider_error

from insight import pivot_data, pivots, rdap
from insight.connectors import ProviderError
from insight.lookups import THROTTLES, Throttle

FIXTURES = Path(__file__).parents[1] / 'fixtures'


@pytest.mark.parametrize('provider', ['rdap', 'asn'])
async def test_only_bounded_allowlisted_requests_supply_the_projection(
    monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    requests: list[tuple[str, dict[str, str] | None]] = []

    async def fetch(url: str, params: dict[str, str] | None = None, **options: Any) -> bytes:
        requests.append((url, params))
        assert options['max_bytes'] == pivot_data.MAX_BYTES
        if provider == 'rdap':
            assert url == 'https://rdap.example/ip/' + IP
            assert options['allowed_hosts'] == frozenset({'rdap.example'})
            return (FIXTURES / 'rdap-ip.json').read_bytes()
        assert options['allowed_hosts'] == frozenset({'stat.ripe.net'})
        fixture = 'ripe-network.json' if len(requests) == 1 else 'ripe-prefix.json'
        return (FIXTURES / fixture).read_bytes()

    monkeypatch.setattr(pivots, 'download', fetch)
    monkeypatch.setattr(
        rdap, 'destination', lambda value: ('https://rdap.example/ip/' + value, frozenset({'rdap.example'}))
    )
    monkeypatch.setitem(THROTTLES, 'asn', Throttle(0))
    result = await pivots._fetch(provider, IP)
    assert result['found']
    if provider == 'asn':
        assert requests == [
            ('https://stat.ripe.net/data/network-info/data.json', {'resource': IP}),
            (
                'https://stat.ripe.net/data/prefix-overview/data.json',
                {'resource': '8.8.8.0/24', 'max_related': '0'},
            ),
        ]
    else:
        assert len(requests) == 1


async def test_an_unannounced_address_does_not_trigger_a_second_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    async def fetch(*args: Any, **kwargs: Any) -> bytes:
        nonlocal calls
        calls += 1
        return json.dumps(
            {'status': 'ok', 'data_call_name': 'network-info', 'data': {'prefix': None, 'asns': []}}
        ).encode()

    monkeypatch.setattr(pivots, 'download', fetch)
    assert await pivots._fetch('asn', IP) == {'found': False, 'nodes': []}
    assert calls == 1


@pytest.mark.parametrize(
    'error',
    [
        provider_error(401),
        provider_error(302),
        httpx.ConnectError('PRIVATE-RAW'),
        OSError('PRIVATE-RAW'),
        ValueError('PRIVATE-RAW'),
        TimeoutError('PRIVATE-RAW'),
    ],
)
async def test_transport_failures_do_not_echo_upstream_urls_or_payloads(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    """Regression: provider connection and status failures must never echo untrusted response details."""

    async def fetch(*args: Any, **kwargs: Any) -> bytes:
        raise error

    monkeypatch.setattr(pivots, 'download', fetch)
    with pytest.raises(ProviderError) as caught:
        await pivots._request('https://rdap.example/domain/example.com', 'rdap', frozenset({'rdap.example'}))
    assert 'PRIVATE-RAW' not in str(caught.value)
    assert 'https://' not in str(caught.value)


@pytest.mark.parametrize(('header', 'seconds'), [('31', 31), ('0', 1), ('nonsense', 60), ('9' * 20, 60)])
async def test_provider_rate_limits_defer_every_caller_without_echoing_headers(
    monkeypatch: pytest.MonkeyPatch, header: str, seconds: int
) -> None:
    async def fetch(*args: Any, **kwargs: Any) -> bytes:
        raise provider_error(429, header)

    throttle = Throttle(2, clock=lambda: 0)
    monkeypatch.setitem(THROTTLES, 'rdap', throttle)
    monkeypatch.setattr(pivots, 'download', fetch)
    with pytest.raises(pivots.RateLimited) as caught:
        await pivots._request('https://rdap.example/', 'rdap', frozenset({'rdap.example'}))
    assert caught.value.seconds == seconds
    assert throttle.wait_time() == max(0, seconds if header != '0' else 0)
    assert 'PRIVATE-RAW' not in str(caught.value)


async def test_missing_bootstrap_is_a_sanitized_configuration_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: missing local bootstrap data must not turn into an unhandled server error or path leak."""

    def missing(value: str) -> tuple[str, frozenset[str]]:
        raise FileNotFoundError('PRIVATE-LOCAL-PATH')

    monkeypatch.setattr(rdap, 'destination', missing)
    with pytest.raises(pivots.NotConfigured) as caught:
        await pivots._fetch('rdap', 'example.com')
    assert 'PRIVATE-LOCAL-PATH' not in str(caught.value)


@pytest.mark.parametrize('raw', [b'{', b'[]', b'{"entities":[null]}', b' ' * (pivot_data.MAX_BYTES + 1)])
async def test_invalid_provider_answers_are_sanitized(monkeypatch: pytest.MonkeyPatch, raw: bytes) -> None:
    async def fetch(*args: Any, **kwargs: Any) -> bytes:
        return raw

    monkeypatch.setattr(pivots, 'download', fetch)
    with pytest.raises(ProviderError, match='invalid or unrelated'):
        await pivots._fetch('rdap', 'example.com')
