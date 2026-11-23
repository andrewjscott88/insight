"""Offline crt.sh contract, response binding, bounds and sanitized failure cases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from insight import certificate_transparency as ct
from insight import pivot_data, pivots
from insight.connectors import ProviderError
from insight.lookups import THROTTLES

FIXTURE = Path(__file__).parents[1] / 'fixtures' / 'crtsh.json'


def _row(**changes: Any) -> dict[str, Any]:
    row: dict[str, Any] = json.loads(FIXTURE.read_text())[0]
    return row | changes


def test_names_issuer_dates_dedup_and_only_selected_metadata() -> None:
    raw = FIXTURE.read_bytes()
    rows = json.loads(raw)
    result = ct.parse(json.dumps([*rows, rows[0]]).encode(), 'example.com')
    assert result['found']
    assert not result['truncated']
    assert [r['name'] for r in result['certificates']] == [
        '*.example.com',
        'co.example.net',
        'www.example.com',
    ]
    last = result['certificates'][-1]
    assert last['issuer'] == 'CN=Synthetic Renewal'
    assert last['not_before'] == '2026-01-01T00:00:00+00:00'
    assert all(n['type'] == 'certificate_name' for n in result['nodes'])
    assert 'DO-NOT-STORE' not in json.dumps(result)
    assert ct.parse(json.dumps(list(reversed(rows))).encode(), 'example.com') == result
    assert ct.parse(b'[]', 'example.com') == {
        'found': False,
        'certificates': [],
        'truncated': False,
        'nodes': [],
    }


@pytest.mark.parametrize(
    'changes',
    [
        {'name_value': 'notexample.com'},
        {'name_value': 'example.com.attacker.net'},
        {'name_value': 'https://example.com'},
        {'name_value': '*.*.example.com'},
        {'name_value': 'www.example.com\n'},
        {'name_value': ['example.com']},
        {'name_value': 'x' * (ct.MAX_NAME_TEXT + 1)},
        {'issuer_name': 'line\nbreak'},
        {'issuer_name': ''},
        {'issuer_name': 42},
        {'not_before': 'not-a-date'},
        {'not_after': '2020-01-01T00:00:00'},
        {'not_after': None},
    ],
)
def test_invalid_or_unrelated_certificate_row_is_refused(changes: dict[str, Any]) -> None:
    if changes == {'name_value': 'www.example.com\n'}:
        # A normal trailing line ending from the upstream list is allowed.
        assert ct.parse(json.dumps([_row(**changes)]).encode(), 'example.com')['found']
        return
    with pytest.raises((ValueError, TypeError)):
        ct.parse(json.dumps([_row(**changes)]).encode(), 'example.com')


@pytest.mark.parametrize('raw', [b'{}', b'null', b'[1]', b'<html>unavailable</html>', b'\xff'])
def test_non_json_list_or_bad_encoding_is_refused(raw: bytes) -> None:
    with pytest.raises(ValueError, match=r'Invalid|Expecting|codec'):
        ct.parse(raw, 'example.com')


def test_response_bytes_records_and_unique_names_are_bounded() -> None:
    with pytest.raises(ValueError, match='too large'):
        ct.parse(b' ' * (pivot_data.MAX_BYTES + 1), 'example.com')
    with pytest.raises(ValueError, match='certificate list'):
        ct.parse(json.dumps([{}] * (ct.MAX_CERTIFICATES + 1)).encode(), 'example.com')
    names = '\n'.join(f'n{n}.example.com' for n in range(pivot_data.MAX_ROWS + 1))
    result = ct.parse(json.dumps([_row(name_value=names)]).encode(), 'example.com')
    assert len(result['certificates']) == len(result['nodes']) == pivot_data.MAX_ROWS
    assert result['truncated']


def test_every_row_is_bound_even_after_an_output_cap_or_an_earlier_match() -> None:
    """Regression: one matching row must not bless an unrelated later certificate response."""
    rows = [_row(), _row(name_value='unrelated.example.net')]
    with pytest.raises(ValueError, match='requested domain'):
        ct.parse(json.dumps(rows).encode(), 'example.com')
    with pytest.raises(ValueError, match='domain'):
        ct.parse(b'[]', '8.8.8.8')


async def test_fetch_uses_fixed_https_host_query_and_response_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, dict[str, str] | None, dict[str, Any]]] = []

    async def fake(url: str, params: dict[str, str] | None = None, **kwargs: Any) -> bytes:
        seen.append((url, params, kwargs))
        return FIXTURE.read_bytes()

    monkeypatch.setattr(pivots, 'download', fake)
    assert (await pivots._fetch('crtsh', 'example.com'))['found']
    assert seen == [
        (
            'https://crt.sh/',
            {'q': '%.example.com', 'output': 'json'},
            {'headers': None, 'allowed_hosts': frozenset({'crt.sh'}), 'max_bytes': pivot_data.MAX_BYTES},
        )
    ]
    assert THROTTLES['crtsh'].interval == 60


@pytest.mark.parametrize('status', [401, 403, 429, 500, 502])
async def test_provider_errors_never_echo_untrusted_response_or_url(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    async def fail(*args: Any, **kwargs: Any) -> bytes:
        request = httpx.Request('GET', 'https://crt.sh/?secret=DO-NOT-ECHO')
        response = httpx.Response(status, request=request, headers={'Retry-After': '120'})
        raise httpx.HTTPStatusError('DO-NOT-ECHO', request=request, response=response)

    monkeypatch.setattr(pivots, 'download', fail)
    THROTTLES['crtsh'].reset()
    with pytest.raises((ProviderError, pivots.RateLimited)) as raised:
        await pivots._fetch('crtsh', 'example.com')
    assert 'DO-NOT-ECHO' not in str(raised.value)
    assert 'https://' not in str(raised.value)
    if status == 429:
        assert THROTTLES['crtsh'].wait_time() > 119
    THROTTLES['crtsh'].reset()
