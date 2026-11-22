"""Offline provider contracts: subject binding, personal data removal, malformed and oversized answers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from insight import ip_asn, pivot_data, rdap

FIXTURES = Path(__file__).parents[1] / 'fixtures'


@pytest.mark.parametrize(
    ('file', 'value'), [('rdap-domain.json', 'example.com'), ('rdap-ip.json', '8.8.8.8')]
)
def test_rdap_retains_metadata_without_any_contacts(file: str, value: str) -> None:
    result = rdap.parse((FIXTURES / file).read_bytes(), value)
    assert result['found']
    serialized = json.dumps(result)
    assert 'PRIVATE' not in serialized
    assert 'private-contact' not in serialized
    assert 'vcard' not in serialized
    assert 'entities' not in serialized
    assert 'remarks' not in serialized


@pytest.mark.parametrize('raw', [b'[]', b'{', b'null', b'{}', b' ' * (pivot_data.MAX_BYTES + 1)])
def test_provider_parsers_refuse_invalid_or_oversized_answers(raw: bytes) -> None:
    with pytest.raises((ValueError, KeyError, TypeError)):
        rdap.parse(raw, 'example.com')
    with pytest.raises((ValueError, KeyError, TypeError)):
        ip_asn.network(raw, '8.8.8.8')


def test_provider_answers_must_cover_the_requested_subject() -> None:
    with pytest.raises(ValueError, match='another domain'):
        rdap.parse((FIXTURES / 'rdap-domain.json').read_bytes(), 'different.example.com')
    with pytest.raises(ValueError, match='another network'):
        rdap.parse((FIXTURES / 'rdap-ip.json').read_bytes(), '1.1.1.1')
    with pytest.raises(ValueError, match='another address'):
        ip_asn.network((FIXTURES / 'ripe-network.json').read_bytes(), '1.1.1.1')
    with pytest.raises(ValueError, match='disagree'):
        ip_asn.overview((FIXTURES / 'ripe-prefix.json').read_bytes(), '8.8.8.0/24', [64501])


def test_asn_keeps_all_confirmed_origins_and_holder() -> None:
    prefix, asns = ip_asn.network((FIXTURES / 'ripe-network.json').read_bytes(), '8.8.8.8')
    result = ip_asn.overview((FIXTURES / 'ripe-prefix.json').read_bytes(), prefix, asns)
    assert result['networks'] == [{'asn': 64500, 'holder': 'Synthetic network'}]
    assert result['nodes'] == [{'type': 'as', 'value': 'AS64500'}]


@pytest.mark.parametrize('invalid', [64500.9, True, False, 0, -1, 4294967296, '64500.0'])
def test_asn_rejects_coercible_invalid_values(invalid: Any) -> None:
    """Regression: a fractional or boolean provider ASN could be coerced into a valid network number."""
    data = json.loads((FIXTURES / 'ripe-prefix.json').read_bytes())
    data['data']['asns'][0]['asn'] = invalid
    with pytest.raises(ValueError, match='Invalid network number'):
        ip_asn.overview(json.dumps(data).encode(), '8.8.8.0/24', [64500])


@pytest.mark.parametrize(
    'value',
    [
        '127.0.0.1',
        '169.254.169.254',
        '192.168.0.1',
        '::1',
        'https://example.com',
        'example.com/path',
        'EXAMPLE.COM',
        'a.local',
    ],
)
def test_subjects_cannot_be_urls_private_addresses_or_unbounded_queries(value: str) -> None:
    with pytest.raises(ValueError, match='public IP address'):
        pivot_data.subject(value)


def test_bootstrap_is_pinned_and_selects_only_an_iana_https_endpoint() -> None:
    url, hosts = rdap.destination('example.com')
    assert url.startswith('https://')
    assert url.endswith('/domain/example.com')
    assert hosts
    assert 'example.invalid' not in hosts
    ip_url, _ = rdap.destination('8.8.8.8')
    assert ip_url.startswith('https://')
    assert ip_url.endswith('/ip/8.8.8.8')


def test_http_only_bootstrap_service_is_not_upgraded_or_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        rdap, '_bootstrap', lambda kind: {'services': [[['example'], ['http://rdap.example/']]]}
    )
    with pytest.raises(ValueError, match='No pinned HTTPS'):
        rdap.destination('host.example')
