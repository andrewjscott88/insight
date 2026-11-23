"""RIPEstat routing metadata, bounded and bound to the requested address and prefix."""

from __future__ import annotations

import ipaddress
from typing import Any

from . import pivot_data


def _asn(value: Any) -> int:
    if type(value) is int:
        number = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 10:
        number = int(value)
    else:
        raise ValueError('Invalid network number')
    if not 0 < number <= 4294967295:
        raise ValueError('Invalid network number')
    return number


def network(raw: bytes, value: str) -> tuple[str, list[int]]:
    envelope = pivot_data.object_data(raw)
    data = envelope['data']
    if envelope.get('status') != 'ok' or envelope.get('data_call_name') != 'network-info':
        raise ValueError('Invalid routing data')
    prefix = data.get('prefix')
    if not prefix and data.get('asns') == []:
        return '', []
    block = ipaddress.ip_network(prefix)
    if ipaddress.ip_address(value) not in block:
        raise ValueError('Routing answer covers another address')
    raw_asns = data['asns']
    if not isinstance(raw_asns, list) or len(raw_asns) > 20:
        raise ValueError('Invalid announcing networks')
    asns = [_asn(a) for a in raw_asns]
    return str(block), sorted(set(asns))


def overview(raw: bytes, prefix: str, asns: list[int]) -> dict[str, Any]:
    envelope = pivot_data.object_data(raw)
    data = envelope['data']
    if (
        envelope.get('status') != 'ok'
        or envelope.get('data_call_name') != 'prefix-overview'
        or data.get('resource') != prefix
        or data.get('announced') is not True
    ):
        raise ValueError('Routing answer covers another prefix')
    rows = data['asns']
    if not isinstance(rows, list) or len(rows) > 20:
        raise ValueError('Invalid announcing networks')
    answers = {_asn(row['asn']): pivot_data.text(row.get('holder') or '') for row in rows}
    if sorted(answers) != asns:
        raise ValueError('Routing answers disagree; retry later')
    return {
        'found': True,
        'prefix': prefix,
        'networks': [{'asn': number, 'holder': answers[number]} for number in asns],
        'nodes': [{'type': 'as', 'value': f'AS{number}'} for number in asns],
    }
