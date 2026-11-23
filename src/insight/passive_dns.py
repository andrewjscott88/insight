"""CIRCL passive DNS metadata: fixed endpoint, passive-only requests and bounded COF rows."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
from datetime import UTC, datetime
from typing import Any, Final

from . import pivot_data

HOST: Final = 'www.circl.lu'
URL: Final = 'https://www.circl.lu/pdns/query/'
MAX_RECORDS: Final = 10_000
_TYPE = re.compile(r'[A-Z][A-Z0-9-]{0,15}|[0-9]{1,5}')


def _credentials() -> tuple[str, str] | None:
    user = os.environ.get('INSIGHT_CIRCL_PDNS_USER', '')
    password = os.environ.get('INSIGHT_CIRCL_PDNS_PASSWORD', '')
    if (
        not user
        or not password
        or ':' in user
        or any(not part.isascii() or not part.isprintable() or len(part) > 1024 for part in (user, password))
    ):
        return None
    return user, password


def configured() -> bool:
    """Expose only availability, never credentials, to Settings and the disclosure boundary."""
    return _credentials() is not None


def request_headers() -> dict[str, str]:
    credentials = _credentials()
    if credentials is None:
        raise ValueError('Set the CIRCL passive DNS credentials on the server first.')
    token = base64.b64encode(':'.join(credentials).encode('ascii')).decode('ascii')
    return {
        'Authorization': 'Basic ' + token,
        # CIRCL defaults to active resolution unless this header is present.
        'dribble-disable-active-query': '1',
        'dribble-paginate-count': str(pivot_data.MAX_ROWS + 1),
    }


def _endpoint(value: str) -> tuple[str, str] | None:
    try:
        return 'address', str(ipaddress.ip_address(value))
    except ValueError:
        try:
            return 'domain', pivot_data.name(value)
        except ValueError:
            return None


def _integer(value: Any) -> int:
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 19:
        value = int(value)
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError('Invalid record count or time')
    return value


def _date(value: Any) -> str:
    return datetime.fromtimestamp(_integer(value), UTC).isoformat()


def parse(raw: bytes, value: str) -> dict[str, Any]:
    """Retain the provider's name/answer orientation; either endpoint must exactly match the query.

    CIRCL's v2 records may put the queried domain in rdata and an address in rrname. Preserving that
    orientation avoids inventing direction. Graph nodes are typed by their validated value, not that label.
    """
    _, subject = pivot_data.subject(value)
    if len(raw) > pivot_data.MAX_BYTES:
        raise ValueError('Response too large')
    lines = raw.decode('utf-8').splitlines()
    if len(lines) > MAX_RECORDS:
        raise ValueError('Too many passive DNS records')
    records: dict[tuple[str, str, str], dict[str, Any]] = {}
    scanned = 0
    for line in lines:
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError('Invalid passive DNS record')
        name = pivot_data.text(row.get('rrname'), 2048)
        rrtype = row.get('rrtype')
        if type(rrtype) is int:
            rrtype = str(rrtype)
        if not isinstance(rrtype, str) or not _TYPE.fullmatch(rrtype):
            raise ValueError('Invalid record type')
        answers = row.get('rdata')
        answers = answers if isinstance(answers, list) else [answers]
        if not answers or len(answers) > pivot_data.MAX_ROWS:
            raise ValueError('Invalid record answers')
        first, last = _date(row.get('time_first')), _date(row.get('time_last'))
        if last < first:
            raise ValueError('Invalid observation interval')
        count = None if row.get('count') is None else _integer(row['count'])
        for item in answers:
            answer = pivot_data.text(item, 2048)
            if not name or not answer:
                raise ValueError('Missing record endpoint')
            endpoints = (_endpoint(name), _endpoint(answer))
            if not any(endpoint and endpoint[1] == subject for endpoint in endpoints):
                raise ValueError('Record does not match the requested value')
            scanned += 1
            if scanned > MAX_RECORDS:
                raise ValueError('Too many passive DNS answers')
            key = (name, rrtype, answer)
            previous = records.get(key)
            counts = [c for c in (count, previous['count'] if previous else None) if c is not None]
            records[key] = {
                'name': name,
                'type': rrtype,
                'answer': answer,
                'first_seen': min(first, previous['first_seen']) if previous else first,
                'last_seen': max(last, previous['last_seen']) if previous else last,
                'count': max(counts) if counts else None,
            }
    selected = [records[key] for key in sorted(records)[: pivot_data.MAX_ROWS]]
    nodes = {
        endpoint
        for row in selected
        for field in ('name', 'answer')
        if (endpoint := _endpoint(row[field])) is not None and endpoint[1] != subject
    }
    return {
        'found': bool(selected),
        'records': selected,
        'truncated': len(records) > pivot_data.MAX_ROWS
        or scanned >= pivot_data.MAX_ROWS + 1
        or len(nodes) > pivot_data.MAX_ROWS,
        'nodes': [{'type': kind, 'value': name} for kind, name in sorted(nodes)[: pivot_data.MAX_ROWS]],
    }
