"""Parse public abuse.ch indicator metadata into reports. No network or file access."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Final

from .extraction import canonical
from .feed_items import MAX_FEED_ITEMS, FeedItem
from .ioc_export import defang
from .schemas import DocumentInput
from .source_registry import Source

_FOX_KINDS: Final = {
    'domain': 'domain',
    'url': 'url',
    'ip:port': 'ip',
    'ip': 'ip',
    'md5_hash': 'md5',
    'sha1_hash': 'sha1',
    'sha256_hash': 'sha256',
}


def _value(row: dict[str, object], field: str) -> str:
    value = row.get(field)
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= 2_000
        or not value.isprintable()
        or re.search(r'[\s<>"\\]', value)
    ):
        raise ValueError('Invalid indicator field')
    return value


def _numeric_id(row: dict[str, object]) -> str:
    value = row.get('id')
    if not isinstance(value, (int, str)) or not re.fullmatch(r'[0-9]{1,20}', str(value)):
        raise ValueError('Invalid record ID')
    return str(value)


def _seen(row: dict[str, object], field: str) -> str:
    """Only include a timestamp in the precise UTC format documented by these feeds."""
    raw = row.get(field)
    if isinstance(raw, str) and len(raw) <= 23:
        try:
            timestamp = datetime.strptime(raw.removesuffix(' UTC'), '%Y-%m-%d %H:%M:%S').replace(tzinfo=UTC)
        except ValueError:
            return ''
        return f'\nFirst seen (UTC): {timestamp:%Y-%m-%d %H:%M:%S}'
    return ''


def _urlhaus(row: dict[str, object], source: Source) -> FeedItem:
    record_id = _numeric_id(row)
    url = canonical('url', _value(row, 'url'))
    body = 'Reported URL: ' + defang('url', url) + _seen(row, 'date_added')
    status = row.get('url_status')
    if status in ('online', 'offline', 'unknown'):
        body += f'\nStatus reported by URLhaus: {status}'
    return FeedItem(
        DocumentInput(
            title=f'URLhaus URL record {record_id}',
            source_name=source.name,
            source_url=f'https://urlhaus.abuse.ch/url/{record_id}/',
            body=body,
            tlp='CLEAR',
        ),
        record_id,
    )


def _threatfox(row: dict[str, object], source: Source) -> FeedItem | None:
    ioc_type = _value(row, 'ioc_type')
    kind = _FOX_KINDS.get(ioc_type)
    if kind is None:
        return None
    record_id = _numeric_id(row)
    raw = _value(row, 'ioc')
    port_line = ''
    if ioc_type == 'ip:port':
        raw, separator, port = raw.rpartition(':')
        if not separator or not re.fullmatch(r'[0-9]{1,5}', port) or not 1 <= int(port) <= 65535:
            raise ValueError('Invalid network port')
        port_line = f'\nPort: {int(port)}'
    body = f'Reported {kind.upper()}: ' + defang(kind, canonical(kind, raw)) + port_line
    body += _seen(row, 'first_seen')
    confidence = row.get('confidence_level')
    if type(confidence) is int and 0 <= confidence <= 100:
        body += f'\nConfidence reported by ThreatFox: {confidence}%'
    return FeedItem(
        DocumentInput(
            title=f'ThreatFox indicator record {record_id}',
            source_name=source.name,
            source_url=f'https://threatfox.abuse.ch/ioc/{record_id}/',
            body=body,
            tlp='CLEAR',
        ),
        record_id,
    )


def _malwarebazaar(row: dict[str, object], source: Source) -> FeedItem:
    sha256 = canonical('sha256', _value(row, 'sha256_hash'))
    lines = [f'SHA-256: {sha256}']
    for kind in ('sha1', 'md5'):
        field = f'{kind}_hash'
        if row.get(field) is not None:
            lines.append(f'{kind.upper()}: {canonical(kind, _value(row, field))}')
    return FeedItem(
        DocumentInput(
            title=f'MalwareBazaar file record {sha256[:12]}',
            source_name=source.name,
            source_url=f'https://bazaar.abuse.ch/sample/{sha256}/',
            body='\n'.join(lines) + _seen(row, 'first_seen'),
            tlp='CLEAR',
        ),
        sha256,
    )


def parse_abusech(payload: bytes, source: Source) -> list[FeedItem]:
    """Read only the metadata fields we display from at most the first MAX_FEED_ITEMS results.

    Errors contain no response text, indicator values, keys or untrusted links. An unsupported
    ThreatFox indicator type is skipped, while a broken response cannot become an empty success.
    """
    parse = {'urlhaus': _urlhaus, 'threatfox': _threatfox, 'malwarebazaar': _malwarebazaar}[source.key]
    try:
        data = json.loads(payload)
    except (ValueError, RecursionError):
        raise ValueError(f'{source.name} returned invalid JSON') from None
    if not isinstance(data, dict):
        raise ValueError(f'{source.name} returned invalid metadata')
    if data.get('query_status') in ('no_result', 'no_results'):
        return []
    rows = data.get('urls' if source.key == 'urlhaus' else 'data')
    if data.get('query_status') != 'ok' or not isinstance(rows, list):
        raise ValueError(f'{source.name} did not return a metadata list')
    items: list[FeedItem] = []
    for row in rows[:MAX_FEED_ITEMS]:
        try:
            if not isinstance(row, dict):
                raise ValueError('Expected an object')
            item = parse(row, source)
        except ValueError:
            raise ValueError(f'{source.name} returned an invalid metadata record') from None
        if item is not None:
            items.append(item)
    return items
