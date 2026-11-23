"""Refresh pinned IANA RDAP bootstrap copies. Manual review of changed HTTPS hosts is required."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

from insight.connectors import download
from insight.pivot_data import object_data

ROOT = Path(__file__).resolve().parents[1] / 'src' / 'insight' / 'data'


async def refresh() -> None:
    collected: dict[str, bytes] = {}
    pins: dict[str, Any] = {}
    for kind in ('dns', 'ipv4', 'ipv6'):
        url = f'https://data.iana.org/rdap/{kind}.json'
        raw = await download(url, allowed_hosts=frozenset({'data.iana.org'}), max_bytes=2_000_000)
        data = object_data(raw)
        if not isinstance(data.get('services'), list) or not isinstance(data.get('publication'), str):
            raise ValueError('Invalid IANA bootstrap file')
        collected[kind] = raw
        pins[kind] = {
            'url': url,
            'publication': data['publication'],
            'sha256': hashlib.sha256(raw).hexdigest(),
        }
    # Validate every response before replacing any pinned file; review the resulting diff before commit.
    for kind, raw in collected.items():
        (ROOT / f'rdap-{kind}.json').write_bytes(raw)
    (ROOT / 'rdap-bootstrap-pins.json').write_text(json.dumps(pins, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    asyncio.run(refresh())
